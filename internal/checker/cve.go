package checker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ismailtrm/secaudit/internal/cache"
)

func init() { Register(cveCheck{}) }

// nvdBaseURL is the NVD 2.0 CVE endpoint; a var so tests can point it at httptest.
var nvdBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// cveCache returns the cache used for NVD responses; a var so tests can disable it.
var cveCache = cache.Default

const (
	cveTTL    = 24 * time.Hour
	cveMaxOut = 15
	cveCaveat = "This match is based on the version string only and is unconfirmed. " +
		"Distributions often backport security fixes while keeping the upstream version number, " +
		"so this may already be patched. External recon also cannot confirm that the vulnerable " +
		"code path is reachable or unmitigated. Verify against the vendor advisory."
)

// cpeMap maps a lowercased banner product to its NVD "<vendor>:<product>" CPE
// prefix. Every entry was verified against the live NVD API (totalResults > 0).
var cpeMap = map[string]string{
	"nginx":         "f5:nginx",
	"apache":        "apache:http_server",
	"apache2":       "apache:http_server",
	"httpd":         "apache:http_server",
	"php":           "php:php",
	"openssh":       "openbsd:openssh",
	"openssl":       "openssl:openssl",
	"lighttpd":      "lighttpd:lighttpd",
	"microsoft-iis": "microsoft:internet_information_services",
}

// cveCheck maps banner-disclosed software versions to known CVEs via NVD.
type cveCheck struct{}

func (cveCheck) ID() string                               { return "vuln.cve" }
func (cveCheck) Name() string                             { return "Known CVEs" }
func (cveCheck) Category() Category                       { return CatVuln }
func (cveCheck) Mode() Mode                               { return Passive }
func (cveCheck) Available(context.Context) (bool, string) { return true, "" }

func (cveCheck) Run(ctx context.Context, t Target) ([]Finding, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, _, err := fetch(ctx, client, t.Host)
	if err != nil {
		return []Finding{{CheckerID: "vuln.cve", Category: CatVuln, Severity: SevInfo,
			Title: "CVE lookup skipped: host unreachable over HTTP(S)"}}, nil
	}
	defer resp.Body.Close()
	return cveFindings(ctx, bannerProducts(resp.Header)), nil
}

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID      string `json:"id"`
	Metrics struct {
		V31 []nvdMetric `json:"cvssMetricV31"`
		V30 []nvdMetric `json:"cvssMetricV30"`
		V2  []nvdMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	Configurations []struct {
		Nodes []struct {
			CPEMatch []nvdCPEMatch `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

type nvdMetric struct {
	CVSSData struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"cvssData"`
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

// score returns the best available CVSS base score (V3.1, V3.0, then V2).
func (c nvdCVE) score() float64 {
	for _, ms := range [][]nvdMetric{c.Metrics.V31, c.Metrics.V30, c.Metrics.V2} {
		if len(ms) > 0 {
			return ms[0].CVSSData.BaseScore
		}
	}
	return 0
}

// cveHit is one CVE that applies to a detected product/version.
type cveHit struct {
	product, version, id string
	score                float64
}

// cveFindings looks up every mapped product and converts applicable CVEs into
// findings, sorted by CVSS and capped. Lookup failures yield one inconclusive finding.
func cveFindings(ctx context.Context, pairs []struct{ Product, Version string }) []Finding {
	var hits []cveHit
	var errs []error
	seen := map[string]bool{}
	for _, p := range pairs {
		cpe, ok := cpeMap[p.Product]
		if !ok || seen[p.Product+"/"+p.Version] {
			continue
		}
		seen[p.Product+"/"+p.Version] = true
		cves, err := nvdLookup(ctx, cpe)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.Product, err))
			continue
		}
		for _, c := range cves {
			if cveApplies(c, cpe, p.Version) {
				hits = append(hits, cveHit{p.Product, p.Version, c.ID, c.score()})
			}
		}
	}

	sort.SliceStable(hits, func(i, j int) bool { return hits[i].score > hits[j].score })
	var out []Finding
	for i, h := range hits {
		if i == cveMaxOut {
			out = append(out, Finding{CheckerID: "vuln.cve", Category: CatVuln, Severity: SevInfo,
				Title: fmt.Sprintf("%d more lower-severity CVEs not shown", len(hits)-cveMaxOut)})
			break
		}
		sev := cvssSeverity(h.score)
		out = append(out, Finding{CheckerID: "vuln.cve", Category: CatVuln, Severity: sev,
			Title:    fmt.Sprintf("Possible CVE %s in %s %s", h.id, h.product, h.version),
			Summary:  fmt.Sprintf("CVSS %.1f %s; needs validation", h.score, sev),
			Detail:   cveCaveat,
			Refs:     []string{"https://nvd.nist.gov/vuln/detail/" + h.id},
			Evidence: map[string]any{"product": h.product, "version": h.version, "cve": h.id, "cvss": h.score}})
	}
	if len(errs) > 0 {
		out = append(out, Finding{CheckerID: "vuln.cve", Category: CatVuln, Severity: SevInfo,
			Title: "CVE lookup inconclusive", Summary: "NVD query failed - could not determine",
			Err: errors.Join(errs...).Error()})
	}
	return out
}

func cvssSeverity(score float64) Severity {
	switch {
	case score >= 9.0:
		return SevCritical
	case score >= 7.0:
		return SevHigh
	case score >= 4.0:
		return SevMedium
	default:
		return SevLow
	}
}

// nvdLookup returns the CVEs NVD lists for a "<vendor>:<product>" CPE prefix,
// served from the cache when fresh. Only successful responses are cached.
func nvdLookup(ctx context.Context, cpe string) ([]nvdCVE, error) {
	key := "nvd:" + cpe
	c := cveCache()
	var body []byte
	if c != nil {
		if b, ok := c.Get(key); ok {
			body = b
		}
	}
	if body == nil {
		q := url.Values{}
		q.Set("virtualMatchString", "cpe:2.3:a:"+cpe)
		q.Set("resultsPerPage", "2000")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, nvdBaseURL+"?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		if k := os.Getenv("NVD_API_KEY"); k != "" {
			req.Header.Set("apiKey", k)
		}
		resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("NVD returned HTTP %d", resp.StatusCode)
		}
		body, err = io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		if err != nil {
			return nil, err
		}
	}
	var parsed nvdResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode NVD response: %w", err)
	}
	if c != nil {
		_ = c.Set(key, body, cveTTL)
	}
	cves := make([]nvdCVE, 0, len(parsed.Vulnerabilities))
	for _, v := range parsed.Vulnerabilities {
		cves = append(cves, v.CVE)
	}
	return cves, nil
}

// cveApplies reports whether any vulnerable cpeMatch of the CVE for the given
// "<vendor>:<product>" covers version v. Uncomparable versions never match.
func cveApplies(c nvdCVE, cpe, v string) bool {
	for _, cfg := range c.Configurations {
		for _, n := range cfg.Nodes {
			for _, m := range n.CPEMatch {
				if m.Vulnerable && matchApplies(m, cpe, v) {
					return true
				}
			}
		}
	}
	return false
}

func matchApplies(m nvdCPEMatch, cpe, v string) bool {
	parts := strings.Split(m.Criteria, ":")
	// cpe:2.3:<part>:<vendor>:<product>:<version>:...
	if len(parts) < 6 || parts[3]+":"+parts[4] != cpe {
		return false
	}
	bounded := m.VersionStartIncluding != "" || m.VersionStartExcluding != "" ||
		m.VersionEndIncluding != "" || m.VersionEndExcluding != ""
	if !bounded {
		if parts[5] == "*" || parts[5] == "-" {
			return false
		}
		c, ok := vercmp(v, parts[5])
		return ok && c == 0
	}
	check := func(bound string, pred func(int) bool) bool {
		if bound == "" {
			return true
		}
		c, ok := vercmp(v, bound)
		return ok && pred(c)
	}
	return check(m.VersionStartIncluding, func(c int) bool { return c >= 0 }) &&
		check(m.VersionStartExcluding, func(c int) bool { return c > 0 }) &&
		check(m.VersionEndIncluding, func(c int) bool { return c <= 0 }) &&
		check(m.VersionEndExcluding, func(c int) bool { return c < 0 })
}

// vercmp compares dotted-numeric versions. ok is false when either side is not
// dotted-numeric; a non-numeric suffix on a component (8.2p1) is ignored.
func vercmp(a, b string) (int, bool) {
	pa, oka := versionParts(a)
	pb, okb := versionParts(b)
	if !oka || !okb {
		return 0, false
	}
	for len(pa) < len(pb) {
		pa = append(pa, 0)
	}
	for len(pb) < len(pa) {
		pb = append(pb, 0)
	}
	for i := range pa {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

func versionParts(v string) ([]int, bool) {
	if v == "" {
		return nil, false
	}
	var out []int
	for _, s := range strings.Split(v, ".") {
		i := 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == 0 {
			return nil, false
		}
		n, err := strconv.Atoi(s[:i])
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}
