package checker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func init() { Register(shodanInternetDB{}) }

// shodanInternetDB queries Shodan's free, keyless InternetDB lookup
// (https://internetdb.shodan.io/<ip>) for the last-known open ports, CPEs, and
// reported CVEs on the target's IP. It is passive from our side: a database
// read, no packets sent to the target.
type shodanInternetDB struct{}

func (shodanInternetDB) ID() string                               { return "osint.internetdb" }
func (shodanInternetDB) Name() string                             { return "Shodan InternetDB" }
func (shodanInternetDB) Category() Category                       { return CatOSINT }
func (shodanInternetDB) Mode() Mode                               { return Passive }
func (shodanInternetDB) Available(context.Context) (bool, string) { return true, "" }

const internetDBID = "osint.internetdb"

// internetDBResult is the JSON shape returned by internetdb.shodan.io.
type internetDBResult struct {
	Ports     []int    `json:"ports"`
	CPEs      []string `json:"cpes"`
	Hostnames []string `json:"hostnames"`
	Tags      []string `json:"tags"`
	Vulns     []string `json:"vulns"`
}

func (shodanInternetDB) Run(ctx context.Context, t Target) ([]Finding, error) {
	info := func(title, summary string) []Finding {
		return []Finding{{CheckerID: internetDBID, Category: CatOSINT, Severity: SevInfo,
			Title: title, Summary: summary}}
	}

	ip := firstIPv4(ctx, t.Host)
	if ip == "" {
		return info("No IP to query", "could not resolve "+t.Host+" to an IPv4 address"), nil
	}

	result, status, err := fetchInternetDB(ctx, ip)
	if err != nil {
		return info("InternetDB unavailable", err.Error()), nil
	}
	if status == http.StatusNotFound {
		return info("No InternetDB data", "Shodan has no InternetDB record for "+ip), nil
	}
	if status != http.StatusOK {
		return info("InternetDB unavailable", fmt.Sprintf("internetdb.shodan.io HTTP %d", status)), nil
	}

	return internetdbFindings(ip, result), nil
}

// firstIPv4 resolves name to its first A record, or "" if none.
func firstIPv4(ctx context.Context, name string) string {
	rrs, err := queryDNS(ctx, name, dns.TypeA)
	if err != nil {
		return ""
	}
	for _, rr := range rrs {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String()
		}
	}
	return ""
}

// fetchInternetDB performs the HTTP GET against internetdb.shodan.io. A
// non-200/404 status is returned alongside a nil error so the caller can
// decide how to report it; only transport-level failures are errors.
func fetchInternetDB(ctx context.Context, ip string) (internetDBResult, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://internetdb.shodan.io/"+ip, nil)
	if err != nil {
		return internetDBResult{}, 0, fmt.Errorf("build internetdb request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return internetDBResult{}, 0, fmt.Errorf("internetdb.shodan.io: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return internetDBResult{}, resp.StatusCode, nil
	}
	var r internetDBResult
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return internetDBResult{}, resp.StatusCode, fmt.Errorf("decode internetdb response: %w", err)
	}
	return r, resp.StatusCode, nil
}

// internetdbFindings turns one InternetDB result into findings. Pure function
// (no I/O) so it is fully unit-testable.
func internetdbFindings(ip string, r internetDBResult) []Finding {
	var findings []Finding

	if len(r.Ports) > 0 {
		ports := make([]string, len(r.Ports))
		for i, p := range r.Ports {
			ports[i] = strconv.Itoa(p)
		}
		findings = append(findings, Finding{
			CheckerID: internetDBID, Category: CatPort, Severity: SevInfo,
			Title: "Open ports (Shodan)",
			Summary: fmt.Sprintf("Shodan's last scan of %s reported open ports: %s (data may be stale)",
				ip, strings.Join(ports, ", ")),
			Evidence: map[string]any{"ip": ip, "ports": r.Ports, "hostnames": r.Hostnames, "tags": r.Tags},
		})
	}

	if len(r.Vulns) > 0 {
		findings = append(findings, Finding{
			CheckerID: internetDBID, Category: CatVuln, Severity: SevMedium,
			Title: "Known CVEs (Shodan)",
			Summary: fmt.Sprintf("%d CVE(s) reported by Shodan for %s, verify applicability: %s",
				len(r.Vulns), ip, strings.Join(r.Vulns, ", ")),
			Evidence: map[string]any{"ip": ip, "vulns": r.Vulns, "cpes": r.CPEs, "tags": r.Tags},
		})
	}

	if len(findings) == 0 {
		findings = append(findings, Finding{
			CheckerID: internetDBID, Category: CatOSINT, Severity: SevInfo,
			Title:    "InternetDB: no ports or CVEs",
			Summary:  "Shodan InternetDB has no open ports or known vulnerabilities on record for " + ip,
			Evidence: map[string]any{"ip": ip, "hostnames": r.Hostnames, "tags": r.Tags},
		})
	}

	return findings
}
