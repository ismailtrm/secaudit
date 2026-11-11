package checker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ismailtrm/secaudit/internal/cache"
)

func TestVercmp(t *testing.T) {
	tests := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.18.0", "1.20.0", -1, true},
		{"1.20.0", "1.18.0", 1, true},
		{"1.20.0", "1.20.0", 0, true},
		{"1.20", "1.20.0", 0, true},
		{"8.2p1", "8.2", 1, true},
		{"1.0.2k", "1.0.2h", 1, true},
		{"1.1.1", "1.1.1a", -1, true},
		{"1.1.1w", "1.1.1k", 1, true},
		{"beta", "1.0", 0, false},
		{"8.2p1", "8.3", -1, true},
		{"abc", "1.0", 0, false},
		{"1.0", "", 0, false},
		{"1..0", "1.0", 0, false},
	}
	for _, tc := range tests {
		got, ok := vercmp(tc.a, tc.b)
		if got != tc.want || ok != tc.ok {
			t.Errorf("vercmp(%q,%q) = %d,%v; want %d,%v", tc.a, tc.b, got, ok, tc.want, tc.ok)
		}
	}
}

func TestCVEApplies(t *testing.T) {
	cve := func(m nvdCPEMatch) nvdCVE {
		var c nvdCVE
		c.Configurations = []struct {
			Nodes []struct {
				CPEMatch []nvdCPEMatch `json:"cpeMatch"`
			} `json:"nodes"`
		}{{Nodes: []struct {
			CPEMatch []nvdCPEMatch `json:"cpeMatch"`
		}{{CPEMatch: []nvdCPEMatch{m}}}}}
		return c
	}
	const crit = "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
	endEx := nvdCPEMatch{Vulnerable: true, Criteria: crit, VersionEndExcluding: "1.20.0"}
	tests := []struct {
		name string
		m    nvdCPEMatch
		v    string
		want bool
	}{
		{"below end", endEx, "1.18.0", true},
		{"at excluded end", endEx, "1.20.0", false},
		{"above end", endEx, "1.21.0", false},
		{"start incl", nvdCPEMatch{Vulnerable: true, Criteria: crit, VersionStartIncluding: "1.0.0", VersionEndIncluding: "1.2.0"}, "1.0.0", true},
		{"start excl", nvdCPEMatch{Vulnerable: true, Criteria: crit, VersionStartExcluding: "1.0.0", VersionEndIncluding: "1.2.0"}, "1.0.0", false},
		{"exact pin", nvdCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"}, "1.18.0", true},
		{"exact pin other", nvdCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"}, "1.19.0", false},
		{"not vulnerable", nvdCPEMatch{Vulnerable: false, Criteria: crit, VersionEndExcluding: "1.20.0"}, "1.18.0", false},
		{"other product", nvdCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:f5:njs:*:*:*:*:*:*:*:*", VersionEndExcluding: "1.20.0"}, "1.18.0", false},
		{"unparseable version", endEx, "weird", false},
		{"unbounded wildcard", nvdCPEMatch{Vulnerable: true, Criteria: crit}, "1.18.0", false},
		{"short version vs bound", nvdCPEMatch{Vulnerable: true, Criteria: crit, VersionEndExcluding: "2.4.52"}, "2.4", false},
		{"short version vs exact", nvdCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:f5:nginx:2.4.1:*:*:*:*:*:*:*"}, "2.4", false},
		{"letter above end incl", nvdCPEMatch{Vulnerable: true, Criteria: crit, VersionEndIncluding: "1.0.2h"}, "1.0.2k", false},
		{"letter below end incl", nvdCPEMatch{Vulnerable: true, Criteria: crit, VersionEndIncluding: "1.0.2h"}, "1.0.2c", true},
		{"letter exact mismatch", nvdCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:f5:nginx:1.1.1k:*:*:*:*:*:*:*"}, "1.1.1w", false},
	}
	for _, tc := range tests {
		if got := cveApplies(cve(tc.m), "f5:nginx", tc.v); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

const nvdFixture = `{"vulnerabilities":[{"cve":{"id":"CVE-2099-0001",
"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]},
"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,
"criteria":"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*","versionEndExcluding":"1.20.0"}]}]}]}}]}`

func useNVD(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	oldURL, oldCache := nvdBaseURL, cveCache
	nvdBaseURL = srv.URL
	cveCache = func() *cache.Cache { return nil }
	t.Cleanup(func() { srv.Close(); nvdBaseURL, cveCache = oldURL, oldCache })
}

func TestCVEFindingsFromNVD(t *testing.T) {
	var gotQuery string
	useNVD(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("virtualMatchString")
		_, _ = w.Write([]byte(nvdFixture))
	})
	pair := func(v string) []struct{ Product, Version string } {
		return []struct{ Product, Version string }{{"nginx", v}}
	}

	fs := cveFindings(context.Background(), pair("1.18.0"))
	if gotQuery != "cpe:2.3:a:f5:nginx" {
		t.Errorf("query = %q", gotQuery)
	}
	if len(fs) != 1 || fs[0].Severity != SevMedium ||
		fs[0].Title != "Possible CVE CVE-2099-0001 in nginx 1.18.0" ||
		fs[0].Summary != "CVSS 9.8 CRITICAL; needs validation" || fs[0].Err != "" {
		t.Fatalf("unexpected findings: %+v", fs)
	}

	if fs := cveFindings(context.Background(), pair("1.21.0")); len(fs) != 0 {
		t.Errorf("out-of-range version produced findings: %+v", fs)
	}
	if fs := cveFindings(context.Background(), []struct{ Product, Version string }{{"unknownthing", "1.0"}}); len(fs) != 0 {
		t.Errorf("unmapped product produced findings: %+v", fs)
	}
}

func TestCVEFindingsInconclusive(t *testing.T) {
	useNVD(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })
	fs := cveFindings(context.Background(), []struct{ Product, Version string }{{"nginx", "1.18.0"}})
	if len(fs) != 1 || fs[0].Title != "CVE lookup inconclusive" || fs[0].Severity != SevInfo ||
		!strings.Contains(fs[0].Err, "403") {
		t.Fatalf("unexpected findings: %+v", fs)
	}
}

func TestCVECap(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"vulnerabilities":[`)
	for i := 0; i < 17; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"cve":{"id":"CVE-2099-` + strings.Repeat("1", i+1) + `","metrics":{"cvssMetricV2":[{"cvssData":{"baseScore":5.0}}]},"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*","versionEndExcluding":"2.0"}]}]}]}}`)
	}
	sb.WriteString(`]}`)
	useNVD(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(sb.String())) })
	fs := cveFindings(context.Background(), []struct{ Product, Version string }{{"nginx", "1.0"}})
	if len(fs) != cveMaxOut+1 || fs[cveMaxOut].Title != "2 more lower-severity CVEs not shown" {
		t.Fatalf("got %d findings, last %q", len(fs), fs[len(fs)-1].Title)
	}
}

func TestCVETruncated(t *testing.T) {
	body := strings.Replace(nvdFixture, `{"vulnerabilities"`, `{"totalResults":2500,"vulnerabilities"`, 1)
	useNVD(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) })
	fs := cveFindings(context.Background(), []struct{ Product, Version string }{{"nginx", "1.18.0"}})
	var found bool
	for _, f := range fs {
		if f.Title == "CVE list incomplete for nginx" {
			found = true
			if f.Severity != SevInfo || f.Summary != "NVD lists 2500 CVEs; only the first 2000 were checked" {
				t.Errorf("unexpected truncation finding: %+v", f)
			}
		}
	}
	if !found {
		t.Fatalf("missing truncation finding: %+v", fs)
	}
}
