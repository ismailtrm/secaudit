package checker

import "testing"

func TestInternetDBFindings(t *testing.T) {
	tests := []struct {
		name   string
		ip     string
		result internetDBResult
		want   []struct {
			title string
			sev   Severity
			cat   Category
		}
	}{
		{
			name: "ports and vulns",
			ip:   "1.2.3.4",
			result: internetDBResult{
				Ports:     []int{22, 80, 443},
				CPEs:      []string{"cpe:/a:openbsd:openssh"},
				Hostnames: []string{"host.example.com"},
				Tags:      []string{"cloud"},
				Vulns:     []string{"CVE-2024-0001", "CVE-2024-0002"},
			},
			want: []struct {
				title string
				sev   Severity
				cat   Category
			}{
				{"Open ports (Shodan)", SevInfo, CatPort},
				{"Known CVEs (Shodan)", SevMedium, CatVuln},
			},
		},
		{
			name:   "empty result",
			ip:     "5.6.7.8",
			result: internetDBResult{},
			want: []struct {
				title string
				sev   Severity
				cat   Category
			}{
				{"InternetDB: no ports or CVEs", SevInfo, CatOSINT},
			},
		},
		{
			name: "only tags and hostnames, no ports or vulns",
			ip:   "9.9.9.9",
			result: internetDBResult{
				Hostnames: []string{"foo.example.com"},
				Tags:      []string{"cdn"},
			},
			want: []struct {
				title string
				sev   Severity
				cat   Category
			}{
				{"InternetDB: no ports or CVEs", SevInfo, CatOSINT},
			},
		},
		{
			name: "only ports, no vulns",
			ip:   "10.0.0.1",
			result: internetDBResult{
				Ports: []int{8080},
			},
			want: []struct {
				title string
				sev   Severity
				cat   Category
			}{
				{"Open ports (Shodan)", SevInfo, CatPort},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := internetdbFindings(tt.ip, tt.result)
			if len(got) != len(tt.want) {
				t.Fatalf("internetdbFindings() returned %d findings, want %d: %+v", len(got), len(tt.want), got)
			}
			for i, w := range tt.want {
				f := got[i]
				if f.Title != w.title {
					t.Errorf("finding %d Title = %q, want %q", i, f.Title, w.title)
				}
				if f.Severity != w.sev {
					t.Errorf("finding %d Severity = %v, want %v", i, f.Severity, w.sev)
				}
				if f.Category != w.cat {
					t.Errorf("finding %d Category = %v, want %v", i, f.Category, w.cat)
				}
				if f.CheckerID != internetDBID {
					t.Errorf("finding %d CheckerID = %q, want %q", i, f.CheckerID, internetDBID)
				}
			}
		})
	}

	// Tags and hostnames must be folded into evidence, not separate findings.
	res := internetDBResult{
		Ports:     []int{80},
		Hostnames: []string{"foo.example.com"},
		Tags:      []string{"cdn"},
	}
	got := internetdbFindings("1.1.1.1", res)
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 finding for ports-only result, got %d", len(got))
	}
	ev := got[0].Evidence
	if hn, ok := ev["hostnames"].([]string); !ok || len(hn) != 1 || hn[0] != "foo.example.com" {
		t.Errorf("expected hostnames folded into evidence, got %v", ev["hostnames"])
	}
	if tg, ok := ev["tags"].([]string); !ok || len(tg) != 1 || tg[0] != "cdn" {
		t.Errorf("expected tags folded into evidence, got %v", ev["tags"])
	}
}
