package checker

import (
	"context"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func findingByTitle(fs []Finding, title string) (Finding, bool) {
	for _, f := range fs {
		if f.Title == title {
			return f, true
		}
	}
	return Finding{}, false
}

func TestFix(t *testing.T) {
	d, refs := fix("no-dmarc", "example.com")
	if !strings.Contains(d, "_dmarc.example.com") || strings.Contains(d, "{{domain}}") || len(refs) == 0 {
		t.Errorf("unexpected fix: %q %v", d, refs)
	}
	for _, key := range []string{"", "bogus"} {
		if d, refs := fix(key, "x"); d != "" || refs != nil {
			t.Errorf("fix(%q) = %q, %v; want empty", key, d, refs)
		}
	}
}

func TestPolicyRemediation(t *testing.T) {
	target := Target{Domain: "example.com", Host: "example.com"}
	tests := []struct {
		name       string
		spf, dm    string
		wantDetail map[string]bool
	}{
		{"gaps", "", "", map[string]bool{"No SPF record": true, "No DMARC record": true}},
		{"good config", "v=spf1 -all", "v=DMARC1; p=reject", map[string]bool{"SPF record": false, "DMARC record": false}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := startStub(t, func(w dns.ResponseWriter, r *dns.Msg) {
				name := r.Question[0].Name
				txt := ""
				switch {
				case strings.HasPrefix(name, "_dmarc."):
					txt = tc.dm
				case name == "example.com.":
					txt = tc.spf
				}
				reply(t, w, r, dns.RcodeSuccess, false, txt)
			}, nil)
			overrideResolvers(t, []string{srv}, []string{failingDoH(t)})
			fs, err := dnsPolicy{}.Run(context.Background(), target)
			if err != nil {
				t.Fatal(err)
			}
			for title, want := range tc.wantDetail {
				f, ok := findingByTitle(fs, title)
				if !ok {
					t.Fatalf("finding %q missing: %+v", title, fs)
				}
				if got := f.Detail != "" && len(f.Refs) > 0; got != want {
					t.Errorf("%q has remediation = %v, want %v: %+v", title, got, want, f)
				}
				if !want && (f.Detail != "" || len(f.Refs) != 0) {
					t.Errorf("%q must carry no remediation: %+v", title, f)
				}
			}
		})
	}
}

func TestDNSSECAndDKIMRemediation(t *testing.T) {
	target := Target{Domain: "example.com", Host: "example.com"}
	srv := startStub(t, fixed(t, nil, dns.RcodeSuccess, false, ""), nil)
	overrideResolvers(t, []string{srv}, []string{failingDoH(t)})
	tests := []struct {
		name  string
		title string
		run   func() ([]Finding, error)
	}{
		{"dnssec off", "DNSSEC not enabled", func() ([]Finding, error) { return dnssecCheck{}.Run(context.Background(), target) }},
		{"no dkim", "No common DKIM selector found", func() ([]Finding, error) { return dkimCheck{}.Run(context.Background(), target) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs, err := tc.run()
			if err != nil {
				t.Fatal(err)
			}
			f, ok := findingByTitle(fs, tc.title)
			if !ok {
				t.Fatalf("finding %q missing: %+v", tc.title, fs)
			}
			if f.Detail == "" || len(f.Refs) == 0 {
				t.Errorf("%q lacks remediation: %+v", tc.title, f)
			}
		})
	}
}
