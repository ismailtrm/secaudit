package checker

import (
	"context"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestPolicySPFDMARCCorrelation(t *testing.T) {
	const title = "SPF without enforced DMARC: From-header spoofing still possible"
	tests := []struct {
		name string
		spf  string
		dm   string
		want bool
	}{
		{"spf, no dmarc", "v=spf1 -all", "", true},
		{"spf, dmarc none", "v=spf1 -all", "v=DMARC1; p=none", true},
		{"spf, dmarc reject", "v=spf1 -all", "v=DMARC1; p=reject", false},
		{"spf, dmarc quarantine", "v=spf1 -all", "v=DMARC1; p=quarantine", false},
		{"no spf, no dmarc", "", "", false},
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
			fs, err := dnsPolicy{}.Run(context.Background(), Target{Domain: "example.com", Host: "example.com"})
			if err != nil {
				t.Fatal(err)
			}
			if got := hasTitle(fs, title); got != tc.want {
				t.Errorf("correlation finding present = %v, want %v: %+v", got, tc.want, fs)
			}
		})
	}
}

func TestDKIMScenarios(t *testing.T) {
	target := Target{Domain: "example.com", Host: "example.com"}
	t.Run("selector present", func(t *testing.T) {
		srv := startStub(t, func(w dns.ResponseWriter, r *dns.Msg) {
			txt := ""
			if r.Question[0].Name == "selector1._domainkey.example.com." {
				txt = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"
			}
			reply(t, w, r, dns.RcodeSuccess, false, txt)
		}, nil)
		overrideResolvers(t, []string{srv}, []string{failingDoH(t)})
		fs, err := dkimCheck{}.Run(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}
		if len(fs) != 1 || fs[0].Title != "DKIM selector 'selector1' present" {
			t.Errorf("unexpected findings: %+v", fs)
		}
	})
	t.Run("none found", func(t *testing.T) {
		srv := startStub(t, fixed(t, nil, dns.RcodeNameError, false, ""), nil)
		overrideResolvers(t, []string{srv}, []string{failingDoH(t)})
		fs, err := dkimCheck{}.Run(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}
		if len(fs) != 1 || fs[0].Title != "No common DKIM selector found" || fs[0].Err != "" {
			t.Errorf("unexpected findings: %+v", fs)
		}
		if !strings.Contains(fs[0].Summary, "custom selector") {
			t.Errorf("summary lacks caveat: %q", fs[0].Summary)
		}
	})
	t.Run("lookup errors", func(t *testing.T) {
		srv := startStub(t, fixed(t, nil, dns.RcodeServerFailure, false, ""), nil)
		overrideResolvers(t, []string{srv}, []string{failingDoH(t)})
		fs, err := dkimCheck{}.Run(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}
		if len(fs) != 1 || fs[0].Title != "DKIM: lookup inconclusive" || fs[0].Err == "" {
			t.Errorf("unexpected findings: %+v", fs)
		}
		if hasTitle(fs, "No common DKIM selector found") {
			t.Error("false 'no selector' on lookup failure")
		}
	})
	t.Run("revoked key not counted", func(t *testing.T) {
		// "v=DKIM1; p=" (empty key) is a revoked selector, not an active one.
		srv := startStub(t, func(w dns.ResponseWriter, r *dns.Msg) {
			txt := ""
			if r.Question[0].Name == "selector1._domainkey.example.com." {
				txt = "v=DKIM1; p="
			}
			reply(t, w, r, dns.RcodeSuccess, false, txt)
		}, nil)
		overrideResolvers(t, []string{srv}, []string{failingDoH(t)})
		fs, err := dkimCheck{}.Run(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}
		if hasTitle(fs, "DKIM selector 'selector1' present") {
			t.Error("revoked key (empty p=) counted as present")
		}
		if len(fs) != 1 || fs[0].Title != "No common DKIM selector found" {
			t.Errorf("unexpected findings: %+v", fs)
		}
	})
	t.Run("wildcard domainkey", func(t *testing.T) {
		// A live key for every _domainkey name (including the random probe)
		// must be reported once as a wildcard, not as every selector present.
		srv := startStub(t, func(w dns.ResponseWriter, r *dns.Msg) {
			reply(t, w, r, dns.RcodeSuccess, false, "v=DKIM1; k=rsa; p=MIGfMA0GCSqG")
		}, nil)
		overrideResolvers(t, []string{srv}, []string{failingDoH(t)})
		fs, err := dkimCheck{}.Run(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}
		if len(fs) != 1 || fs[0].Title != "Wildcard _domainkey record present" {
			t.Errorf("wildcard not detected, got: %+v", fs)
		}
	})
}
