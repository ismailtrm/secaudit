package checker

import (
	"testing"
	"time"
)

func TestNewTarget(t *testing.T) {
	tests := []struct {
		raw        string
		wantDomain string
		wantHost   string
		wantErr    bool
	}{
		{"example.com", "example.com", "example.com", false},
		{"https://www.example.com/path", "example.com", "www.example.com", false},
		{"http://sub.example.co.uk", "example.co.uk", "sub.example.co.uk", false},
		{"  example.com  ", "example.com", "example.com", false},
		{"1.2.3.4", "", "", true}, // IPs rejected
		{"", "", "", true},        // empty rejected
		{"münchen.de", "xn--mnchen-3ya.de", "xn--mnchen-3ya.de", false}, // IDN → punycode
	}
	for _, tc := range tests {
		got, err := NewTarget(tc.raw, Own)
		if tc.wantErr {
			if err == nil {
				t.Errorf("NewTarget(%q): want error, got %+v", tc.raw, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("NewTarget(%q): unexpected error %v", tc.raw, err)
			continue
		}
		if got.Domain != tc.wantDomain || got.Host != tc.wantHost {
			t.Errorf("NewTarget(%q) = domain %q host %q, want domain %q host %q",
				tc.raw, got.Domain, got.Host, tc.wantDomain, tc.wantHost)
		}
	}
}

func TestSPFQuality(t *testing.T) {
	tests := []struct {
		spf string
		sev Severity
	}{
		{"v=spf1 include:_spf.google.com -all", SevInfo},
		{"v=spf1 a mx ~all", SevLow},
		{"v=spf1 ?all", SevLow},
		{"v=spf1 +all", SevHigh},
		{"v=spf1 a mx", SevInfo},
	}
	for _, tc := range tests {
		if sev, _ := spfQuality(tc.spf); sev != tc.sev {
			t.Errorf("spfQuality(%q) = %v, want %v", tc.spf, sev, tc.sev)
		}
	}
}

func TestDMARCQuality(t *testing.T) {
	tests := []struct {
		dmarc string
		sev   Severity
	}{
		{"v=DMARC1; p=reject; rua=mailto:x@y.com", SevInfo},
		{"v=DMARC1; p=quarantine", SevInfo},
		{"v=DMARC1; p=none", SevLow},
		{"v=DMARC1", SevLow},
	}
	for _, tc := range tests {
		if sev, _ := dmarcQuality(tc.dmarc); sev != tc.sev {
			t.Errorf("dmarcQuality(%q) = %v, want %v", tc.dmarc, sev, tc.sev)
		}
	}
}

func TestTagValue(t *testing.T) {
	rec := "v=DMARC1; p=reject; sp=quarantine; pct=100"
	for tag, want := range map[string]string{
		"v": "DMARC1", "p": "reject", "sp": "quarantine", "pct": "100", "missing": "",
	} {
		if got := tagValue(rec, tag); got != want {
			t.Errorf("tagValue(%q) = %q, want %q", tag, got, want)
		}
	}
}

func TestExpirySeverity(t *testing.T) {
	fmtDate := func(d time.Duration) string { return time.Now().Add(d).Format(time.RFC3339) }
	tests := []struct {
		date string
		sev  Severity
	}{
		{fmtDate(-24 * time.Hour), SevHigh},       // expired
		{fmtDate(10 * 24 * time.Hour), SevMedium}, // <30 days
		{fmtDate(400 * 24 * time.Hour), SevInfo},  // far out
		{"not-a-date", SevInfo},                   // unparseable → info
	}
	for _, tc := range tests {
		if sev, _ := expirySeverity(tc.date); sev != tc.sev {
			t.Errorf("expirySeverity(%q) = %v, want %v", tc.date, sev, tc.sev)
		}
	}
}
