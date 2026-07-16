package checker

import (
	"net/http"
	"testing"
)

func TestHSTSQuality(t *testing.T) {
	tests := []struct {
		name string
		hsts string
		sev  Severity
	}{
		{"strong with preload", "max-age=63072000; includeSubDomains; preload", SevInfo},
		{"strong without preload", "max-age=31536000; includeSubDomains", SevInfo},
		{"short max-age", "max-age=3600; includeSubDomains", SevLow},
		{"missing includeSubDomains", "max-age=63072000", SevLow},
		{"disabled", "max-age=0", SevMedium},
		{"unparsable max-age", "max-age=notanumber", SevLow},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if sev, note := hstsQuality(tc.hsts); sev != tc.sev {
				t.Errorf("hstsQuality(%q) = %v (%q), want %v", tc.hsts, sev, note, tc.sev)
			}
		})
	}
}

func TestCSPQuality(t *testing.T) {
	tests := []struct {
		name string
		csp  string
		sev  Severity
	}{
		{"strict policy", "default-src 'self'; script-src 'self'", SevInfo},
		{"unsafe-inline", "script-src 'self' 'unsafe-inline'", SevLow},
		{"unsafe-eval", "script-src 'self' 'unsafe-eval'", SevLow},
		{"wildcard default-src", "default-src *", SevLow},
		{"wildcard script-src", "script-src *", SevLow},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if sev, note := cspQuality(tc.csp); sev != tc.sev {
				t.Errorf("cspQuality(%q) = %v (%q), want %v", tc.csp, sev, note, tc.sev)
			}
		})
	}
}

func TestCookieIssues(t *testing.T) {
	tests := []struct {
		name   string
		cookie *http.Cookie
		https  bool
		want   []string
	}{
		{
			name:   "missing Secure over https",
			cookie: &http.Cookie{Name: "sess", HttpOnly: true, SameSite: http.SameSiteStrictMode},
			https:  true,
			want:   []string{"Secure"},
		},
		{
			name:   "missing both Secure and HttpOnly over https",
			cookie: &http.Cookie{Name: "sess", SameSite: http.SameSiteStrictMode},
			https:  true,
			want:   []string{"Secure", "HttpOnly"},
		},
		{
			name:   "fully hardened",
			cookie: &http.Cookie{Name: "sess", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode},
			https:  true,
			want:   nil,
		},
		{
			name:   "SameSite unset is a weaker issue",
			cookie: &http.Cookie{Name: "sess", Secure: true, HttpOnly: true},
			https:  true,
			want:   []string{"SameSite"},
		},
		{
			name:   "SameSite None is a weaker issue",
			cookie: &http.Cookie{Name: "sess", Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode},
			https:  true,
			want:   []string{"SameSite"},
		},
		{
			name:   "Secure not required over plain http",
			cookie: &http.Cookie{Name: "sess", HttpOnly: true, SameSite: http.SameSiteStrictMode},
			https:  false,
			want:   nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cookieIssues(tc.cookie, tc.https)
			if len(got) != len(tc.want) {
				t.Fatalf("cookieIssues() = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("cookieIssues() = %v, want %v", got, tc.want)
				}
			}
		})
	}
}
