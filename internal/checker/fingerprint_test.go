package checker

import (
	"net/http"
	"reflect"
	"testing"
)

func TestFingerprint(t *testing.T) {
	tests := []struct {
		name         string
		headers      map[string]string
		cookies      []*http.Cookie
		wantTech     []string
		wantVersions []string
	}{
		{
			name:         "server and powered-by versions",
			headers:      map[string]string{"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3"},
			wantTech:     []string{"PHP", "nginx"},
			wantVersions: []string{"PHP/7.4.3", "nginx/1.18.0"},
		},
		{
			name:         "server without version",
			headers:      map[string]string{"Server": "cloudflare"},
			wantTech:     []string{},
			wantVersions: []string{},
		},
		{
			name:         "php session cookie",
			cookies:      []*http.Cookie{{Name: "PHPSESSID", Value: "x"}},
			wantTech:     []string{"PHP"},
			wantVersions: []string{},
		},
		{
			name:         "drupal header",
			headers:      map[string]string{"X-Drupal-Cache": "HIT"},
			wantTech:     []string{"Drupal"},
			wantVersions: []string{},
		},
		{
			name:         "x-generator verbatim and dedup",
			headers:      map[string]string{"X-Generator": "Drupal 9", "X-Pingback": "x"},
			cookies:      []*http.Cookie{{Name: "wordpress_logged_in_abc", Value: "x"}},
			wantTech:     []string{"Drupal 9", "WordPress"},
			wantVersions: []string{},
		},
		{
			name:         "parenthesized comment stripped",
			headers:      map[string]string{"Server": "Apache/2.4.41 (Ubuntu)"},
			wantTech:     []string{"Apache"},
			wantVersions: []string{"Apache/2.4.41"},
		},
		{
			name:         "hostname-style value has no version",
			headers:      map[string]string{"Server": "github.com"},
			wantTech:     []string{},
			wantVersions: []string{},
		},
		{
			name:         "parenthesized token ignored",
			headers:      map[string]string{"Server": "ECS (nyb/1D2E)"},
			wantTech:     []string{},
			wantVersions: []string{},
		},
		{
			name:         "case-insensitive tech dedup",
			headers:      map[string]string{"X-Generator": "wordpress"},
			cookies:      []*http.Cookie{{Name: "wordpress_logged_in_abc", Value: "x"}},
			wantTech:     []string{"WordPress"},
			wantVersions: []string{},
		},
		{
			name:         "no signals",
			wantTech:     []string{},
			wantVersions: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			for k, v := range tt.headers {
				h.Set(k, v)
			}
			tech, versions := fingerprint(h, tt.cookies)
			if !reflect.DeepEqual(tech, tt.wantTech) {
				t.Errorf("tech = %v, want %v", tech, tt.wantTech)
			}
			if !reflect.DeepEqual(versions, tt.wantVersions) {
				t.Errorf("versions = %v, want %v", versions, tt.wantVersions)
			}
		})
	}
}
