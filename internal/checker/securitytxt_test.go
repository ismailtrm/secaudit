package checker

import "testing"

func TestParseSecurityTxt(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantContact string
		wantOK      bool
	}{
		{
			name:        "valid body with Contact",
			body:        "# comment\nContact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00.000Z\n",
			wantContact: "mailto:security@example.com",
			wantOK:      true,
		},
		{
			name:        "case-insensitive field name",
			body:        "CONTACT: https://example.com/security\n",
			wantContact: "https://example.com/security",
			wantOK:      true,
		},
		{
			name:   "random HTML",
			body:   "<html><head><title>404 Not Found</title></head><body>Not Found</body></html>",
			wantOK: false,
		},
		{
			name:   "empty body",
			body:   "",
			wantOK: false,
		},
		{
			name:   "comments only, no contact",
			body:   "# security.txt\n# see RFC 9116\n",
			wantOK: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			contact, ok := parseSecurityTxt(tc.body)
			if ok != tc.wantOK {
				t.Fatalf("parseSecurityTxt(%q) ok = %v, want %v", tc.body, ok, tc.wantOK)
			}
			if ok && contact != tc.wantContact {
				t.Errorf("parseSecurityTxt(%q) contact = %q, want %q", tc.body, contact, tc.wantContact)
			}
		})
	}
}
