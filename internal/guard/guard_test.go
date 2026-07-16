package guard

import (
	"errors"
	"testing"

	"github.com/ismailtrm/secaudit/internal/checker"
)

func TestAuthorize(t *testing.T) {
	tests := []struct {
		name    string
		o       checker.Ownership
		mode    checker.Mode
		wantErr bool
	}{
		{"own/passive", checker.Own, checker.Passive, false},
		{"own/active", checker.Own, checker.Active, false},
		{"authorized/passive", checker.Authorized, checker.Passive, false},
		{"authorized/active", checker.Authorized, checker.Active, false},
		{"third-party/passive", checker.ThirdParty, checker.Passive, false},
		{"third-party/active", checker.ThirdParty, checker.Active, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Authorize(tc.o, tc.mode)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Authorize(%v, %v) = nil, want error", tc.o, tc.mode)
				}
				if !errors.Is(err, ErrUnauthorized) {
					t.Errorf("Authorize(%v, %v) = %v, want error satisfying errors.Is(err, ErrUnauthorized)", tc.o, tc.mode, err)
				}
				return
			}
			if err != nil {
				t.Errorf("Authorize(%v, %v) = %v, want nil", tc.o, tc.mode, err)
			}
		})
	}
}

func TestParseOwnership(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    checker.Ownership
		wantErr bool
	}{
		{"own", "own", checker.Own, false},
		{"self", "self", checker.Own, false},
		{"authorized", "authorized", checker.Authorized, false},
		{"auth", "auth", checker.Authorized, false},
		{"third-party", "third-party", checker.ThirdParty, false},
		{"thirdparty", "thirdparty", checker.ThirdParty, false},
		{"3rd-party", "3rd-party", checker.ThirdParty, false},
		{"third", "third", checker.ThirdParty, false},
		{"mixed case padded own", "  Own  ", checker.Own, false},
		{"mixed case third-party", "THIRD-PARTY", checker.ThirdParty, false},
		{"unknown", "bogus", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseOwnership(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseOwnership(%q) = %v, nil, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseOwnership(%q): unexpected error %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("ParseOwnership(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseMode(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    checker.Mode
		wantErr bool
	}{
		{"passive", "passive", checker.Passive, false},
		{"empty defaults to passive", "", checker.Passive, false},
		{"active", "active", checker.Active, false},
		{"mixed case padded active", "  Active  ", checker.Active, false},
		{"mixed case passive", "PASSIVE", checker.Passive, false},
		{"unknown", "bogus", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseMode(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseMode(%q) = %v, nil, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseMode(%q): unexpected error %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("ParseMode(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
