package checker

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Target is the normalized scan subject, built once and shared read-only across
// all checkers. Domain is the registrable apex (punycoded); Host is the FQDN
// actually probed.
type Target struct {
	Raw       string // exactly what the user typed
	Domain    string // registrable apex, ASCII/punycode ("example.com")
	Host      string // FQDN scanned ("www.example.com")
	URL       *url.URL
	Ownership Ownership
}

// NewTarget normalizes raw user input into a Target. It accepts bare domains,
// hosts with a scheme, and hosts with a path, and rejects IPs and empty input.
func NewTarget(raw string, owner Ownership) (Target, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Target{}, fmt.Errorf("empty target")
	}
	// Strip a scheme if present so we can parse host uniformly.
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return Target{}, fmt.Errorf("parse %q: %w", raw, err)
	}
	host := u.Hostname()
	if host == "" {
		return Target{}, fmt.Errorf("no host in %q", raw)
	}
	if ip := net.ParseIP(host); ip != nil {
		return Target{}, fmt.Errorf("%q is an IP; secaudit scans domains", host)
	}

	// Punycode the host (IDNA2008) so DNS/RDAP get ASCII labels.
	asciiHost, err := idna.Lookup.ToASCII(strings.TrimSuffix(host, "."))
	if err != nil {
		return Target{}, fmt.Errorf("idna %q: %w", host, err)
	}
	apex, err := publicsuffix.EffectiveTLDPlusOne(asciiHost)
	if err != nil {
		// Unknown suffix (e.g. internal TLD): fall back to the host itself.
		apex = asciiHost
	}

	return Target{
		Raw:       raw,
		Domain:    apex,
		Host:      asciiHost,
		URL:       &url.URL{Scheme: "https", Host: asciiHost},
		Ownership: owner,
	}, nil
}
