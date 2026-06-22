package checker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

func init() { Register(tlsCert{}) }

// tlsCert dials :443 and inspects the served certificate: expiry, hostname
// coverage, chain trust, and negotiated protocol version. The dial itself is a
// handshake any client performs, so it is passive.
type tlsCert struct{}

func (tlsCert) ID() string                               { return "tls.cert" }
func (tlsCert) Name() string                             { return "TLS Certificate" }
func (tlsCert) Category() Category                       { return CatTLS }
func (tlsCert) Mode() Mode                               { return Passive }
func (tlsCert) Available(context.Context) (bool, string) { return true, "" }

func (tlsCert) Run(ctx context.Context, t Target) ([]Finding, error) {
	add := func(sev Severity, title, summary string, ev map[string]any) Finding {
		return Finding{CheckerID: "tls.cert", Category: CatTLS, Severity: sev,
			Title: title, Summary: summary, Evidence: ev}
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		// Inspect the cert even when invalid; trust is evaluated manually below.
		Config: &tls.Config{ServerName: t.Host, InsecureSkipVerify: true},
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(t.Host, "443"))
	if err != nil {
		return []Finding{add(SevLow, "No HTTPS on :443", err.Error(),
			map[string]any{"host": t.Host})}, nil
	}
	defer conn.Close()

	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return []Finding{add(SevMedium, "No certificate presented", "server sent no certificate", nil)}, nil
	}
	leaf := state.PeerCertificates[0]
	var findings []Finding

	// Expiry — clear severity ladder from the cert's own NotAfter.
	now := time.Now()
	switch days := int(time.Until(leaf.NotAfter).Hours() / 24); {
	case now.After(leaf.NotAfter):
		findings = append(findings, add(SevCritical, "Certificate expired",
			"expired "+leaf.NotAfter.Format("2006-01-02"), map[string]any{"not_after": leaf.NotAfter}))
	case now.Before(leaf.NotBefore):
		findings = append(findings, add(SevHigh, "Certificate not yet valid",
			"valid from "+leaf.NotBefore.Format("2006-01-02"), nil))
	case days < 14:
		findings = append(findings, add(SevHigh, "Certificate expiring soon",
			fmt.Sprintf("%d days left (%s)", days, leaf.NotAfter.Format("2006-01-02")), nil))
	case days < 30:
		findings = append(findings, add(SevMedium, "Certificate expiring soon",
			fmt.Sprintf("%d days left (%s)", days, leaf.NotAfter.Format("2006-01-02")), nil))
	default:
		findings = append(findings, add(SevInfo, "Certificate validity",
			fmt.Sprintf("%d days left (%s)", days, leaf.NotAfter.Format("2006-01-02")),
			map[string]any{"not_after": leaf.NotAfter}))
	}

	// Negotiated protocol version.
	if state.Version < tls.VersionTLS12 {
		findings = append(findings, add(SevHigh, "Weak TLS version",
			"negotiated "+tlsVersion(state.Version), map[string]any{"version": tlsVersion(state.Version)}))
	} else {
		findings = append(findings, add(SevInfo, "TLS version",
			"negotiated "+tlsVersion(state.Version), map[string]any{"version": tlsVersion(state.Version)}))
	}

	// Issuer + SANs (informational).
	findings = append(findings, add(SevInfo, "Issuer", leaf.Issuer.String(),
		map[string]any{"issuer": leaf.Issuer.String(), "sans": leaf.DNSNames}))

	// Chain trust against system roots (manual, since we skipped verify on dial).
	if err := verifyChain(t.Host, state.PeerCertificates); err != nil {
		var inv x509.CertificateInvalidError
		// An expiry failure is already reported above; don't double-count it.
		if !(errors.As(err, &inv) && inv.Reason == x509.Expired) {
			findings = append(findings, add(SevHigh, "Certificate chain not trusted",
				err.Error(), nil))
		}
	}

	// Hostname coverage (independent of full-chain trust).
	if err := leaf.VerifyHostname(t.Host); err != nil {
		findings = append(findings, add(SevMedium, "Certificate does not cover host",
			err.Error(), map[string]any{"host": t.Host, "sans": leaf.DNSNames}))
	}

	return findings, nil
}

// verifyChain validates the leaf against system roots using the served chain as
// intermediates.
func verifyChain(host string, chain []*x509.Certificate) error {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return err
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err = chain[0].Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: inter,
	})
	return err
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return strings.TrimSpace(fmt.Sprintf("0x%04x", v))
	}
}
