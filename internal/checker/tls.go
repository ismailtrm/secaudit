package checker

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
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
		Config: &tls.Config{ServerName: t.Host, InsecureSkipVerify: true}, // #nosec G402 -- deliberately inspecting invalid certs; chain trust is verified manually via verifyChain
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

	// Weak signature algorithm (SHA1/MD5/MD2-based signing is forgeable today).
	if weak, name := weakSignature(leaf.SignatureAlgorithm); weak {
		findings = append(findings, add(SevHigh, "Weak certificate signature",
			"signed with "+name, map[string]any{"algorithm": name}))
	}

	// Public key strength.
	keySev, keyNote := keyStrength(leaf.PublicKey)
	keyTitle := "Public key strength"
	if keySev != SevInfo {
		keyTitle = "Weak public key"
	}
	findings = append(findings, add(keySev, keyTitle, keyNote, map[string]any{"key": keyNote}))

	// Chain trust against system roots (manual, since we skipped verify on dial).
	if err := verifyChain(t.Host, state.PeerCertificates); err != nil {
		var inv x509.CertificateInvalidError
		// An expiry failure is already reported above; don't double-count it.
		if !errors.As(err, &inv) || inv.Reason != x509.Expired {
			findings = append(findings, add(SevHigh, "Certificate chain not trusted",
				err.Error(), nil))
		}
	}

	// Self-signed: complements (doesn't replace) the chain-trust finding above.
	if leaf.Issuer.String() == leaf.Subject.String() {
		findings = append(findings, add(SevMedium, "Self-signed certificate",
			"issuer and subject are identical: "+leaf.Subject.String(), nil))
	}

	// Hostname coverage (independent of full-chain trust).
	if err := leaf.VerifyHostname(t.Host); err != nil {
		findings = append(findings, add(SevMedium, "Certificate does not cover host",
			err.Error(), map[string]any{"host": t.Host, "sans": leaf.DNSNames}))
	}

	// Downgrade probe: does the server still accept obsolete protocol versions?
	// A single extra dial capped at TLS 1.1 - success means the server hasn't
	// disabled legacy protocols; failure (the expected case) is not a finding.
	if version, ok := probeObsoleteTLS(ctx, t.Host); ok {
		findings = append(findings, add(SevMedium, "Obsolete TLS supported",
			"server also accepts "+version, map[string]any{"version": version}))
	}

	return findings, nil
}

// probeObsoleteTLS makes one additional dial capped at TLS 1.1 to check
// whether the server still negotiates an obsolete protocol version. ok is
// true only when that handshake succeeds.
func probeObsoleteTLS(ctx context.Context, host string) (version string, ok bool) {
	dialCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 8 * time.Second},
		Config: &tls.Config{
			ServerName:         host,
			MaxVersion:         tls.VersionTLS11,
			InsecureSkipVerify: true, // #nosec G402 -- probing supported protocol versions only
		},
	}
	conn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return "", false
	}
	defer conn.Close()

	return tlsVersion(conn.(*tls.Conn).ConnectionState().Version), true
}

// weakSignature reports whether a is a SHA1- or MD5/MD2-based signature
// algorithm, considered forgeable by modern standards.
func weakSignature(a x509.SignatureAlgorithm) (bool, string) {
	switch a {
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1, x509.MD5WithRSA, x509.MD2WithRSA:
		return true, a.String()
	default:
		return false, a.String()
	}
}

// keyStrength grades a leaf certificate's public key. RSA below 2048 bits and
// ECDSA curves below 256 bits are flagged as weak; anything else adequate is
// reported at SevInfo with its type and size.
func keyStrength(pub any) (Severity, string) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		if bits < 2048 {
			return SevMedium, fmt.Sprintf("RSA %d-bit key (weak, want >= 2048)", bits)
		}
		return SevInfo, fmt.Sprintf("RSA %d-bit key", bits)
	case *ecdsa.PublicKey:
		bits := k.Curve.Params().BitSize
		if bits < 256 {
			return SevLow, fmt.Sprintf("ECDSA %d-bit key (weak, want >= 256)", bits)
		}
		return SevInfo, fmt.Sprintf("ECDSA %d-bit key", bits)
	default:
		return SevInfo, fmt.Sprintf("%T key", pub)
	}
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
