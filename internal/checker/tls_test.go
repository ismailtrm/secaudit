package checker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"testing"
)

// rsaKeyOfBits builds an *rsa.PublicKey whose modulus has exactly the
// requested bit length, without paying for a real key generation.
func rsaKeyOfBits(bits int) *rsa.PublicKey {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	return &rsa.PublicKey{N: n, E: 65537}
}

func TestWeakSignature(t *testing.T) {
	tests := []struct {
		name string
		alg  x509.SignatureAlgorithm
		want bool
	}{
		{"sha1-rsa", x509.SHA1WithRSA, true},
		{"dsa-sha1", x509.DSAWithSHA1, true},
		{"ecdsa-sha1", x509.ECDSAWithSHA1, true},
		{"md5-rsa", x509.MD5WithRSA, true},
		{"md2-rsa", x509.MD2WithRSA, true},
		{"sha256-rsa", x509.SHA256WithRSA, false},
		{"sha384-rsa", x509.SHA384WithRSA, false},
		{"sha512-rsa", x509.SHA512WithRSA, false},
		{"ecdsa-sha256", x509.ECDSAWithSHA256, false},
		{"ecdsa-sha384", x509.ECDSAWithSHA384, false},
		{"pure-ed25519", x509.PureEd25519, false},
		{"unknown", x509.UnknownSignatureAlgorithm, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			weak, name := weakSignature(tt.alg)
			if weak != tt.want {
				t.Errorf("weakSignature(%v) weak = %v, want %v", tt.alg, weak, tt.want)
			}
			if name == "" {
				t.Errorf("weakSignature(%v) returned empty name", tt.alg)
			}
		})
	}
}

func TestKeyStrength(t *testing.T) {
	tests := []struct {
		name    string
		pub     any
		wantSev Severity
	}{
		{"rsa-1024-weak", rsaKeyOfBits(1024), SevMedium},
		{"rsa-1536-weak", rsaKeyOfBits(1536), SevMedium},
		{"rsa-2047-weak", rsaKeyOfBits(2047), SevMedium},
		{"rsa-2048-ok", rsaKeyOfBits(2048), SevInfo},
		{"rsa-4096-ok", rsaKeyOfBits(4096), SevInfo},
		{"ecdsa-p224-weak", &ecdsa.PublicKey{Curve: elliptic.P224()}, SevLow},
		{"ecdsa-p256-ok", &ecdsa.PublicKey{Curve: elliptic.P256()}, SevInfo},
		{"ecdsa-p384-ok", &ecdsa.PublicKey{Curve: elliptic.P384()}, SevInfo},
		{"ecdsa-p521-ok", &ecdsa.PublicKey{Curve: elliptic.P521()}, SevInfo},
		{"unknown-type", "not-a-key", SevInfo},
		{"nil-pub", nil, SevInfo},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sev, note := keyStrength(tt.pub)
			if sev != tt.wantSev {
				t.Errorf("keyStrength(%s) severity = %v, want %v (note=%q)", tt.name, sev, tt.wantSev, note)
			}
			if note == "" {
				t.Errorf("keyStrength(%s) returned empty note", tt.name)
			}
		})
	}
}

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		name string
		v    uint16
		want string
	}{
		{"tls13", tls.VersionTLS13, "TLS 1.3"},
		{"tls12", tls.VersionTLS12, "TLS 1.2"},
		{"tls11", tls.VersionTLS11, "TLS 1.1"},
		{"tls10", tls.VersionTLS10, "TLS 1.0"},
		{"unknown", 0x9999, "0x9999"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tlsVersion(tt.v); got != tt.want {
				t.Errorf("tlsVersion(0x%04x) = %q, want %q", tt.v, got, tt.want)
			}
		})
	}
}
