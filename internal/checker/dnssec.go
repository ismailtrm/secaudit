package checker

import (
	"context"

	"github.com/miekg/dns"
)

func init() { Register(dnssecCheck{}) }

// dnssecCheck verifies DNSSEC from live DNS: a DS record at the parent (chain of
// trust anchor) plus DNSKEY and RRSIG at the apex (the zone actually serving
// signatures). This supersedes RDAP's registry-only "delegation signed" flag.
type dnssecCheck struct{}

func (dnssecCheck) ID() string                               { return "dns.dnssec" }
func (dnssecCheck) Name() string                             { return "DNSSEC" }
func (dnssecCheck) Category() Category                       { return CatDNS }
func (dnssecCheck) Mode() Mode                               { return Passive }
func (dnssecCheck) Available(context.Context) (bool, string) { return true, "" }

func (dnssecCheck) Run(ctx context.Context, t Target) ([]Finding, error) {
	one := func(sev Severity, title, summary string) []Finding {
		return []Finding{{CheckerID: "dns.dnssec", Category: CatDNS, Severity: sev,
			Title: title, Summary: summary}}
	}

	dsRRs, _ := queryDNS(ctx, t.Domain, dns.TypeDS)
	hasDS := hasRRType(dsRRs, dns.TypeDS)

	keyRRs, _ := queryDNS(ctx, t.Domain, dns.TypeDNSKEY)
	hasKey := hasRRType(keyRRs, dns.TypeDNSKEY)

	soaRRs, _ := queryWithDNSSEC(ctx, t.Domain, dns.TypeSOA)
	hasSig := hasRRType(soaRRs, dns.TypeRRSIG)
	signed := hasKey && hasSig

	switch {
	case signed && hasDS:
		return one(SevInfo, "DNSSEC enabled", "signed zone with DS at parent: chain of trust intact"), nil
	case signed && !hasDS:
		return one(SevLow, "DNSSEC chain incomplete",
			"zone is signed (DNSKEY+RRSIG) but no DS at the registry: resolvers can't validate it"), nil
	case hasDS && !signed:
		return one(SevLow, "DNSSEC inconsistent",
			"DS present at parent but the zone is not serving signatures"), nil
	default:
		return one(SevLow, "DNSSEC not enabled", "zone is unsigned: DNS responses can be spoofed"), nil
	}
}
