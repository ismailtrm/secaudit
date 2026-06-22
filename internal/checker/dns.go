package checker

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

func init() { Register(dnsRecords{}) }

// dnsRecords resolves the foundational record types. Output is informational;
// security-relevant DNS (SPF/DMARC/CAA/MTA-STS) lives in dnsPolicy.
type dnsRecords struct{}

func (dnsRecords) ID() string                               { return "dns.records" }
func (dnsRecords) Name() string                             { return "DNS Records" }
func (dnsRecords) Category() Category                       { return CatDNS }
func (dnsRecords) Mode() Mode                               { return Passive }
func (dnsRecords) Available(context.Context) (bool, string) { return true, "" }

func (dnsRecords) Run(ctx context.Context, t Target) ([]Finding, error) {
	var findings []Finding

	add := func(sev Severity, title, summary string, ev map[string]any) {
		findings = append(findings, Finding{
			CheckerID: "dns.records", Category: CatDNS, Severity: sev,
			Title: title, Summary: summary, Evidence: ev,
		})
	}

	// A / AAAA live on the scanned host; MX / NS / SOA on the zone apex.
	a := answerValues(ctx, t.Host, dns.TypeA)
	aaaa := answerValues(ctx, t.Host, dns.TypeAAAA)
	mx := answerValues(ctx, t.Domain, dns.TypeMX)
	ns := answerValues(ctx, t.Domain, dns.TypeNS)
	soa := answerValues(ctx, t.Domain, dns.TypeSOA)

	if len(a) == 0 && len(aaaa) == 0 {
		add(SevMedium, "No A/AAAA records", t.Host+" does not resolve to any address",
			map[string]any{"host": t.Host})
	} else {
		if len(a) > 0 {
			add(SevInfo, "A records", strings.Join(a, ", "), map[string]any{"a": a})
		}
		if len(aaaa) > 0 {
			add(SevInfo, "AAAA records", strings.Join(aaaa, ", "), map[string]any{"aaaa": aaaa})
		} else {
			add(SevInfo, "No IPv6 (AAAA)", "host has no AAAA record", map[string]any{"host": t.Host})
		}
	}

	if len(mx) > 0 {
		add(SevInfo, "Mail exchangers (MX)", strings.Join(mx, ", "), map[string]any{"mx": mx})
	} else {
		add(SevInfo, "No MX records", t.Domain+" is not configured to receive mail",
			map[string]any{"domain": t.Domain})
	}

	if len(ns) > 0 {
		add(SevInfo, "Nameservers (NS)", strings.Join(ns, ", "), map[string]any{"ns": ns})
	} else {
		add(SevMedium, "No NS records", "could not determine authoritative nameservers",
			map[string]any{"domain": t.Domain})
	}

	if len(soa) > 0 {
		add(SevInfo, "SOA", soa[0], map[string]any{"soa": soa[0]})
	}

	return findings, nil
}

// answerValues queries one record type and returns human-readable values,
// swallowing transport errors (best-effort, per-type).
func answerValues(ctx context.Context, name string, qtype uint16) []string {
	rrs, err := queryDNS(ctx, name, qtype)
	if err != nil {
		return nil
	}
	var out []string
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.A:
			out = append(out, v.A.String())
		case *dns.AAAA:
			out = append(out, v.AAAA.String())
		case *dns.MX:
			host := strings.TrimSuffix(v.Mx, ".")
			if host == "" {
				// RFC 7505 null MX: "0 ." means the domain accepts no mail.
				out = append(out, "null MX (accepts no mail, RFC 7505)")
			} else {
				out = append(out, fmt.Sprintf("%d %s", v.Preference, host))
			}
		case *dns.NS:
			out = append(out, strings.TrimSuffix(v.Ns, "."))
		case *dns.SOA:
			out = append(out, strings.TrimSuffix(v.Ns, ".")+" (serial "+strconv.FormatUint(uint64(v.Serial), 10)+")")
		}
	}
	return out
}
