package checker

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/openrdap/rdap"
)

func init() { Register(rdapInfo{}) }

// rdapInfo queries RDAP (the structured successor to WHOIS) for registration
// data: registrar, creation/expiry dates, nameservers, DNSSEC delegation, and
// the hosting IP network. WHOIS port 43 is being decommissioned, so RDAP is the
// forward-looking source.
type rdapInfo struct{}

func (rdapInfo) ID() string                               { return "rdap" }
func (rdapInfo) Name() string                             { return "RDAP Registration" }
func (rdapInfo) Category() Category                       { return CatWhois }
func (rdapInfo) Mode() Mode                               { return Passive }
func (rdapInfo) Available(context.Context) (bool, string) { return true, "" }

func (rdapInfo) Run(ctx context.Context, t Target) ([]Finding, error) {
	add := func(sev Severity, title, summary string, ev map[string]any) Finding {
		return Finding{CheckerID: "rdap", Category: CatWhois, Severity: sev,
			Title: title, Summary: summary, Evidence: ev}
	}

	client := &rdap.Client{}
	dom, err := client.QueryDomain(t.Domain)
	if err != nil {
		// Some ccTLDs have no RDAP endpoint — informational, not a failure.
		return []Finding{add(SevInfo, "RDAP unavailable",
			"no RDAP data for ."+tld(t.Domain)+" ("+err.Error()+")",
			map[string]any{"domain": t.Domain})}, nil
	}

	var findings []Finding

	// Registrar (entity with the "registrar" role).
	if name := registrarName(dom); name != "" {
		findings = append(findings, add(SevInfo, "Registrar", name, map[string]any{"registrar": name}))
	}

	// Registration / expiry events.
	if d := eventDate(dom, "registration"); d != "" {
		findings = append(findings, add(SevInfo, "Registered", d, map[string]any{"registered": d}))
	}
	if exp := eventDate(dom, "expiration"); exp != "" {
		sev, summary := expirySeverity(exp)
		findings = append(findings, add(sev, "Expiry", summary, map[string]any{"expiry": exp}))
	}

	// Nameservers per RDAP (may differ from live NS).
	if ns := nameservers(dom); len(ns) > 0 {
		findings = append(findings, add(SevInfo, "Registry nameservers",
			strings.Join(ns, ", "), map[string]any{"nameservers": ns}))
	}

	// DNSSEC is reported by the dedicated dns.dnssec checker (live DS/DNSKEY/RRSIG).

	// Hosting IP network (best-effort ASN/network attribution).
	if netFinding := ipNetwork(ctx, client, t); netFinding != nil {
		findings = append(findings, *netFinding)
	}

	return findings, nil
}

func registrarName(d *rdap.Domain) string {
	for _, e := range d.Entities {
		for _, role := range e.Roles {
			if role == "registrar" && e.VCard != nil {
				if n := e.VCard.Name(); n != "" {
					return n
				}
				return e.Handle
			}
		}
	}
	return ""
}

func eventDate(d *rdap.Domain, action string) string {
	for _, e := range d.Events {
		if e.Action == action {
			return e.Date
		}
	}
	return ""
}

func nameservers(d *rdap.Domain) []string {
	var out []string
	for _, ns := range d.Nameservers {
		out = append(out, strings.ToLower(ns.LDHName))
	}
	return out
}

// expirySeverity flags domains close to (or past) expiry.
func expirySeverity(date string) (Severity, string) {
	exp, err := time.Parse(time.RFC3339, date)
	if err != nil {
		return SevInfo, date
	}
	days := int(time.Until(exp).Hours() / 24)
	switch {
	case days < 0:
		return SevHigh, "expired " + exp.Format("2006-01-02")
	case days < 30:
		return SevMedium, fmt.Sprintf("expires in %d days (%s)", days, exp.Format("2006-01-02"))
	default:
		return SevInfo, fmt.Sprintf("expires %s (%d days)", exp.Format("2006-01-02"), days)
	}
}

// ipNetwork resolves the apex to an IP and queries RDAP for its network.
func ipNetwork(ctx context.Context, client *rdap.Client, t Target) *Finding {
	rrs, err := queryDNS(ctx, t.Host, dns.TypeA)
	if err != nil || len(rrs) == 0 {
		return nil
	}
	var ip net.IP
	for _, rr := range rrs {
		if a, ok := rr.(*dns.A); ok {
			ip = a.A
			break
		}
	}
	if ip == nil {
		return nil
	}
	netw, err := client.QueryIP(ip.String())
	if err != nil {
		return nil
	}
	desc := strings.TrimSpace(netw.Handle + " " + netw.Name)
	if netw.Country != "" {
		desc += " (" + netw.Country + ")"
	}
	return &Finding{CheckerID: "rdap", Category: CatWhois, Severity: SevInfo,
		Title: "Hosting network", Summary: desc,
		Evidence: map[string]any{"ip": ip.String(), "handle": netw.Handle, "name": netw.Name, "country": netw.Country}}
}

func tld(domain string) string {
	if i := strings.LastIndex(domain, "."); i >= 0 {
		return domain[i+1:]
	}
	return domain
}
