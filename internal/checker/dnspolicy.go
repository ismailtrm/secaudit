package checker

import (
	"context"
	"strings"

	"github.com/miekg/dns"
)

func init() { Register(dnsPolicy{}) }

// dnsPolicy inspects the DNS-published security policies: SPF and DMARC (mail
// anti-spoofing), CAA (which CAs may issue certs), and MTA-STS / TLS-RPT
// (SMTP transport security). These are the highest-value passive signals.
type dnsPolicy struct{}

func (dnsPolicy) ID() string                               { return "dns.policy" }
func (dnsPolicy) Name() string                             { return "DNS Security Policy" }
func (dnsPolicy) Category() Category                       { return CatEmail }
func (dnsPolicy) Mode() Mode                               { return Passive }
func (dnsPolicy) Available(context.Context) (bool, string) { return true, "" }

func (dnsPolicy) Run(ctx context.Context, t Target) ([]Finding, error) {
	var findings []Finding
	add := func(cat Category, sev Severity, title, summary string, ev map[string]any) {
		findings = append(findings, Finding{
			CheckerID: "dns.policy", Category: cat, Severity: sev,
			Title: title, Summary: summary, Evidence: ev,
		})
	}

	// --- SPF (TXT on apex) ---
	if spf := firstWithPrefix(ctx, t.Domain, "v=spf1"); spf != "" {
		sev, note := spfQuality(spf)
		add(CatEmail, sev, "SPF record", note, map[string]any{"spf": spf})
	} else {
		add(CatEmail, SevMedium, "No SPF record",
			"domain can be more easily spoofed in SMTP envelope", map[string]any{"domain": t.Domain})
	}

	// --- DMARC (TXT at _dmarc) ---
	if dmarc := firstWithPrefix(ctx, "_dmarc."+t.Domain, "v=DMARC1"); dmarc != "" {
		sev, note := dmarcQuality(dmarc)
		add(CatEmail, sev, "DMARC record", note, map[string]any{"dmarc": dmarc})
	} else {
		add(CatEmail, SevMedium, "No DMARC record",
			"no policy telling receivers how to handle spoofed mail", map[string]any{"domain": t.Domain})
	}

	// --- CAA (apex) ---
	if caa := caaIssuers(ctx, t.Domain); len(caa) > 0 {
		add(CatTLS, SevInfo, "CAA record", strings.Join(caa, ", "), map[string]any{"caa": caa})
	} else {
		add(CatTLS, SevLow, "No CAA record",
			"any CA may issue certificates for this domain", map[string]any{"domain": t.Domain})
	}

	// --- MTA-STS (TXT at _mta-sts) ---
	if sts := firstWithPrefix(ctx, "_mta-sts."+t.Domain, "v=STSv1"); sts != "" {
		add(CatEmail, SevInfo, "MTA-STS enabled", sts, map[string]any{"mta_sts": sts})
	} else {
		add(CatEmail, SevInfo, "No MTA-STS", "SMTP TLS not enforced via MTA-STS", nil)
	}

	// --- TLS-RPT (TXT at _smtp._tls) ---
	if rpt := firstWithPrefix(ctx, "_smtp._tls."+t.Domain, "v=TLSRPTv1"); rpt != "" {
		add(CatEmail, SevInfo, "TLS-RPT enabled", rpt, map[string]any{"tls_rpt": rpt})
	}

	return findings, nil
}

// firstWithPrefix returns the first TXT record at name beginning with prefix.
func firstWithPrefix(ctx context.Context, name, prefix string) string {
	txts, err := txtRecords(ctx, name)
	if err != nil {
		return ""
	}
	for _, txt := range txts {
		if strings.HasPrefix(strings.ToLower(txt), strings.ToLower(prefix)) {
			return txt
		}
	}
	return ""
}

// spfQuality rates an SPF record by its terminating "all" mechanism.
func spfQuality(spf string) (Severity, string) {
	low := strings.ToLower(spf)
	switch {
	case strings.Contains(low, "+all"):
		return SevHigh, "+all permits any sender — SPF provides no protection"
	case strings.Contains(low, "-all"):
		return SevInfo, "-all (hard fail) — strict, recommended"
	case strings.Contains(low, "~all"):
		return SevLow, "~all (soft fail) — consider tightening to -all"
	case strings.Contains(low, "?all"):
		return SevLow, "?all (neutral) — provides little protection"
	default:
		return SevInfo, "SPF present"
	}
}

// dmarcQuality rates a DMARC record by its policy.
func dmarcQuality(dmarc string) (Severity, string) {
	p := tagValue(dmarc, "p")
	switch strings.ToLower(p) {
	case "reject":
		return SevInfo, "p=reject — strongest policy"
	case "quarantine":
		return SevInfo, "p=quarantine — spoofed mail sent to spam"
	case "none":
		return SevLow, "p=none — monitoring only, no enforcement"
	default:
		return SevLow, "DMARC present but policy unclear"
	}
}

// tagValue extracts a "tag=value" field from a semicolon-separated policy string.
func tagValue(record, tag string) string {
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if k, v, ok := strings.Cut(part, "="); ok && strings.EqualFold(strings.TrimSpace(k), tag) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// caaIssuers returns the "issue"/"issuewild" CA values from CAA records.
func caaIssuers(ctx context.Context, name string) []string {
	rrs, err := queryDNS(ctx, name, dns.TypeCAA)
	if err != nil {
		return nil
	}
	var out []string
	for _, rr := range rrs {
		if c, ok := rr.(*dns.CAA); ok {
			out = append(out, c.Tag+":"+c.Value)
		}
	}
	return out
}
