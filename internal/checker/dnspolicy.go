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

	addFix := func(cat Category, sev Severity, title, summary, fixKey string, ev map[string]any) {
		d, refs := fix(fixKey, t.Domain)
		findings = append(findings, Finding{
			CheckerID: "dns.policy", Category: cat, Severity: sev,
			Title: title, Summary: summary, Detail: d, Refs: refs, Evidence: ev,
		})
	}

	inconclusive := func(cat Category, title string, err error) {
		findings = append(findings, Finding{
			CheckerID: "dns.policy", Category: cat, Severity: SevInfo,
			Title: title, Summary: "DNS query failed (all resolvers + DoH) - could not determine",
			Err: err.Error(),
		})
	}

	var spfPresent, dmarcEnforced, dmarcKnown bool

	// --- SPF (TXT on apex) ---
	if spf, err := firstWithPrefix(ctx, t.Domain, "v=spf1"); err != nil {
		inconclusive(CatEmail, "SPF: lookup inconclusive", err)
	} else if spf != "" {
		spfPresent = true
		sev, note, fixKey := spfQuality(spf)
		addFix(CatEmail, sev, "SPF record", note, fixKey, map[string]any{"spf": spf})
	} else {
		addFix(CatEmail, SevMedium, "No SPF record",
			"domain can be more easily spoofed in SMTP envelope", "no-spf", map[string]any{"domain": t.Domain})
	}

	// --- DMARC (TXT at _dmarc) ---
	if dmarc, err := firstWithPrefix(ctx, "_dmarc."+t.Domain, "v=DMARC1"); err != nil {
		inconclusive(CatEmail, "DMARC: lookup inconclusive", err)
	} else if dmarcKnown = true; dmarc != "" {
		switch strings.ToLower(tagValue(dmarc, "p")) {
		case "reject", "quarantine":
			dmarcEnforced = true
		}
		sev, note, fixKey := dmarcQuality(dmarc)
		addFix(CatEmail, sev, "DMARC record", note, fixKey, map[string]any{"dmarc": dmarc})
	} else {
		addFix(CatEmail, SevMedium, "No DMARC record",
			"no policy telling receivers how to handle spoofed mail", "no-dmarc", map[string]any{"domain": t.Domain})
	}

	if spfPresent && dmarcKnown && !dmarcEnforced {
		findings = append(findings, Finding{
			CheckerID: "dns.policy", Category: CatEmail, Severity: SevLow,
			Title:   "SPF without enforced DMARC: From-header spoofing still possible",
			Summary: "SPF protects the envelope only; without DMARC p=reject/quarantine, a forged visible From: @" + t.Domain + " is not rejected",
			Detail: "SPF validates the SMTP envelope (MAIL FROM), not the visible `From:` header that users see. " +
				"The visible From header is only checked through DMARC alignment. With DMARC absent or `p=none`, " +
				"a message spoofing the visible From address can still be delivered even though SPF is strict.\n\n" +
				"Recommendation: publish DMARC with `p=reject` after a `p=none` monitoring phase.",
			Refs: []string{"https://www.rfc-editor.org/rfc/rfc7489"},
		})
	}

	// --- CAA (apex) ---
	if caa, err := caaIssuers(ctx, t.Domain); err != nil {
		inconclusive(CatTLS, "CAA: lookup inconclusive", err)
	} else if len(caa) > 0 {
		add(CatTLS, SevInfo, "CAA record", strings.Join(caa, ", "), map[string]any{"caa": caa})
	} else {
		addFix(CatTLS, SevLow, "No CAA record",
			"any CA may issue certificates for this domain", "no-caa", map[string]any{"domain": t.Domain})
	}

	// --- MTA-STS (TXT at _mta-sts) ---
	if sts, err := firstWithPrefix(ctx, "_mta-sts."+t.Domain, "v=STSv1"); err != nil {
		inconclusive(CatEmail, "MTA-STS: lookup inconclusive", err)
	} else if sts != "" {
		add(CatEmail, SevInfo, "MTA-STS enabled", sts, map[string]any{"mta_sts": sts})
	} else {
		addFix(CatEmail, SevInfo, "No MTA-STS", "SMTP TLS not enforced via MTA-STS", "no-mta-sts", nil)
	}

	// --- TLS-RPT (TXT at _smtp._tls) ---
	if rpt, err := firstWithPrefix(ctx, "_smtp._tls."+t.Domain, "v=TLSRPTv1"); err != nil {
		inconclusive(CatEmail, "TLS-RPT: lookup inconclusive", err)
	} else if rpt != "" {
		add(CatEmail, SevInfo, "TLS-RPT enabled", rpt, map[string]any{"tls_rpt": rpt})
	}

	return findings, nil
}

// firstWithPrefix returns the first TXT record at name beginning with prefix.
func firstWithPrefix(ctx context.Context, name, prefix string) (string, error) {
	txts, err := txtRecords(ctx, name)
	if err != nil {
		return "", err
	}
	for _, txt := range txts {
		if strings.HasPrefix(strings.ToLower(txt), strings.ToLower(prefix)) {
			return txt, nil
		}
	}
	return "", nil
}

// spfQuality rates an SPF record by its terminating "all" mechanism.
func spfQuality(spf string) (Severity, string, string) {
	low := strings.ToLower(spf)
	switch {
	case strings.Contains(low, "+all"):
		return SevHigh, "+all permits any sender: SPF provides no protection", "spf-weak"
	case strings.Contains(low, "-all"):
		return SevInfo, "-all (hard fail): strict, recommended", ""
	case strings.Contains(low, "~all"):
		return SevLow, "~all (soft fail): consider tightening to -all", "spf-soften"
	case strings.Contains(low, "?all"):
		return SevLow, "?all (neutral): provides little protection", "spf-soften"
	default:
		return SevInfo, "SPF present", ""
	}
}

// dmarcQuality rates a DMARC record by its policy.
func dmarcQuality(dmarc string) (Severity, string, string) {
	p := tagValue(dmarc, "p")
	switch strings.ToLower(p) {
	case "reject":
		return SevInfo, "p=reject: strongest policy", ""
	case "quarantine":
		return SevInfo, "p=quarantine: spoofed mail sent to spam", ""
	case "none":
		return SevLow, "p=none: monitoring only, no enforcement", "dmarc-none"
	default:
		return SevLow, "DMARC present but policy unclear", "dmarc-unclear"
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
func caaIssuers(ctx context.Context, name string) ([]string, error) {
	rrs, err := queryDNS(ctx, name, dns.TypeCAA)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range rrs {
		if c, ok := rr.(*dns.CAA); ok {
			out = append(out, c.Tag+":"+c.Value)
		}
	}
	return out, nil
}
