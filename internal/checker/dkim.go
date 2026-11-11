package checker

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

func init() { Register(dkimCheck{}) }

// dkimCheck probes a fixed list of common DKIM selectors. DKIM selectors are
// arbitrary, so absence of a hit is never proof that DKIM is missing.
type dkimCheck struct{}

func (dkimCheck) ID() string                               { return "dns.dkim" }
func (dkimCheck) Name() string                             { return "DKIM" }
func (dkimCheck) Category() Category                       { return CatEmail }
func (dkimCheck) Mode() Mode                               { return Passive }
func (dkimCheck) Available(context.Context) (bool, string) { return true, "" }

// dkimSelectors maps common selector names to the provider that uses them.
// An empty hint means a generic name with no single known provider.
var dkimSelectors = []struct{ name, hint string }{
	{"selector1", "Microsoft 365"},
	{"selector2", "Microsoft 365"},
	{"google", "Google Workspace"},
	{"default", ""},
	{"dkim", ""},
	{"mail", ""},
	{"k1", "Mailchimp"},
	{"s1", ""},
	{"s2", ""},
	{"mandrill", "Mandrill"},
	{"zoho", "Zoho Mail"},
}

func (dkimCheck) Run(ctx context.Context, t Target) ([]Finding, error) {
	// A wildcard *._domainkey answers every selector, which would make each
	// probe a false positive. Detect it with a random name no real setup uses.
	if wild, err := txtRecords(ctx, "zzqx-dkim-probe._domainkey."+t.Domain); err == nil && hasDKIMRecord(wild) {
		return []Finding{{
			CheckerID: "dns.dkim", Category: CatEmail, Severity: SevInfo,
			Title:   "Wildcard _domainkey record present",
			Summary: "a *._domainkey wildcard answers every selector; individual selectors cannot be enumerated",
		}}, nil
	}

	var findings []Finding
	var errs []error
	for _, sel := range dkimSelectors {
		txts, err := txtRecords(ctx, sel.name+"._domainkey."+t.Domain)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !hasDKIMRecord(txts) {
			continue
		}
		ev := map[string]any{"selector": sel.name}
		if sel.hint != "" {
			ev["provider"] = sel.hint
		}
		findings = append(findings, Finding{
			CheckerID: "dns.dkim", Category: CatEmail, Severity: SevInfo,
			Title:    fmt.Sprintf("DKIM selector '%s' present", sel.name),
			Summary:  sel.name + "._domainkey." + t.Domain,
			Evidence: ev,
		})
	}
	if len(findings) > 0 {
		return findings, nil
	}
	if len(errs) > 0 {
		return []Finding{{
			CheckerID: "dns.dkim", Category: CatEmail, Severity: SevInfo,
			Title:   "DKIM: lookup inconclusive",
			Summary: "DNS query failed (all resolvers + DoH) - could not determine",
			Err:     errors.Join(errs...).Error(),
		}}, nil
	}
	return []Finding{{
		CheckerID: "dns.dkim", Category: CatEmail, Severity: SevInfo,
		Title: "No common DKIM selector found",
		Summary: fmt.Sprintf("probed %d common selectors; the domain may still sign with a custom selector not covered here",
			len(dkimSelectors)),
	}}, nil
}

// hasDKIMRecord reports whether any TXT is a DKIM key record with a live
// public key. An empty "p=" means the key was revoked (RFC 6376 3.6.1), so a
// "v=DKIM1; p=" record (common as a wildcard null record) is not an active
// selector and must not count as present.
func hasDKIMRecord(txts []string) bool {
	for _, txt := range txts {
		if strings.Contains(strings.ToLower(txt), "v=dkim1") && tagValue(txt, "p") != "" {
			return true
		}
	}
	return false
}
