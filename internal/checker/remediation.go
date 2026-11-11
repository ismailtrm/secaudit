package checker

import "strings"

type remedy struct {
	detail string
	refs   []string
}

// remedies maps a stable fix key to guidance. "{{domain}}" is substituted at lookup.
var remedies = map[string]remedy{
	"no-spf": {
		"Publish an SPF TXT record at the apex of {{domain}}. For a single mail provider use `v=spf1 include:<provider> -all`. List every legitimate sender, then end with `-all` (hard fail).",
		[]string{"https://www.rfc-editor.org/rfc/rfc7208"},
	},
	"spf-soften": {
		"Tighten the SPF all mechanism to `-all` (hard fail) once every legitimate sender is listed. `~all` (softfail) and `?all` (neutral) let receivers accept unlisted senders.",
		[]string{"https://www.rfc-editor.org/rfc/rfc7208"},
	},
	"spf-weak": {
		"Remove `+all` from the SPF record now: it authorizes any sender and gives no protection. Replace it with `-all` after listing legitimate senders.",
		[]string{"https://www.rfc-editor.org/rfc/rfc7208"},
	},
	"no-dmarc": {
		"Publish a DMARC TXT record at `_dmarc.{{domain}}`. Start in monitoring mode: `v=DMARC1; p=none; rua=mailto:dmarc@{{domain}}`. After the aggregate reports confirm legitimate mail aligns, raise the policy to `p=quarantine`, then `p=reject`.",
		[]string{"https://www.rfc-editor.org/rfc/rfc7489"},
	},
	"dmarc-none": {
		"DMARC is in monitoring only (`p=none`), so forged mail is not rejected. After the `rua` reports confirm legitimate mail passes, raise the policy to `p=quarantine`, then `p=reject`.",
		[]string{"https://www.rfc-editor.org/rfc/rfc7489"},
	},
	"dmarc-unclear": {
		"A DMARC record exists but its `p` policy is missing or unrecognized. Set an explicit policy at `_dmarc.{{domain}}`: `p=reject` (after a `p=none` monitoring phase).",
		[]string{"https://www.rfc-editor.org/rfc/rfc7489"},
	},
	"no-dkim": {
		"If {{domain}} sends mail, enable DKIM at your mail provider and publish the selector record(s) it gives you under `<selector>._domainkey.{{domain}}` (Microsoft 365 publishes selector1/selector2 CNAMEs, Google Workspace uses the `google` selector). DKIM lets DMARC pass by alignment even when mail is forwarded.",
		[]string{"https://www.rfc-editor.org/rfc/rfc6376"},
	},
	"no-mta-sts": {
		"Enforce TLS for inbound SMTP with MTA-STS: publish a TXT record at `_mta-sts.{{domain}}` (`v=STSv1; id=...`) and serve a policy file at `https://mta-sts.{{domain}}/.well-known/mta-sts.txt`.",
		[]string{"https://www.rfc-editor.org/rfc/rfc8461"},
	},
	"no-caa": {
		"Publish a CAA record at the apex of {{domain}} naming the CAs allowed to issue certificates, for example `0 issue \"letsencrypt.org\"`. This limits certificate mis-issuance by other CAs.",
		[]string{"https://www.rfc-editor.org/rfc/rfc8659"},
	},
	"dnssec-off": {
		"Enable DNSSEC for {{domain}} at your DNS provider or registrar: sign the zone and publish the DS record at the registry so resolvers can validate answers and detect spoofing.",
		[]string{"https://www.rfc-editor.org/rfc/rfc9364"},
	},
	"dnssec-incomplete": {
		"The zone is signed but has no DS record at the registry, so resolvers cannot validate it. Add the DS record (derived from the zone's DNSKEY) at the registrar for {{domain}}.",
		[]string{"https://www.rfc-editor.org/rfc/rfc9364"},
	},
	"dnssec-inconsistent": {
		"A DS record exists at the registry but the zone is not serving signatures, which breaks validation. Either re-sign the zone or remove the stale DS record at the registrar for {{domain}}.",
		[]string{"https://www.rfc-editor.org/rfc/rfc9364"},
	},
}

// fix returns remediation guidance for key with {{domain}} substituted. An
// empty key or an unknown key yields no guidance.
func fix(key, domain string) (string, []string) {
	r, ok := remedies[key]
	if !ok {
		return "", nil
	}
	return strings.ReplaceAll(r.detail, "{{domain}}", domain), r.refs
}
