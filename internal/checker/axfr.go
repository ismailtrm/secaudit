package checker

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func init() { Register(axfrChecker{}) }

// axfrChecker attempts a DNS zone transfer (AXFR) against every nameserver of
// the target domain. A nameserver that hands over the whole zone on an
// unauthenticated request is a serious misconfiguration: it leaks every
// hostname in the zone. Refusal is the healthy, expected outcome.
type axfrChecker struct{}

func (axfrChecker) ID() string                               { return "dns.axfr" }
func (axfrChecker) Name() string                             { return "Zone Transfer (AXFR)" }
func (axfrChecker) Category() Category                       { return CatDNS }
func (axfrChecker) Mode() Mode                               { return Passive }
func (axfrChecker) Available(context.Context) (bool, string) { return true, "" }

// axfrTimeout bounds each per-nameserver transfer attempt.
const axfrTimeout = 8 * time.Second

func (axfrChecker) Run(ctx context.Context, t Target) ([]Finding, error) {
	rrs, err := queryDNS(ctx, t.Domain, dns.TypeNS)
	if err != nil {
		return []Finding{{CheckerID: "dns.axfr", Category: CatDNS, Severity: SevInfo,
			Title: "AXFR check skipped", Summary: "could not resolve nameservers: " + err.Error()}}, nil
	}

	var nameservers []string
	for _, rr := range rrs {
		if ns, ok := rr.(*dns.NS); ok {
			nameservers = append(nameservers, normalizeNS(ns.Ns))
		}
	}
	if len(nameservers) == 0 {
		return []Finding{{CheckerID: "dns.axfr", Category: CatDNS, Severity: SevInfo,
			Title: "AXFR check skipped", Summary: "no nameservers found for " + t.Domain}}, nil
	}

	results := make([]axfrResult, 0, len(nameservers))
	for _, ns := range nameservers {
		if ctx.Err() != nil {
			results = append(results, axfrResult{ns: ns, err: ctx.Err()})
			continue
		}
		count, err := attemptAXFR(ctx, ns, t.Domain)
		results = append(results, axfrResult{ns: ns, count: count, err: err})
	}

	return summarizeAXFR(results), nil
}

// axfrResult is the outcome of one attempted zone transfer against one
// nameserver. err is nil only when the transfer succeeded and handed over
// zone records.
type axfrResult struct {
	ns    string
	count int
	err   error
}

// normalizeNS strips the trailing FQDN dot and lowercases a nameserver name
// for consistent display and dialing.
func normalizeNS(ns string) string {
	return strings.ToLower(strings.TrimSuffix(ns, "."))
}

// attemptAXFR tries a zone transfer against one nameserver, bounded by
// axfrTimeout. Refusal (REFUSED, NOTAUTH, connection reset, ...) is expected
// and normal: it is returned as a plain error for the caller to summarize,
// never treated as a hard failure. A nil error with count > 0 means the
// nameserver handed over the zone.
func attemptAXFR(ctx context.Context, ns, domain string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, axfrTimeout)
	defer cancel()

	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(domain))

	tr := &dns.Transfer{
		DialTimeout:  axfrTimeout,
		ReadTimeout:  axfrTimeout,
		WriteTimeout: axfrTimeout,
	}

	env, err := tr.In(m, net.JoinHostPort(ns, "53"))
	if err != nil {
		return 0, fmt.Errorf("axfr to %s: %w", ns, err)
	}

	count := 0
	for {
		select {
		case <-ctx.Done():
			return count, fmt.Errorf("axfr to %s: %w", ns, ctx.Err())
		case e, ok := <-env:
			if !ok {
				return count, nil
			}
			if e.Error != nil {
				return count, fmt.Errorf("axfr to %s: %w", ns, e.Error)
			}
			count += len(e.RR)
		}
	}
}

// summarizeAXFR turns per-nameserver transfer attempts into findings: one
// SevHigh finding per nameserver that handed over the zone, or a single
// SevInfo finding if every nameserver refused (the healthy case).
func summarizeAXFR(results []axfrResult) []Finding {
	var findings []Finding
	var refused []string

	for _, r := range results {
		if r.err == nil {
			findings = append(findings, Finding{
				CheckerID: "dns.axfr", Category: CatDNS, Severity: SevHigh,
				Title: "Zone transfer allowed",
				Summary: fmt.Sprintf("%s allowed an unauthenticated AXFR: ~%d records exposed",
					r.ns, r.count),
				Evidence: map[string]any{"nameserver": r.ns, "record_count": r.count},
			})
			continue
		}
		refused = append(refused, r.ns)
	}

	if len(refused) == len(results) && len(results) > 0 {
		findings = append(findings, Finding{
			CheckerID: "dns.axfr", Category: CatDNS, Severity: SevInfo,
			Title:    "AXFR refused",
			Summary:  fmt.Sprintf("all %d nameserver(s) refused zone transfer", len(refused)),
			Evidence: map[string]any{"nameservers": refused},
		})
	}

	return findings
}
