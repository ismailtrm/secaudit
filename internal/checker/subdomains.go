package checker

import (
	"context"
	_ "embed"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

//go:embed wordlist.txt
var wordlistRaw string

func init() { Register(subdomainProbe{}) }

// subdomainProbe resolves a built-in wordlist of common labels against the
// target zone. Resolution goes through the system resolver (it doesn't touch the
// target's hosts directly), so it is passive. A catch-all "wildcard" zone is
// detected first to avoid reporting every label as a false positive.
type subdomainProbe struct{}

func (subdomainProbe) ID() string                               { return "dns.subdomains" }
func (subdomainProbe) Name() string                             { return "Subdomain Probe (wordlist)" }
func (subdomainProbe) Category() Category                       { return CatOSINT }
func (subdomainProbe) Mode() Mode                               { return Passive }
func (subdomainProbe) Available(context.Context) (bool, string) { return true, "" }

const probeConcurrency = 25

func (subdomainProbe) Run(ctx context.Context, t Target) ([]Finding, error) {
	if resolves(ctx, "zzqx-secaudit-wildcard-probe."+t.Domain) {
		return []Finding{{CheckerID: "dns.subdomains", Category: CatOSINT, Severity: SevInfo,
			Title:   "Wildcard DNS",
			Summary: "every label resolves (wildcard record): wordlist probe skipped"}}, nil
	}

	words := parseWordlist(wordlistRaw)
	found := probeNames(ctx, t.Domain, words, probeConcurrency)
	sort.Strings(found)

	summary := fmt.Sprintf("%d of %d probed labels resolve", len(found), len(words))
	if len(found) > 0 {
		summary += ": " + clip(strings.Join(found, ", "))
	}
	return []Finding{{
		CheckerID: "dns.subdomains", Category: CatOSINT, Severity: SevInfo,
		Title:    "Subdomains (wordlist)",
		Summary:  summary,
		Detail:   strings.Join(found, "\n"),
		Evidence: map[string]any{"found": found, "probed": len(words)},
	}}, nil
}

// probeNames resolves word.domain for each word with bounded concurrency.
func probeNames(ctx context.Context, domain string, words []string, conc int) []string {
	sem := make(chan struct{}, conc)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var found []string

probeLoop:
	for _, w := range words {
		select {
		case <-ctx.Done():
			break probeLoop
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(w string) {
			defer wg.Done()
			defer func() { <-sem }()
			host := w + "." + domain
			if resolves(ctx, host) {
				mu.Lock()
				found = append(found, host)
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	return found
}

// resolves reports whether name has at least one A or AAAA record (an
// IPv6-only host still counts as live).
func resolves(ctx context.Context, name string) bool {
	if rrs, err := queryDNS(ctx, name, dns.TypeA); err == nil && hasRRType(rrs, dns.TypeA) {
		return true
	}
	rrs, err := queryDNS(ctx, name, dns.TypeAAAA)
	return err == nil && hasRRType(rrs, dns.TypeAAAA)
}

// parseWordlist returns non-empty, non-comment lines from the embedded list.
func parseWordlist(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}
