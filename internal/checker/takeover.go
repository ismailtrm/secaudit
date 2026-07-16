package checker

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func init() { Register(takeoverCheck{}) }

// takeoverCheck looks for dangling CNAMEs: a subdomain that still points at a
// third-party service (GitHub Pages, S3, Heroku, ...) after the resource on
// that service was deleted, which lets anyone else claim the name and serve
// content under the target's domain. It reuses gatherHosts for discovery, so
// it inherits the apex/www/crt.sh/wordlist candidate list rather than
// re-scanning. Only hosts whose CNAME matches a known service get an HTTP
// probe, keeping the request count small.
type takeoverCheck struct{}

func (takeoverCheck) ID() string                               { return "dns.takeover" }
func (takeoverCheck) Name() string                             { return "Subdomain Takeover" }
func (takeoverCheck) Category() Category                       { return CatDNS }
func (takeoverCheck) Mode() Mode                               { return Passive }
func (takeoverCheck) Available(context.Context) (bool, string) { return true, "" }

// takeoverEntry describes one takeover-prone service: the CNAME suffixes that
// route to it and the substring its "unclaimed resource" response contains.
type takeoverEntry struct {
	service       string
	cnameSuffixes []string
	fingerprint   string
}

// takeoverServices is curated from the public subjack / can-i-take-over-xyz
// fingerprint lists: well-known services whose unclaimed-resource page has a
// stable, identifiable body.
var takeoverServices = []takeoverEntry{
	{"GitHub Pages", []string{"github.io"}, "There isn't a GitHub Pages site here"},
	{"AWS S3", []string{"s3.amazonaws.com", "s3-website"}, "NoSuchBucket"},
	{"Heroku", []string{"herokudns.com", "herokuapp.com"}, "No such app"},
	{"Azure", []string{"azurewebsites.net", "cloudapp.net", "trafficmanager.net"}, "404 Web Site not found"},
	{"Fastly", []string{"fastly.net"}, "Fastly error: unknown domain"},
	{"Shopify", []string{"myshopify.com"}, "Sorry, this shop is currently unavailable"},
	{"Surge", []string{"surge.sh"}, "project not found"},
	{"Zendesk", []string{"zendesk.com"}, "Help Center Closed"},
	{"Read the Docs", []string{"readthedocs.io"}, "unknown to Read the Docs"},
	{"Tumblr", []string{"domains.tumblr.com"}, "Whatever you were looking for doesn't currently exist at this address"},
}

// takeoverService maps a CNAME target to the known service it resolves to, if
// any. Matching is substring-based (not a strict suffix) because some
// services embed a region between the marker and the TLD, e.g. an S3 website
// endpoint is "<bucket>.s3-website-us-east-1.amazonaws.com" - "s3-website" is
// not the end of the string. This mirrors how subjack/can-i-take-over-xyz
// style tools match CNAME fingerprints. Pure and network-free so it can be
// table-tested directly.
func takeoverService(cname string) (svc string, ok bool) {
	c := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cname), "."))
	if c == "" {
		return "", false
	}
	for _, e := range takeoverServices {
		for _, suf := range e.cnameSuffixes {
			if strings.Contains(c, suf) {
				return e.service, true
			}
		}
	}
	return "", false
}

// matchesFingerprint reports whether an HTTP response for a host whose CNAME
// points at svc looks like the service's "resource not claimed" page. status
// is accepted for evidence/future refinement; the match itself is body-based
// since these services return varying status codes (200, 404, 526) for the
// same unclaimed state. Pure and network-free so it can be table-tested
// directly.
func matchesFingerprint(svc, body string, status int) bool {
	_ = status
	for _, e := range takeoverServices {
		if !strings.EqualFold(e.service, svc) {
			continue
		}
		return strings.Contains(strings.ToLower(body), strings.ToLower(e.fingerprint))
	}
	return false
}

func (takeoverCheck) Run(ctx context.Context, t Target) ([]Finding, error) {
	hosts := gatherHosts(ctx, t)

	type candidate struct {
		host  string
		cname string
		svc   string
	}

	sem := make(chan struct{}, probeConcurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var candidates []candidate

	for _, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			cname := lookupCNAME(ctx, host)
			if cname == "" {
				return
			}
			svc, ok := takeoverService(cname)
			if !ok {
				return
			}
			mu.Lock()
			candidates = append(candidates, candidate{host: host, cname: cname, svc: svc})
			mu.Unlock()
		}(h)
	}
	wg.Wait()

	sort.Slice(candidates, func(i, j int) bool { return candidates[i].host < candidates[j].host })

	client := &http.Client{Timeout: 10 * time.Second}
	var findings []Finding
	for _, c := range candidates {
		if ctx.Err() != nil {
			break
		}
		body, status, err := probeTakeoverHTTP(ctx, client, c.host)
		if err != nil {
			// Unreachable host is not evidence either way: skip rather than guess.
			continue
		}
		if matchesFingerprint(c.svc, body, status) {
			findings = append(findings, Finding{
				CheckerID: "dns.takeover", Category: CatDNS, Severity: SevHigh,
				Title: fmt.Sprintf("Potential subdomain takeover: %s", c.host),
				Summary: fmt.Sprintf("%s has a CNAME to %s (%s) and the service reports the resource is unclaimed",
					c.host, c.cname, c.svc),
				Evidence: map[string]any{"host": c.host, "cname": c.cname, "service": c.svc, "http_status": status},
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, Finding{
			CheckerID: "dns.takeover", Category: CatDNS, Severity: SevInfo,
			Title:   "No takeover signals",
			Summary: fmt.Sprintf("checked %d candidate host(s), no dangling CNAME to a known service", len(hosts)),
		})
	}
	return findings, nil
}

// lookupCNAME returns the CNAME target for host, or "" if it has none.
func lookupCNAME(ctx context.Context, host string) string {
	rrs, err := queryDNS(ctx, host, dns.TypeCNAME)
	if err != nil {
		return ""
	}
	for _, rr := range rrs {
		if c, ok := rr.(*dns.CNAME); ok {
			return strings.TrimSuffix(c.Target, ".")
		}
	}
	return ""
}

// probeTakeoverHTTP does a single bounded GET against host, trying https then
// falling back to http, and returns the response body (capped) and status.
func probeTakeoverHTTP(ctx context.Context, client *http.Client, host string) (string, int, error) {
	var lastErr error
	for _, scheme := range []string{"https", "http"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+host+"/", nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		return string(body), resp.StatusCode, nil
	}
	return "", 0, fmt.Errorf("takeover probe %s: %w", host, lastErr)
}
