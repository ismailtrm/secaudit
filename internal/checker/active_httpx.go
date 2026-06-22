package checker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/ismailtrm/secaudit/internal/cache"
	"github.com/ismailtrm/secaudit/internal/tool"
)

func init() { Register(httpxScan{}) }

// httpxScan alive-probes the apex plus discovered subdomains (cached crt.sh +
// wordlist resolution) and reports live hosts with their tech stack. It gathers
// its own host list so it has no cross-checker dependency. Active: gated by guard.
type httpxScan struct{}

func (httpxScan) ID() string                               { return "active.httpx" }
func (httpxScan) Name() string                             { return "httpx Probe" }
func (httpxScan) Category() Category                       { return CatHTTP }
func (httpxScan) Mode() Mode                               { return Active }
func (httpxScan) Available(context.Context) (bool, string) { return tool.Available("httpx") }

func (c httpxScan) Run(ctx context.Context, t Target) ([]Finding, error) {
	return c.RunStream(ctx, t, func(Finding) {})
}

func (httpxScan) RunStream(ctx context.Context, t Target, emit Emitter) ([]Finding, error) {
	hosts := gatherHosts(ctx, t)

	var findings []Finding
	err := tool.Stream(ctx, strings.Join(hosts, "\n"), func(line string) {
		if !strings.HasPrefix(strings.TrimSpace(line), "{") {
			return
		}
		var r httpxResult
		if json.Unmarshal([]byte(line), &r) != nil || r.Failed || r.URL == "" {
			return
		}
		f := httpxFinding(r)
		findings = append(findings, f)
		emit(f)
	}, "httpx", "-json", "-tech-detect", "-status-code", "-title", "-silent", "-no-color")
	if err != nil {
		return findings, fmt.Errorf("httpx: %w", err)
	}
	if len(findings) == 0 {
		f := Finding{CheckerID: "active.httpx", Category: CatHTTP, Severity: SevInfo,
			Title: "No live hosts", Summary: "no probed host responded over HTTP(S)"}
		emit(f)
		findings = append(findings, f)
	}
	return findings, nil
}

// gatherHosts builds the probe list: apex, www, cached crt.sh subdomains, and
// wordlist resolutions (skipped on a wildcard zone).
func gatherHosts(ctx context.Context, t Target) []string {
	set := map[string]struct{}{t.Host: {}, "www." + t.Domain: {}}

	if c := cache.Default(); c != nil {
		if data, ok := c.Get("crtsh:" + t.Domain); ok {
			if subs, err := parseCrtSh(data, t.Domain); err == nil {
				for _, s := range subs {
					set[s] = struct{}{}
				}
			}
		}
	}
	if !resolves(ctx, "zzqx-secaudit-wildcard-probe."+t.Domain) {
		for _, h := range probeNames(ctx, t.Domain, parseWordlist(wordlistRaw), probeConcurrency) {
			set[h] = struct{}{}
		}
	}

	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

type httpxResult struct {
	URL        string   `json:"url"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	Webserver  string   `json:"webserver"`
	Tech       []string `json:"tech"`
	Failed     bool     `json:"failed"`
}

func httpxFinding(r httpxResult) Finding {
	parts := []string{fmt.Sprintf("HTTP %d", r.StatusCode)}
	if r.Webserver != "" {
		parts = append(parts, r.Webserver)
	}
	// Drop the webserver from the tech list so it isn't shown twice.
	var techs []string
	for _, tech := range r.Tech {
		if !strings.EqualFold(tech, r.Webserver) {
			techs = append(techs, tech)
		}
	}
	if len(techs) > 0 {
		parts = append(parts, strings.Join(techs, ", "))
	}
	host := r.URL
	if u, err := url.Parse(r.URL); err == nil && u.Host != "" {
		host = u.Host
	}
	return Finding{
		CheckerID: "active.httpx", Category: CatHTTP, Severity: SevInfo,
		Title: "Live: " + host, Summary: strings.Join(parts, " · "),
		Evidence: map[string]any{"url": r.URL, "status": r.StatusCode, "webserver": r.Webserver, "tech": r.Tech, "title": r.Title},
	}
}
