package checker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ismailtrm/secaudit/internal/cache"
)

func init() { Register(crtSh{}) }

// crtSh discovers subdomains from Certificate Transparency logs via crt.sh.
// crt.sh is frequently slow or returns 502, so results are retried and cached;
// a failure degrades to an informational "unavailable" finding, never an error.
type crtSh struct{}

func (crtSh) ID() string                               { return "osint.crtsh" }
func (crtSh) Name() string                             { return "crt.sh Subdomains" }
func (crtSh) Category() Category                       { return CatOSINT }
func (crtSh) Mode() Mode                               { return Passive }
func (crtSh) Available(context.Context) (bool, string) { return true, "" }

const crtShTTL = 6 * time.Hour

func (crtSh) Run(ctx context.Context, t Target) ([]Finding, error) {
	info := func(title, summary string) []Finding {
		return []Finding{{CheckerID: "osint.crtsh", Category: CatOSINT,
			Severity: SevInfo, Title: title, Summary: summary}}
	}

	key := "crtsh:" + t.Domain
	var raw []byte
	cached := false
	if c := cache.Default(); c != nil {
		if data, ok := c.Get(key); ok {
			raw, cached = data, true
		}
	}
	if raw == nil {
		data, err := fetchCrtSh(ctx, t.Domain)
		if err != nil {
			return info("crt.sh unavailable", err.Error()), nil
		}
		raw = data
		if c := cache.Default(); c != nil {
			_ = c.Set(key, raw, crtShTTL)
		}
	}

	subs, err := parseCrtSh(raw, t.Domain)
	if err != nil {
		return info("crt.sh parse error", err.Error()), nil
	}

	src := "crt.sh"
	if cached {
		src += " (cached)"
	}
	summary := fmt.Sprintf("%d unique subdomain(s) via %s", len(subs), src)
	if len(subs) > 0 {
		summary += ": " + clip(strings.Join(subs, ", "))
	}
	return []Finding{{
		CheckerID: "osint.crtsh", Category: CatOSINT, Severity: SevInfo,
		Title:    "Subdomains (CT logs)",
		Summary:  summary,
		Detail:   strings.Join(subs, "\n"),
		Evidence: map[string]any{"subdomains": subs, "count": len(subs), "cached": cached},
	}}, nil
}

// fetchCrtSh queries crt.sh with bounded retries. crt.sh either fails fast (502)
// or hangs; a hard total-time budget keeps one flaky service from dominating the
// whole scan's wall-clock (fast 502s still get retried within the budget).
func fetchCrtSh(ctx context.Context, domain string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	url := "https://crt.sh/?q=%25." + domain + "&output=json"
	client := &http.Client{}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, lastErr
			case <-time.After(time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil { // total budget exhausted (hang) — stop retrying
				return nil, lastErr
			}
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("crt.sh HTTP %d (attempt %d/3)", resp.StatusCode, attempt+1)
			continue
		}
		if len(body) == 0 {
			lastErr = fmt.Errorf("crt.sh returned empty response")
			continue
		}
		return body, nil
	}
	return nil, lastErr
}

// parseCrtSh extracts unique subdomains of domain from a crt.sh JSON response.
// name_value fields hold newline-separated names and may include "*." wildcards.
func parseCrtSh(data []byte, domain string) ([]string, error) {
	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	set := map[string]struct{}{}
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(name)), "*.")
			if name == "" {
				continue
			}
			if name == domain || strings.HasSuffix(name, "."+domain) {
				set[name] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}
