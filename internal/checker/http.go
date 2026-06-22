package checker

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func init() { Register(httpHeaders{}) }

// httpHeaders fetches the site once and reports both the server banner / redirect
// chain and the presence/quality of HTTP security headers. Merged into one
// checker so the response is fetched a single time.
type httpHeaders struct{}

func (httpHeaders) ID() string                               { return "http.headers" }
func (httpHeaders) Name() string                             { return "HTTP & Security Headers" }
func (httpHeaders) Category() Category                       { return CatHTTP }
func (httpHeaders) Mode() Mode                               { return Passive }
func (httpHeaders) Available(context.Context) (bool, string) { return true, "" }

func (httpHeaders) Run(ctx context.Context, t Target) ([]Finding, error) {
	add := func(sev Severity, title, summary string, ev map[string]any) Finding {
		return Finding{CheckerID: "http.headers", Category: CatHTTP, Severity: sev,
			Title: title, Summary: summary, Evidence: ev}
	}

	var chain []string
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			chain = append(chain, req.URL.String())
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	resp, scheme, err := fetch(ctx, client, t.Host)
	if err != nil {
		return []Finding{add(SevMedium, "Site unreachable over HTTP(S)", err.Error(),
			map[string]any{"host": t.Host})}, nil
	}
	defer resp.Body.Close()

	var findings []Finding

	// Banner.
	server := resp.Header.Get("Server")
	powered := resp.Header.Get("X-Powered-By")
	banner := strings.TrimSpace(strings.Join([]string{server, powered}, " "))
	if banner == "" {
		banner = "(no Server header)"
	}
	findings = append(findings, add(SevInfo, "Server banner",
		fmt.Sprintf("%s (HTTP %d)", banner, resp.StatusCode),
		map[string]any{"server": server, "x_powered_by": powered, "status": resp.StatusCode}))

	// Redirect chain / HTTPS reachability.
	if scheme == "http" {
		findings = append(findings, add(SevMedium, "No HTTPS",
			"site served over plaintext HTTP only", map[string]any{"host": t.Host}))
	}
	if len(chain) > 0 {
		findings = append(findings, add(SevInfo, "Redirect chain",
			strings.Join(append(chain, resp.Request.URL.String()), " → "),
			map[string]any{"chain": chain}))
	}

	// Security headers. Only meaningful over HTTPS for HSTS.
	h := resp.Header
	https := resp.Request.URL.Scheme == "https"

	if https {
		if hsts := h.Get("Strict-Transport-Security"); hsts == "" {
			findings = append(findings, add(SevMedium, "Missing HSTS",
				"no Strict-Transport-Security header", nil))
		} else {
			findings = append(findings, add(SevInfo, "HSTS", clip(hsts),
				map[string]any{"hsts": hsts}))
		}
	}
	checkPresent(&findings, add, h, "Content-Security-Policy", SevLow,
		"no CSP: reduced XSS/injection mitigation")
	checkPresent(&findings, add, h, "X-Frame-Options", SevLow,
		"no X-Frame-Options: clickjacking possible (unless CSP frame-ancestors set)")
	checkPresent(&findings, add, h, "X-Content-Type-Options", SevLow,
		"no X-Content-Type-Options: nosniff. MIME sniffing possible")
	checkPresent(&findings, add, h, "Referrer-Policy", SevInfo,
		"no Referrer-Policy")

	return findings, nil
}

// checkPresent emits a missing-header finding at sev, or an Info finding if set.
func checkPresent(findings *[]Finding, add func(Severity, string, string, map[string]any) Finding,
	h http.Header, name string, missingSev Severity, missingMsg string) {
	if v := h.Get(name); v == "" {
		*findings = append(*findings, add(missingSev, "Missing "+name, missingMsg, nil))
	} else {
		*findings = append(*findings, add(SevInfo, name, clip(v), map[string]any{name: v}))
	}
}

// clip shortens a long header value for one-line summaries; the full value is
// preserved in Finding.Evidence.
func clip(s string) string {
	const max = 100
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// fetch tries HTTPS then falls back to HTTP, returning the final response and
// the scheme that succeeded.
func fetch(ctx context.Context, client *http.Client, host string) (*http.Response, string, error) {
	for _, scheme := range []string{"https", "http"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+host, nil)
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("User-Agent", "secaudit/1.0 (+passive recon)")
		resp, err := client.Do(req)
		if err == nil {
			return resp, scheme, nil
		}
		if scheme == "http" {
			return nil, "", err
		}
	}
	return nil, "", fmt.Errorf("unreachable")
}
