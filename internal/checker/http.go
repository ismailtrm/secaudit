package checker

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
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
			sev, note := hstsQuality(hsts)
			findings = append(findings, add(sev, "HSTS", note,
				map[string]any{"hsts": hsts}))
		}
	}
	if csp := h.Get("Content-Security-Policy"); csp == "" {
		findings = append(findings, add(SevLow, "Missing Content-Security-Policy",
			"no CSP: reduced XSS/injection mitigation", nil))
	} else {
		sev, note := cspQuality(csp)
		findings = append(findings, add(sev, "Content-Security-Policy", note,
			map[string]any{"Content-Security-Policy": csp}))
	}
	checkPresent(&findings, add, h, "X-Frame-Options", SevLow,
		"no X-Frame-Options: clickjacking possible (unless CSP frame-ancestors set)")
	checkPresent(&findings, add, h, "X-Content-Type-Options", SevLow,
		"no X-Content-Type-Options: nosniff. MIME sniffing possible")
	checkPresent(&findings, add, h, "Referrer-Policy", SevInfo,
		"no Referrer-Policy")
	checkPresent(&findings, add, h, "Permissions-Policy", SevInfo,
		"no Permissions-Policy")
	checkPresent(&findings, add, h, "Cross-Origin-Opener-Policy", SevInfo,
		"no Cross-Origin-Opener-Policy")
	checkPresent(&findings, add, h, "Cross-Origin-Resource-Policy", SevInfo,
		"no Cross-Origin-Resource-Policy")

	// Cookie hardening. One finding per cookie missing flags; SevMedium only
	// when a cookie lacks both Secure and HttpOnly over HTTPS.
	for _, c := range resp.Cookies() {
		issues := cookieIssues(c, https)
		if len(issues) == 0 {
			continue
		}
		sev := SevLow
		if https && !c.Secure && !c.HttpOnly {
			sev = SevMedium
		}
		findings = append(findings, add(sev,
			fmt.Sprintf("Cookie %q missing hardening", c.Name),
			"missing: "+strings.Join(issues, ", "),
			map[string]any{"cookie": c.Name, "missing": issues}))
	}

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

// cookieIssues returns which hardening flags a cookie is missing. https
// indicates whether the response was served over TLS: Secure is only
// meaningful there. SameSite unset (the zero value when no attribute was
// sent, or the equivalent SameSiteDefaultMode) or explicit None is reported
// as a weaker issue but does not affect finding severity on its own.
func cookieIssues(c *http.Cookie, https bool) []string {
	var issues []string
	if https && !c.Secure {
		issues = append(issues, "Secure")
	}
	if !c.HttpOnly {
		issues = append(issues, "HttpOnly")
	}
	if c.SameSite == 0 || c.SameSite == http.SameSiteDefaultMode || c.SameSite == http.SameSiteNoneMode {
		issues = append(issues, "SameSite")
	}
	return issues
}

// hstsQuality parses a Strict-Transport-Security header value and rates it by
// max-age and the includeSubDomains/preload directives.
func hstsQuality(v string) (Severity, string) {
	maxAge := -1
	includeSub := false
	preload := false
	for _, part := range strings.Split(v, ";") {
		part = strings.TrimSpace(part)
		lower := strings.ToLower(part)
		switch {
		case lower == "includesubdomains":
			includeSub = true
		case lower == "preload":
			preload = true
		case strings.HasPrefix(lower, "max-age"):
			if _, val, ok := strings.Cut(part, "="); ok {
				if n, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
					maxAge = n
				}
			}
		}
	}

	const minStrongAge = 15552000 // 180 days
	switch {
	case maxAge == 0:
		return SevMedium, "max-age=0: HSTS disabled"
	case maxAge < 0:
		return SevLow, "max-age missing or unparsable"
	case maxAge < minStrongAge:
		return SevLow, fmt.Sprintf("max-age=%d is short (recommended >= 15552000 / 180 days)", maxAge)
	case !includeSub:
		return SevLow, "missing includeSubDomains"
	default:
		note := "strong HSTS policy"
		if preload {
			note += ", preload set"
		}
		return SevInfo, note
	}
}

// cspQuality inspects a Content-Security-Policy value for common weaknesses:
// unsafe-inline, unsafe-eval, or a wildcard default-src/script-src.
func cspQuality(v string) (Severity, string) {
	low := strings.ToLower(v)
	var weak []string
	if strings.Contains(low, "unsafe-inline") {
		weak = append(weak, "unsafe-inline")
	}
	if strings.Contains(low, "unsafe-eval") {
		weak = append(weak, "unsafe-eval")
	}
	if strings.Contains(low, "default-src *") || strings.Contains(low, "script-src *") {
		weak = append(weak, "wildcard source")
	}
	if len(weak) > 0 {
		return SevLow, "CSP weakened by: " + strings.Join(weak, ", ")
	}
	return SevInfo, "CSP present"
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
		req.Header.Set("User-Agent", userAgent)
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
