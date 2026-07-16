package checker

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func init() { Register(securityTxt{}) }

// securityTxt checks for an RFC 9116 security.txt file, first at the
// well-known location and falling back to the legacy root path. Its presence
// (or absence) is a maturity signal, not a pass/fail control, so every
// outcome is reported at Info.
type securityTxt struct{}

func (securityTxt) ID() string                               { return "http.securitytxt" }
func (securityTxt) Name() string                             { return "security.txt (RFC 9116)" }
func (securityTxt) Category() Category                       { return CatHTTP }
func (securityTxt) Mode() Mode                               { return Passive }
func (securityTxt) Available(context.Context) (bool, string) { return true, "" }

const securityTxtTimeout = 10 * time.Second

func (securityTxt) Run(ctx context.Context, t Target) ([]Finding, error) {
	info := func(title, summary string, ev map[string]any) []Finding {
		return []Finding{{CheckerID: "http.securitytxt", Category: CatHTTP,
			Severity: SevInfo, Title: title, Summary: summary, Evidence: ev}}
	}

	client := &http.Client{Timeout: securityTxtTimeout}

	body, foundURL, err := fetchSecurityTxt(ctx, client, t.Host)
	if err != nil {
		return info("security.txt check failed", err.Error(), nil), nil
	}
	if body == "" {
		return info("No security.txt",
			"no security.txt at /.well-known/security.txt or /security.txt (a maturity signal, not a defect)",
			nil), nil
	}

	contact, ok := parseSecurityTxt(body)
	if !ok {
		return info("No security.txt",
			"a file was served but did not look like a valid security.txt (no Contact field)",
			map[string]any{"url": foundURL}), nil
	}

	expires := securityTxtField(body, "Expires")
	summary := "Contact: " + contact
	ev := map[string]any{"url": foundURL, "contact": contact}
	if expires != "" {
		summary += "; Expires: " + expires
		ev["expires"] = expires
	}

	return []Finding{{CheckerID: "http.securitytxt", Category: CatHTTP, Severity: SevInfo,
		Title: "security.txt present", Summary: summary, Evidence: ev}}, nil
}

// fetchSecurityTxt tries the well-known path then the legacy root path,
// returning the body of the first 200 response. A 404 (or other non-200) on
// both paths returns ("", "", nil) — that's the healthy "absent" case, not an
// error. Only a transport failure on both attempts is returned as an error.
func fetchSecurityTxt(ctx context.Context, client *http.Client, host string) (body, foundURL string, err error) {
	paths := []string{"/.well-known/security.txt", "/security.txt"}
	var lastErr error
	for _, p := range paths {
		u := "https://" + host + p
		b, status, ferr := getSecurityTxtURL(ctx, client, u)
		if ferr != nil {
			lastErr = ferr
			continue
		}
		lastErr = nil
		if status == http.StatusOK {
			return b, u, nil
		}
	}
	if lastErr != nil {
		return "", "", lastErr
	}
	return "", "", nil
}

// getSecurityTxtURL performs a single GET, returning the body and status code.
func getSecurityTxtURL(ctx context.Context, client *http.Client, url string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", 0, fmt.Errorf("build request for %s: %w", url, err)
	}
	req.Header.Set("User-Agent", "secaudit/1.0 (+passive recon)")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, fmt.Errorf("read %s: %w", url, err)
	}
	return string(data), resp.StatusCode, nil
}

// parseSecurityTxt is a pure check for whether body looks like an RFC 9116
// security.txt: it must contain a "Contact:" field (case-insensitive). It
// returns the trimmed value of the first Contact field found.
func parseSecurityTxt(body string) (contact string, ok bool) {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, val, found := strings.Cut(line, ":")
		if found && strings.EqualFold(strings.TrimSpace(name), "contact") {
			return strings.TrimSpace(val), true
		}
	}
	return "", false
}

// securityTxtField returns the trimmed value of the first line in body whose
// field name matches field, case-insensitive. Empty string if absent.
func securityTxtField(body, field string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, val, found := strings.Cut(line, ":")
		if found && strings.EqualFold(strings.TrimSpace(name), field) {
			return strings.TrimSpace(val)
		}
	}
	return ""
}
