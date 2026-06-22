package checker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ismailtrm/secaudit/internal/cache"
)

func init() { Register(wayback{}) }

// wayback checks whether the domain is archived in the Internet Archive's
// Wayback Machine and reports the closest snapshot. Result is cached (24h).
type wayback struct{}

func (wayback) ID() string                               { return "osint.wayback" }
func (wayback) Name() string                             { return "Wayback Machine" }
func (wayback) Category() Category                       { return CatOSINT }
func (wayback) Mode() Mode                               { return Passive }
func (wayback) Available(context.Context) (bool, string) { return true, "" }

const waybackTTL = 24 * time.Hour

type waybackResp struct {
	ArchivedSnapshots struct {
		Closest struct {
			Available bool   `json:"available"`
			URL       string `json:"url"`
			Timestamp string `json:"timestamp"`
			Status    string `json:"status"`
		} `json:"closest"`
	} `json:"archived_snapshots"`
}

func (wayback) Run(ctx context.Context, t Target) ([]Finding, error) {
	info := func(title, summary string, ev map[string]any) []Finding {
		return []Finding{{CheckerID: "osint.wayback", Category: CatOSINT,
			Severity: SevInfo, Title: title, Summary: summary, Evidence: ev}}
	}

	key := "wayback:" + t.Domain
	var raw []byte
	if c := cache.Default(); c != nil {
		if data, ok := c.Get(key); ok {
			raw = data
		}
	}
	if raw == nil {
		data, err := fetchWayback(ctx, t.Domain)
		if err != nil {
			return info("Wayback unavailable", err.Error(), nil), nil
		}
		raw = data
		if c := cache.Default(); c != nil {
			_ = c.Set(key, raw, waybackTTL)
		}
	}

	var wr waybackResp
	if err := json.Unmarshal(raw, &wr); err != nil {
		return info("Wayback parse error", err.Error(), nil), nil
	}

	closest := wr.ArchivedSnapshots.Closest
	if !closest.Available {
		return info("Not archived", "no Wayback Machine snapshots for this domain", nil), nil
	}
	when := closest.Timestamp
	if ts, err := time.Parse("20060102150405", closest.Timestamp); err == nil {
		when = ts.Format("2006-01-02")
	}
	return info("Archived in Wayback",
		fmt.Sprintf("closest snapshot %s: %s", when, closest.URL),
		map[string]any{"timestamp": closest.Timestamp, "url": closest.URL}), nil
}

func fetchWayback(ctx context.Context, domain string) ([]byte, error) {
	url := "http://archive.org/wayback/available?url=" + domain
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "secaudit/1.0 (+passive recon)")
	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("archive.org HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
