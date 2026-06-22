package checker

import (
	"context"
	"encoding/xml"
	"fmt"
	"strconv"

	"github.com/ismailtrm/secaudit/internal/tool"
)

func init() { Register(nmapScan{}) }

// nmapScan runs an nmap connect-scan of the top ports and flags risky exposed
// services. Active: only runs on own/authorized targets (gated by guard).
type nmapScan struct{}

func (nmapScan) ID() string                               { return "active.nmap" }
func (nmapScan) Name() string                             { return "nmap Port Scan" }
func (nmapScan) Category() Category                       { return CatPort }
func (nmapScan) Mode() Mode                               { return Active }
func (nmapScan) Available(context.Context) (bool, string) { return tool.Available("nmap") }

func (c nmapScan) Run(ctx context.Context, t Target) ([]Finding, error) {
	return c.RunStream(ctx, t, func(Finding) {})
}

func (nmapScan) RunStream(ctx context.Context, t Target, emit Emitter) ([]Finding, error) {
	// -Pn: skip host discovery; -T4: faster timing; top 1000 TCP ports; XML to stdout.
	out, err := tool.Output(ctx, "nmap", "-Pn", "-T4", "--top-ports", "1000", "-oX", "-", t.Host)
	if err != nil {
		return nil, fmt.Errorf("nmap: %w", err)
	}
	ports, err := parseNmapXML(out)
	if err != nil {
		return nil, fmt.Errorf("nmap parse: %w", err)
	}

	var findings []Finding
	for _, p := range ports {
		f := nmapFinding(p)
		findings = append(findings, f)
		emit(f)
	}
	if len(findings) == 0 {
		f := Finding{CheckerID: "active.nmap", Category: CatPort, Severity: SevInfo,
			Title: "No open ports", Summary: "no open ports found in the top 1000"}
		emit(f)
		findings = append(findings, f)
	}
	return findings, nil
}

type nmapPort struct {
	num     int
	proto   string
	service string
	product string
	version string
}

func parseNmapXML(data []byte) ([]nmapPort, error) {
	var run struct {
		Hosts []struct {
			Ports struct {
				Ports []struct {
					Protocol string `xml:"protocol,attr"`
					PortID   int    `xml:"portid,attr"`
					State    struct {
						State string `xml:"state,attr"`
					} `xml:"state"`
					Service struct {
						Name    string `xml:"name,attr"`
						Product string `xml:"product,attr"`
						Version string `xml:"version,attr"`
					} `xml:"service"`
				} `xml:"port"`
			} `xml:"ports"`
		} `xml:"host"`
	}
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, err
	}
	var out []nmapPort
	for _, h := range run.Hosts {
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			out = append(out, nmapPort{
				num: p.PortID, proto: p.Protocol, service: p.Service.Name,
				product: p.Service.Product, version: p.Service.Version,
			})
		}
	}
	return out, nil
}

// riskyPort maps a port to a severity + note when exposure is a concern.
var riskyPort = map[int]struct {
	sev  Severity
	note string
}{
	21:    {SevMedium, "FTP — frequently plaintext"},
	23:    {SevHigh, "Telnet — plaintext credentials, should never be exposed"},
	135:   {SevMedium, "MSRPC exposed"},
	445:   {SevMedium, "SMB exposed"},
	1433:  {SevHigh, "MSSQL exposed to the internet"},
	2375:  {SevCritical, "Docker API exposed — unauthenticated root"},
	3306:  {SevHigh, "MySQL exposed to the internet"},
	3389:  {SevMedium, "RDP exposed"},
	5432:  {SevHigh, "PostgreSQL exposed to the internet"},
	5900:  {SevMedium, "VNC exposed"},
	6379:  {SevHigh, "Redis exposed — often unauthenticated"},
	9200:  {SevHigh, "Elasticsearch exposed — often unauthenticated"},
	11211: {SevHigh, "Memcached exposed — amplification/abuse risk"},
	27017: {SevHigh, "MongoDB exposed to the internet"},
}

func nmapFinding(p nmapPort) Finding {
	svc := p.service
	if svc == "" {
		svc = "unknown"
	}
	if p.product != "" {
		svc += " (" + p.product
		if p.version != "" {
			svc += " " + p.version
		}
		svc += ")"
	}
	title := "Port " + strconv.Itoa(p.num) + "/" + p.proto + " open — " + p.service
	sev := SevInfo
	summary := svc
	if r, ok := riskyPort[p.num]; ok {
		sev = r.sev
		summary = r.note + " — " + svc
	}
	return Finding{
		CheckerID: "active.nmap", Category: CatPort, Severity: sev,
		Title: title, Summary: summary,
		Evidence: map[string]any{"port": p.num, "service": p.service, "product": p.product, "version": p.version},
	}
}
