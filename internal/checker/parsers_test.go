package checker

import (
	"strings"
	"testing"
)

const nmapXMLFixture = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="6379">
        <state state="open"/>
        <service name="redis" product="Redis" version="6.2.6"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="filtered"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>`

func TestParseNmapXML(t *testing.T) {
	ports, err := parseNmapXML([]byte(nmapXMLFixture))
	if err != nil {
		t.Fatalf("parseNmapXML: unexpected error: %v", err)
	}
	if len(ports) != 1 {
		t.Fatalf("parseNmapXML: got %d ports, want 1 (closed/filtered must be excluded): %+v", len(ports), ports)
	}
	got := ports[0]
	want := nmapPort{num: 6379, proto: "tcp", service: "redis", product: "Redis", version: "6.2.6"}
	if got != want {
		t.Errorf("parseNmapXML: got %+v, want %+v", got, want)
	}
}

func TestNmapFindingSeverity(t *testing.T) {
	tests := []struct {
		name string
		port nmapPort
		sev  Severity
		note string
	}{
		{"redis", nmapPort{num: 6379, proto: "tcp", service: "redis"}, SevHigh, "Redis exposed: often unauthenticated"},
		{"docker", nmapPort{num: 2375, proto: "tcp", service: "docker"}, SevCritical, "Docker API exposed: unauthenticated root"},
		{"benign http", nmapPort{num: 80, proto: "tcp", service: "http"}, SevInfo, ""},
	}
	for _, tc := range tests {
		f := nmapFinding(tc.port)
		if f.Severity != tc.sev {
			t.Errorf("%s: nmapFinding severity = %v, want %v", tc.name, f.Severity, tc.sev)
		}
		if tc.note != "" && !strings.Contains(f.Summary, tc.note) {
			t.Errorf("%s: nmapFinding summary %q does not contain note %q", tc.name, f.Summary, tc.note)
		}
	}
}

func TestNucleiSev(t *testing.T) {
	tests := []struct {
		in  string
		sev Severity
	}{
		{"critical", SevCritical},
		{"CRITICAL", SevCritical},
		{"high", SevHigh},
		{"High", SevHigh},
		{"medium", SevMedium},
		{"low", SevLow},
		{"", SevInfo},
		{"info", SevInfo},
		{"unknown", SevInfo},
	}
	for _, tc := range tests {
		if got := nucleiSev(tc.in); got != tc.sev {
			t.Errorf("nucleiSev(%q) = %v, want %v", tc.in, got, tc.sev)
		}
	}
}

func TestNucleiFinding(t *testing.T) {
	r := nucleiResult{
		TemplateID: "exposed-panel",
		MatchedAt:  "https://example.com/admin",
	}
	r.Info.Name = ""
	r.Info.Severity = "high"

	f := nucleiFinding(r)
	if f.Title != r.TemplateID {
		t.Errorf("nucleiFinding: Title = %q, want fallback to TemplateID %q", f.Title, r.TemplateID)
	}
	if f.Severity != SevHigh {
		t.Errorf("nucleiFinding: Severity = %v, want %v", f.Severity, SevHigh)
	}
	if !strings.Contains(f.Summary, r.MatchedAt) {
		t.Errorf("nucleiFinding: Summary %q does not contain MatchedAt %q", f.Summary, r.MatchedAt)
	}
}

func TestHttpxFinding(t *testing.T) {
	r := httpxResult{
		URL:        "https://example.com",
		StatusCode: 200,
		Webserver:  "nginx",
		Tech:       []string{"nginx", "PHP", "jQuery"},
	}
	f := httpxFinding(r)

	if strings.Contains(f.Summary, "nginx, PHP") || strings.Count(f.Summary, "nginx") != 1 {
		t.Errorf("httpxFinding: Summary %q should de-duplicate webserver out of tech list", f.Summary)
	}
	if !strings.Contains(f.Summary, "PHP") || !strings.Contains(f.Summary, "jQuery") {
		t.Errorf("httpxFinding: Summary %q missing remaining tech entries", f.Summary)
	}
	if !strings.Contains(f.Summary, "HTTP 200") {
		t.Errorf("httpxFinding: Summary %q does not contain %q", f.Summary, "HTTP 200")
	}
}
