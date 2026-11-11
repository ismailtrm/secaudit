package checker

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

func overrideResolvers(t *testing.T, list []string, doh []string) {
	t.Helper()
	oldList, oldDoH := resolverList, dohEndpoints
	resolverList = func() []string { return list }
	dohEndpoints = doh
	t.Cleanup(func() { resolverList, dohEndpoints = oldList, oldDoH })
}

func TestBuildResolverList(t *testing.T) {
	got := buildResolverList([]string{"10.0.0.1", "10.0.0.1", "1.1.1.1"}, "53")
	want := []string{"10.0.0.1:53", "1.1.1.1:53", "8.8.8.8:53"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	got = buildResolverList(nil, "53")
	want = []string{"1.1.1.1:53", "8.8.8.8:53"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestQueryDNSDoHFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/dns-message" {
			t.Errorf("unexpected Content-Type %q", r.Header.Get("Content-Type"))
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		var req dns.Msg
		if err := req.Unpack(body); err != nil {
			t.Errorf("unpack: %v", err)
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(&req)
		resp.Answer = append(resp.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{"v=spf1 -all"},
		})
		out, err := resp.Pack()
		if err != nil {
			t.Errorf("pack: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		if _, err := w.Write(out); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	defer srv.Close()
	overrideResolvers(t, []string{"127.0.0.1:1"}, []string{srv.URL})

	got, err := firstWithPrefix(context.Background(), "example.com", "v=spf1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "v=spf1 -all" {
		t.Errorf("got %q", got)
	}
}

func TestQueryDNSInconclusive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	overrideResolvers(t, []string{"127.0.0.1:1"}, []string{srv.URL})

	if _, err := queryDNS(context.Background(), "example.com", dns.TypeTXT); err == nil {
		t.Fatal("queryDNS: expected error, got nil")
	}
	spf, err := firstWithPrefix(context.Background(), "example.com", "v=spf1")
	if err == nil {
		t.Fatalf("firstWithPrefix: expected error, got %q", spf)
	}
}

type stubHandler func(w dns.ResponseWriter, r *dns.Msg)

// startStub runs a UDP+TCP DNS server on one 127.0.0.1 port and returns its
// address. tcp may be nil, in which case no TCP listener is started.
func startStub(t *testing.T, udp, tcp stubHandler) string {
	t.Helper()
	var tl net.Listener
	var err error
	var addr string
	if tcp != nil {
		tl, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr = tl.Addr().String()
	} else {
		addr = "127.0.0.1:0"
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	addr = pc.LocalAddr().String()
	servers := []*dns.Server{{PacketConn: pc, Handler: dns.HandlerFunc(udp)}}
	if tcp != nil {
		servers = append(servers, &dns.Server{Listener: tl, Handler: dns.HandlerFunc(tcp)})
	}
	for _, srv := range servers {
		started := make(chan struct{})
		srv.NotifyStartedFunc = func() { close(started) }
		go func() { _ = srv.ActivateAndServe() }()
		<-started
		t.Cleanup(func() { _ = srv.Shutdown() })
	}
	return addr
}

func reply(t *testing.T, w dns.ResponseWriter, r *dns.Msg, rcode int, truncated bool, txt string) {
	t.Helper()
	m := new(dns.Msg)
	m.SetReply(r)
	m.Rcode = rcode
	m.Truncated = truncated
	if txt != "" && r.Question[0].Qtype == dns.TypeTXT {
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{txt},
		})
	}
	if err := w.WriteMsg(m); err != nil {
		t.Errorf("stub write: %v", err)
	}
}

func fixed(t *testing.T, n *atomic.Int32, rcode int, truncated bool, txt string) stubHandler {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		if n != nil {
			n.Add(1)
		}
		reply(t, w, r, rcode, truncated, txt)
	}
}

func dohStub(t *testing.T, rcode int, txt string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		var req dns.Msg
		if err := req.Unpack(body); err != nil {
			t.Errorf("unpack: %v", err)
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(&req)
		resp.Rcode = rcode
		if txt != "" {
			resp.Answer = append(resp.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{txt},
			})
		}
		out, err := resp.Pack()
		if err != nil {
			t.Errorf("pack: %v", err)
			return
		}
		if _, err := w.Write(out); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func failingDoH(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func hasTitle(fs []Finding, title string) bool {
	for _, f := range fs {
		if f.Title == title {
			return true
		}
	}
	return false
}

func TestExchangeScenarios(t *testing.T) {
	const spf = "v=spf1 -all"
	tests := []struct {
		name     string
		setup    func(t *testing.T, hits *atomic.Int32) ([]string, []string)
		wantSPF  string
		wantErr  bool
		wantHits int32 // -1 = don't check
	}{
		{
			name: "SERVFAIL then success on second resolver",
			setup: func(t *testing.T, hits *atomic.Int32) ([]string, []string) {
				r1 := startStub(t, fixed(t, hits, dns.RcodeServerFailure, false, ""), nil)
				r2 := startStub(t, fixed(t, hits, dns.RcodeSuccess, false, spf), nil)
				return []string{r1, r2}, []string{failingDoH(t)}
			},
			wantSPF: spf, wantHits: 2,
		},
		{
			name: "NXDOMAIN is definitive",
			setup: func(t *testing.T, hits *atomic.Int32) ([]string, []string) {
				r1 := startStub(t, fixed(t, hits, dns.RcodeNameError, false, ""), nil)
				r2 := startStub(t, fixed(t, hits, dns.RcodeSuccess, false, spf), nil)
				return []string{r1, r2}, []string{dohStub(t, dns.RcodeSuccess, spf)}
			},
			wantSPF: "", wantHits: 1,
		},
		{
			name: "SERVFAIL on all resolvers, DoH answers",
			setup: func(t *testing.T, hits *atomic.Int32) ([]string, []string) {
				r1 := startStub(t, fixed(t, hits, dns.RcodeServerFailure, false, ""), nil)
				r2 := startStub(t, fixed(t, hits, dns.RcodeServerFailure, false, ""), nil)
				return []string{r1, r2}, []string{dohStub(t, dns.RcodeSuccess, spf)}
			},
			wantSPF: spf, wantHits: 2,
		},
		{
			name: "truncated UDP retried over TCP",
			setup: func(t *testing.T, hits *atomic.Int32) ([]string, []string) {
				r1 := startStub(t, fixed(t, hits, dns.RcodeSuccess, true, ""), fixed(t, nil, dns.RcodeSuccess, false, spf))
				return []string{r1}, []string{failingDoH(t)}
			},
			wantSPF: spf, wantHits: 1,
		},
		{
			name: "truncated UDP, no TCP, DoH answers",
			setup: func(t *testing.T, hits *atomic.Int32) ([]string, []string) {
				r1 := startStub(t, fixed(t, hits, dns.RcodeSuccess, true, ""), nil)
				return []string{r1}, []string{dohStub(t, dns.RcodeSuccess, spf)}
			},
			wantSPF: spf, wantHits: 1,
		},
		{
			name: "truncated UDP, no TCP, DoH fails is an error not an empty answer",
			setup: func(t *testing.T, hits *atomic.Int32) ([]string, []string) {
				r1 := startStub(t, fixed(t, hits, dns.RcodeSuccess, true, ""), nil)
				return []string{r1}, []string{failingDoH(t)}
			},
			wantErr: true, wantHits: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			list, doh := tc.setup(t, &hits)
			overrideResolvers(t, list, doh)
			got, err := firstWithPrefix(context.Background(), "example.com", "v=spf1")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.wantSPF {
				t.Errorf("got %q, want %q", got, tc.wantSPF)
			}
			if tc.wantHits >= 0 && hits.Load() != tc.wantHits {
				t.Errorf("UDP hits = %d, want %d", hits.Load(), tc.wantHits)
			}
		})
	}
}

func TestExchangeHonorsCancelledContext(t *testing.T) {
	var hits atomic.Int32
	r1 := startStub(t, fixed(t, &hits, dns.RcodeSuccess, false, "x"), nil)
	overrideResolvers(t, []string{r1}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := queryDNS(ctx, "example.com", dns.TypeTXT); err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if hits.Load() != 0 {
		t.Errorf("resolver contacted %d times despite cancelled ctx", hits.Load())
	}
}

func TestPolicyInconclusiveNotAbsent(t *testing.T) {
	overrideResolvers(t, []string{"127.0.0.1:1"}, []string{failingDoH(t)})
	fs, err := dnsPolicy{}.Run(context.Background(), Target{Domain: "example.com", Host: "www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasTitle(fs, "SPF: lookup inconclusive") {
		t.Errorf("missing SPF inconclusive finding: %+v", fs)
	}
	if hasTitle(fs, "No SPF record") {
		t.Error("false 'No SPF record' finding emitted on lookup failure")
	}
	for _, f := range fs {
		if strings.HasSuffix(f.Title, "lookup inconclusive") && f.Err == "" {
			t.Errorf("%s: Err not set", f.Title)
		}
	}
}

func TestRecordsInconclusiveNotAbsent(t *testing.T) {
	overrideResolvers(t, []string{"127.0.0.1:1"}, []string{failingDoH(t)})
	fs, err := dnsRecords{}.Run(context.Background(), Target{Domain: "example.com", Host: "www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasTitle(fs, "A/AAAA: lookup inconclusive") {
		t.Errorf("missing A/AAAA inconclusive finding: %+v", fs)
	}
	if hasTitle(fs, "No A/AAAA records") {
		t.Error("false 'No A/AAAA records' finding emitted on lookup failure")
	}
}

func TestRecordsPartialAAAA(t *testing.T) {
	// A fails (SERVFAIL, DoH 500); AAAA and everything else resolve empty.
	srv := startStub(t, func(w dns.ResponseWriter, r *dns.Msg) {
		rc := dns.RcodeSuccess
		if r.Question[0].Qtype == dns.TypeA {
			rc = dns.RcodeServerFailure
		}
		reply(t, w, r, rc, false, "")
	}, nil)
	overrideResolvers(t, []string{srv}, []string{failingDoH(t)})
	fs, err := dnsRecords{}.Run(context.Background(), Target{Domain: "example.com", Host: "www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if hasTitle(fs, "No A/AAAA records") {
		t.Error("false 'No A/AAAA records' when A lookup errored")
	}
	if !hasTitle(fs, "A/AAAA: lookup inconclusive") {
		t.Errorf("missing A/AAAA inconclusive finding: %+v", fs)
	}
}

func TestRecordsGenuinelyAbsent(t *testing.T) {
	srv := startStub(t, fixed(t, nil, dns.RcodeSuccess, false, ""), nil)
	overrideResolvers(t, []string{srv}, []string{failingDoH(t)})
	fs, err := dnsRecords{}.Run(context.Background(), Target{Domain: "example.com", Host: "www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasTitle(fs, "No A/AAAA records") {
		t.Errorf("expected 'No A/AAAA records' when both resolve empty: %+v", fs)
	}
}

func TestDNSSECInconclusive(t *testing.T) {
	overrideResolvers(t, []string{"127.0.0.1:1"}, []string{failingDoH(t)})
	fs, err := dnssecCheck{}.Run(context.Background(), Target{Domain: "example.com", Host: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Title != "DNSSEC: lookup inconclusive" || fs[0].Err == "" {
		t.Errorf("unexpected findings: %+v", fs)
	}
}

func TestPolicyNoCorrelationOnDMARCFailure(t *testing.T) {
	r1 := startStub(t, func(w dns.ResponseWriter, r *dns.Msg) {
		if strings.HasPrefix(r.Question[0].Name, "_dmarc.") {
			reply(t, w, r, dns.RcodeServerFailure, false, "")
			return
		}
		reply(t, w, r, dns.RcodeSuccess, false, "v=spf1 -all")
	}, nil)
	overrideResolvers(t, []string{r1}, []string{failingDoH(t)})
	fs, err := dnsPolicy{}.Run(context.Background(), Target{Domain: "example.com", Host: "www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasTitle(fs, "DMARC: lookup inconclusive") {
		t.Errorf("missing DMARC inconclusive finding: %+v", fs)
	}
	if hasTitle(fs, "SPF without enforced DMARC: From-header spoofing still possible") {
		t.Error("correlation finding emitted despite DMARC lookup failure")
	}
}
