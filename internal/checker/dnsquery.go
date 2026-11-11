package checker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	resolverOnce sync.Once
	resolverAddr []string
	dnsClient    = &dns.Client{}
	tcpClient    = &dns.Client{Net: "tcp"}

	// resolverList returns the resolvers to try in order. Tests override it.
	resolverList = systemResolvers

	// dohEndpoints are the RFC 8484 fallbacks used when no UDP/TCP resolver
	// gave a definitive answer. Tests override it.
	dohEndpoints = []string{"https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"}
	dohClient    = &http.Client{Timeout: 5 * time.Second}
)

// buildResolverList dedups the given system servers and appends the public
// fallbacks (1.1.1.1, 8.8.8.8) when not already present.
func buildResolverList(servers []string, port string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(addr string) {
		if !seen[addr] {
			seen[addr] = true
			out = append(out, addr)
		}
	}
	for _, s := range servers {
		add(net.JoinHostPort(s, port))
	}
	add("1.1.1.1:53")
	add("8.8.8.8:53")
	return out
}

// systemResolvers returns every /etc/resolv.conf server followed by the public
// fallbacks. Resolved once.
func systemResolvers() []string {
	resolverOnce.Do(func() {
		var servers []string
		port := "53"
		if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil {
			servers, port = cfg.Servers, cfg.Port
		}
		resolverAddr = buildResolverList(servers, port)
	})
	return resolverAddr
}

// exchange sends m to each resolver in turn, then to the DoH endpoints. A
// Success or NXDOMAIN response is definitive; transport errors, truncated
// responses (retried over TCP first) and other rcodes move on to the next
// resolver.
func exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	var errs []error
	for _, addr := range resolverList() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resp, _, err := dnsClient.ExchangeContext(ctx, m, addr)
		if err != nil {
			errs = append(errs, fmt.Errorf("resolver %s: %w", addr, err))
			continue
		}
		if resp.Truncated {
			resp, _, err = tcpClient.ExchangeContext(ctx, m, addr)
			if err != nil {
				errs = append(errs, fmt.Errorf("resolver %s (tcp): %w", addr, err))
				continue
			}
			if resp.Truncated {
				errs = append(errs, fmt.Errorf("resolver %s (tcp): truncated response", addr))
				continue
			}
		}
		if resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError {
			return resp, nil
		}
		errs = append(errs, fmt.Errorf("resolver %s: %s", addr, dns.RcodeToString[resp.Rcode]))
	}
	resp, err := exchangeDoH(ctx, m)
	if err == nil {
		return resp, nil
	}
	errs = append(errs, err)
	return nil, fmt.Errorf("dns lookup failed (resolvers and DoH): %w", errors.Join(errs...))
}

// exchangeDoH sends m over DNS-over-HTTPS (RFC 8484 wire format), which keeps
// every RR type including RRSIG.
func exchangeDoH(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	packed, err := m.Pack()
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, url := range dohEndpoints {
		r, err := doh(ctx, url, packed)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if r.Rcode == dns.RcodeSuccess || r.Rcode == dns.RcodeNameError {
			return r, nil
		}
		errs = append(errs, fmt.Errorf("doh %s: %s", url, dns.RcodeToString[r.Rcode]))
	}
	if len(errs) == 0 {
		return nil, fmt.Errorf("no DoH endpoints configured")
	}
	return nil, errors.Join(errs...)
}

// doh posts one packed query to a single DoH endpoint and unpacks the reply.
func doh(ctx context.Context, url string, packed []byte) (*dns.Msg, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := dohClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var r dns.Msg
	if err := r.Unpack(body); err != nil {
		return nil, err
	}
	return &r, nil
}

// queryDNS performs one DNS query via exchange (system resolvers, then DoH).
// NXDOMAIN is not an error (it returns an empty answer); failure of every
// resolver is.
func queryDNS(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.SetEdns0(4096, false)
	m.RecursionDesired = true
	resp, err := exchange(ctx, m)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", name, dns.TypeToString[qtype], err)
	}
	return resp.Answer, nil
}

// queryWithDNSSEC queries name/qtype with the EDNS0 DO bit set so the resolver
// returns RRSIG records, which prove a zone is actually serving signatures.
func queryWithDNSSEC(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.SetEdns0(4096, true)
	m.RecursionDesired = true
	resp, err := exchange(ctx, m)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", name, dns.TypeToString[qtype], err)
	}
	return resp.Answer, nil
}

// hasRRType reports whether any RR in rrs has the given type.
func hasRRType(rrs []dns.RR, qtype uint16) bool {
	for _, rr := range rrs {
		if rr.Header().Rrtype == qtype {
			return true
		}
	}
	return false
}

// txtRecords returns the concatenated TXT strings for name.
func txtRecords(ctx context.Context, name string) ([]string, error) {
	rrs, err := queryDNS(ctx, name, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range rrs {
		if t, ok := rr.(*dns.TXT); ok {
			out = append(out, joinTXT(t.Txt))
		}
	}
	return out, nil
}

// joinTXT concatenates the character-strings of one TXT record (DNS splits long
// TXT values into 255-byte chunks that must be rejoined).
func joinTXT(parts []string) string {
	s := ""
	for _, p := range parts {
		s += p
	}
	return s
}
