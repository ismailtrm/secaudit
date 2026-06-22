package checker

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/miekg/dns"
)

var (
	resolverOnce sync.Once
	resolverAddr string
	dnsClient    = &dns.Client{}
)

// resolver returns "ip:port" of the first system resolver, falling back to
// Cloudflare if /etc/resolv.conf can't be read. Resolved once.
func resolver() string {
	resolverOnce.Do(func() {
		resolverAddr = "1.1.1.1:53"
		if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cfg.Servers) > 0 {
			resolverAddr = net.JoinHostPort(cfg.Servers[0], cfg.Port)
		}
	})
	return resolverAddr
}

// queryDNS performs one DNS query against the system resolver. NXDOMAIN is not
// an error (it returns an empty answer); transport and SERVFAIL are.
func queryDNS(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	resp, _, err := dnsClient.ExchangeContext(ctx, m, resolver())
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("dns %s for %s: %s", dns.TypeToString[qtype], name, dns.RcodeToString[resp.Rcode])
	}
	return resp.Answer, nil
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
