package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

type DNSClient struct {
	resolver *net.Resolver
	timeout  time.Duration
}

func NewDNSClient() *DNSClient {
	return &DNSClient{
		resolver: net.DefaultResolver,
		timeout:  10 * time.Second,
	}
}

func (c *DNSClient) Resolve(ctx context.Context, domain string) ([]string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !domainRegex.MatchString(domain) {
		return nil, fmt.Errorf("Dns: invalid domain %q", domain)
	}

	lookupCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	addrs, err := c.resolver.LookupHost(lookupCtx, domain)
	if err != nil {
		return nil, fmt.Errorf("dns: lookup %q: %w", domain, err)
	}

	seen := make(map[string]struct{}, len(addrs))
	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		seen[addr] = struct{}{}
	}

	result := make([]string, 0, len(seen))
	for addr := range seen {
		result = append(result, addr)
	}
	sort.Strings(result)
	return result, nil
}

type ExtendedDNS struct {
	MX  []string `json:"mx"`
	TXT []string `json:"txt"`
	NS  []string `json:"ns"`
}

func (c *DNSClient) ResolveExtended(ctx context.Context, domain string) ExtendedDNS {
	var res ExtendedDNS
	if mxs, err := net.LookupMX(domain); err == nil {
		for _, mx := range mxs {
			res.MX = append(res.MX, mx.Host)
		}
	}

	if txts, err := net.LookupTXT(domain); err == nil {
		res.TXT = txts
	}

	if nss, err := net.LookupNS(domain); err == nil {
		for _, ns := range nss {
			res.NS = append(res.NS, ns.Host)
		}
	}
	return res
}
