package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

var defaultWordlist = []string{
	"www", "mail", "api", "dev", "test", "staging",
	"admin", "vpn", "blog", "shop", "git", "cdn",
	"static", "media", "docs", "support", "app",
}

type WordlistClient struct {
	dns     *DNSClient
	words   []string
	timeout time.Duration
	workers int
}

func NewWordlistClient(dns *DNSClient) *WordlistClient {
	return &WordlistClient{
		dns:     dns,
		words:   defaultWordlist,
		timeout: 3 * time.Second,
		workers: 10,
	}
}

func (c *WordlistClient) BruteSubdomains(ctx context.Context, domain string) ([]string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !domainRegex.MatchString(domain) {
		return nil, fmt.Errorf("wordlist: invalid domain %q", domain)
	}

	jobs := make(chan string, len(c.words))
	results := make(chan string, len(c.words))

	go func() {
		defer close(jobs)
		for _, word := range c.words {
			select {
			case jobs <- word:
			case <-ctx.Done():
				return
			}
		}
	}()

	runPool(ctx, c.workers, jobs, results, func(ctx context.Context, word string) (string, bool) {
		candidate := word + "." + domain
		exists, err := c.exists(ctx, candidate)
		if err != nil || !exists {
			return "", false
		}
		return candidate, true
	})

	var found []string
	for sub := range results {
		found = append(found, sub)
	}

	if err := ctx.Err(); err != nil {
		return found, err
	}

	sort.Strings(found)
	return found, nil
}

func (c *WordlistClient) exists(ctx context.Context, domain string) (bool, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	ips, err := c.dns.resolver.LookupHost(lookupCtx, domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return false, nil
		}
		return false, err
	}
	return len(ips) > 0, nil
}
