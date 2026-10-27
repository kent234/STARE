package scanner

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

var embeddedWordlist string

type WordlistClient struct {
	dns        *DNSClient
	words      []string
	timeout    time.Duration
	workers    int
	wildcardIP string
}

func NewWordlistClient(dns *DNSClient) *WordlistClient {
	rawWords := strings.Split(embeddedWordlist, "\n")
	words := make([]string, 0, len(rawWords))
	for _, w := range rawWords {
		w = strings.TrimSpace(w)
		if w != "" && !strings.HasPrefix(w, "#") {
			words = append(words, w)
		}
	}
	return &WordlistClient{
		dns:     dns,
		words:   words,
		timeout: 2 * time.Second,
		workers: 20,
	}
}

func (c *WordlistClient) BruteSubdomains(ctx context.Context, domain string) ([]string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !domainRegex.MatchString(domain) {
		return nil, fmt.Errorf("wordlist: invalid domain %q", domain)
	}

	fakeDomain := fmt.Sprintf("fake-%d.%s", time.Now().UnixNano(), domain)
	fakeIPs, _ := c.dns.Resolve(ctx, fakeDomain)
	if len(fakeIPs) > 0 {
		c.wildcardIP = fakeIPs[0]
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
		ips, err := c.dns.resolver.LookupHost(ctx, candidate)
		if err != nil {
			return "", false
		}

		// Если сработал Wildcard
		if c.wildcardIP != "" && len(ips) > 0 && ips[0] == c.wildcardIP {
			// Проверяем HTTP-контент (обход заглушки)
			client := &http.Client{Timeout: 3 * time.Second}
			resp, err := client.Get("http://" + candidate)
			if err == nil {
				defer resp.Body.Close()
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024)) // Читаем 1КБ
				// Если контент НЕ похож на стандартную заглушку (например, не 404 и не пустая страница)
				if resp.StatusCode != 404 && len(body) > 100 {
					return candidate, true // Это реальный сервис!
				}
			}
			return "", false // Это фейк
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

func (c *WordlistClient) WildcardDetected() bool {
	return c.wildcardIP != ""
}
