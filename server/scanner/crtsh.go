package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

type CRTshClient struct {
	http    *http.Client
	baseURL string
}

func NewCRTShClient() *CRTshClient {
	return &CRTshClient{
		http: &http.Client{
			Timeout: 500 * time.Second,
		},
		baseURL: "https://crt.sh",
	}
}

type crtShEntry struct {
	NameValue string `json:"name_value"`
}

const crtShMaxBodyBytes = 8 << 20

var domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)

func (c *CRTshClient) FetchSubdomains(ctx context.Context, domain string) ([]string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))

	if !domainRegex.MatchString(domain) {
		return nil, fmt.Errorf("crtsh: invalid domain %q", domain)
	}

	endpoint := c.buildURL(domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("crtsh: new request: %w", err)
	}
	req.Header.Set("User-Agent", "STARE/0.1")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crtsh: do request %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crtsh: unexpected status %d", resp.StatusCode)
	}

	body := io.LimitReader(resp.Body, crtShMaxBodyBytes)

	var entries []crtShEntry
	if err := json.NewDecoder(body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("crtsh: decode response: %w", err)
	}
	return normalizeSubdomains(entries, domain), nil
}

func (c *CRTshClient) buildURL(domain string) string {
	q := url.Values{}
	q.Set("q", "%."+domain)
	q.Set("output", "json")
	return c.baseURL + "/?" + q.Encode()
}

func normalizeSubdomains(entries []crtShEntry, domain string) []string {
	suffix := "." + domain
	seen := make(map[string]struct{})

	for _, e := range entries {
		for _, raw := range strings.Split(e.NameValue, "\n") {
			name := strings.ToLower(strings.TrimSpace(raw))
			if name == "" {
				continue
			}
			name = strings.TrimPrefix(name, "*.")

			if !strings.HasSuffix(name, suffix) {
				continue
			}

			seen[name] = struct{}{}
		}
	}

	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	sort.Strings(result)
	return result

}
