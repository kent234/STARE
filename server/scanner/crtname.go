package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func FetchCRTName(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.name/v1/search?apex=%s", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("crt.name request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; STARE/0.1)")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.name do: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.name status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return nil, fmt.Errorf("crt.name read: %w", err)
	}

	lines := strings.Split(string(body), "\n")
	var subs []string
	seen := make(map[string]struct{})

	for _, line := range lines {
		line = strings.TrimSpace(strings.ToLower(line))
		if line == "" {
			continue
		}

		line = strings.Trim(line, ".,;\"' ")

		if strings.HasSuffix(line, "."+domain) {
			if _, ok := seen[line]; !ok {
				seen[line] = struct{}{}
				subs = append(subs, line)
			}
		}
	}

	return subs, nil
}
