package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type rapidDNSResponse struct {
	Data []struct {
		Subdomain string `json:"subdomain"`
	} `json:"data"`
}

func FetchRapidDNS(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://rapiddns.io/api/search?domain=%s&full=1", domain)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)

	if err != nil {
		return nil, fmt.Errorf("rapidDNS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RapidDNS status: %d", resp.StatusCode)
	}

	var data rapidDNSResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("RapidDNS decode: %w", err)
	}

	var subs []string
	for _, item := range data.Data {
		if item.Subdomain != "" {
			subs = append(subs, item.Subdomain)
		}
	}
	return subs, nil
}
