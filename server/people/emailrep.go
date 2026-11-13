package people

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"stare/server/scanner"
)

// EmailRepCollector — бесплатный tier EmailRep (250 запросов/мес, ключ обязателен).
type EmailRepCollector struct{}

func (c *EmailRepCollector) Name() string { return "emailrep" }

func (c *EmailRepCollector) Collect(ctx context.Context, target string) ([]scanner.Observation, error) {
	key := os.Getenv("EMAILREP_API_KEY")
	if key == "" || !stringsContainsAt(target) {
		return nil, nil
	}

	endpoint := "https://emailrep.io/" + url.PathEscape(target)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Key", key)
	req.Header.Set("User-Agent", "Stare/1.0 (+osint)")

	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusTooManyRequests {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("emailrep status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}

	var payload struct {
		Details struct {
			Profiles []string `json:"profiles"`
		} `json:"details"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	obs := make([]scanner.Observation, 0, len(payload.Details.Profiles))
	seen := map[string]struct{}{}
	for _, profile := range payload.Details.Profiles {
		platform := canonicalPlatform(profile)
		if platform == "" {
			continue
		}
		if _, ok := seen[platform]; ok {
			continue
		}
		seen[platform] = struct{}{}
		obs = append(obs, Observation("emailrep", scanner.ConfidenceLow, map[string]any{
			"kind":     "registration",
			"platform": platform,
			"email":    target,
		}))
	}
	return obs, nil
}

func stringsContainsAt(value string) bool {
	for _, r := range value {
		if r == '@' {
			return true
		}
	}
	return false
}
