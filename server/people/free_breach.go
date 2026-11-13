package people

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"stare/server/scanner"
)

// XposedOrNotCollector — бесплатный breach-поиск без API-ключа.
type XposedOrNotCollector struct{}

func (c *XposedOrNotCollector) Name() string { return "xposedornot" }

func (c *XposedOrNotCollector) Collect(ctx context.Context, target string) ([]scanner.Observation, error) {
	endpoint := "https://api.xposedornot.com/v1/check-email/" + url.PathEscape(target)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
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
		return nil, fmt.Errorf("xposedornot status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}

	var payload struct {
		Breaches [][]string `json:"breaches"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	var obs []scanner.Observation
	seen := map[string]struct{}{}
	for _, group := range payload.Breaches {
		for _, name := range group {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			obs = append(obs, Observation("xposedornot", scanner.ConfidenceHigh, map[string]any{
				"kind":        "breach",
				"breach_name": name,
				"email":       target,
			}))
		}
	}
	return obs, nil
}

// HudsonRockCollector — бесплатный поиск infostealer-логов по email.
type HudsonRockCollector struct{}

func (c *HudsonRockCollector) Name() string { return "hudsonrock" }

func (c *HudsonRockCollector) Collect(ctx context.Context, target string) ([]scanner.Observation, error) {
	endpoint := "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=" + url.QueryEscape(target)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
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
		return nil, fmt.Errorf("hudsonrock status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}

	var payload struct {
		Message  string `json:"message"`
		Stealers []struct {
			DateCompromised string `json:"date_compromised"`
			ComputerName    string `json:"computer_name"`
			OperatingSystem string `json:"operating_system"`
			IP              string `json:"ip"`
		} `json:"stealers"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	var obs []scanner.Observation
	for i, s := range payload.Stealers {
		if i >= 5 {
			break
		}
		obs = append(obs, Observation("hudsonrock", scanner.ConfidenceHigh, map[string]any{
			"kind":         "breach",
			"breach_name":  "Infostealer log",
			"email":        target,
			"date":         s.DateCompromised,
			"data_classes": []string{"credentials", "cookies"},
			"computer":     s.ComputerName,
			"os":           s.OperatingSystem,
			"ip":           s.IP,
		}))
	}
	return obs, nil
}

// GitHubNameCollector — бесплатный поиск GitHub-аккаунтов по реальному имени.
type GitHubNameCollector struct{}

func (c *GitHubNameCollector) Name() string { return "githubname" }

func (c *GitHubNameCollector) Collect(ctx context.Context, target string) ([]scanner.Observation, error) {
	endpoint := "https://api.github.com/search/users?q=fullname:" + url.QueryEscape("\""+target+"\"") + "&per_page=20"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Stare/1.0 (+osint)")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusTooManyRequests {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github search status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}

	var payload struct {
		Items []struct {
			Login   string `json:"login"`
			HTMLURL string `json:"html_url"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	obs := make([]scanner.Observation, 0, len(payload.Items))
	for _, item := range payload.Items {
		if item.Login == "" {
			continue
		}
		obs = append(obs, Observation("githubname", scanner.ConfidenceLow, map[string]any{
			"platform": "github",
			"handle":   item.Login,
			"url":      item.HTMLURL,
		}))
	}
	return obs, nil
}
