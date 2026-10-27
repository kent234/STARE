package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ---------- HackerTarget ----------
func FetchHackerTarget(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hackertarget status: %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	lines := strings.Split(string(body), "\n")
	var subs []string
	seen := make(map[string]struct{})
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "error") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) > 0 {
			name := strings.ToLower(strings.TrimSpace(parts[0]))
			if name != "" && strings.HasSuffix(name, "."+domain) {
				if _, ok := seen[name]; !ok {
					seen[name] = struct{}{}
					subs = append(subs, name)
				}
			}
		}
	}
	return subs, nil
}

// ---------- AlienVault OTX ----------
func FetchAlienVaultOTX(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 25 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("otx status: %d", resp.StatusCode)
	}

	var data struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var subs []string
	seen := make(map[string]struct{})
	for _, item := range data.PassiveDNS {
		name := strings.ToLower(strings.TrimSpace(item.Hostname))
		if name != "" && strings.HasSuffix(name, "."+domain) {
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				subs = append(subs, name)
			}
		}
	}
	return subs, nil
}

// ---------- AnubisDB ----------
func FetchAnubisDB(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anubis status: %d", resp.StatusCode)
	}

	var raw []string
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}

	var subs []string
	seen := make(map[string]struct{})
	for _, name := range raw {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" && strings.HasSuffix(name, "."+domain) {
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				subs = append(subs, name)
			}
		}
	}
	return subs, nil
}

// ---------- ThreatMiner ----------
func FetchThreatMiner(ctx context.Context, domain string) ([]string, error) {
	// rt=5 — это флаг для получения списка поддоменов
	url := fmt.Sprintf("https://api.threatminer.org/v2/domain.php?q=%s&rt=5", domain)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// ThreatMiner возвращает 404, если ничего не найдено — это не критичная ошибка
	if resp.StatusCode == http.StatusNotFound {
		return []string{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("threatminer status: %d", resp.StatusCode)
	}

	var data struct {
		Results []string `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var subs []string
	seen := make(map[string]struct{})
	for _, name := range data.Results {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" && strings.HasSuffix(name, "."+domain) {
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				subs = append(subs, name)
			}
		}
	}
	return subs, nil
}

// ---------- URLScan.io ----------
func FetchURLScan(ctx context.Context, domain string) ([]string, error) {
	// Ищем сканы, где фигурировал этот домен
	url := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=10000", domain)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	req.Header.Set("API-Key", "01a17f3a-969c-758d-8c72-3929a5b7deef")

	client := &http.Client{Timeout: 25 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("urlscan status: %d", resp.StatusCode)
	}

	var data struct {
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
			} `json:"page"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var subs []string
	seen := make(map[string]struct{})
	for _, item := range data.Results {
		name := strings.ToLower(strings.TrimSpace(item.Page.Domain))
		if name != "" && strings.HasSuffix(name, "."+domain) {
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				subs = append(subs, name)
			}
		}
	}
	return subs, nil
}
