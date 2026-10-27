package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

var (
	wappClient *wappalyzer.Wappalyze
	wappOnce   sync.Once
	wappErr    error
)

func getWappClient() (*wappalyzer.Wappalyze, error) {
	wappOnce.Do(func() {
		wappClient, wappErr = wappalyzer.New()
	})
	return wappClient, wappErr
}

// FingerprintTech возвращает список технологий, найденных на целевом ресурсе.
func FingerprintTech(ctx context.Context, target string) ([]string, error) {
	client, err := getWappClient()
	if err != nil {
		return nil, fmt.Errorf("wappalyzer init: %w", err)
	}

	urls := []string{fmt.Sprintf("https://%s", target), fmt.Sprintf("http://%s", target)}
	httpClient := &http.Client{Timeout: 10 * time.Second}

	var lastErr error
	for _, url := range urls {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
		resp.Body.Close()

		fingerprints := client.Fingerprint(resp.Header, body)
		var techs []string
		for tech, _ := range fingerprints {
			techs = append(techs, tech)
		}
		sort.Strings(techs)
		return techs, nil
	}

	return nil, fmt.Errorf("fingerprint request failed: %w", lastErr)
}

// AnalyzeArtifacts расширяет старую функцию CheckArtifacts, добавляя поиск технологий.
func AnalyzeArtifacts(ctx context.Context, domain string) (Artifacts, []string) {
	arts := CheckArtifacts(ctx, domain)
	techs, err := FingerprintTech(ctx, domain)
	if err != nil {
		techs = []string{"Unknown (Wappalyzer failed)"}
	}
	return arts, techs
}

// вспомогательная функция для объединения строк
func joinString(s []string) string {
	return strings.Join(s, ", ")
}
