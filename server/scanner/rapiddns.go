package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// FetchRapidDNS парсит HTML-таблицу rapiddns.io (API отключён, страница доступна).
func FetchRapidDNS(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rapidDNS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RapidDNS status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}

	var subs []string
	seen := make(map[string]struct{})
	inCell := false
	var cell strings.Builder

	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			name, _ := z.TagName()
			if string(name) == "td" {
				inCell = true
				cell.Reset()
			}
		case html.TextToken:
			if inCell {
				cell.Write(z.Text())
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			if string(name) != "td" || !inCell {
				continue
			}
			inCell = false
			value := strings.ToLower(strings.TrimSpace(cell.String()))
			if value == "" || !strings.HasSuffix(value, "."+domain) {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			subs = append(subs, value)
		}
	}
	return subs, nil
}
