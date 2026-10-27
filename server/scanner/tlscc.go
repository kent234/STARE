package scanner

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type tlsccEntry struct {
	NameValue string `json:"name_value"`
}

func FetchTLSCC(ctx context.Context, domain string) ([]string, error) {
	q := url.Values{}
	q.Set("q", "%."+domain)
	q.Set("output", "json")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ct.tlscc.ru/?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "STARE/0.1")

	// Отключаем проверку TLS-сертификата для российского сервера
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   20 * time.Second,
		Transport: tr,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tlscc status: %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	var entries []tlsccEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}

	var subs []string
	seen := make(map[string]struct{})
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			name = strings.TrimPrefix(name, "*.")
			if strings.HasSuffix(name, "."+domain) {
				if _, ok := seen[name]; !ok {
					seen[name] = struct{}{}
					subs = append(subs, name)
				}
			}
		}
	}
	return subs, nil
}