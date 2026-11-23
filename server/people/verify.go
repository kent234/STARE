package people

import (
	"context"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// VerifyAccountURLs проверяет кандидатов HTTP-запросом:
//   - 404/410 — профиль удалён/не существует, аккаунт отбрасывается;
//   - 2xx/3xx + handle в теле — аккаунт подтверждён;
//   - 403/429/5xx/timeout — оставляем, но не помечаем verified
//     (многие сайты блокируют ботов, это не доказательство отсутствия).
func VerifyAccountURLs(ctx context.Context, accounts []Account) []Account {
	// Ограничиваем число проверок, чтобы не превратить скан в сотни запросов.
	const maxChecks = 80
	candidates := make([]int, 0, len(accounts))
	for i := range accounts {
		if accounts[i].Verified || accounts[i].URL == "" || !accounts[i].URLValid {
			continue
		}
		candidates = append(candidates, i)
	}
	sort.Slice(candidates, func(a, b int) bool {
		return accounts[candidates[a]].Score > accounts[candidates[b]].Score
	})
	if len(candidates) > maxChecks {
		candidates = candidates[:maxChecks]
	}

	client := &http.Client{
		Timeout: 6 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	sem := make(chan struct{}, 10)
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		dropped = map[int]struct{}{}
	)
	for _, i := range candidates {
		i := i
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			status, body, err := fetchProfileBody(ctx, client, accounts[i].URL)
			accounts[i].HTTPChecked = true
			accounts[i].HTTPStatus = status
			if err != nil {
				return
			}
			if status == http.StatusNotFound || status == http.StatusGone {
				mu.Lock()
				dropped[i] = struct{}{}
				mu.Unlock()
				return
			}
			if status < 200 || status >= 400 {
				return
			}
			// Подтверждаем только если в ответе реально есть handle.
			if strings.Contains(strings.ToLower(body), strings.ToLower(accounts[i].Handle)) {
				accounts[i].Verified = true
				accounts[i].Score += 10
				if accounts[i].Score > 100 {
					accounts[i].Score = 100
				}
				if accounts[i].Confidence == "low" {
					accounts[i].Confidence = "medium"
				}
			}
		}()
	}
	wg.Wait()

	out := make([]Account, 0, len(accounts))
	for i := range accounts {
		if _, bad := dropped[i]; bad {
			continue
		}
		out = append(out, accounts[i])
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Platform < out[j].Platform
	})
	return out
}

func fetchProfileBody(ctx context.Context, client *http.Client, link string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36")
	req.Header.Set("Accept-Language", "en-US,en;q=0.8,ru;q=0.7")
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(body), nil
}
