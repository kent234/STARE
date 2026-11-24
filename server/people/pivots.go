package people

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"stare/server/scanner"
)

// EnrichArchives добавляет ссылку на ближайший снимок Wayback Machine.
// Это не создаёт аккаунтов, но фиксирует, что профиль существовал раньше.
func EnrichArchives(ctx context.Context, accounts []Account, limit int) ([]Account, int, time.Duration) {
	started := time.Now()
	if limit <= 0 {
		limit = 10
	}
	candidates := enrichmentCandidates(accounts, limit, func(acc Account) bool {
		return acc.ArchivedURL == ""
	})
	if len(candidates) == 0 {
		return accounts, 0, time.Since(started)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	sem := make(chan struct{}, 5)
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		enriched int
	)
	for _, i := range candidates {
		i := i
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			link := "https://archive.org/wayback/available?url=" + url.QueryEscape(accounts[i].URL)
			resp, err := client.Get(link)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return
			}
			var payload struct {
				Snapshots struct {
					Closest struct {
						Available bool   `json:"available"`
						URL       string `json:"url"`
						Timestamp string `json:"timestamp"`
						Status    string `json:"status"`
					} `json:"closest"`
				} `json:"archived_snapshots"`
			}
			if json.NewDecoder(resp.Body).Decode(&payload) != nil {
				return
			}
			closest := payload.Snapshots.Closest
			if !closest.Available || closest.URL == "" || closest.Status != "200" {
				return
			}
			mu.Lock()
			accounts[i].ArchivedURL = closest.URL
			accounts[i].ArchivedAt = closest.Timestamp
			enriched++
			mu.Unlock()
		}()
	}
	wg.Wait()
	return accounts, enriched, time.Since(started)
}

// EnrichAvatarHashes скачивает аватары top-N подтверждённых аккаунтов и
// считает sha256. Хэш — сильный кросс-сигнал, если URL аватара отличается.
func EnrichAvatarHashes(ctx context.Context, accounts []Account, limit int) ([]Account, int, time.Duration) {
	started := time.Now()
	if limit <= 0 {
		limit = 10
	}
	candidates := enrichmentCandidates(accounts, limit, func(acc Account) bool {
		return acc.Avatar != "" && acc.AvatarHash == ""
	})
	if len(candidates) == 0 {
		return accounts, 0, time.Since(started)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	sem := make(chan struct{}, 5)
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		enriched int
	)
	for _, i := range candidates {
		i := i
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if !safePublicURL(accounts[i].Avatar) {
				return
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, accounts[i].Avatar, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Stare/1.0 (+osint)")
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
			if err != nil || len(body) == 0 {
				return
			}
			sum := sha256.Sum256(body)
			mu.Lock()
			accounts[i].AvatarHash = hex.EncodeToString(sum[:])
			enriched++
			mu.Unlock()
		}()
	}
	wg.Wait()
	return accounts, enriched, time.Since(started)
}

func enrichmentCandidates(accounts []Account, limit int, want func(Account) bool) []int {
	candidates := make([]int, 0, len(accounts))
	for i := range accounts {
		acc := accounts[i]
		if acc.Sensitive || acc.Provider || acc.URL == "" || acc.Existence != ExistenceConfirmed {
			continue
		}
		if !want(acc) {
			continue
		}
		candidates = append(candidates, i)
	}
	sort.Slice(candidates, func(a, b int) bool {
		left, right := accounts[candidates[a]], accounts[candidates[b]]
		if left.Score != right.Score {
			return left.Score > right.Score
		}
		if left.Platform != right.Platform {
			return left.Platform < right.Platform
		}
		return left.Handle < right.Handle
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	return candidates
}

// safePublicURL не даёт пивотам ходить в localhost/RFC1918 (SSRF).
func safePublicURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return false
	}
	ips, err := net.LookupIP(u.Hostname())
	if err != nil || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if !scanner.IsPublicIP(ip) {
			return false
		}
	}
	return true
}
