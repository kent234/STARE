package people

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

// EnrichProfiles добирает name/bio/avatar/links из OG-метаданных для top-N
// подтверждённых аккаунтов. Без этого Actor не может найти кросс-сигналы,
// а UI показывает только handle.
//
// Обогащение никогда не меняет existence/verification: это атрибуты,
// а не доказательство существования.
func EnrichProfiles(ctx context.Context, accounts []Account, limit int) ([]Account, int, time.Duration) {
	started := time.Now()
	if limit <= 0 {
		limit = 10
	}

	candidates := make([]int, 0, len(accounts))
	for i := range accounts {
		acc := accounts[i]
		if acc.Sensitive || acc.Provider || acc.URL == "" || !acc.URLValid {
			continue
		}
		if acc.Existence != ExistenceConfirmed {
			continue
		}
		if acc.Name != "" && acc.Bio != "" && acc.Avatar != "" && len(acc.Links) > 0 {
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

			meta := fetchProfileMeta(ctx, accounts[i].URL)
			if meta.Title == "" && meta.Description == "" && meta.Avatar == "" && len(meta.Links) == 0 {
				return
			}
			acc := &accounts[i]
			if acc.Name == "" {
				acc.Name = cleanMetaTitle(meta.Title, acc.Handle)
			}
			if acc.Bio == "" {
				acc.Bio = cleanText(meta.Description)
			}
			if acc.Avatar == "" {
				acc.Avatar = meta.Avatar
			}
			for _, link := range meta.Links {
				if len(acc.Links) >= 20 {
					break
				}
				if link != "" && !contains(acc.Links, link) {
					acc.Links = append(acc.Links, link)
				}
			}
			mu.Lock()
			enriched++
			mu.Unlock()
		}()
	}
	wg.Wait()
	return accounts, enriched, time.Since(started)
}

func cleanMetaTitle(title, handle string) string {
	value := cleanText(title)
	// OG-заголовки часто имеют вид "Name · Platform".
	if i := strings.Index(value, " · "); i > 0 {
		value = strings.TrimSpace(value[:i])
	}
	if strings.EqualFold(value, handle) {
		return ""
	}
	return value
}
