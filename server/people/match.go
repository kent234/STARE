package people

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

// ApplyProfileMatch сравнивает кандидатов с реальным профилем-источником
// (имя/bio/avatar/ссылки), а не только по совпадению handle.
func ApplyProfileMatch(ctx context.Context, target string, accounts []Account) []Account {
	srcPlatform, srcHandle, ok := ParseProfileURL(target)
	if !ok {
		return accounts
	}
	srcIdx := -1
	for i := range accounts {
		if accounts[i].Platform == srcPlatform && strings.EqualFold(accounts[i].Handle, srcHandle) {
			srcIdx = i
			break
		}
	}
	if srcIdx < 0 {
		return accounts
	}

	source := accounts[srcIdx]
	accounts[srcIdx].MatchScore = 100
	accounts[srcIdx].MatchReason = "input profile"

	srcMeta := profileMeta{
		Title:       source.Name,
		Description: source.Bio,
		Avatar:      source.Avatar,
		Links:       source.Links,
	}
	hasMeta := srcMeta.Title != "" || srcMeta.Description != "" || srcMeta.Avatar != "" || len(srcMeta.Links) > 0

	var candidates []int
	for i := range accounts {
		if i == srcIdx || accounts[i].URL == "" {
			continue
		}
		candidates = append(candidates, i)
	}
	sort.Slice(candidates, func(a, b int) bool {
		return accounts[candidates[a]].Score > accounts[candidates[b]].Score
	})
	if len(candidates) > 25 {
		candidates = candidates[:25]
	}

	if !hasMeta {
		// Профиль закрыт (VK/Instagram): опираемся только на API-верификацию
		// и консенсус, но не на «чистый handle».
		for _, i := range candidates {
			if !strings.EqualFold(accounts[i].Handle, srcHandle) {
				continue
			}
			if accounts[i].Verified {
				accounts[i].MatchScore = 70
				accounts[i].MatchReason = "same handle + verified API profile"
			} else if len(accounts[i].Sources) >= 2 {
				accounts[i].MatchScore = 55
				accounts[i].MatchReason = "same handle + multi-source"
			}
		}
		return accounts
	}

	avatarHash := ""
	if srcMeta.Avatar != "" {
		avatarHash = hashRemote(ctx, srcMeta.Avatar)
	}

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	for _, i := range candidates {
		i := i
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			meta := fetchProfileMeta(ctx, accounts[i].URL)
			score, reasons := semanticScore(srcMeta, srcHandle, accounts[i], meta)

			if avatarHash != "" && meta.Avatar != "" && score >= 15 {
				if h := hashRemote(ctx, meta.Avatar); h != "" && h == avatarHash {
					score += 40
					reasons = append(reasons, "same avatar")
				}
			}
			if score > 100 {
				score = 100
			}
			accounts[i].MatchScore = score
			accounts[i].MatchReason = strings.Join(reasons, ", ")
			if score >= 50 {
				accounts[i].Verified = true
				if accounts[i].Confidence == "low" {
					accounts[i].Confidence = "medium"
				}
			}
		}()
	}
	wg.Wait()
	return accounts
}

func semanticScore(src profileMeta, srcHandle string, cand Account, meta profileMeta) (int, []string) {
	score := 0
	var reasons []string

	if strings.EqualFold(srcHandle, cand.Handle) {
		score += 10
		reasons = append(reasons, "same handle")
	}

	srcName := tokenSet(src.Title)
	candName := tokenSet(meta.Title)
	delete(srcName, strings.ToLower(srcHandle))
	delete(candName, strings.ToLower(srcHandle))
	nameSim, nameInter := tokenOverlap(srcName, candName)
	if nameInter == 0 {
		nameSim = 0
	}
	switch {
	case nameSim >= 0.75:
		score += 45
		reasons = append(reasons, "name match")
	case nameSim >= 0.5:
		score += 25
		reasons = append(reasons, "name partial")
	}

	srcBio := tokenSet(src.Description)
	candBio := tokenSet(meta.Description)
	delete(srcBio, strings.ToLower(srcHandle))
	delete(candBio, strings.ToLower(srcHandle))
	bioSim, bioInter := tokenOverlap(srcBio, candBio)
	if bioInter < 2 {
		bioSim = 0
	}
	switch {
	case bioSim >= 0.5:
		score += 25
		reasons = append(reasons, "bio match")
	case bioSim >= 0.25:
		score += 12
		reasons = append(reasons, "bio partial")
	}

	if sharedLink(src.Links, meta.Links) {
		score += 25
		reasons = append(reasons, "shared link")
	}
	if cand.Verified {
		score += 10
		reasons = append(reasons, "API verified")
	}
	return score, reasons
}

func tokenSet(value string) map[string]struct{} {
	set := map[string]struct{}{}
	fields := strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	for _, f := range fields {
		if len(f) < 3 {
			continue
		}
		switch f {
		case "the", "and", "for", "with", "from", "this", "that", "profile", "user", "account", "page":
			continue
		}
		set[f] = struct{}{}
	}
	return set
}

func overlapCoefficient(a, b map[string]struct{}) float64 {
	ratio, _ := tokenOverlap(a, b)
	return ratio
}

func tokenOverlap(a, b map[string]struct{}) (float64, int) {
	if len(a) == 0 || len(b) == 0 {
		return 0, 0
	}
	inter := 0
	for token := range a {
		if _, ok := b[token]; ok {
			inter++
		}
	}
	min := len(a)
	if len(b) < min {
		min = len(b)
	}
	return float64(inter) / float64(min), inter
}

func sharedLink(a, b []string) bool {
	for _, left := range a {
		l := normalizeLink(left)
		if l == "" {
			continue
		}
		for _, right := range b {
			if normalizeLink(right) == l {
				return true
			}
		}
	}
	return false
}

func normalizeLink(link string) string {
	l := strings.ToLower(strings.TrimSpace(link))
	l = strings.TrimPrefix(l, "https://")
	l = strings.TrimPrefix(l, "http://")
	l = strings.TrimPrefix(l, "www.")
	l = strings.TrimSuffix(l, "/")
	return l
}

func hashRemote(ctx context.Context, link string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Stare/1.0 (+osint)")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	defer resp.Body.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(resp.Body, 2<<20)); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
