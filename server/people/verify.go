package people

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"stare/server/scanner"
)

// profileFetch — минимальный снимок HTTP-ответа для проверки профиля.
type profileFetch struct {
	Status      int
	Body        string
	ContentType string
	FinalURL    string
}

// VerifyAccountURLs проверяет кандидатов HTTP-запросом и выставляет
// existence/verification. Коллекторский "verified" больше не пропускает
// проверку: доказательством считается только HTTP-ответ с признаками
// профиля либо API провайдера (Microsoft/PGP).
//
//   - 404/410 — existence=absent, аккаунт уходит в removed[];
//   - 401/403/429/451 и login-wall — existence=blocked, tier=low;
//   - 5xx/timeout/network — existence=unknown, tier=low;
//   - 2xx + подтверждённая страница — existence=confirmed, verification=http.
func VerifyAccountURLs(ctx context.Context, accounts []Account) ([]Account, []RemovedAccount) {
	limit := verifyLimit()
	candidates := make([]int, 0, len(accounts))
	for i := range accounts {
		acc := &accounts[i]
		// Provider подтверждён своим API; повторный HTTP только создаст шум.
		if acc.Provider {
			acc.Existence = ExistenceConfirmed
			acc.Verified = true
			if acc.Verification == VerificationNone {
				acc.Verification = VerificationCollector
			}
			if acc.VerificationSource == "" {
				acc.VerificationSource = "provider"
			}
			continue
		}
		if acc.Verification == VerificationHTTP || acc.URL == "" || !acc.URLValid {
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
		// Не прячем факт пропуска: пользователь должен видеть, что часть
		// аккаунтов не проверялась, а не считать их «несуществующими».
		for _, i := range candidates[limit:] {
			accounts[i].HTTPError = "skipped: verification limit (PEOPLE_VERIFY_MAX)"
		}
		candidates = candidates[:limit]
	}

	client := &http.Client{
		Timeout: 8 * time.Second,
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
		removed []RemovedAccount
	)
	for _, i := range candidates {
		i := i
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			acc := &accounts[i]
			acc.HTTPAttempted = true
			f, err := fetchProfile(ctx, client, acc.URL)
			if f.Status > 0 {
				acc.HTTPStatus = f.Status
				acc.URLReachable = true
			}
			if err != nil {
				acc.HTTPError = err.Error()
				acc.Existence = ExistenceUnknown
				applyExistence(acc)
				return
			}

			switch {
			case f.Status == http.StatusNotFound || f.Status == http.StatusGone:
				acc.Existence = ExistenceAbsent
				mu.Lock()
				removed = append(removed, RemovedAccount{
					ID:       acc.ID,
					Platform: acc.Platform,
					Handle:   acc.Handle,
					URL:      acc.URL,
					Status:   f.Status,
				})
				mu.Unlock()
			case f.Status == http.StatusUnauthorized || f.Status == http.StatusForbidden ||
				f.Status == http.StatusTooManyRequests || f.Status == http.StatusUnavailableForLegalReasons:
				acc.Existence = ExistenceBlocked
			case f.Status >= 500:
				acc.Existence = ExistenceUnknown
			case f.Status >= 200 && f.Status < 400:
				acc.Existence = evaluateProfilePage(acc, f)
			default:
				acc.Existence = ExistenceUnknown
			}
			applyExistence(acc)
		}()
	}
	wg.Wait()

	out := make([]Account, 0, len(accounts))
	for i := range accounts {
		if accounts[i].Existence == ExistenceAbsent {
			continue
		}
		out = append(out, accounts[i])
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if out[i].Platform != out[j].Platform {
			return out[i].Platform < out[j].Platform
		}
		return out[i].Handle < out[j].Handle
	})
	sort.Slice(removed, func(i, j int) bool {
		if removed[i].Platform != removed[j].Platform {
			return removed[i].Platform < removed[j].Platform
		}
		return removed[i].Handle < removed[j].Handle
	})
	return out, removed
}

func verifyLimit() int {
	const fallback = 200
	if raw := os.Getenv("PEOPLE_VERIFY_MAX"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

// applyExistence приводит score/tier/verified к состоянию доказанности.
func applyExistence(acc *Account) {
	switch acc.Existence {
	case ExistenceConfirmed:
		acc.Verified = true
		acc.Verification = VerificationHTTP
		acc.VerificationSource = "http"
		acc.Score += 10
		if acc.Score > 100 {
			acc.Score = 100
		}
		if confidenceRank(acc.Confidence) < confidenceRank(scanner.ConfidenceMedium) {
			acc.Confidence = scanner.ConfidenceMedium
		}
	case ExistenceBlocked:
		acc.Verified = false
		acc.Confidence = scanner.ConfidenceLow
		acc.Score -= 20
	case ExistenceUnknown:
		acc.Verified = false
		acc.Confidence = scanner.ConfidenceLow
		acc.Score -= 10
	case ExistenceAbsent:
		acc.Verified = false
		acc.Confidence = scanner.ConfidenceLow
	}
	if acc.Score < 0 {
		acc.Score = 0
	}
}

// evaluateProfilePage отличает реальный профиль от soft-404/login-wall.
// Порядок важен: сначала site-specific маркеры WhatsMyName, затем title/og,
// и только потом эвристика по телу страницы.
func evaluateProfilePage(acc *Account, f profileFetch) ExistenceState {
	body := f.Body
	lowerBody := strings.ToLower(body)
	title := strings.ToLower(htmlTitle(body))
	ogTitle := strings.ToLower(ogTitle(body))

	if isLoginWall(f.FinalURL, title+" "+ogTitle) {
		return ExistenceBlocked
	}
	if hasAny(lowerBody, strongAbsenceMarkers) {
		// HTTP 200 с текстом «not found» — это soft-404, а не подтверждение.
		return ExistenceUnknown
	}
	if acc.PageNegative != "" && strings.Contains(lowerBody, strings.ToLower(acc.PageNegative)) {
		return ExistenceUnknown
	}
	if acc.PageMarker != "" {
		if strings.Contains(body, acc.PageMarker) {
			return ExistenceConfirmed
		}
		return ExistenceUnknown
	}
	handle := strings.ToLower(acc.Handle)
	if handle == "" {
		return ExistenceUnknown
	}
	if strings.Contains(title, handle) || strings.Contains(ogTitle, handle) {
		return ExistenceConfirmed
	}
	// JSON API-ответ — надёжнее HTML-эвристики.
	if strings.Contains(strings.ToLower(f.ContentType), "json") && strings.Contains(lowerBody, handle) {
		return ExistenceConfirmed
	}
	// Тело без профильной разметки и без handle в заголовке легко даёт
	// ложное подтверждение на SPA/catch-all — не подтверждаем.
	if strings.Contains(lowerBody, handle) && looksLikeProfileMarkup(lowerBody) {
		return ExistenceConfirmed
	}
	return ExistenceUnknown
}

var (
	titleRe    = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	ogTitleRe  = regexp.MustCompile(`(?is)<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']*)["']`)
	ogTitleRev = regexp.MustCompile(`(?is)<meta[^>]+content=["']([^"']*)["'][^>]+property=["']og:title["']`)
)

func htmlTitle(body string) string {
	if m := titleRe.FindStringSubmatch(body); len(m) == 2 {
		return strings.TrimSpace(html.UnescapeString(m[1]))
	}
	return ""
}

func ogTitle(body string) string {
	if m := ogTitleRe.FindStringSubmatch(body); len(m) == 2 {
		return strings.TrimSpace(html.UnescapeString(m[1]))
	}
	if m := ogTitleRev.FindStringSubmatch(body); len(m) == 2 {
		return strings.TrimSpace(html.UnescapeString(m[1]))
	}
	return ""
}

var strongAbsenceMarkers = []string{
	"user not found",
	"profile not found",
	"page not found",
	"account not found",
	"couldn't find",
	"could not find",
	"doesn't exist",
	"does not exist",
	"no longer available",
	"account suspended",
	"this account doesn't exist",
}

var loginWallMarkers = []string{
	"log in to continue",
	"sign in to continue",
	"login to view",
	"log in to view",
	"sign in to view",
	"authorization required",
	"just a moment",
	"attention required",
}

func isLoginWall(finalURL, title string) bool {
	lowerTitle := strings.ToLower(title)
	if hasAny(lowerTitle, loginWallMarkers) {
		return true
	}
	if lowerTitle == "login" || lowerTitle == "sign in" || lowerTitle == "log in" ||
		strings.HasPrefix(lowerTitle, "login") || strings.Contains(lowerTitle, "log in") ||
		strings.Contains(lowerTitle, "sign in") {
		return true
	}
	u, err := url.Parse(finalURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(strings.Trim(u.Path, "/"))
	if path == "" {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		switch segment {
		case "login", "signin", "sign-in", "log-in", "session":
			return true
		}
	}
	return false
}

func looksLikeProfileMarkup(lowerBody string) bool {
	for _, marker := range []string{
		`og:type" content="profile`,
		`og:type' content='profile`,
		`"@type":"person"`,
		`"@type": "person"`,
		`rel="me"`,
		`itemprop="name"`,
	} {
		if strings.Contains(lowerBody, marker) {
			return true
		}
	}
	return false
}

func hasAny(haystack string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(haystack, needle) {
			return true
		}
	}
	return false
}

func fetchProfile(ctx context.Context, client *http.Client, link string) (profileFetch, error) {
	var result profileFetch
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return result, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36")
	req.Header.Set("Accept-Language", "en-US,en;q=0.8,ru;q=0.7")
	resp, err := client.Do(req)
	if err != nil {
		if resp != nil {
			result.Status = resp.StatusCode
		}
		return result, err
	}
	defer resp.Body.Close()
	result.Status = resp.StatusCode
	result.ContentType = resp.Header.Get("Content-Type")
	if resp.Request != nil && resp.Request.URL != nil {
		result.FinalURL = resp.Request.URL.String()
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	result.Body = string(body)
	return result, nil
}
