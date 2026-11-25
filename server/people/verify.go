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
			acc.Score = computeAccountScore(*acc)
			acc.Confidence = evidenceTier(*acc)
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
			if acc.Existence == ExistenceAbsent {
				// 200 + strong negative — тоже негативный факт, не только 404/410.
				mu.Lock()
				removed = append(removed, RemovedAccount{
					ID:       acc.ID,
					Platform: acc.Platform,
					Handle:   acc.Handle,
					URL:      acc.URL,
					Status:   f.Status,
				})
				mu.Unlock()
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
	if deepMode() {
		// В deep mode проверяем всё, что нашли, а не первые 200.
		return 100000
	}
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
	default:
		acc.Verified = false
	}
	acc.Score = computeAccountScore(*acc)
	acc.Confidence = evidenceTier(*acc)
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
	// Login-wall может быть в теле при нормальном title (Pinterest, Reddit и т.п.).
	if hasAny(lowerBody, loginWallBodyMarkers) {
		return ExistenceBlocked
	}

	// 1. Positive marker сильнее любого negative: страница с реальным
	// профильным маркером не должна теряться из-за слова "not found" в футере.
	if hasPositiveProfileMarker(acc, f, lowerBody) {
		return ExistenceConfirmed
	}

	// 2. Сильный negative без positive — это absent, а не unknown.
	if hasStrongNegative(acc, lowerBody, title+" "+ogTitle) {
		return ExistenceAbsent
	}
	// 3. Слабый site-specific negative оставляет неопределённость.
	if acc.PageNegative != "" && !isGenericNegativeMarker(acc.PageNegative) &&
		strings.Contains(lowerBody, strings.ToLower(acc.PageNegative)) {
		return ExistenceUnknown
	}

	handle := strings.ToLower(acc.Handle)
	if handle == "" {
		return ExistenceUnknown
	}
	// JSON API-ответ — надёжнее HTML-эвристики.
	if strings.Contains(strings.ToLower(f.ContentType), "json") && strings.Contains(lowerBody, handle) {
		return ExistenceConfirmed
	}
	// API/utility не подтверждаются только HTTP 200 + title/handle:
	// нужна JSON-семантика или положительный маркер (проверены выше).
	if acc.URLKind == URLKindAPI || acc.URLKind == URLKindUtility {
		return ExistenceUnknown
	}
	if strings.Contains(title, handle) || strings.Contains(ogTitle, handle) {
		return ExistenceConfirmed
	}
	// Тело без профильной разметки и без handle в заголовке легко даёт
	// ложное подтверждение на SPA/catch-all — не подтверждаем.
	if strings.Contains(lowerBody, handle) && looksLikeProfileMarkup(lowerBody) {
		return ExistenceConfirmed
	}
	return ExistenceUnknown
}

func hasPositiveProfileMarker(acc *Account, f profileFetch, lowerBody string) bool {
	if acc.PageMarker != "" && strings.Contains(f.Body, acc.PageMarker) {
		return true
	}
	// Chess.com API отдаёт стабильный player_id; generic code:0 его не отменяет.
	if acc.Platform == "chess.com" && strings.Contains(lowerBody, `"player_id"`) {
		return true
	}
	return false
}

func hasStrongNegative(acc *Account, lowerBody, lowerTitle string) bool {
	if hasAny(lowerBody, strongAbsenceMarkers) {
		return true
	}
	// Duolingo и подобные API: users: [] — отсутствие, а не неизвестность.
	if emptyUsersRe.MatchString(lowerBody) {
		return true
	}
	if hasAny(lowerTitle, strongAbsenceMarkers) ||
		hasAny(lowerTitle, titleAbsenceMarkers) {
		return true
	}
	negative := strings.TrimSpace(acc.PageNegative)
	if negative != "" && !isGenericNegativeMarker(negative) &&
		strings.Contains(lowerBody, strings.ToLower(negative)) &&
		isStrongNegativeText(negative) {
		return true
	}
	return false
}

// isGenericNegativeMarker отсеивает служебные JSON-флаги, которые не являются
// признаком отсутствия профиля.
func isGenericNegativeMarker(value string) bool {
	compact := strings.ToLower(value)
	compact = strings.NewReplacer(" ", "", "\"", "", "'", "").Replace(compact)
	switch compact {
	case "code:0", "error:0", "status:ok", "success:true":
		return true
	default:
		return false
	}
}

func isStrongNegativeText(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"not found", "doesn't exist", "does not exist", "not available", "suspended", "no such"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

var emptyUsersRe = regexp.MustCompile(`(?i)"users"\s*:\s*\[\s*\]`)

var titleAbsenceMarkers = []string{
	"not found",
	"404",
	"not available",
	"doesn't exist",
	"does not exist",
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
	"site not found",
	"account not found",
	"couldn't find",
	"could not find",
	"doesn't exist",
	"does not exist",
	"no longer available",
	"account suspended",
	"this account doesn't exist",
}

var loginWallBodyMarkers = []string{
	"log in to continue",
	"sign in to continue",
	"login to view",
	"log in to view",
	"sign in to view",
	"authorization required",
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
