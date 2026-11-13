package people

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"stare/server/scanner"
)

var profileURLRe = regexp.MustCompile(`^(https?://)?([a-z0-9-]+\.)+[a-z]{2,}/.+`)

func isProfileURL(value string) bool {
	s := strings.TrimSpace(value)
	return profileURLRe.MatchString(strings.ToLower(s))
}

// ParseProfileURL извлекает платформу и handle из публичной ссылки на профиль.
func ParseProfileURL(raw string) (platform, handle string, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" || !profileURLRe.MatchString(strings.ToLower(s)) {
		return "", "", false
	}
	if !strings.HasPrefix(strings.ToLower(s), "http://") && !strings.HasPrefix(strings.ToLower(s), "https://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" {
		return "", "", false
	}

	host := strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
	platform = strings.Split(host, ".")[0]
	if platform == "" {
		return "", "", false
	}

	path := strings.Trim(u.Path, "/")
	if path == "" {
		return "", "", false
	}
	parts := strings.Split(path, "/")
	handle = strings.TrimPrefix(parts[len(parts)-1], "@")
	if strings.HasSuffix(strings.ToLower(handle), ".php") {
		handle = u.Query().Get("id")
	}
	handle = strings.TrimSpace(handle)
	if handle == "" || isReservedPath(handle) {
		return "", "", false
	}
	return platform, handle, true
}

func isReservedPath(value string) bool {
	switch strings.ToLower(value) {
	case "p", "reel", "reels", "stories", "explore", "watch", "hashtag", "status", "i", "search", "login", "signup":
		return true
	default:
		return false
	}
}

func normalizeProfileURL(raw string) string {
	s := strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(s), "http://") && !strings.HasPrefix(strings.ToLower(s), "https://") {
		s = "https://" + s
	}
	return s
}

// ProfileCollector забирает публичные метаданные профиля (OpenGraph/title/links).
type ProfileCollector struct{}

func (c *ProfileCollector) Name() string { return "profile" }

type profileMeta struct {
	Title       string
	Description string
	Avatar      string
	Links       []string
}

var (
	titleTagRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	metaTagRe  = regexp.MustCompile(`(?is)<meta\s+[^>]*?(?:property|name)=["'](og:title|og:description|og:image|description)["'][^>]*?content=["']([^"']*)["']`)
	metaRevRe  = regexp.MustCompile(`(?is)<meta\s+[^>]*?content=["']([^"']*)["'][^>]*?(?:property|name)=["'](og:title|og:description|og:image|description)["']`)
	hrefRe     = regexp.MustCompile(`(?is)href=["'](https?://[^"']+)["']`)
	nameAttrRe = regexp.MustCompile(`(?is)<(?:span|div|h1)[^>]*(?:itemprop=["']name["']|class=["'][^"']*p-name[^"']*["'])[^>]*>(.*?)</(?:span|div|h1)>`)
	tagRe      = regexp.MustCompile(`(?s)<[^>]+>`)
)

func (c *ProfileCollector) Collect(ctx context.Context, target string) ([]scanner.Observation, error) {
	platform, handle, ok := ParseProfileURL(target)
	if !ok {
		return nil, nil
	}
	link := normalizeProfileURL(target)
	meta := fetchProfileMeta(ctx, link)

	payload := map[string]any{
		"kind":     "profile",
		"platform": platform,
		"handle":   handle,
		"url":      link,
		"verified": true,
	}
	if meta.Title != "" {
		payload["name"] = meta.Title
	}
	if meta.Description != "" {
		payload["bio"] = meta.Description
	}
	if meta.Avatar != "" {
		payload["avatar"] = meta.Avatar
	}
	if len(meta.Links) > 0 {
		payload["links"] = meta.Links
	}
	return []scanner.Observation{Observation("profile", scanner.ConfidenceHigh, payload)}, nil
}

func fetchProfileMeta(ctx context.Context, link string) profileMeta {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return profileMeta{}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36")
	req.Header.Set("Accept-Language", "en-US,en;q=0.8,ru;q=0.7")

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return profileMeta{}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return profileMeta{}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return profileMeta{}
	}
	text := string(body)

	meta := profileMeta{}
	for _, m := range metaTagRe.FindAllStringSubmatch(text, -1) {
		setMeta(&meta, strings.ToLower(m[1]), m[2])
	}
	for _, m := range metaRevRe.FindAllStringSubmatch(text, -1) {
		setMeta(&meta, strings.ToLower(m[2]), m[1])
	}
	if meta.Title == "" {
		if m := titleTagRe.FindStringSubmatch(text); len(m) > 1 {
			title := cleanText(m[1])
			if !isBoilerplate(title) {
				meta.Title = title
			}
		}
	}
	if m := nameAttrRe.FindStringSubmatch(text); len(m) > 1 {
		name := cleanText(tagRe.ReplaceAllString(m[1], " "))
		if name != "" && !isBoilerplate(name) && len(name) < 100 && (meta.Title == "" || strings.Contains(name, " ")) {
			meta.Title = name
		}
	}

	host := ""
	if u, err := url.Parse(link); err == nil {
		host = u.Hostname()
	}
	for _, m := range hrefRe.FindAllStringSubmatch(text, -1) {
		candidate := strings.TrimSpace(m[1])
		if host != "" && strings.Contains(candidate, host) {
			continue
		}
		if !usefulProfileLink(candidate) {
			continue
		}
		if !contains(meta.Links, candidate) {
			meta.Links = append(meta.Links, candidate)
		}
		if len(meta.Links) >= 10 {
			break
		}
	}
	return meta
}

func usefulProfileLink(link string) bool {
	lower := strings.ToLower(link)
	for _, suffix := range []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf"} {
		if strings.HasSuffix(lower, suffix) {
			return false
		}
	}
	for _, marker := range []string{"/css/", "/js/", "/img/", "/images/", "/static/", "/assets/"} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	for _, host := range []string{
		"githubassets.com", "avatars.githubusercontent.com", "user-images.githubusercontent.com",
		"github-cloud.s3.amazonaws.com", "st.vk.ru", "vk.com/images", "instagram.com/static",
	} {
		if strings.Contains(lower, host) {
			return false
		}
	}
	return true
}

var boilerplateTitles = []string{
	"your browser is out of date",
	"access denied",
	"just a moment",
	"attention required",
	"log in",
	"sign in",
	"sign up",
	"instagram",
	"facebook",
	"vk",
	"telegram",
}

func isBoilerplate(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	for _, bad := range boilerplateTitles {
		if v == bad || strings.HasPrefix(v, bad+" ") || strings.HasPrefix(v, bad+" |") {
			return true
		}
	}
	return false
}

func setMeta(meta *profileMeta, key, value string) {
	value = cleanText(value)
	if value == "" || isBoilerplate(value) {
		return
	}
	value = cleanProfileTitle(value)
	switch key {
	case "og:title":
		meta.Title = value
	case "og:description", "description":
		if meta.Description == "" {
			meta.Description = value
		}
	case "og:image":
		meta.Avatar = value
	}
}

func cleanText(value string) string {
	value = html.UnescapeString(value)
	value = strings.Join(strings.Fields(value), " ")
	return strings.TrimSpace(value)
}

func cleanProfileTitle(value string) string {
	suffixes := []string{
		" - Overview", " · GitHub", " | GitHub", " • Instagram photos and videos",
		" (@", " | Facebook",
	}
	for _, suffix := range suffixes {
		if i := strings.Index(value, suffix); i > 0 {
			value = value[:i]
		}
	}
	if i := strings.Index(value, " (@"); i > 0 {
		value = value[:i]
	}
	return strings.TrimSpace(value)
}
