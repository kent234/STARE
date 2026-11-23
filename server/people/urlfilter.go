package people

import (
	"net/url"
	"strings"
)

// trackerHosts — сторонние агрегаторы, которые не являются профилем пользователя.
var trackerHosts = map[string]struct{}{
	"twitchtracker.com":    {},
	"socialblade.com":      {},
	"similarweb.com":       {},
	"statsroyale.com":      {},
	"chess.com":            {}, // реальный профиль обрабатывается отдельно по path
	"twitchtracker.com.br": {},
	"streamscharts.com":    {},
}

// searchQueryKeys — query-параметры, которые выдают страницу поиска, а не профиль.
var searchQueryKeys = map[string]struct{}{
	"q":        {},
	"query":    {},
	"search":   {},
	"keywords": {},
	"keyword":  {},
	"type":     {},
	"term":     {},
	"find":     {},
}

// isValidProfileURL отбрасывает корневые страницы, поиск, агрегаторы и ссылки,
// в которых нет самого handle. Это главный барьер от «мусорных» совпадений
// Sherlock/Maigret/Blackbird.
func isValidProfileURL(platform, handle, link string) bool {
	if link == "" || handle == "" {
		return false
	}
	u, err := url.Parse(link)
	if err != nil || u.Hostname() == "" {
		return false
	}
	host := strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
	path := strings.ToLower(strings.Trim(u.Path, "/"))
	h := strings.ToLower(handle)

	// Явные агрегаторы и трекеры — не аккаунты соцсетей.
	if _, bad := trackerHosts[host]; bad && host != "chess.com" {
		return false
	}
	// Страницы поиска/каталога.
	if strings.Contains(path, "/search") || strings.Contains(path, "/find") ||
		strings.Contains(path, "/lookup") || strings.Contains(path, "/catalog") {
		return false
	}
	for key := range u.Query() {
		if _, bad := searchQueryKeys[strings.ToLower(key)]; bad {
			return false
		}
	}

	// Профиль на поддомене: https://<handle>.rajce.idnes.cz/
	if path == "" {
		return strings.Contains(host, h)
	}
	// Основное правило: handle присутствует в пути профиля.
	if strings.Contains(path, h) {
		return true
	}
	// Некоторые API отдают профиль по ID, но handle всё равно в query/path.
	return strings.Contains(strings.ToLower(u.RawQuery), h)
}

// canonicalPlatformForURL приводит платформу к единому имени по домену.
// Это устраняет дубли вида "Chess" / "Chess.com".
func canonicalPlatformForURL(link, fallback string) string {
	u, err := url.Parse(link)
	if err != nil || u.Hostname() == "" {
		return canonicalPlatform(fallback)
	}
	host := strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
	switch {
	case host == "chess.com" || strings.HasSuffix(host, ".chess.com"):
		return "chess.com"
	case host == "github.com" || strings.HasSuffix(host, ".github.com"):
		return "github"
	case host == "gitlab.com" || strings.HasSuffix(host, ".gitlab.com"):
		return "gitlab"
	case host == "twitch.tv" || strings.HasSuffix(host, ".twitch.tv"):
		return "twitch"
	case host == "x.com" || host == "twitter.com":
		return "twitter"
	case host == "reddit.com" || strings.HasSuffix(host, ".reddit.com"):
		return "reddit"
	case host == "t.me":
		return "telegram"
	case host == "vk.com" || strings.HasSuffix(host, ".vk.com"):
		return "vk"
	case host == "ok.ru" || strings.HasSuffix(host, ".ok.ru"):
		return "ok"
	case host == "instagram.com" || strings.HasSuffix(host, ".instagram.com"):
		return "instagram"
	case host == "facebook.com" || strings.HasSuffix(host, ".facebook.com"):
		return "facebook"
	case host == "youtube.com" || strings.HasSuffix(host, ".youtube.com"):
		return "youtube"
	case host == "mojang.com" || strings.HasSuffix(host, ".mojang.com"):
		return "minecraft"
	case host == "venmo.com" || strings.HasSuffix(host, ".venmo.com"):
		return "venmo"
	case host == "pinterest.com" || strings.HasSuffix(host, ".pinterest.com"):
		return "pinterest"
	case host == "keybase.io":
		return "keybase"
	case host == "gravatar.com":
		return "gravatar"
	default:
		return canonicalPlatform(fallback)
	}
}
