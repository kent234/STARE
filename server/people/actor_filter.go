package people

import (
	"net/url"
	"sort"
	"strings"
)

// defaultAvatarMarkers — плейсхолдеры, которые не должны становиться
// кросс-сигналом: у тысяч профилей они одинаковы.
var defaultAvatarMarkers = []string{
	"default.png",
	"default.jpg",
	"default_profile",
	"default-avatar",
	"default_avatar",
	"placeholder",
	"no-avatar",
	"no_avatar",
	"blank.png",
	"avatar-default",
	"/images/default",
}

func isDefaultAvatar(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return false
	}
	for _, marker := range defaultAvatarMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// boilerplateHosts — шрифты, CDN, поддержка и навигация платформ.
var boilerplateHosts = map[string]struct{}{
	"fonts.gstatic.com":        {},
	"fonts.googleapis.com":     {},
	"cdn.jsdelivr.net":         {},
	"cdnjs.cloudflare.com":     {},
	"unpkg.com":                {},
	"ajax.googleapis.com":      {},
	"support.github.com":       {},
	"help.github.com":          {},
	"github.com":               {},
	"gitlab.com":               {},
	"support.discord.com":      {},
	"help.twitter.com":         {},
	"support.twitter.com":      {},
	"help.instagram.com":       {},
	"policies.google.com":      {},
	"accounts.google.com":      {},
	"www.googletagmanager.com": {},
}

// boilerplatePathMarkers — служебные разделы внутри платформенного домена.
var boilerplatePathMarkers = []string{
	"/features",
	"/pricing",
	"/about",
	"/contact",
	"/support",
	"/terms",
	"/privacy",
	"/login",
	"/signup",
	"/following",
	"/followers",
	"/settings",
	"/help",
}

// filteredPersonalLinks оставляет только внешние персональные ссылки:
// без CDN, без навигации и без собственного домена платформы.
func filteredPersonalLinks(links []string, platform string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(links))
	platformHost := strings.ToLower(strings.TrimSpace(platform))
	for _, link := range links {
		value := strings.TrimSpace(link)
		if value == "" {
			continue
		}
		u, err := url.Parse(value)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			continue
		}
		host := strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
		if _, bad := boilerplateHosts[host]; bad {
			continue
		}
		lowerPath := strings.ToLower(u.Path)
		skip := false
		for _, marker := range boilerplatePathMarkers {
			if strings.Contains(lowerPath, marker) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		if platformHost != "" && (host == platformHost || strings.HasSuffix(host, "."+platformHost)) {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}

// genericPhrases — описательные фразы платформ, которые не являются именем.
var genericPhrases = []string{
	"best place to",
	"one of the millions",
	"check out",
	"profile page",
	"home page",
	"official site",
	"official website",
	"welcome to",
	"follow me",
	"my profile",
	"online store",
	"sign up",
	"log in",
}

func isGenericPhrase(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return true
	}
	for _, phrase := range genericPhrases {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}

// actorBrandWords — названия платформ, которые не могут быть частью имени.
var actorBrandWords = []string{
	"github", "gitlab", "chess.com", "pinterest", "tweakers", "sketchfab",
	"telegram", "twitter", "reddit", "wordpress", "notion", "youtube",
	"tiktok", "steam", "keybase", "gravatar", "minecraft", "duolingo",
}

// plausibleActorName проверяет, годится ли отображаемое имя в качестве label:
// 2–4 токена, не платформа, не generic-фраза, не равен исходному handle.
func plausibleActorName(name, platform, handle string) bool {
	value := strings.TrimSpace(name)
	if value == "" {
		return false
	}
	lower := strings.ToLower(value)
	if lower == strings.ToLower(strings.TrimSpace(platform)) ||
		lower == strings.ToLower(strings.TrimSpace(handle)) {
		return false
	}
	if isGenericPhrase(value) {
		return false
	}
	tokens := strings.Fields(value)
	if len(tokens) < 2 || len(tokens) > 4 {
		return false
	}
	for _, brand := range actorBrandWords {
		if strings.Contains(lower, brand) {
			return false
		}
	}
	for _, token := range tokens {
		if !strings.ContainsFunc(token, isLetter) {
			return false
		}
	}
	return true
}

func isLetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
		(r >= 'а' && r <= 'я') || (r >= 'А' && r <= 'Я') || r == 'ё' || r == 'Ё'
}

// genericBioPhrases — штатные описания платформ. Они не характеризуют
// человека и не должны участвовать в matching или Actor.
var genericBioPhrases = []string{
	"best place for",
	"best place to",
	"one of the millions",
	"check out my",
	"check out my profile",
	"largest professional network",
	"world's largest",
	"the world's largest",
	"share your photos",
	"share photos and videos",
	"connect with friends",
	"your daily dose",
	"home of the best",
	"member since",
	"profile page",
	"official profile",
	"follow me on",
}

// isGenericBio сообщает, что строка — платформенное клише, а не описание.
func isGenericBio(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return true
	}
	for _, phrase := range genericBioPhrases {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	if isGenericPhrase(lower) {
		return true
	}
	return false
}
