package people

import "strings"

// sensitivePlatforms — платформы, которые нельзя показывать в общем списке
// и которые не должны влиять на уверенность Actor. Список сознательно
// консервативный: лучше скрыть, чем случайно раскрыть.
var sensitivePlatforms = map[string]struct{}{
	"pornhub":           {},
	"xvideos":           {},
	"xnxx":              {},
	"redtube":           {},
	"youporn":           {},
	"chaturbate":        {},
	"stripchat":         {},
	"cam4":              {},
	"bongacams":         {},
	"livejasmin":        {},
	"manyvids":          {},
	"clips4sale":        {},
	"onlyfans":          {},
	"fansly":            {},
	"fetlife":           {},
	"adultfriendfinder": {},
	"ashleymadison":     {},
	"tinder":            {},
	"grindr":            {},
}

func isSensitivePlatform(platform string) bool {
	p := strings.ToLower(strings.TrimSpace(platform))
	if _, ok := sensitivePlatforms[p]; ok {
		return true
	}
	// canonicalPlatform снимает суффиксы вида "Pornhub (User)".
	_, ok := sensitivePlatforms[canonicalPlatform(p)]
	return ok
}
