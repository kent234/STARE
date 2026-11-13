package people

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"stare/server/scanner"
)

// Kind — тип входных данных People-OSINT.
type Kind string

const (
	KindUsername   Kind = "username"
	KindEmail      Kind = "email"
	KindPhone      Kind = "phone"
	KindRealName   Kind = "real_name"
	KindProfileURL Kind = "profile_url"
)

// Account — найденный аккаунт на платформе.
type Account struct {
	ID          string                 `json:"id"`
	Platform    string                 `json:"platform"`
	Handle      string                 `json:"handle"`
	URL         string                 `json:"url,omitempty"`
	Name        string                 `json:"name,omitempty"`
	Bio         string                 `json:"bio,omitempty"`
	Avatar      string                 `json:"avatar,omitempty"`
	Links       []string               `json:"links,omitempty"`
	Sources     []string               `json:"sources"`
	Confidence  scanner.ConfidenceTier `json:"confidence_tier"`
	MultiSource bool                   `json:"multi_source"`
	Verified    bool                   `json:"verified"`
	Score       int                    `json:"score"`
	MatchScore  int                    `json:"match_score,omitempty"`
	MatchReason string                 `json:"match_reason,omitempty"`
}

// Registration — факт регистрации email на сайте (Holehe), не профиль.
type Registration struct {
	Platform   string                 `json:"platform"`
	Email      string                 `json:"email"`
	Source     string                 `json:"source"`
	Confidence scanner.ConfidenceTier `json:"confidence_tier"`
}

// Breach — факт утечки (без сырых паролей/токенов).
type Breach struct {
	Name        string   `json:"name"`
	Date        string   `json:"date,omitempty"`
	DataClasses []string `json:"data_classes,omitempty"`
	Email       string   `json:"email,omitempty"`
}

// PhoneInfo — базовые атрибуты номера.
type PhoneInfo struct {
	Indicator   string `json:"indicator"`
	E164        string `json:"e164,omitempty"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	Carrier     string `json:"carrier,omitempty"`
	Valid       bool   `json:"valid"`
}

// Actor — гипотеза о человеке, связанная с аккаунтами.
type Actor struct {
	ID         string                 `json:"id"`
	Label      string                 `json:"label"`
	Confidence scanner.ConfidenceTier `json:"confidence_tier"`
	Accounts   []string               `json:"accounts"`
	Signals    []string               `json:"signals,omitempty"`
}

// Result — ответ /api/people и данные для графа.
type Result struct {
	Target        string                `json:"target"`
	Kind          string                `json:"kind"`
	InputType     Kind                  `json:"input_type"`
	FetchedAt     time.Time             `json:"fetched_at"`
	Observations  []scanner.Observation `json:"observations"`
	Accounts      []Account             `json:"accounts"`
	Registrations []Registration        `json:"registrations,omitempty"`
	Actor         *Actor                `json:"actor,omitempty"`
	Breaches      []Breach              `json:"breaches,omitempty"`
	Phone         *PhoneInfo            `json:"phone,omitempty"`
	Errors        []string              `json:"errors,omitempty"`
}

// Collector — отдельный бесплатный инструмент/источник.
type Collector interface {
	Name() string
	Collect(ctx context.Context, target string) ([]scanner.Observation, error)
}

var collectors = []Collector{
	&ProfileCollector{},
	&SherlockCollector{},
	&MaigretCollector{},
	&BlackbirdCollector{},
	&WhatsMyNameCollector{},
	&HoleheCollector{},
	&GravatarCollector{},
	&EmailRepCollector{},
	&XposedOrNotCollector{},
	&HudsonRockCollector{},
	&GHuntCollector{},
	&GitHubUserCollector{},
	&GitLabUserCollector{},
	&KeybaseCollector{},
	&GitHubNameCollector{},
	&PhoneCollector{},
	&PhoneInfogaCollector{},
}

// Detect определяет тип ввода без выпадающего списка.
func Detect(input string) Kind {
	s := strings.TrimSpace(input)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "@") && !strings.ContainsAny(s, " \t") {
		return KindEmail
	}
	if isProfileURL(s) {
		return KindProfileURL
	}
	if isPhone(s) {
		return KindPhone
	}
	if strings.ContainsAny(s, " \t") {
		return KindRealName
	}
	return KindUsername
}

func isPhone(s string) bool {
	digits := 0
	for i, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r == '+' && i == 0:
		case r == '-' || r == ' ' || r == '(' || r == ')':
		default:
			return false
		}
	}
	return digits >= 7 && digits <= 15
}

// Run выполняет конвейер: detect → collectors → normalize → actor.
func Run(ctx context.Context, target string) Result {
	kind := Detect(target)
	res := Result{
		Target:    strings.TrimSpace(target),
		Kind:      "people",
		InputType: kind,
		FetchedAt: time.Now().UTC(),
	}

	if kind == "" {
		res.Errors = append(res.Errors, "empty target")
		return res
	}

	var (
		mu           sync.Mutex
		wg           sync.WaitGroup
		observations []scanner.Observation
	)
	collectorTarget := target
	if kind == KindProfileURL {
		_, handle, ok := ParseProfileURL(target)
		if !ok {
			res.Errors = append(res.Errors, "cannot parse profile URL")
			return res
		}
		collectorTarget = handle
	}
	for _, collector := range collectors {
		if !collectorApplies(collector.Name(), kind) {
			continue
		}
		cTarget := collectorTarget
		if collector.Name() == "profile" {
			cTarget = target
		}
		wg.Add(1)
		go func(collector Collector, cTarget string) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 600*time.Second)
			obs, err := collector.Collect(cctx, cTarget)
			cancel()
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", collector.Name(), err))
				return
			}
			observations = append(observations, obs...)
		}(collector, cTarget)
	}
	wg.Wait()

	res.Observations = observations
	res.Accounts, res.Breaches, res.Phone, res.Registrations = Normalize(observations)
	if kind == KindProfileURL {
		res.Accounts = ApplyProfileMatch(ctx, target, res.Accounts)
	}
	res.Actor = BuildActor(target, res.Accounts)
	return res
}

func collectorApplies(name string, kind Kind) bool {
	switch name {
	case "sherlock", "maigret", "whatsmyname", "githubuser", "gitlab", "keybase":
		return kind == KindUsername || kind == KindProfileURL
	case "blackbird":
		return kind == KindUsername || kind == KindProfileURL || kind == KindEmail
	case "profile":
		return kind == KindProfileURL
	case "holehe", "xposedornot", "hudsonrock", "ghunt", "gravatar", "emailrep":
		return kind == KindEmail
	case "phone", "phoneinfoga":
		return kind == KindPhone
	case "githubname":
		return kind == KindRealName
	default:
		return false
	}
}

// Normalize превращает сырые Observation в аккаунты/утечки/телефон и дедуплицирует.
// Регистрации (Holehe) не считаются аккаунтами — они выносятся отдельно.
func Normalize(observations []scanner.Observation) ([]Account, []Breach, *PhoneInfo, []Registration) {
	byKey := map[string]*Account{}
	regSeen := map[string]struct{}{}
	var breaches []Breach
	var registrations []Registration
	var phone *PhoneInfo

	for _, obs := range observations {
		var payload map[string]any
		if err := json.Unmarshal(obs.Payload, &payload); err != nil {
			continue
		}
		kind, _ := payload["kind"].(string)
		switch kind {
		case "breach":
			b := Breach{
				Name:  str(payload["breach_name"]),
				Date:  str(payload["date"]),
				Email: str(payload["email"]),
			}
			if classes, ok := payload["data_classes"].([]any); ok {
				for _, c := range classes {
					if s := str(c); s != "" {
						b.DataClasses = append(b.DataClasses, s)
					}
				}
			}
			breaches = append(breaches, b)
			continue
		case "registration":
			platform := canonicalPlatform(str(payload["platform"]))
			email := str(payload["email"])
			if platform == "" {
				continue
			}
			key := platform + "|" + strings.ToLower(email)
			if _, ok := regSeen[key]; ok {
				continue
			}
			regSeen[key] = struct{}{}
			registrations = append(registrations, Registration{
				Platform:   platform,
				Email:      email,
				Source:     obs.Source,
				Confidence: scanner.ConfidenceLow,
			})
			continue
		case "phone":
			if phone == nil {
				phone = &PhoneInfo{}
			}
			if v := str(payload["indicator"]); v != "" {
				phone.Indicator = v
			}
			if v := str(payload["e164"]); v != "" {
				phone.E164 = v
			}
			if v := str(payload["country"]); v != "" {
				phone.Country = v
			}
			if v := str(payload["country_code"]); v != "" {
				phone.CountryCode = v
			}
			if v := str(payload["carrier"]); v != "" {
				phone.Carrier = v
			}
			if boolVal(payload["valid"]) {
				phone.Valid = true
			}
			continue
		}

		platform := canonicalPlatform(str(payload["platform"]))
		handle := normalizeHandle(str(payload["handle"]))
		if platform == "" || handle == "" {
			continue
		}
		link := str(payload["url"])
		verified := boolVal(payload["verified"])
		score := accountScore(obs.Confidence, verified, link, handle, obs.Source)

		key := platform + "|" + strings.ToLower(handle)
		acc, ok := byKey[key]
		if !ok {
			acc = &Account{
				ID:         "account:" + platform + ":" + strings.ToLower(handle),
				Platform:   platform,
				Handle:     handle,
				URL:        link,
				Confidence: obs.Confidence,
				Verified:   verified,
				Score:      score,
			}
			byKey[key] = acc
		}
		if !contains(acc.Sources, obs.Source) {
			acc.Sources = append(acc.Sources, obs.Source)
		}
		if confidenceRank(obs.Confidence) > confidenceRank(acc.Confidence) {
			acc.Confidence = obs.Confidence
		}
		if score > acc.Score {
			acc.Score = score
		}
		acc.Verified = acc.Verified || verified
		if acc.URL == "" {
			acc.URL = link
		}
		if acc.Name == "" || betterName(acc.Name, cleanText(str(payload["name"]))) {
			acc.Name = cleanText(str(payload["name"]))
		}
		if bio := cleanText(str(payload["bio"])); len(bio) > len(acc.Bio) {
			acc.Bio = bio
		}
		if avatar := str(payload["avatar"]); avatar != "" && (acc.Avatar == "" || verified) {
			acc.Avatar = avatar
		}
		if links, ok := payload["links"].([]any); ok {
			for _, link := range links {
				if s := str(link); s != "" && !contains(acc.Links, s) {
					acc.Links = append(acc.Links, s)
				}
			}
		}
	}

	accounts := make([]Account, 0, len(byKey))
	for _, acc := range byKey {
		sort.Strings(acc.Sources)
		acc.MultiSource = len(acc.Sources) > 1
		if acc.Verified && acc.Confidence == scanner.ConfidenceLow {
			acc.Confidence = scanner.ConfidenceMedium
		}
		// Отсекаем явный мусор: неподтверждённые записи с низким score
		// (корневые URL, несовпадение handle, слабые эвристики).
		if !acc.Verified && acc.Score < 30 {
			continue
		}
		accounts = append(accounts, *acc)
	}
	sort.Slice(accounts, func(i, j int) bool {
		if accounts[i].Score != accounts[j].Score {
			return accounts[i].Score > accounts[j].Score
		}
		if accounts[i].Platform != accounts[j].Platform {
			return accounts[i].Platform < accounts[j].Platform
		}
		return accounts[i].Handle < accounts[j].Handle
	})
	sort.Slice(registrations, func(i, j int) bool {
		return registrations[i].Platform < registrations[j].Platform
	})
	return accounts, breaches, phone, registrations
}

var bracketedRe = regexp.MustCompile(`\s*[\(\[].*?[\)\]]`)

func canonicalPlatform(value string) string {
	p := strings.ToLower(strings.TrimSpace(value))
	p = bracketedRe.ReplaceAllString(p, "")
	p = strings.TrimSpace(p)
	for _, suffix := range []string{" username", " user", " community", " api", " profile"} {
		p = strings.TrimSuffix(p, suffix)
	}
	p = strings.ReplaceAll(p, " ", "")
	aliases := map[string]string{
		"githubgist":      "github",
		"githubgists":     "github",
		"steamcommunity":  "steam",
		"dockerhub":       "dockerhub",
		"bluesky":         "bluesky",
		"internetarchive": "archive.org",
	}
	if mapped, ok := aliases[p]; ok {
		return mapped
	}
	return p
}

func normalizeHandle(value string) string {
	h := strings.TrimSpace(value)
	h = strings.TrimPrefix(h, "@")
	h = strings.Trim(h, "/")
	return h
}

// betterName предпочитает полное имя (с пробелом) короткому нику/заголовку.
func betterName(current, candidate string) bool {
	if candidate == "" {
		return false
	}
	if current == "" {
		return true
	}
	return len(candidate) > len(current) && strings.Contains(candidate, " ")
}

func accountScore(confidence scanner.ConfidenceTier, verified bool, link, handle, source string) int {
	score := 25
	switch confidence {
	case scanner.ConfidenceHigh:
		score = 65
	case scanner.ConfidenceMedium:
		score = 45
	}
	if verified {
		score += 25
	}
	lowerLink := strings.ToLower(link)
	if link == "" {
		score -= 10
	} else if strings.Contains(lowerLink, strings.ToLower(handle)) {
		score += 10
	} else {
		score -= 15
	}
	if isRootOrLoginURL(link) {
		score -= 30
	}
	if source == "whatsmyname" {
		score -= 10
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}

func isRootOrLoginURL(link string) bool {
	if link == "" {
		return true
	}
	u, err := url.Parse(link)
	if err != nil {
		return true
	}
	path := strings.Trim(strings.ToLower(u.Path), "/")
	if path == "" {
		return true
	}
	switch path {
	case "login", "signin", "signup", "register", "search":
		return true
	}
	return false
}

// BuildActor строит гипотезу Actor. Confidence не выше самого сильного доказательства.
func BuildActor(target string, accounts []Account) *Actor {
	if len(accounts) == 0 {
		return nil
	}
	best := scanner.ConfidenceLow
	label := strings.TrimSpace(target)
	bestNamedRank := -1
	ids := make([]string, 0, len(accounts))
	for _, acc := range accounts {
		ids = append(ids, acc.ID)
		rank := confidenceRank(acc.Confidence)
		if rank > confidenceRank(best) {
			best = acc.Confidence
		}
		if acc.Name != "" && rank > bestNamedRank {
			label = acc.Name
			bestNamedRank = rank
		}
	}
	sort.Strings(ids)

	if label == strings.TrimSpace(target) {
		if _, handle, ok := ParseProfileURL(target); ok {
			label = handle
		}
	}

	return &Actor{
		ID:         "actor:" + strings.ToLower(strings.TrimSpace(target)),
		Label:      label,
		Confidence: best,
		Accounts:   ids,
	}
}

func confidenceRank(c scanner.ConfidenceTier) int {
	switch c {
	case scanner.ConfidenceHigh:
		return 3
	case scanner.ConfidenceMedium:
		return 2
	default:
		return 1
	}
}

func str(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func boolVal(v any) bool {
	b, _ := v.(bool)
	return b
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// Observation — helper для коллекторов.
func Observation(source string, confidence scanner.ConfidenceTier, payload map[string]any) scanner.Observation {
	raw, _ := json.Marshal(payload)
	return scanner.Observation{
		Source:     source,
		FetchedAt:  time.Now().UTC(),
		Confidence: confidence,
		Payload:    raw,
	}
}
