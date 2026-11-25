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
	"unicode"

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

// VerificationState — чем именно подтверждён аккаунт.
// none — только эвристика коллектора; collector — коллектор/провайдер API;
// http — успешный HTTP-запрос с проверкой страницы.
type VerificationState string

const (
	VerificationNone      VerificationState = "none"
	VerificationCollector VerificationState = "collector"
	VerificationHTTP      VerificationState = "http"
)

// ExistenceState — что именно доказано про существование профиля.
// blocked/unknown никогда не должны трактоваться как «аккаунт есть».
type ExistenceState string

const (
	ExistenceConfirmed ExistenceState = "confirmed"
	ExistenceBlocked   ExistenceState = "blocked"
	ExistenceUnknown   ExistenceState = "unknown"
	ExistenceAbsent    ExistenceState = "absent"
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
	// Verified — совместимое поле: true только при existence=confirmed.
	Verified           bool              `json:"verified"`
	Verification       VerificationState `json:"verification"`
	VerificationSource string            `json:"verification_source,omitempty"`
	Existence          ExistenceState    `json:"existence"`
	URLValid           bool              `json:"url_valid"`
	URLKind            URLKind           `json:"url_kind,omitempty"`
	URLReachable       bool              `json:"url_reachable"`
	HTTPAttempted      bool              `json:"http_attempted,omitempty"`
	HTTPStatus         int               `json:"http_status,omitempty"`
	HTTPError          string            `json:"http_error,omitempty"`
	// Provider — аккаунт подтверждён API провайдера (Microsoft/PGP),
	// повторная HTTP-проверка ему не нужна.
	Provider bool `json:"provider,omitempty"`
	// PageMarker/PageNegative — site-specific e_string/m_string из WhatsMyName:
	// позволяют подтверждать страницу без повторной эвристики по handle.
	PageMarker   string   `json:"page_marker,omitempty"`
	PageNegative string   `json:"page_negative,omitempty"`
	EvidenceURLs []string `json:"evidence_urls,omitempty"`
	// Sensitive — платформа для взрослых/чувствительные данные.
	// Такие аккаунты скрыты по умолчанию и не влияют на Actor.
	Sensitive bool `json:"sensitive,omitempty"`
	// VariantOf — исходный ник, если аккаунт найден через variant expansion.
	VariantOf string `json:"variant_of,omitempty"`
	// ProviderName — конкретный хостинг для personal_site (notion.site и т.п.).
	ProviderName string `json:"provider_name,omitempty"`
	// Архив и хэш аватара — пивоты для корреляции и доказательства.
	ArchivedURL string `json:"archived_url,omitempty"`
	ArchivedAt  string `json:"archived_at,omitempty"`
	AvatarHash  string `json:"avatar_hash,omitempty"`
	Score       int    `json:"score"`
	MatchScore  int    `json:"match_score,omitempty"`
	MatchReason string `json:"match_reason,omitempty"`
}

// RemovedAccount — негативный факт: профиль отдал 404/410.
// Нужен, чтобы между сканами была видна динамика удаления.
type RemovedAccount struct {
	ID       string `json:"id"`
	Platform string `json:"platform"`
	Handle   string `json:"handle"`
	URL      string `json:"url,omitempty"`
	Status   int    `json:"http_status"`
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
	// Signals всегда массив: high выдаётся только при 2+ независимых сигналах.
	Signals           []string `json:"signals"`
	SensitiveAccounts []string `json:"sensitive_accounts,omitempty"`
}

// Result — ответ /api/people и данные для графа.
type Result struct {
	Target        string                `json:"target"`
	SchemaVersion string                `json:"schema_version"`
	ScanID        string                `json:"scan_id"`
	DurationMS    int64                 `json:"duration_ms"`
	Kind          string                `json:"kind"`
	InputType     Kind                  `json:"input_type"`
	FetchedAt     time.Time             `json:"fetched_at"`
	Collectors    []CollectorStatus     `json:"collectors,omitempty"`
	Versions      map[string]string     `json:"versions,omitempty"`
	Observations  []scanner.Observation `json:"observations"`
	Accounts      []Account             `json:"accounts"`
	Mentions      []Mention             `json:"mentions,omitempty"`
	Removed       []RemovedAccount      `json:"removed,omitempty"`
	Registrations []Registration        `json:"registrations,omitempty"`
	Actor         *Actor                `json:"actor,omitempty"`
	Breaches      []Breach              `json:"breaches,omitempty"`
	Phone         *PhoneInfo            `json:"phone,omitempty"`
	Email         *EmailIntel           `json:"email,omitempty"`
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
	&RegistryCollector{},
	&VariantCollector{},
	&SubdomainPatternCollector{},
	&URLScanCollector{},
	&HNMentionsCollector{},
	&GrepAppCollector{},
	&SearchAPICollector{},
	&HoleheCollector{},
	&GravatarCollector{},
	&MicrosoftCollector{},
	&PGPCollector{},
	&DisifyCollector{},
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
	startedAt := time.Now()
	kind := Detect(target)
	res := Result{
		Target:        strings.TrimSpace(target),
		SchemaVersion: scanner.SchemaVersion,
		ScanID:        scanner.NewScanID(),
		Kind:          "people",
		InputType:     kind,
		FetchedAt:     time.Now().UTC(),
	}

	if kind == "" {
		res.Errors = append(res.Errors, "empty target")
		res.DurationMS = time.Since(startedAt).Milliseconds()
		return res
	}

	var (
		mu           sync.Mutex
		wg           sync.WaitGroup
		observations []scanner.Observation
		statuses     []CollectorStatus
	)
	appliedCollectors := make([]string, 0, len(collectors))
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
		appliedCollectors = append(appliedCollectors, collector.Name())

		// Опциональный поиск без API-ключа не запускается и помечается missing.
		if collector.Name() == "search_api" && !searchAPIKeysPresent() {
			mu.Lock()
			statuses = append(statuses, CollectorStatus{Name: "search_api", Status: CollectorMissing})
			mu.Unlock()
			continue
		}

		// Внешний CLI может отсутствовать. Это missing, а не «ничего не нашёл».
		if envKey, binaries, required := collectorRequirement(collector.Name()); required {
			if _, ok := lookBinary(envKey, binaries...); !ok {
				mu.Lock()
				statuses = append(statuses, CollectorStatus{
					Name:   collector.Name(),
					Status: CollectorMissing,
				})
				mu.Unlock()
				continue
			}
		}

		cTarget := collectorTarget
		if collector.Name() == "profile" {
			cTarget = target
		}
		wg.Add(1)
		go func(collector Collector, cTarget string) {
			defer wg.Done()
			started := time.Now()
			timeout := 900 * time.Second
			if deepMode() {
				timeout = 1800 * time.Second
			}
			cctx, cancel := context.WithTimeout(ctx, timeout)
			obs, err := collector.Collect(cctx, cTarget)
			cancel()

			status := CollectorStatus{
				Name:         collector.Name(),
				Status:       CollectorRan,
				Observations: len(obs),
				DurationMS:   time.Since(started).Milliseconds(),
			}
			if err != nil {
				status.Status = CollectorError
				status.Error = err.Error()
			}

			mu.Lock()
			defer mu.Unlock()
			statuses = append(statuses, status)
			if err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", collector.Name(), err))
				return
			}
			observations = append(observations, obs...)
		}(collector, cTarget)
	}
	wg.Wait()
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].Name < statuses[j].Name })

	res.Observations = observations
	res.Mentions = ExtractMentions(observations)
	res.Email = ExtractEmailIntel(observations)
	res.Accounts, res.Breaches, res.Phone, res.Registrations = Normalize(observations)
	res.Accounts, res.Removed = VerifyAccountURLs(ctx, res.Accounts)
	if kind == KindProfileURL {
		res.Accounts = ApplyProfileMatch(ctx, target, res.Accounts)
	}
	refreshAccountEvidence(res.Accounts)

	// После верификации добираем name/bio/avatar/links для top-N:
	// без этих полей Actor не может найти кросс-сигналы.
	var enriched int
	var enrichDuration time.Duration
	res.Accounts, enriched, enrichDuration = EnrichProfiles(ctx, res.Accounts, 10)
	refreshAccountEvidence(res.Accounts)
	statuses = append(statuses, CollectorStatus{
		Name:         "enrichment",
		Status:       CollectorRan,
		Observations: enriched,
		DurationMS:   enrichDuration.Milliseconds(),
	})

	// Пивоты: архивные снимки и хэши аватаров. Оба работают только по
	// публичным URL и не меняют existence.
	var archived, hashed int
	var archiveDuration, hashDuration time.Duration
	res.Accounts, archived, archiveDuration = EnrichArchives(ctx, res.Accounts, 10)
	res.Accounts, hashed, hashDuration = EnrichAvatarHashes(ctx, res.Accounts, 10)
	refreshAccountEvidence(res.Accounts)
	statuses = append(statuses,
		CollectorStatus{Name: "archives", Status: CollectorRan, Observations: archived, Kept: archived, DurationMS: archiveDuration.Milliseconds()},
		CollectorStatus{Name: "avatar_hash", Status: CollectorRan, Observations: hashed, Kept: hashed, DurationMS: hashDuration.Milliseconds()},
	)

	res.Actor = BuildActor(target, res.Accounts)

	// Kept — сколько финальных аккаунтов реально опирается на коллектор.
	for i := range statuses {
		for _, acc := range res.Accounts {
			if contains(acc.Sources, statuses[i].Name) {
				statuses[i].Kept++
			}
		}
		switch statuses[i].Name {
		case "enrichment":
			statuses[i].Kept = enriched
		case "archives":
			statuses[i].Kept = archived
		case "avatar_hash":
			statuses[i].Kept = hashed
		}
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].Name < statuses[j].Name })
	res.Collectors = statuses
	res.Versions = collectorVersions(appliedCollectors)
	res.DurationMS = time.Since(startedAt).Milliseconds()
	return res
}

func collectorApplies(name string, kind Kind) bool {
	switch name {
	case "sherlock", "maigret", "whatsmyname", "githubuser", "gitlab", "keybase":
		return kind == KindUsername || kind == KindProfileURL
	case "registry":
		return (kind == KindUsername || kind == KindProfileURL) && registryEnabled()
	case "variants":
		return (kind == KindUsername || kind == KindProfileURL) && variantsEnabled() && registryEnabled()
	case "subdomain_patterns":
		return (kind == KindUsername || kind == KindProfileURL) && patternsEnabled()
	case "urlscan_search", "hn_algolia", "grepapp", "search_api":
		return kind == KindUsername || kind == KindProfileURL
	case "blackbird":
		return kind == KindUsername || kind == KindProfileURL || kind == KindEmail
	case "profile":
		return kind == KindProfileURL
	case "holehe", "xposedornot", "hudsonrock", "ghunt", "gravatar", "microsoft", "pgp", "disify":
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

		rawPlatform := strings.ToLower(strings.TrimSpace(str(payload["platform"])))
		platform := canonicalPlatform(rawPlatform)
		handle := normalizeHandle(str(payload["handle"]))
		if platform == "" || handle == "" {
			continue
		}
		link := str(payload["url"])
		// Архив — это mention, а не профиль. В аккаунты не попадает.
		if classifyURLKind(link) == URLKindArchive || strings.Contains(rawPlatform, "archive") {
			continue
		}
		// Отсекаем search-URL, корневые страницы, сторонние трекеры и ссылки
		// без самого handle — это основной источник «мусорных» совпадений.
		provider := kind == "provider"
		providerName := str(payload["provider_name"])
		if !provider && !isValidProfileURL(platform, handle, link) {
			continue
		}
		platform = canonicalPlatformForURL(link, platform)

		// Utility-сервисы не являются отдельными соцсетями:
		// mcuuid/playerdb — provider-доказательство Minecraft,
		// gdbrowser — provider Geometry Dash.
		host := hostOfURL(link)
		switch {
		case rawPlatform == "mcuuid" || rawPlatform == "playerdb" || host == "mcuuid.net" || host == "playerdb.co":
			platform = "minecraft"
			if providerName == "" {
				providerName = firstNonEmptyString(rawPlatform, host)
			}
		case rawPlatform == "gdbrowser" || host == "gdbrowser.com":
			platform = "geometrydash"
			if providerName == "" {
				providerName = "gdbrowser"
			}
		}

		// "verified" из коллектора — это лишь evidence, а не доказательство
		// существования: такие аккаунты всё равно проходят HTTP-проверку.
		collectorVerified := boolVal(payload["verified"])
		verification := VerificationNone
		existence := ExistenceUnknown
		if provider {
			// Microsoft/PGP подтверждают аккаунт своим API; HTTP не нужен.
			verification = VerificationCollector
			existence = ExistenceConfirmed
		} else if collectorVerified {
			verification = VerificationCollector
		}
		key := platform + "|" + strings.ToLower(handle)
		acc, ok := byKey[key]
		if !ok {
			acc = &Account{
				ID:                 "account:" + platform + ":" + strings.ToLower(handle),
				Platform:           platform,
				Handle:             handle,
				URL:                link,
				Confidence:         obs.Confidence,
				Verification:       verification,
				VerificationSource: verificationSource(verification, obs.Source),
				Existence:          existence,
				Provider:           provider,
				ProviderName:       providerName,
				Sensitive:          isSensitivePlatform(platform),
				URLValid:           true,
				URLKind:            classifyURLKind(link),
			}
			if link != "" {
				acc.EvidenceURLs = []string{link}
			}
			byKey[key] = acc
		}
		if !contains(acc.Sources, obs.Source) {
			acc.Sources = append(acc.Sources, obs.Source)
		}
		if confidenceRank(obs.Confidence) > confidenceRank(acc.Confidence) {
			acc.Confidence = obs.Confidence
		}
		acc.Sensitive = acc.Sensitive || isSensitivePlatform(platform)
		acc.Provider = acc.Provider || provider
		if providerName != "" && (acc.ProviderName == "" || providerName < acc.ProviderName) {
			acc.ProviderName = providerName
		}
		if provider {
			acc.Existence = ExistenceConfirmed
		}
		// Сильнейшее доказательство побеждает: http > collector > none.
		if verificationRank(verification) > verificationRank(acc.Verification) {
			acc.Verification = verification
			acc.VerificationSource = verificationSource(verification, obs.Source)
		} else if verification == acc.Verification && verificationSource(verification, obs.Source) != "" {
			// Источник выбираем детерминированно, а не по порядку горутин.
			if src := verificationSource(verification, obs.Source); acc.VerificationSource == "" || src < acc.VerificationSource {
				acc.VerificationSource = src
			}
		}
		if link != "" {
			// API-ссылка остаётся в evidence, но canonical выбирается
			// по рангу: профиль важнее API/галереи.
			if !contains(acc.EvidenceURLs, link) {
				acc.EvidenceURLs = append(acc.EvidenceURLs, link)
			}
			acc.URL = preferURL(acc.URL, link, handle)
		}
		if marker := str(payload["page_marker"]); marker != "" &&
			(acc.PageMarker == "" || marker < acc.PageMarker) {
			acc.PageMarker = marker
		}
		if negative := str(payload["page_negative"]); negative != "" &&
			(acc.PageNegative == "" || negative < acc.PageNegative) {
			acc.PageNegative = negative
		}
		if variant := str(payload["variant_of"]); variant != "" && acc.VariantOf == "" {
			acc.VariantOf = variant
		}
		if acc.Name == "" || betterName(acc.Name, cleanText(str(payload["name"]))) {
			acc.Name = cleanText(str(payload["name"]))
		}
		// Платформенные клише ("best place for...") не описывают человека
		// и не должны участвовать в matching/Actor.
		if bio := cleanText(str(payload["bio"])); len(bio) > len(acc.Bio) && !isGenericBio(bio) {
			acc.Bio = bio
		}
		if avatar := str(payload["avatar"]); avatar != "" && (acc.Avatar == "" || provider || collectorVerified) {
			acc.Avatar = avatar
		}
		if links, ok := payload["links"].([]any); ok {
			raw := make([]string, 0, len(links))
			for _, link := range links {
				if s := str(link); s != "" {
					raw = append(raw, s)
				}
			}
			// Персональные ссылки: без CDN/навигации/своего домена,
			// дедуп и максимум пять — иначе shared_link ложно срабатывает.
			for _, s := range filteredPersonalLinks(append(acc.Links, raw...), acc.Platform) {
				if !contains(acc.Links, s) {
					acc.Links = append(acc.Links, s)
				}
			}
		}
	}

	accounts := make([]Account, 0, len(byKey))
	for _, acc := range byKey {
		sort.Strings(acc.Sources)
		// Minecraft: canonical — профильная страница, API/utility остаются evidence.
		if acc.Platform == "minecraft" {
			canonical := "https://namemc.com/profile/" + url.PathEscape(acc.Handle)
			if !contains(acc.EvidenceURLs, canonical) {
				acc.EvidenceURLs = append(acc.EvidenceURLs, canonical)
			}
			acc.URL = canonical
		}
		acc.URLKind = classifyURLKind(acc.URL)
		sort.Slice(acc.EvidenceURLs, func(i, j int) bool {
			ri, rj := canonicalURLRank(acc.EvidenceURLs[i], acc.Handle), canonicalURLRank(acc.EvidenceURLs[j], acc.Handle)
			if ri != rj {
				return ri > rj
			}
			return acc.EvidenceURLs[i] < acc.EvidenceURLs[j]
		})
		acc.MultiSource = len(acc.Sources) > 1
		acc.Sensitive = acc.Sensitive || isSensitivePlatform(acc.Platform)
		acc.Score = computeAccountScore(*acc)
		// Tier выводится из доказательств, а не из уверенности источника:
		// high требует confirmed + provider/multi-source; blocked/unknown — low.
		acc.Confidence = evidenceTier(*acc)
		acc.Verified = acc.Existence == ExistenceConfirmed
		// Оставляем всё, что прошло URL-фильтр: blocked/unknown должны быть
		// видны в отчёте как негативные факты, а не исчезать.
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
		"chess":           "chess.com",
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

// Веса score-модели (сумма ограничена 40):
//
//	API/verified: profile, githubuser, gitlab, keybase, microsoft, pgp, gravatar — 12
//	CLI-поиск:    maigret — 8, sherlock/blackbird — 6
//	эвристики:    whatsmyname, holehe, breach-источники — 4
//	телефон:      phone/phoneinfoga — 6
//
// Далее: +25 confirmed, -25 blocked, -10 unknown, +5 reachable,
// +5 handle в URL, +4 за каждое непустое поле профиля (name/bio/avatar/links),
// +30 provider, +match_score/10. Итог ограничен 0..100.
func sourceWeight(source string) int {
	switch source {
	case "profile", "githubuser", "gitlab", "keybase", "microsoft", "pgp", "gravatar", "registry":
		return 12
	case "subdomain_patterns":
		return 10
	case "variants":
		return 4
	case "maigret":
		return 8
	case "sherlock", "blackbird":
		return 6
	case "phone", "phoneinfoga":
		return 6
	case "whatsmyname", "holehe", "xposedornot", "hudsonrock", "ghunt":
		return 4
	case "disify":
		return 3
	default:
		return 5
	}
}

func computeAccountScore(acc Account) int {
	score := 5
	weight := 0
	for _, source := range acc.Sources {
		weight += sourceWeight(source)
	}
	if weight > 40 {
		weight = 40
	}
	score += weight

	switch acc.Existence {
	case ExistenceConfirmed:
		score += 25
	case ExistenceBlocked:
		score -= 25
	case ExistenceUnknown:
		score -= 10
	}
	if acc.URLReachable {
		score += 5
	}
	if acc.URL != "" {
		if strings.Contains(strings.ToLower(acc.URL), strings.ToLower(acc.Handle)) {
			score += 5
		} else {
			score -= 5
		}
	}
	if acc.Name != "" {
		score += 4
	}
	if acc.Bio != "" {
		score += 4
	}
	if acc.Avatar != "" {
		score += 4
	}
	switch {
	case len(acc.Links) >= 2:
		score += 8
	case len(acc.Links) == 1:
		score += 4
	}
	if acc.Provider {
		score += 30
	}
	if acc.MatchScore > 0 {
		score += acc.MatchScore / 10
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}

// refreshAccountEvidence пересчитывает score/tier после изменения полей
// (semantic match, enrichment) — формула всегда одна и та же.
func refreshAccountEvidence(accounts []Account) {
	for i := range accounts {
		accounts[i].Score = computeAccountScore(accounts[i])
		accounts[i].Confidence = evidenceTier(accounts[i])
		accounts[i].Verified = accounts[i].Existence == ExistenceConfirmed
	}
}

// evidenceTier — уверенность, которую можно защитить перед клиентом.
func evidenceTier(acc Account) scanner.ConfidenceTier {
	if acc.Existence != ExistenceConfirmed {
		return scanner.ConfidenceLow
	}
	if acc.Provider || acc.MultiSource {
		return scanner.ConfidenceHigh
	}
	return scanner.ConfidenceMedium
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
// BuildActor описывает кластер подтверждённых аккаунтов одного хэндла.
// Это не «человек»: high выдаётся только при 2+ независимых кросс-сигналах
// (имя, аватар, общая ссылка), а sensitive-аккаунты не влияют на tier.
func BuildActor(target string, accounts []Account) *Actor {
	if len(accounts) == 0 {
		return nil
	}

	confirmed := make([]Account, 0, len(accounts))
	sensitiveIDs := make([]string, 0)
	for _, acc := range accounts {
		if acc.Sensitive {
			sensitiveIDs = append(sensitiveIDs, acc.ID)
			continue
		}
		if acc.Existence == ExistenceConfirmed {
			confirmed = append(confirmed, acc)
		}
	}
	sort.Strings(sensitiveIDs)

	label := actorLabel(target)
	named := false
	ids := make([]string, 0, len(confirmed))
	for _, acc := range confirmed {
		ids = append(ids, acc.ID)
		// Имя берём, только если оно похоже на человеческое: 2–4 токена,
		// не равно платформе и не является generic-фразой.
		if !named && plausibleActorName(acc.Name, acc.Platform, acc.Handle) {
			label = strings.TrimSpace(acc.Name)
			named = true
		}
	}
	sort.Strings(ids)

	signals := actorSignals(confirmed, target)
	confidence := scanner.ConfidenceLow
	if len(confirmed) > 0 {
		confidence = scanner.ConfidenceMedium
	}
	if len(confirmed) >= 2 && len(signals) >= 2 {
		confidence = scanner.ConfidenceHigh
	}

	return &Actor{
		ID:                actorID(target),
		Label:             label,
		Confidence:        confidence,
		Accounts:          ids,
		Signals:           signals,
		SensitiveAccounts: sensitiveIDs,
	}
}

func actorLabel(target string) string {
	if _, handle, ok := ParseProfileURL(target); ok {
		return handle
	}
	value := strings.TrimSpace(target)
	if i := strings.IndexByte(value, '@'); i > 0 {
		return value[:i]
	}
	return value
}

var actorIDRe = regexp.MustCompile(`[^a-z0-9._@+-]+`)

// actorID нормализует сырой ввод: profile_url → handle, email → адрес,
// real_name → slug. Сырой URL в id больше не попадает.
func actorID(target string) string {
	if _, handle, ok := ParseProfileURL(target); ok {
		return "actor:" + strings.ToLower(handle)
	}
	value := strings.ToLower(strings.TrimSpace(target))
	if strings.Contains(value, "@") {
		return "actor:" + value
	}
	value = strings.Trim(actorIDRe.ReplaceAllString(value, "-"), "-")
	if value == "" {
		value = "unknown"
	}
	return "actor:" + value
}

func actorSignals(accounts []Account, target string) []string {
	set := map[string]struct{}{}
	names := map[string]int{}
	avatars := map[string]int{}
	links := map[string]int{}

	for _, acc := range accounts {
		name := normalizeSignalName(acc.Name)
		if name != "" && name != normalizeSignalName(acc.Handle) && !isGenericPhrase(name) {
			names[name]++
		}
		avatar := ""
		if acc.AvatarHash != "" {
			avatar = "hash:" + acc.AvatarHash
		} else if !isDefaultAvatar(acc.Avatar) {
			avatar = normalizeSignalAvatar(acc.Avatar)
		}
		if avatar != "" {
			avatars[avatar]++
		}
		// Ссылка должна встречаться у ≥2 РАЗНЫХ аккаунтов. Дубль внутри
		// одного профиля не является доказательством связи.
		perAccount := map[string]struct{}{}
		for _, link := range filteredPersonalLinks(acc.Links, acc.Platform) {
			if key := normalizeSignalLink(link); key != "" {
				perAccount[key] = struct{}{}
			}
		}
		for key := range perAccount {
			links[key]++
		}
	}
	addRepeated := func(signal string, values map[string]int) {
		for _, count := range values {
			if count >= 2 {
				set[signal] = struct{}{}
				return
			}
		}
	}
	addRepeated("same_name", names)
	addRepeated("same_avatar", avatars)
	addRepeated("shared_link", links)

	if _, _, ok := ParseProfileURL(target); ok {
		for _, acc := range accounts {
			if acc.MatchScore >= 50 {
				set["profile_match"] = struct{}{}
				break
			}
		}
	}

	out := make([]string, 0, len(set))
	for signal := range set {
		out = append(out, signal)
	}
	sort.Strings(out)
	return out
}

func normalizeSignalName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	space := false
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			if space && b.Len() > 0 {
				b.WriteByte(' ')
			}
			b.WriteRune(r)
			space = false
		} else {
			space = true
		}
	}
	return strings.TrimSpace(b.String())
}

func normalizeSignalAvatar(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	if u, err := url.Parse(value); err == nil && u.Hostname() != "" {
		return u.Scheme + "://" + strings.TrimPrefix(u.Hostname(), "www.") + strings.TrimSuffix(u.Path, "/")
	}
	return strings.TrimSuffix(value, "/")
}

func normalizeSignalLink(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	if u, err := url.Parse(value); err == nil && u.Hostname() != "" {
		return strings.TrimPrefix(u.Hostname(), "www.") + strings.TrimSuffix(u.Path, "/")
	}
	return strings.TrimSuffix(value, "/")
}

// verificationRank задаёт приоритет доказательства при merge.
func verificationRank(v VerificationState) int {
	switch v {
	case VerificationHTTP:
		return 2
	case VerificationCollector:
		return 1
	default:
		return 0
	}
}

func verificationSource(v VerificationState, source string) string {
	if v == VerificationNone {
		return ""
	}
	return source
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
