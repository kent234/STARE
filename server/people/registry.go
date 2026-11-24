package people

import (
	"context"
	_ "embed"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"stare/server/scanner"
)

//go:embed data/platforms.json
var platformsJSON []byte

type platformDef struct {
	Name         string `json:"name"`
	Display      string `json:"display"`
	URL          string `json:"url"`
	Method       string `json:"method"`
	Body         string `json:"body"`
	Detector     string `json:"detector"` // status|json_path|body_contains|body_absent
	Path         string `json:"path"`
	Contains     string `json:"contains"`
	Confidence   string `json:"confidence"`
	Weight       int    `json:"weight"`
	Sensitive    bool   `json:"sensitive"`
	RequiresAuth bool   `json:"requires_auth"`
}

var (
	platformsOnce sync.Once
	platforms     []platformDef
)

func loadPlatforms() []platformDef {
	platformsOnce.Do(func() {
		var payload struct {
			Platforms []platformDef `json:"platforms"`
		}
		if err := json.Unmarshal(platformsJSON, &payload); err == nil {
			platforms = payload.Platforms
		}
	})
	return platforms
}

// RegistryCollector — декларативные API-детекторы без API-ключей.
// JSON-ответы надёжнее HTML: 404/JSON не даёт soft-404.
type RegistryCollector struct{}

func (c *RegistryCollector) Name() string { return "registry" }

func (c *RegistryCollector) Collect(ctx context.Context, target string) ([]scanner.Observation, error) {
	handle := registryHandle(target)
	if handle == "" {
		return nil, nil
	}
	return collectRegistry(ctx, handle, "registry", ""), nil
}

// VariantCollector проверяет производные написания ника только по registry:
// полный Maigret/Sherlock для каждого варианта был бы слишком дорогим.
type VariantCollector struct{}

func (c *VariantCollector) Name() string { return "variants" }

func (c *VariantCollector) Collect(ctx context.Context, target string) ([]scanner.Observation, error) {
	handle := registryHandle(target)
	if handle == "" {
		return nil, nil
	}
	base := strings.ToLower(handle)
	var out []scanner.Observation
	for _, variant := range expandVariants(base) {
		out = append(out, collectRegistry(ctx, variant, "variants", base)...)
	}
	return out, nil
}

// SubdomainPatternCollector проверяет {handle}.github.io и похожие бесплатные
// хостинги: дешёвый источник личных сайтов, которых нет в датасетах.
type SubdomainPatternCollector struct{}

func (c *SubdomainPatternCollector) Name() string { return "subdomain_patterns" }

var subdomainSuffixes = []string{
	"github.io", "gitlab.io", "wordpress.com", "blogspot.com", "tumblr.com",
	"neocities.org", "carrd.co", "linktr.ee", "beacons.ai", "taplink.cc",
	"notion.site", "framer.website", "webflow.io", "wixsite.com", "weebly.com",
	"jimdosite.com", "vercel.app", "netlify.app", "pages.dev", "web.app",
	"glitch.me", "replit.app",
}

var missingSiteMarkers = []string{
	"there isn't a github pages site here",
	"site not found",
	"page not found",
	"project not found",
	"repository not found",
	"this site is not available",
	"no such app",
	"doesn't exist",
	"does not exist",
	"domain is available",
}

func (c *SubdomainPatternCollector) Collect(ctx context.Context, target string) ([]scanner.Observation, error) {
	original := registryHandle(target)
	if original == "" {
		return nil, nil
	}
	handle := sanitizeDNSLabel(original)
	if handle == "" {
		return nil, nil
	}

	client := &http.Client{Timeout: 8 * time.Second}
	sem := make(chan struct{}, 10)
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		obs []scanner.Observation
	)
	for _, suffix := range subdomainSuffixes {
		suffix := suffix
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			link := "https://" + handle + "." + suffix
			status, body, err := fetchRegistryPage(ctx, client, http.MethodGet, link, "")
			if err != nil || status < 200 || status >= 400 {
				return
			}
			lower := strings.ToLower(body)
			for _, marker := range missingSiteMarkers {
				if strings.Contains(lower, marker) {
					return
				}
			}
			payload := map[string]any{
				"platform": suffix,
				"handle":   handle,
				"url":      link,
				"verified": true,
				// Страница уже проверена на 200 + отсутствие missing-маркеров;
				// marker нужен только чтобы повторная верификация не сочла
				// сайт soft-404 из-за ника в поддомене, а не в title.
				"page_marker": "</html>",
			}
			if handle != strings.ToLower(original) {
				payload["variant_of"] = original
			}
			mu.Lock()
			obs = append(obs, Observation("subdomain_patterns", scanner.ConfidenceMedium, payload))
			mu.Unlock()
		}()
	}
	wg.Wait()
	return obs, nil
}

func collectRegistry(ctx context.Context, handle, source, variantOf string) []scanner.Observation {
	defs := loadPlatforms()
	if len(defs) == 0 {
		return nil
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	sem := make(chan struct{}, 10)
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		obs []scanner.Observation
	)
	for _, def := range defs {
		def := def
		if def.RequiresAuth || def.URL == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			link := buildRegistryURL(def.URL, handle)
			body := buildRegistryBody(def.Body, handle)
			status, page, err := fetchRegistryPage(ctx, client, def.Method, link, body)
			if err != nil {
				return
			}
			if !detectRegistry(status, page, def) {
				return
			}
			confidence := registryConfidence(def.Confidence)
			if variantOf != "" {
				confidence = downgradeConfidence(confidence)
			}
			payload := map[string]any{
				"platform":        def.Name,
				"handle":          handle,
				"url":             link,
				"verified":        true,
				"registry_weight": def.Weight,
			}
			// Слабый body_contains (TikTok и т.п.) не должен сам себя
			// «подтверждать» повторной проверкой — marker только для
			// достаточно надёжных страниц.
			if def.Detector == "body_contains" && def.Contains != "" &&
				confidence != scanner.ConfidenceLow {
				payload["page_marker"] = def.Contains
			}
			if variantOf != "" {
				payload["variant_of"] = variantOf
				payload["match_reason"] = "variant of " + variantOf
			}
			mu.Lock()
			obs = append(obs, Observation(source, confidence, payload))
			mu.Unlock()
		}()
	}
	wg.Wait()
	return obs
}

func fetchRegistryPage(ctx context.Context, client *http.Client, method, link, body string) (int, string, error) {
	if method == "" {
		method = http.MethodGet
	}
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, link, reader)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/html;q=0.9, */*;q=0.8")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	return resp.StatusCode, string(data), nil
}

func detectRegistry(status int, body string, def platformDef) bool {
	if status < 200 || status >= 400 {
		return false
	}
	switch def.Detector {
	case "status":
		return true
	case "json_path":
		var payload any
		if json.Unmarshal([]byte(body), &payload) != nil {
			return false
		}
		return lookupJSONPath(payload, def.Path)
	case "body_contains":
		return def.Contains != "" && strings.Contains(strings.ToLower(body), strings.ToLower(def.Contains))
	case "body_absent":
		return def.Contains != "" && !strings.Contains(strings.ToLower(body), strings.ToLower(def.Contains))
	default:
		return false
	}
}

func lookupJSONPath(payload any, path string) bool {
	if path == "" {
		return payload != nil
	}
	current := payload
	for _, part := range strings.Split(path, ".") {
		switch node := current.(type) {
		case map[string]any:
			value, ok := node[part]
			if !ok {
				return false
			}
			current = value
		case []any:
			idx, err := strconv.Atoi(part)
			if err != nil || idx < 0 || idx >= len(node) {
				return false
			}
			current = node[idx]
		default:
			return false
		}
	}
	switch value := current.(type) {
	case nil:
		return false
	case bool:
		return value
	case string:
		return strings.TrimSpace(value) != ""
	case float64:
		return value != 0
	case map[string]any:
		return len(value) > 0
	case []any:
		return len(value) > 0
	default:
		return current != nil
	}
}

func buildRegistryURL(template, handle string) string {
	escaped := url.PathEscape(handle)
	return strings.ReplaceAll(template, "{handle}", escaped)
}

func buildRegistryBody(template, handle string) string {
	if template == "" {
		return ""
	}
	encoded, _ := json.Marshal(handle)
	handleJSON := strings.Trim(string(encoded), `"`)
	return strings.ReplaceAll(template, "{handle}", handleJSON)
}

func registryHandle(target string) string {
	value := strings.TrimSpace(target)
	if _, handle, ok := ParseProfileURL(value); ok {
		value = handle
	}
	value = normalizeHandle(value)
	if value == "" || strings.Contains(value, "@") {
		return ""
	}
	return value
}

func sanitizeDNSLabel(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" || len(out) > 63 {
		return ""
	}
	return out
}

func expandVariants(handle string) []string {
	base := strings.ToLower(strings.TrimSpace(handle))
	if base == "" {
		return nil
	}
	candidates := []string{
		strings.ReplaceAll(base, "-", "_"),
		strings.ReplaceAll(base, "_", "-"),
		strings.NewReplacer("-", "", "_", "", ".", "").Replace(base),
		base + "_",
		base + "_official",
		base + ".official",
	}
	seen := map[string]struct{}{base: struct{}{}}
	out := make([]string, 0, 4)
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || len(candidate) > 64 {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
		if len(out) >= 4 {
			break
		}
	}
	sort.Strings(out)
	return out
}

func registryConfidence(value string) scanner.ConfidenceTier {
	switch strings.ToLower(value) {
	case "high":
		return scanner.ConfidenceHigh
	case "low":
		return scanner.ConfidenceLow
	default:
		return scanner.ConfidenceMedium
	}
}

func downgradeConfidence(value scanner.ConfidenceTier) scanner.ConfidenceTier {
	switch value {
	case scanner.ConfidenceHigh:
		return scanner.ConfidenceMedium
	case scanner.ConfidenceMedium:
		return scanner.ConfidenceLow
	default:
		return scanner.ConfidenceLow
	}
}

func variantsEnabled() bool {
	return os.Getenv("PEOPLE_VARIANTS") != "0"
}

func patternsEnabled() bool {
	return os.Getenv("PEOPLE_PATTERNS") != "0"
}

func registryEnabled() bool {
	return os.Getenv("PEOPLE_REGISTRY") != "0"
}
