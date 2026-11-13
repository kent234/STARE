package people

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"stare/server/scanner"
)

func lookBinary(envKey string, names ...string) (string, bool) {
	if bin := os.Getenv(envKey); bin != "" {
		if path, err := exec.LookPath(bin); err == nil {
			return path, true
		}
	}
	for _, name := range names {
		if path, err := exec.LookPath(name); err == nil {
			return path, true
		}
	}
	return "", false
}

func runBinary(ctx context.Context, bin string, args ...string) string {
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		// Некоторые версии CLI не понимают флаги — пробуем минимальный запуск.
		fallback := exec.CommandContext(ctx, bin, args[0])
		out, _ = fallback.CombinedOutput()
	}
	return string(out)
}

var foundLineRe = regexp.MustCompile(`(?m)^\[\+\]\s*([^:\n]+):\s*(https?://\S+)`)
var foundURLRe = regexp.MustCompile(`(?m)^\[\+\]\s*(https?://\S+)`)
var holeheLineRe = regexp.MustCompile(`(?m)^\[\+\]\s*([a-z0-9][a-z0-9.-]+\.[a-z]{2,})\s*$`)

func parseFoundLines(source, output, handle string) []scanner.Observation {
	var obs []scanner.Observation
	seen := map[string]struct{}{}

	add := func(platform, link string) {
		platform = strings.ToLower(strings.TrimSpace(platform))
		link = strings.TrimSpace(link)
		if platform == "" || link == "" {
			return
		}
		key := platform + "|" + link
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		obs = append(obs, Observation(source, scanner.ConfidenceMedium, map[string]any{
			"platform": platform,
			"handle":   handle,
			"url":      link,
		}))
	}

	for _, m := range foundLineRe.FindAllStringSubmatch(output, -1) {
		add(m[1], m[2])
	}
	for _, m := range foundURLRe.FindAllStringSubmatch(output, -1) {
		u, err := url.Parse(m[1])
		if err != nil {
			continue
		}
		add(u.Hostname(), m[1])
	}
	return obs
}

func parseHolehe(output, email string) []scanner.Observation {
	var obs []scanner.Observation
	seen := map[string]struct{}{}
	for _, m := range holeheLineRe.FindAllStringSubmatch(output, -1) {
		platform := canonicalPlatform(strings.TrimSpace(m[1]))
		if platform == "" {
			continue
		}
		if _, ok := seen[platform]; ok {
			continue
		}
		seen[platform] = struct{}{}
		obs = append(obs, Observation("holehe", scanner.ConfidenceLow, map[string]any{
			"kind":     "registration",
			"platform": platform,
			"email":    email,
		}))
	}
	return obs
}

// ---------- Sherlock ----------

type SherlockCollector struct{}

func (c *SherlockCollector) Name() string { return "sherlock" }

func (c *SherlockCollector) Collect(ctx context.Context, target string) ([]scanner.Observation, error) {
	bin, ok := lookBinary("SHERLOCK_BIN", "sherlock")
	if !ok {
		return nil, nil
	}
	out := runBinary(ctx, bin, target, "--print-found", "--no-color")
	return parseFoundLines("sherlock", out, target), nil
}

// ---------- Maigret ----------

type MaigretCollector struct{}

func (c *MaigretCollector) Name() string { return "maigret" }

func (c *MaigretCollector) Collect(ctx context.Context, target string) ([]scanner.Observation, error) {
	bin, ok := lookBinary("MAIGRET_BIN", "maigret")
	if !ok {
		return nil, nil
	}
	obs := runMaigretJSON(ctx, bin, target)
	if len(obs) == 0 {
		out := runBinary(ctx, bin, target, "--no-color", "--timeout", "10")
		obs = parseFoundLines("maigret", out, target)
	}
	return obs, nil
}

// runMaigretJSON запускает Maigret с JSON-отчётом и читает report_<user>_simple.json.
func runMaigretJSON(ctx context.Context, bin, target string) []scanner.Observation {
	dir, err := os.MkdirTemp("", "stare-maigret-")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(dir)

	maxSites := os.Getenv("MAIGRET_MAX_SITES")
	if maxSites == "" {
		maxSites = "1000"
	}
	cmd := exec.CommandContext(ctx, bin, target, "--no-color", "--timeout", "10",
		"--json", "simple", "--top-sites", maxSites)
	cmd.Dir = dir
	_, _ = cmd.CombinedOutput()

	report := filepath.Join(dir, "reports", "report_"+sanitizeFile(target)+"_simple.json")
	data, err := os.ReadFile(report)
	if err != nil {
		return nil
	}
	var raw map[string]struct {
		HTTPStatus int `json:"http_status"`
		Status     struct {
			SiteName string `json:"site_name"`
			URL      string `json:"url"`
			Status   string `json:"status"`
		} `json:"status"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}

	var obs []scanner.Observation
	for site, entry := range raw {
		if !strings.EqualFold(entry.Status.Status, "Claimed") {
			continue
		}
		if entry.HTTPStatus != 0 && entry.HTTPStatus != http.StatusOK {
			continue
		}
		platform := entry.Status.SiteName
		if platform == "" {
			platform = site
		}
		obs = append(obs, Observation("maigret", scanner.ConfidenceHigh, map[string]any{
			"platform": platform,
			"handle":   target,
			"url":      entry.Status.URL,
		}))
	}
	return obs
}

func sanitizeFile(value string) string {
	return strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_").Replace(value)
}

// ---------- Holehe ----------

type HoleheCollector struct{}

func (c *HoleheCollector) Name() string { return "holehe" }

func (c *HoleheCollector) Collect(ctx context.Context, target string) ([]scanner.Observation, error) {
	bin, ok := lookBinary("HOLEHE_BIN", "holehe")
	if !ok {
		return nil, nil
	}
	out := runBinary(ctx, bin, target, "--only-used", "--no-color")
	obs := parseHolehe(out, target)
	// Holehe сообщает только факт регистрации, а не профиль.
	for i := range obs {
		obs[i].Confidence = scanner.ConfidenceLow
	}
	return obs, nil
}

// ---------- CyberFind (optional) ----------

type CyberFindCollector struct{}

func (c *CyberFindCollector) Name() string { return "cyberfind" }

func (c *CyberFindCollector) Collect(ctx context.Context, target string) ([]scanner.Observation, error) {
	bin, ok := lookBinary("CYBERFIND_BIN", "cyberfind")
	if !ok {
		return nil, nil
	}
	out := runBinary(ctx, bin, target, "--json")
	var rows []struct {
		Platform string `json:"platform"`
		Handle   string `json:"handle"`
		URL      string `json:"url"`
	}
	if err := json.Unmarshal([]byte(out), &rows); err == nil && len(rows) > 0 {
		obs := make([]scanner.Observation, 0, len(rows))
		for _, row := range rows {
			if row.Platform == "" || row.URL == "" {
				continue
			}
			obs = append(obs, Observation("cyberfind", scanner.ConfidenceMedium, map[string]any{
				"platform": row.Platform,
				"handle":   row.Handle,
				"url":      row.URL,
			}))
		}
		return obs, nil
	}
	return parseFoundLines("cyberfind", out, target), nil
}

// ---------- Phone ----------

type PhoneCollector struct{}

func (c *PhoneCollector) Name() string { return "phone" }

var phoneCountries = map[string]string{
	"1": "US", "7": "RU", "20": "EG", "33": "FR", "34": "ES", "39": "IT",
	"44": "GB", "49": "DE", "52": "MX", "55": "BR", "61": "AU", "81": "JP",
	"86": "CN", "90": "TR", "91": "IN", "380": "UA", "375": "BY", "998": "UZ",
}

func (c *PhoneCollector) Collect(_ context.Context, target string) ([]scanner.Observation, error) {
	digits := onlyDigits(target)
	if digits == "" {
		return nil, nil
	}
	code := ""
	for _, size := range []int{3, 2, 1} {
		if len(digits) > size {
			if _, ok := phoneCountries[digits[:size]]; ok {
				code = digits[:size]
				break
			}
		}
	}
	country := phoneCountries[code]
	e164 := ""
	if strings.HasPrefix(strings.TrimSpace(target), "+") {
		e164 = "+" + digits
	}
	obs := Observation("phone", scanner.ConfidenceMedium, map[string]any{
		"kind":         "phone",
		"indicator":    target,
		"e164":         e164,
		"country":      country,
		"country_code": code,
		"valid":        len(digits) >= 7 && len(digits) <= 15,
	})
	return []scanner.Observation{obs}, nil
}

func onlyDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
