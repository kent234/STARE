package people

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"stare/server/scanner"
)

// ---------- Blackbird ----------

type BlackbirdCollector struct{}

func (c *BlackbirdCollector) Name() string { return "blackbird" }

func (c *BlackbirdCollector) Collect(ctx context.Context, target string) ([]scanner.Observation, error) {
	bin, ok := lookBinary("BLACKBIRD_BIN", "blackbird", "blackbird.py")
	if !ok {
		return nil, nil
	}
	isEmail := strings.Contains(target, "@")
	out := runBlackbirdJSON(ctx, bin, target, isEmail)
	conf := scanner.ConfidenceMedium
	obs := parseJSONAccounts(out, "blackbird", target, conf)
	if len(obs) == 0 {
		obs = parseFoundLines("blackbird", out, target)
	}
	return obs, nil
}

// runBlackbirdJSON запускает Blackbird в его каталоге (нужен data/wmn-data.json)
// и читает свежий JSON-отчёт, который CLI пишет в файл.
func runBlackbirdJSON(ctx context.Context, bin, target string, email bool) string {
	dir := os.Getenv("BLACKBIRD_DIR")
	if dir == "" {
		dir, _ = os.Getwd()
	}
	start := time.Now()
	args := []string{"--json", "--timeout", "10"}
	if email {
		args = append([]string{"-e", target}, args...)
	} else {
		args = append([]string{"-u", target}, args...)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	out, _ := cmd.CombinedOutput()

	root := filepath.Join(dir, "results")
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		root = dir
	}
	best := ""
	var bestTime time.Time
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".json") {
			return nil
		}
		if info.ModTime().Before(start.Add(-2 * time.Second)) {
			return nil
		}
		if best == "" || info.ModTime().After(bestTime) {
			best = path
			bestTime = info.ModTime()
		}
		return nil
	})
	if best != "" {
		if data, err := os.ReadFile(best); err == nil {
			return string(data)
		}
	}
	return string(out)
}

// ---------- GHunt ----------

type GHuntCollector struct{}

func (c *GHuntCollector) Name() string { return "ghunt" }

func (c *GHuntCollector) Collect(ctx context.Context, target string) ([]scanner.Observation, error) {
	bin, ok := lookBinary("GHUNT_BIN", "ghunt")
	if !ok {
		return nil, nil
	}
	out := runGHuntJSON(ctx, bin, target)
	return parseGHunt(out, target), nil
}

func parseGHunt(raw, email string) []scanner.Observation {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, "{") {
		return nil
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return nil
	}
	name := firstString(data, "name", "display_name")
	avatar := firstString(data, "profile_picture", "avatar", "photo")
	if name == "" && avatar == "" {
		return nil
	}
	return []scanner.Observation{Observation("ghunt", scanner.ConfidenceHigh, map[string]any{
		"platform": "google",
		"handle":   email,
		"url":      "https://accounts.google.com",
		"name":     name,
		"avatar":   avatar,
		"verified": true,
	})}
}

// GHunt пишет JSON в файл (--json <path>), а не в stdout.
func runGHuntJSON(ctx context.Context, bin, target string) string {
	dir, err := os.MkdirTemp("", "stare-ghunt-")
	if err != nil {
		return ""
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, "ghunt.json")
	cmd := exec.CommandContext(ctx, bin, "email", target, "--json", file)
	cmd.Dir = dir
	_, _ = cmd.CombinedOutput()
	if data, err := os.ReadFile(file); err == nil {
		return string(data)
	}
	return ""
}

// ---------- PhoneInfoga ----------

type PhoneInfogaCollector struct{}

func (c *PhoneInfogaCollector) Name() string { return "phoneinfoga" }

func (c *PhoneInfogaCollector) Collect(ctx context.Context, target string) ([]scanner.Observation, error) {
	bin, ok := lookBinary("PHONEINFOGA_BIN", "phoneinfoga")
	if !ok {
		return nil, nil
	}
	out := runBinary(ctx, bin, "scan", "-n", target)
	payload := map[string]any{
		"kind":      "phone",
		"indicator": target,
		"valid":     true,
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "country:"):
			payload["country"] = strings.TrimSpace(line[len("country:"):])
		case strings.HasPrefix(lower, "carrier:"):
			payload["carrier"] = strings.TrimSpace(line[len("carrier:"):])
		case strings.HasPrefix(lower, "e164:"):
			payload["e164"] = strings.TrimSpace(line[len("e164:"):])
		case strings.HasPrefix(lower, "international:"):
			v := strings.TrimSpace(line[len("international:"):])
			if v != "" && !strings.HasPrefix(v, "+") {
				v = "+" + v
			}
			payload["e164"] = v
		}
	}
	if _, ok := payload["carrier"]; !ok {
		if c := phoneCarrier(ctx, target); c != "" {
			payload["carrier"] = c
		}
	}
	return []scanner.Observation{Observation("phoneinfoga", scanner.ConfidenceMedium, payload)}, nil
}

// phoneCarrier — бесплатный offline-поиск оператора через python-phonenumbers.
func phoneCarrier(ctx context.Context, target string) string {
	script := `import sys, phonenumbers
from phonenumbers import carrier
try:
    n = phonenumbers.parse(sys.argv[1], None)
    print(carrier.name_for_number(n, "en") or "")
except Exception:
    print("")`
	candidates := []string{os.Getenv("PHONENUMBERS_PYTHON"), "/opt/osint/bin/python", "python3"}
	for _, python := range candidates {
		if python == "" {
			continue
		}
		if _, err := exec.LookPath(python); err != nil {
			continue
		}
		out, err := exec.CommandContext(ctx, python, "-c", script, target).Output()
		if err == nil {
			if name := strings.TrimSpace(string(out)); name != "" {
				return name
			}
		}
	}
	return ""
}

// ---------- WhatsMyName ----------

type WhatsMyNameCollector struct{}

func (c *WhatsMyNameCollector) Name() string { return "whatsmyname" }

type wmnSite struct {
	Name    string `json:"name"`
	URI     string `json:"uri_check"`
	EString string `json:"e_string"`
	MString string `json:"m_string"`
}

type wmnData struct {
	Sites []wmnSite `json:"sites"`
}

func (c *WhatsMyNameCollector) Collect(ctx context.Context, target string) ([]scanner.Observation, error) {
	data, err := fetchWMNData(ctx)
	if err != nil || len(data.Sites) == 0 {
		return nil, err
	}
	handle := target
	if i := strings.IndexByte(target, '@'); i > 0 {
		handle = target[:i]
	}
	max := 200
	if v := os.Getenv("WMN_MAX_SITES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			max = n
		}
	}
	if len(data.Sites) > max {
		data.Sites = data.Sites[:max]
	}

	client := &http.Client{Timeout: 8 * time.Second}
	sem := make(chan struct{}, 20)
	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		obs []scanner.Observation
	)
	for _, site := range data.Sites {
		site := site
		if !strings.Contains(site.URI, "{account}") {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			link := strings.ReplaceAll(site.URI, "{account}", url.PathEscape(handle))
			if !wmnProfileExists(ctx, client, link, site.EString, site.MString) {
				return
			}
			mu.Lock()
			obs = append(obs, Observation("whatsmyname", scanner.ConfidenceLow, map[string]any{
				"platform": strings.ToLower(site.Name),
				"handle":   handle,
				"url":      link,
				"verified": true,
			}))
			mu.Unlock()
		}()
	}
	wg.Wait()
	return obs, nil
}

func fetchWMNData(ctx context.Context) (wmnData, error) {
	endpoint := os.Getenv("WMN_URL")
	if endpoint == "" {
		endpoint = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return wmnData{}, err
	}
	req.Header.Set("User-Agent", "Stare/1.0 (+osint)")
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return wmnData{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return wmnData{}, fmt.Errorf("whatsmyname status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return wmnData{}, err
	}
	var data wmnData
	if err := json.Unmarshal(body, &data); err != nil {
		return wmnData{}, err
	}
	return data, nil
}

func wmnProfileExists(ctx context.Context, client *http.Client, link, eString, mString string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false
	}
	if eString != "" && !bytes.Contains(body, []byte(eString)) {
		return false
	}
	if mString != "" && bytes.Contains(body, []byte(mString)) {
		return false
	}
	return true
}

// parseJSONAccounts разбирает распространённые JSON-форматы CLI (массив или object).
func parseJSONAccounts(raw, source, fallbackHandle string, confidence scanner.ConfidenceTier) []scanner.Observation {
	raw = strings.TrimSpace(raw)
	if raw == "" || (!strings.HasPrefix(raw, "[") && !strings.HasPrefix(raw, "{")) {
		return nil
	}

	var rows []map[string]any
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		rows = rowsFromJSON([]byte(raw))
	}

	var obs []scanner.Observation
	for _, row := range rows {
		if status := firstString(row, "status"); status != "" {
			switch strings.ToLower(status) {
			case "found", "claimed", "active", "true":
			default:
				continue
			}
		}
		platform := firstString(row, "platform", "site", "name")
		handle := firstString(row, "handle", "username", "user")
		link := firstString(row, "url", "profile", "profile_url")
		if platform == "" && link == "" {
			continue
		}
		if platform == "" {
			if u, err := url.Parse(link); err == nil {
				platform = u.Hostname()
			}
		}
		if handle == "" {
			handle = fallbackHandle
		}
		obs = append(obs, Observation(source, confidence, map[string]any{
			"platform": platform,
			"handle":   handle,
			"url":      link,
		}))
	}
	return obs
}

func rowsFromJSON(raw []byte) []map[string]any {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil
	}
	for _, key := range []string{"results", "sites", "accounts", "data"} {
		if v, ok := obj[key]; ok {
			if rows := rowsFromAny(v); len(rows) > 0 {
				return rows
			}
		}
	}
	if rows := rowsFromAny(obj); len(rows) > 0 {
		return rows
	}
	return []map[string]any{obj}
}

func rowsFromAny(value any) []map[string]any {
	switch typed := value.(type) {
	case []any:
		rows := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			if row, ok := item.(map[string]any); ok {
				rows = append(rows, row)
			}
		}
		return rows
	case map[string]any:
		rows := make([]map[string]any, 0, len(typed))
		for key, item := range typed {
			row, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if _, exists := row["platform"]; !exists {
				row["platform"] = key
			}
			rows = append(rows, row)
		}
		return rows
	default:
		return nil
	}
}

func firstString(row map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := row[key]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}
