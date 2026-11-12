package scanner

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// abuseCHSource — общий HTTP-адаптер для bulk-фидов abuse.ch (без API-ключа).
type abuseCHSource struct {
	name       string
	url        string
	method     string
	body       []byte
	headers    map[string]string
	confidence ConfidenceTier
	parse      func(target string, body []byte) ([]map[string]any, error)
	client     *http.Client
	limiter    *rateLimiter
}

func (s *abuseCHSource) Name() string { return s.name }

func (s *abuseCHSource) Fetch(ctx context.Context, target string) ([]Observation, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if s.limiter != nil {
		if err := s.limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}

	method := s.method
	if method == "" {
		method = http.MethodGet
	}
	var bodyReader io.Reader
	if len(s.body) > 0 {
		bodyReader = bytes.NewReader(s.body)
	}

	req, err := http.NewRequestWithContext(ctx, method, s.url, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Stare/1.0 (+osint)")
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s status: %d", s.name, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}

	hits, err := s.parse(target, body)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	obs := make([]Observation, 0, len(hits))
	for _, h := range hits {
		payload, err := json.Marshal(h)
		if err != nil {
			continue
		}
		obs = append(obs, Observation{
			Source:     s.name,
			FetchedAt:  now,
			Confidence: s.confidence,
			Payload:    payload,
		})
	}
	return obs, nil
}

func init() {
	if os.Getenv("STARE_DISABLE_FEEDS") == "1" {
		return
	}
	// URLhaus и ThreatFox с 2026 требуют бесплатный abuse.ch Auth-Key.
	if os.Getenv("ABUSECH_AUTH_KEY") != "" {
		RegisterSource(NewURLhausSource())
		RegisterSource(NewThreatFoxSource())
	}
	// Feodo Tracker остаётся доступен без ключа.
	RegisterSource(NewFeodoSource())
}

// NewURLhausSource — URLhaus (authenticated CSV export, Auth-Key в пути).
func NewURLhausSource() Source {
	key := os.Getenv("ABUSECH_AUTH_KEY")
	return &abuseCHSource{
		name:       "urlhaus",
		url:        envOr("ABUSECH_URLHAUS_URL", "https://urlhaus-api.abuse.ch/v2/files/exports/"+url.PathEscape(key)+"/recent.csv"),
		confidence: ConfidenceHigh,
		parse:      parseURLhaus,
		client:     &http.Client{Timeout: 30 * time.Second},
		limiter:    newRateLimiter(2 * time.Second),
	}
}

// NewThreatFoxSource — ThreatFox API v1 (Auth-Key в заголовке).
func NewThreatFoxSource() Source {
	return &abuseCHSource{
		name:       "threatfox",
		url:        envOr("ABUSECH_THREATFOX_URL", "https://threatfox-api.abuse.ch/api/v1/"),
		method:     http.MethodPost,
		body:       []byte(`{"query":"get_iocs","days":7}`),
		headers:    map[string]string{"Auth-Key": os.Getenv("ABUSECH_AUTH_KEY"), "Content-Type": "application/json"},
		confidence: ConfidenceMedium,
		parse:      parseThreatFox,
		client:     &http.Client{Timeout: 30 * time.Second},
		limiter:    newRateLimiter(2 * time.Second),
	}
}

// NewFeodoSource — Feodo Tracker (botnet C2 JSON, без ключа).
func NewFeodoSource() Source {
	return &abuseCHSource{
		name:       "feodo",
		url:        envOr("ABUSECH_FEODO_URL", "https://feodotracker.abuse.ch/downloads/ipblocklist.json"),
		confidence: ConfidenceHigh,
		parse:      parseFeodo,
		client:     &http.Client{Timeout: 30 * time.Second},
		limiter:    newRateLimiter(2 * time.Second),
	}
}

// ---------- URLhaus: id,dateadded,url,url_status,last_online,threat,tags,link,reporter ----------

func parseURLhaus(target string, body []byte) ([]map[string]any, error) {
	r := csv.NewReader(bytes.NewReader(body))
	r.Comment = '#'
	r.FieldsPerRecord = -1
	r.LazyQuotes = true

	var out []map[string]any
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(rec) < 6 {
			continue
		}
		rawURL := strings.TrimSpace(rec[2])
		host := hostFromURL(rawURL)
		if !indicatorMatches(target, host) {
			continue
		}
		out = append(out, map[string]any{
			"indicator":   host,
			"url":         rawURL,
			"status":      strings.TrimSpace(rec[3]),
			"threat":      strings.TrimSpace(rec[5]),
			"tags":        splitTags(rec[6]),
			"reported_at": strings.TrimSpace(rec[1]),
		})
	}
	return out, nil
}

func hostFromURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func splitTags(s string) []string {
	parts := strings.Split(strings.TrimSpace(s), ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ---------- ThreatFox ----------

type threatFoxEntry struct {
	IOC              string   `json:"ioc"`
	IOCValue         string   `json:"ioc_value"`
	IOCType          string   `json:"ioc_type"`
	ThreatType       string   `json:"threat_type"`
	Malware          string   `json:"malware"`
	MalwarePrintable string   `json:"malware_printable"`
	ConfidenceLevel  int      `json:"confidence_level"`
	FirstSeen        string   `json:"first_seen"`
	Tags             []string `json:"tags"`
}

func parseThreatFox(target string, body []byte) ([]map[string]any, error) {
	entries, err := decodeThreatFox(body)
	if err != nil {
		return nil, err
	}

	var out []map[string]any
	for _, e := range entries {
		ind := e.IOC
		if ind == "" {
			ind = e.IOCValue
		}
		if !indicatorMatches(target, ind) {
			continue
		}
		out = append(out, map[string]any{
			"indicator":         ind,
			"ioc_type":          e.IOCType,
			"threat_type":       e.ThreatType,
			"malware":           e.Malware,
			"malware_printable": e.MalwarePrintable,
			"confidence_level":  e.ConfidenceLevel,
			"first_seen":        e.FirstSeen,
			"tags":              e.Tags,
		})
	}
	return out, nil
}

// decodeThreatFox поддерживает оба формата экспорта: массив и объект по ID.
func decodeThreatFox(body []byte) ([]threatFoxEntry, error) {
	var arr []threatFoxEntry
	if err := json.Unmarshal(body, &arr); err == nil {
		return arr, nil
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, err
	}
	if data, ok := obj["data"]; ok {
		if err := json.Unmarshal(data, &arr); err == nil {
			return arr, nil
		}
	}

	var out []threatFoxEntry
	for _, raw := range obj {
		var list []threatFoxEntry
		if err := json.Unmarshal(raw, &list); err == nil {
			out = append(out, list...)
			continue
		}
		var one threatFoxEntry
		if err := json.Unmarshal(raw, &one); err == nil && (one.IOC != "" || one.IOCValue != "") {
			out = append(out, one)
		}
	}
	return out, nil
}

// ---------- Feodo Tracker ----------

type feodoEntry struct {
	IP         string `json:"ip_address"`
	Port       int    `json:"port"`
	Status     string `json:"status"`
	Hostname   string `json:"hostname"`
	ASNumber   int    `json:"as_number"`
	ASName     string `json:"as_name"`
	Country    string `json:"country"`
	FirstSeen  string `json:"first_seen"`
	LastOnline string `json:"last_online"`
	Malware    string `json:"malware"`
}

func parseFeodo(target string, body []byte) ([]map[string]any, error) {
	var entries []feodoEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}

	var out []map[string]any
	for _, e := range entries {
		if !indicatorMatches(target, e.IP) && !indicatorMatches(target, e.Hostname) {
			continue
		}
		out = append(out, map[string]any{
			"indicator":   e.IP,
			"port":        e.Port,
			"status":      e.Status,
			"hostname":    e.Hostname,
			"as_number":   e.ASNumber,
			"as_name":     e.ASName,
			"country":     e.Country,
			"first_seen":  e.FirstSeen,
			"last_online": e.LastOnline,
			"malware":     e.Malware,
		})
	}
	return out, nil
}
