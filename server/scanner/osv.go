package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// osvSource — уязвимости из OSV. Цель: CVE/GHSA-ID либо <ecosystem>/<package>[@version].
type osvSource struct {
	baseURL string
	client  *http.Client
	limiter *rateLimiter
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvAffected struct {
	Package osvPackage `json:"package"`
}

type osvVuln struct {
	ID        string        `json:"id"`
	Summary   string        `json:"summary"`
	Aliases   []string      `json:"aliases"`
	Published string        `json:"published"`
	Modified  string        `json:"modified"`
	Severity  []osvSeverity `json:"severity"`
	Affected  []osvAffected `json:"affected"`
}

var osvIDRe = regexp.MustCompile(`^(CVE-[0-9]{4}-[0-9]+|GHSA(-[0-9a-z]{4}){3})$`)

func (s *osvSource) Name() string { return "osv" }

func (s *osvSource) Fetch(ctx context.Context, target string) ([]Observation, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	isID, id, ecosystem, pkg, version, ok := parseOSVTarget(target)
	if !ok {
		return nil, nil
	}

	var vulns []osvVuln
	var indicator string
	if isID {
		indicator = id
		body, err := s.do(ctx, http.MethodGet, "/v1/vulns/"+url.PathEscape(id), nil)
		if err != nil {
			return nil, err
		}
		var v osvVuln
		if err := json.Unmarshal(body, &v); err != nil {
			return nil, err
		}
		vulns = append(vulns, v)
	} else {
		indicator = ecosystem + "/" + pkg
		if version != "" {
			indicator += "@" + version
		}
		reqPayload := map[string]any{
			"package": osvPackage{Name: pkg, Ecosystem: ecosystem},
		}
		if version != "" {
			reqPayload["version"] = version
		}
		reqBody, err := json.Marshal(reqPayload)
		if err != nil {
			return nil, err
		}
		body, err := s.do(ctx, http.MethodPost, "/v1/query", reqBody)
		if err != nil {
			return nil, err
		}
		var resp struct {
			Vulns []osvVuln `json:"vulns"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}
		vulns = resp.Vulns
	}

	now := time.Now().UTC()
	obs := make([]Observation, 0, len(vulns))
	for _, v := range vulns {
		payload, err := json.Marshal(osvPayload(v, indicator))
		if err != nil {
			continue
		}
		obs = append(obs, Observation{
			Source:     s.Name(),
			FetchedAt:  now,
			Confidence: ConfidenceHigh,
			Payload:    payload,
		})
	}
	return obs, nil
}

func (s *osvSource) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	if err := s.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(s.baseURL, "/")+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Stare/1.0 (+osint)")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv status: %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

func osvPayload(v osvVuln, indicator string) map[string]any {
	severity := make([]string, 0, len(v.Severity))
	for _, sv := range v.Severity {
		severity = append(severity, strings.TrimSpace(sv.Type+" "+sv.Score))
	}
	packages := make([]string, 0, len(v.Affected))
	for _, a := range v.Affected {
		packages = append(packages, a.Package.Ecosystem+"/"+a.Package.Name)
	}
	return map[string]any{
		"indicator": indicator,
		"id":        v.ID,
		"summary":   v.Summary,
		"aliases":   v.Aliases,
		"severity":  severity,
		"packages":  packages,
		"published": v.Published,
		"modified":  v.Modified,
	}
}

// parseOSVTarget разбирает цель без обращения в сеть.
// Поддерживается: CVE-..., GHSA-..., <ecosystem>/<package>[@version],
// либо <package>[@version] с экосистемой из OSV_ECOSYSTEM (по умолчанию npm).
func parseOSVTarget(target string) (isID bool, id, ecosystem, pkg, version string, ok bool) {
	raw := strings.TrimSpace(target)
	if raw == "" {
		return false, "", "", "", "", false
	}
	if osvIDRe.MatchString(raw) {
		return true, raw, "", "", "", true
	}
	// Без явной экосистемы/версии цель неоднозначна (например, домен) — пропускаем.
	if !strings.ContainsAny(raw, "/@") {
		return false, "", "", "", "", false
	}

	ecosystem = envOr("OSV_ECOSYSTEM", "npm")
	rest := raw
	if i := strings.IndexByte(raw, '/'); i > 0 {
		ecosystem = raw[:i]
		rest = raw[i+1:]
	}
	if i := strings.LastIndexByte(rest, '@'); i > 0 {
		version = rest[i+1:]
		rest = rest[:i]
	}
	if rest == "" {
		return false, "", "", "", "", false
	}
	return false, "", ecosystem, rest, version, true
}

// NewOSVSource создаёт источник OSV (без ключа).
func NewOSVSource() Source {
	return &osvSource{
		baseURL: envOr("OSV_BASE_URL", "https://api.osv.dev"),
		client:  &http.Client{Timeout: 15 * time.Second},
		limiter: newRateLimiter(100 * time.Millisecond),
	}
}
