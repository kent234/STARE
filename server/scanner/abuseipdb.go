package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// abuseIPDBSource — репутация IP через AbuseIPDB (нужен ключ).
type abuseIPDBSource struct {
	apiKey  string
	baseURL string
	client  *http.Client
	limiter *rateLimiter
	lookup  func(ctx context.Context, host string) ([]string, error)
}

type abuseIPDBData struct {
	IPAddress            string   `json:"ipAddress"`
	IsPublic             bool     `json:"isPublic"`
	IPVersion            int      `json:"ipVersion"`
	IsWhitelisted        bool     `json:"isWhitelisted"`
	AbuseConfidenceScore int      `json:"abuseConfidenceScore"`
	CountryCode          string   `json:"countryCode"`
	UsageType            string   `json:"usageType"`
	ISP                  string   `json:"isp"`
	Domain               string   `json:"domain"`
	Hostnames            []string `json:"hostnames"`
	TotalReports         int      `json:"totalReports"`
	NumDistinctUsers     int      `json:"numDistinctUsers"`
	LastReportedAt       string   `json:"lastReportedAt"`
}

type abuseIPDBResponse struct {
	Data abuseIPDBData `json:"data"`
}

func (s *abuseIPDBSource) Name() string { return "abuseipdb" }

func (s *abuseIPDBSource) Fetch(ctx context.Context, target string) ([]Observation, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	ips, err := resolveTargets(ctx, target, s.lookup)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	obs := make([]Observation, 0, len(ips))
	var lastErr error
	for _, ip := range ips {
		d, err := s.checkIP(ctx, ip)
		if err != nil {
			lastErr = err
			continue
		}
		if d == nil {
			continue
		}
		payload, err := json.Marshal(map[string]any{
			"indicator":        ip,
			"score":            d.AbuseConfidenceScore,
			"total_reports":    d.TotalReports,
			"distinct_users":   d.NumDistinctUsers,
			"country":          d.CountryCode,
			"isp":              d.ISP,
			"usage_type":       d.UsageType,
			"domain":           d.Domain,
			"hostnames":        d.Hostnames,
			"whitelisted":      d.IsWhitelisted,
			"public":           d.IsPublic,
			"last_reported_at": d.LastReportedAt,
		})
		if err != nil {
			continue
		}
		obs = append(obs, Observation{
			Source:     s.Name(),
			FetchedAt:  now,
			Confidence: ConfidenceMedium,
			Payload:    payload,
		})
	}
	if len(obs) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return obs, nil
}

func (s *abuseIPDBSource) checkIP(ctx context.Context, ip string) (*abuseIPDBData, error) {
	if err := s.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	u := strings.TrimRight(s.baseURL, "/") + "/api/v2/check?ipAddress=" + url.QueryEscape(ip) + "&maxAgeInDays=90"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Stare/1.0 (+osint)")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Key", s.apiKey)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("abuseipdb status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out abuseIPDBResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out.Data, nil
}

// NewAbuseIPDBSource создаёт источник AbuseIPDB (ABUSEIPDB_API_KEY обязателен).
func NewAbuseIPDBSource() Source {
	return &abuseIPDBSource{
		apiKey:  os.Getenv("ABUSEIPDB_API_KEY"),
		baseURL: envOr("ABUSEIPDB_BASE_URL", "https://api.abuseipdb.com"),
		client:  &http.Client{Timeout: 15 * time.Second},
		limiter: newRateLimiter(time.Second),
		lookup: func(ctx context.Context, host string) ([]string, error) {
			return net.DefaultResolver.LookupHost(ctx, host)
		},
	}
}
