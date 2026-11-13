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

// shodanSource — данные Shodan по IP (free API, нужен ключ).
type shodanSource struct {
	apiKey  string
	baseURL string
	client  *http.Client
	limiter *rateLimiter
	lookup  func(ctx context.Context, host string) ([]string, error)
}

type shodanService struct {
	Port      int    `json:"port"`
	Transport string `json:"transport"`
	Product   string `json:"product"`
	Version   string `json:"version"`
}

type shodanHost struct {
	IPStr       string          `json:"ip_str"`
	Org         string          `json:"org"`
	ISP         string          `json:"isp"`
	ASN         string          `json:"asn"`
	CountryName string          `json:"country_name"`
	City        string          `json:"city"`
	Hostnames   []string        `json:"hostnames"`
	Domains     []string        `json:"domains"`
	Ports       []int           `json:"ports"`
	Data        []shodanService `json:"data"`
	Vulns       []string        `json:"vulns"`
}

func (s *shodanSource) Name() string { return "shodan" }

func (s *shodanSource) Fetch(ctx context.Context, target string) ([]Observation, error) {
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
		host, err := s.lookupHost(ctx, ip)
		if err != nil {
			lastErr = err
			continue
		}
		if host == nil {
			continue
		}
		payload, err := json.Marshal(map[string]any{
			"indicator": ip,
			"org":       host.Org,
			"isp":       host.ISP,
			"asn":       host.ASN,
			"country":   host.CountryName,
			"city":      host.City,
			"hostnames": host.Hostnames,
			"domains":   host.Domains,
			"ports":     host.Ports,
			"services":  host.Data,
			"vulns":     host.Vulns,
		})
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
	if len(obs) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return obs, nil
}

func (s *shodanSource) lookupHost(ctx context.Context, ip string) (*shodanHost, error) {
	if err := s.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	u := strings.TrimRight(s.baseURL, "/") + "/shodan/host/" + url.PathEscape(ip) + "?key=" + url.QueryEscape(s.apiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Stare/1.0 (+osint)")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shodan status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	var out shodanHost
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	if out.IPStr == "" {
		out.IPStr = ip
	}
	return &out, nil
}

func (s *shodanSource) FetchBatch(ctx context.Context, targets []string) ([]Observation, error) {
	return fetchBatch(ctx, s, targets)
}

// NewShodanSource создаёт источник Shodan (SHODAN_API_KEY обязателен).
func NewShodanSource() Source {
	return &shodanSource{
		apiKey:  os.Getenv("SHODAN_API_KEY"),
		baseURL: envOr("SHODAN_BASE_URL", "https://api.shodan.io"),
		client:  &http.Client{Timeout: 15 * time.Second},
		limiter: newRateLimiter(time.Second),
		lookup: func(ctx context.Context, host string) ([]string, error) {
			return net.DefaultResolver.LookupHost(ctx, host)
		},
	}
}
