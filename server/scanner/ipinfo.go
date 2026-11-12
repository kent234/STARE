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

// ipinfoSource — обогащение IP через ipinfo.io (token опционален).
type ipinfoSource struct {
	token   string
	baseURL string
	client  *http.Client
	limiter *rateLimiter
	lookup  func(ctx context.Context, host string) ([]string, error)
}

type ipinfoResponse struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Loc      string `json:"loc"`
	Org      string `json:"org"`
	Postal   string `json:"postal"`
	Timezone string `json:"timezone"`
	Bogon    bool   `json:"bogon"`
}

func (s *ipinfoSource) Name() string { return "ipinfo" }

func (s *ipinfoSource) Fetch(ctx context.Context, target string) ([]Observation, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	ips := []string{}
	if ip := net.ParseIP(normalizeIndicator(target)); ip != nil {
		ips = append(ips, ip.String())
	} else if s.lookup != nil {
		found, err := s.lookup(ctx, target)
		if err != nil {
			return nil, err
		}
		ips = found
	}
	if len(ips) == 0 {
		return nil, nil
	}

	now := time.Now().UTC()
	obs := make([]Observation, 0, len(ips))
	var lastErr error
	for _, ip := range ips {
		r, err := s.lookupIP(ctx, ip)
		if err != nil {
			lastErr = err
			continue
		}
		asn, asName := parseOrg(r.Org)
		payload, err := json.Marshal(map[string]any{
			"indicator": ip,
			"hostname":  r.Hostname,
			"city":      r.City,
			"region":    r.Region,
			"country":   r.Country,
			"loc":       r.Loc,
			"asn":       asn,
			"as_name":   asName,
			"timezone":  r.Timezone,
			"bogon":     r.Bogon,
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

func (s *ipinfoSource) lookupIP(ctx context.Context, ip string) (*ipinfoResponse, error) {
	if err := s.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	u := strings.TrimRight(s.baseURL, "/") + "/" + url.PathEscape(ip) + "/json"
	if s.token != "" {
		u += "?token=" + url.QueryEscape(s.token)
	}
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
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ipinfo status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out ipinfoResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	if out.IP == "" {
		out.IP = ip
	}
	return &out, nil
}

func parseOrg(org string) (asn, name string) {
	org = strings.TrimSpace(org)
	if !strings.HasPrefix(strings.ToUpper(org), "AS") {
		return "", org
	}
	if i := strings.IndexByte(org, ' '); i > 0 {
		return org[:i], strings.TrimSpace(org[i+1:])
	}
	return org, ""
}

func init() {
	if os.Getenv("STARE_DISABLE_ENRICH") == "1" {
		return
	}
	RegisterSource(NewIPinfoSource())
	RegisterSource(NewOSVSource())
}

// NewIPinfoSource создаёт источник IPinfo (IPINFO_TOKEN не обязателен).
func NewIPinfoSource() Source {
	return &ipinfoSource{
		token:   os.Getenv("IPINFO_TOKEN"),
		baseURL: envOr("IPINFO_BASE_URL", "https://ipinfo.io"),
		client:  &http.Client{Timeout: 15 * time.Second},
		limiter: newRateLimiter(250 * time.Millisecond),
		lookup: func(ctx context.Context, host string) ([]string, error) {
			return net.DefaultResolver.LookupHost(ctx, host)
		},
	}
}
