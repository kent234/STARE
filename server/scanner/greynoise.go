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

// greynoiseSource — классификация IP через GreyNoise Community API (нужен ключ).
type greynoiseSource struct {
	apiKey  string
	baseURL string
	client  *http.Client
	limiter *rateLimiter
	lookup  func(ctx context.Context, host string) ([]string, error)
}

type greynoiseResponse struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`
	Riot           bool   `json:"riot"`
	Classification string `json:"classification"`
	Name           string `json:"name"`
	Link           string `json:"link"`
	LastSeen       string `json:"last_seen"`
	Message        string `json:"message"`
}

func (s *greynoiseSource) Name() string { return "greynoise" }

func (s *greynoiseSource) Fetch(ctx context.Context, target string) ([]Observation, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	ips, err := resolveTargets(ctx, target, s.lookup)
	if err != nil {
		return nil, err
	}
	// GreyNoise Community принимает только маршрутизируемые IPv4.
	ipv4 := make([]string, 0, len(ips))
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
			ipv4 = append(ipv4, ip)
		}
	}
	ips = ipv4
	now := time.Now().UTC()
	obs := make([]Observation, 0, len(ips))
	var lastErr error
	for _, ip := range ips {
		r, err := s.lookupIP(ctx, ip)
		if err != nil {
			lastErr = err
			continue
		}
		if r == nil {
			continue
		}
		payload, err := json.Marshal(map[string]any{
			"indicator":      ip,
			"classification": r.Classification,
			"name":           r.Name,
			"noise":          r.Noise,
			"riot":           r.Riot,
			"last_seen":      r.LastSeen,
			"link":           r.Link,
			"message":        r.Message,
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

func (s *greynoiseSource) lookupIP(ctx context.Context, ip string) (*greynoiseResponse, error) {
	if err := s.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	u := strings.TrimRight(s.baseURL, "/") + "/v3/community/" + url.PathEscape(ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Stare/1.0 (+osint)")
	if s.apiKey != "" {
		req.Header.Set("key", s.apiKey)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // IP ещё не наблюдался GreyNoise
	}
	if resp.StatusCode == http.StatusBadRequest {
		return nil, nil // не маршрутизируемый IPv4 / неподдерживаемый формат
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("greynoise status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out greynoiseResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *greynoiseSource) FetchBatch(ctx context.Context, targets []string) ([]Observation, error) {
	return fetchBatch(ctx, s, targets)
}

// NewGreyNoiseSource создаёт источник GreyNoise (GREYNOISE_API_KEY опционален).
func NewGreyNoiseSource() Source {
	return &greynoiseSource{
		apiKey:  os.Getenv("GREYNOISE_API_KEY"),
		baseURL: envOr("GREYNOISE_BASE_URL", "https://api.greynoise.io"),
		client:  &http.Client{Timeout: 15 * time.Second},
		limiter: newRateLimiter(time.Second),
		lookup: func(ctx context.Context, host string) ([]string, error) {
			return net.DefaultResolver.LookupHost(ctx, host)
		},
	}
}
