package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ConfidenceTier — степень доверия к наблюдению источника.
type ConfidenceTier string

const (
	ConfidenceHigh   ConfidenceTier = "high"
	ConfidenceMedium ConfidenceTier = "medium"
	ConfidenceLow    ConfidenceTier = "low"
)

// Observation — унифицированный результат любого источника.
type Observation struct {
	Source     string          `json:"source"`
	FetchedAt  time.Time       `json:"fetched_at"`
	Confidence ConfidenceTier  `json:"confidence_tier"`
	Payload    json.RawMessage `json:"payload"`
}

// Source — контракт источника данных. Ошибка источника не должна валить скан.
type Source interface {
	Name() string
	Fetch(ctx context.Context, target string) ([]Observation, error)
}

var (
	registryMu sync.RWMutex
	registry   []Source
)

// RegisterSource добавляет источник в глобальный реестр.
func RegisterSource(s Source) {
	registryMu.Lock()
	registry = append(registry, s)
	registryMu.Unlock()
}

// RegisteredSources возвращает снимок реестра.
func RegisteredSources() []Source {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]Source, len(registry))
	copy(out, registry)
	return out
}

// FetchAllSources опрашивает все источники параллельно, изолируя ошибки per-source.
func FetchAllSources(ctx context.Context, target string) ([]Observation, []string) {
	srcs := RegisteredSources()
	if len(srcs) == 0 {
		return nil, nil
	}

	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		obs  []Observation
		errs []string
	)
	for _, s := range srcs {
		wg.Add(1)
		go func(s Source) {
			defer wg.Done()
			o, err := s.Fetch(ctx, target)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", s.Name(), err))
				return
			}
			obs = append(obs, o...)
		}(s)
	}
	wg.Wait()
	return obs, errs
}

// rateLimiter — минимальный token bucket без внешних зависимостей.
type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newRateLimiter(interval time.Duration) *rateLimiter {
	return &rateLimiter{interval: interval}
}

func (l *rateLimiter) Wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	wait := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	if wait <= 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// normalizeIndicator приводит цель/индикатор к сравнимому виду (host).
func normalizeIndicator(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			s = u.Hostname()
		}
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return strings.Trim(s, "[]")
}

// indicatorMatches сообщает, относится ли индикатор к цели (сам или поддомен).
func indicatorMatches(target, indicator string) bool {
	t := normalizeIndicator(target)
	i := normalizeIndicator(indicator)
	if t == "" || i == "" {
		return false
	}
	return i == t || strings.HasSuffix(i, "."+t)
}

// resolveTargets превращает цель в список IP: сам IP или результат DNS-резолва.
func resolveTargets(ctx context.Context, target string, lookup func(context.Context, string) ([]string, error)) ([]string, error) {
	if ip := net.ParseIP(normalizeIndicator(target)); ip != nil {
		return []string{ip.String()}, nil
	}
	if lookup == nil {
		return nil, nil
	}
	return lookup(ctx, target)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
