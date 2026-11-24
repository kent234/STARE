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

// BatchSource — источник, умеющий обогащать сразу несколько целей (например, все IP скана).
type BatchSource interface {
	Source
	FetchBatch(ctx context.Context, targets []string) ([]Observation, error)
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
// extra — дополнительные индикаторы (например, все найденные IP); batch-источники
// обогащают их, обычные источники по-прежнему работают по основному target.
func FetchAllSources(ctx context.Context, target string, extra ...string) ([]Observation, []string) {
	srcs := RegisteredSources()
	if len(srcs) == 0 {
		return nil, nil
	}

	batchTargets := make([]string, 0, len(extra))
	for _, t := range extra {
		if ip := net.ParseIP(normalizeIndicator(t)); ip != nil && !isPublicIP(ip) {
			continue
		}
		batchTargets = append(batchTargets, t)
	}
	if len(batchTargets) == 0 {
		batchTargets = []string{target}
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
			var (
				o   []Observation
				err error
			)
			if bs, ok := s.(BatchSource); ok {
				o, err = bs.FetchBatch(ctx, batchTargets)
			} else {
				o, err = s.Fetch(ctx, target)
			}
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

// bogonNets — диапазоны, которые не являются публично маршрутизируемыми,
// но не покрываются стандартными предикатами net.IP (CGNAT, benchmark,
// documentation, reserved). Нужны как SSRF-барьер для активных стадий.
var bogonNets = mustCIDRs(
	"0.0.0.0/8",
	"100.64.0.0/10",   // CGNAT
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"192.88.99.0/24",  // 6to4 relay anycast
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"240.0.0.0/4",     // reserved
	"255.255.255.255/32",
	"100::/64",      // discard-only
	"2001:db8::/32", // documentation
)

func mustCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			out = append(out, network)
		}
	}
	return out
}

// isPublicIP — строгий фильтр для адресов, которые разрешено сканировать.
// Приватные, loopback, link-local, multicast и bogon-диапазоны отсекаются,
// чтобы домен с A-записью на 127.0.0.1/RFC1918 не заставил сервер сканировать
// собственную сеть (SSRF).
func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// IPv4-mapped IPv6 приводим к IPv4, чтобы предикаты работали предсказуемо.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, network := range bogonNets {
		if network.Contains(ip) {
			return false
		}
	}
	return true
}

// IsPublicIP — экспорт SSRF-фильтра для других пакетов (People pivots).
func IsPublicIP(ip net.IP) bool { return isPublicIP(ip) }

// isPublicIPString — вариант для JSON/строковых целей.
func isPublicIPString(value string) bool {
	return isPublicIP(net.ParseIP(strings.TrimSpace(value)))
}

// hasPublicIP — есть ли среди адресов хотя бы один публичный.
func hasPublicIP(ips []string) bool {
	for _, value := range ips {
		if isPublicIPString(value) {
			return true
		}
	}
	return false
}

// hostSafeToProbe разрешает активную проверку хоста только если все его
// известные адреса публичные. Если резолва нет, хост не отбрасываем —
// инструмент (httpx/naabu) сам решит, но SSRF-гарантии это не даёт;
// поэтому при наличии приватного адреса проверка безусловно запрещена.
func hostSafeToProbe(ips []string) bool {
	if len(ips) == 0 {
		return true
	}
	for _, value := range ips {
		if !isPublicIPString(value) {
			return false
		}
	}
	return true
}

// splitPublicPrivateIPs делит уникальный список адресов на публичные
// (можно сканировать) и приватные/bogon (только показывать).
func splitPublicPrivateIPs(ips []string) (public, private []string) {
	for _, value := range ips {
		if isPublicIPString(value) {
			public = append(public, value)
		} else {
			private = append(private, value)
		}
	}
	return uniqueSorted(public), uniqueSorted(private)
}

// fetchBatch последовательно обогащает targets через обычный Fetch источника,
// дедуплицируя индикаторы и не прерываясь на ошибке одного из них.
func fetchBatch(ctx context.Context, s Source, targets []string) ([]Observation, error) {
	seen := make(map[string]struct{}, len(targets))
	var (
		out     []Observation
		lastErr error
	)
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}

		if err := ctx.Err(); err != nil {
			if lastErr == nil {
				lastErr = err
			}
			break
		}
		observations, err := s.Fetch(ctx, target)
		if err != nil {
			lastErr = err
			continue
		}
		out = append(out, observations...)
	}
	if len(out) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return out, nil
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
