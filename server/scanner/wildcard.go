package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"time"
)

// WildcardInfo — результат проверки wildcard-DNS.
//
// Detected=true означает, что случайные несуществующие имена резолвятся.
// IPs — объединение адресов, которые отдали пробные запросы. Именно с этим
// набором сравнивается резолв каждого поддомена: если все его адреса входят
// в wildcard-набор, имя считается сгенерированным, а не реальным хостом.
//
// Ограничение: при round-robin wildcard пул адресов может быть шире трёх проб;
// тогда часть имён не будет помечена. Консервативно лучше недометить, чем
// подтвердить мусор — confidence в таком случае останется прежним.
type WildcardInfo struct {
	Detected bool     `json:"detected"`
	IPs      []string `json:"ips,omitempty"`
}

type wildcardLookup func(ctx context.Context, host string) ([]string, error)

// DetectWildcardDNS проверяет, отдаёт ли DNS ответ на случайные
// несуществующие поддомены. Вызывается ДО резолва собранных имён,
// чтобы результат можно было использовать при выставлении confidence.
func DetectWildcardDNS(ctx context.Context, domain string) WildcardInfo {
	return detectWildcardDNS(ctx, domain, net.DefaultResolver.LookupHost)
}

// detectWildcardDNS отделён от сетевого резолвера для unit-тестов.
func detectWildcardDNS(ctx context.Context, domain string, lookup wildcardLookup) WildcardInfo {
	// Для IP-цели wildcard-проверка не имеет смысла.
	if net.ParseIP(domain) != nil {
		return WildcardInfo{}
	}

	var (
		union    []string
		resolved int
	)
	for i := 0; i < 3; i++ {
		lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		ips, err := lookup(lctx, randomLabel()+"."+domain)
		cancel()
		if err != nil || len(ips) == 0 {
			continue
		}
		resolved++
		union = append(union, ips...)
	}

	// Один случайный ответ ещё может быть DNS-аномалией; два и более —
	// устойчивый wildcard (в том числе с ротацией адресов).
	if resolved < 2 {
		return WildcardInfo{}
	}
	return WildcardInfo{Detected: true, IPs: uniqueSorted(union)}
}

// isWildcardResolution сообщает, что все адреса поддомена входят в
// wildcard-набор. Пустой набор или пустой резолв — не доказательство.
func isWildcardResolution(ips, wildcardIPs []string) bool {
	if len(ips) == 0 || len(wildcardIPs) == 0 {
		return false
	}
	allowed := make(map[string]struct{}, len(wildcardIPs))
	for _, ip := range wildcardIPs {
		allowed[ip] = struct{}{}
	}
	for _, ip := range ips {
		if _, ok := allowed[ip]; !ok {
			return false
		}
	}
	return true
}

// subdomainConfidence — единое правило доверия к имени:
// high требует 2+ независимых источника, успешный резолв и отсутствие wildcard.
// Имя без резолва или из wildcard-ответа не может быть подтверждённым.
func subdomainConfidence(sourceCount int, resolved, wildcard bool) string {
	if !resolved || wildcard {
		return "low"
	}
	switch {
	case sourceCount >= 2:
		return "high"
	case sourceCount == 1:
		return "medium"
	default:
		return "low"
	}
}

func randomLabel() string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return "stare-" + hex.EncodeToString(buf)
}
