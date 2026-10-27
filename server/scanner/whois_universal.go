package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/TwiN/whois"
)

// FetchWhoisUniversal — универсальный WHOIS для любой зоны.
// Использует QueryAndParse для получения структурированных данных.
func FetchWhoisUniversal(ctx context.Context, domain string) (map[string]string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, fmt.Errorf("empty domain")
	}

	// Создаём клиент с кэшированием рефералов (чтобы не дёргать IANA каждый раз)
	client := whois.NewClient().WithReferralCache(true)

	// QueryAndParse возвращает структуру с распарсенными полями
	response, err := client.QueryAndParse(domain)
	if err != nil {
		return nil, fmt.Errorf("whois universal: %w", err)
	}

	// Преобразуем структуру в map[string]string для совместимости
	out := make(map[string]string)

	if !response.ExpirationDate.IsZero() {
		out["expiration_date"] = response.ExpirationDate.Format(time.RFC3339)
	}
	if len(response.DomainStatuses) > 0 {
		out["status"] = strings.Join(response.DomainStatuses, ", ")
	}
	if len(response.NameServers) > 0 {
		out["nameservers"] = strings.Join(response.NameServers, ", ")
	}

	// Если ничего не распарсилось (например, для экзотической зоны),
	// возвращаем хотя бы пустую мапу, чтобы не ломать сканер.
	return out, nil
}
