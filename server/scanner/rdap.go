package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/openrdap/rdap/bootstrap"
)

// FetchRDAP получает список RDAP-серверов для домена через IANA Bootstrap.
// В учебных целях возвращает найденные URL. В production здесь нужно
// сделать HTTP GET к одному из URL и распарсить JSON.
func FetchRDAP(ctx context.Context, domain string) (map[string]interface{}, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, fmt.Errorf("empty domain")
	}

	// Создаём вопрос: ищем RDAP-сервер для DNS-зоны домена
	question := &bootstrap.Question{
		RegistryType: bootstrap.DNS,
		Query:        domain,
	}

	// Клиент bootstrap сам скачает реестр IANA и закэширует его
	b := &bootstrap.Client{}
	answer, err := b.Lookup(question)
	if err != nil {
		return nil, fmt.Errorf("rdap lookup: %w", err)
	}

	// Собираем найденные URL серверов
	urls := make([]string, 0, len(answer.URLs))
	for _, u := range answer.URLs {
		urls = append(urls, u.String())
	}

	return map[string]interface{}{
		"rdap_servers": urls,
		"domain":       domain,
	}, nil
}
