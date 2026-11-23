package scanner

import (
	"net"
	"strings"
)

// normalizeSubdomain приводит имя из любого источника к каноническому виду:
// lowercase, без схемы/порта/пути/wildcard-префикса и без мусора декодирования.
// Возвращает false, если имя не является поддоменом root или содержит
// недопустимые label-символы.
func normalizeSubdomain(raw, root string) (string, bool) {
	value := strings.ToLower(strings.TrimSpace(raw))
	value = strings.TrimPrefix(value, "http://")
	value = strings.TrimPrefix(value, "https://")
	if i := strings.IndexAny(value, "/?#"); i >= 0 {
		value = value[:i]
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	value = strings.TrimSuffix(value, ".")
	value = strings.TrimPrefix(value, "*.")
	value = strings.TrimLeft(value, ".")

	// Артефакты вида u003ewww.example.com — результат двойного JSON-декодирования.
	if value == "" || strings.Contains(value, `\u`) || strings.Contains(value, "u003e") ||
		strings.ContainsAny(value, " <>\"'%") {
		return "", false
	}
	if len(value) > 253 {
		return "", false
	}
	if value != root && !strings.HasSuffix(value, "."+root) {
		return "", false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
				continue
			}
			return "", false
		}
	}
	return value, true
}
