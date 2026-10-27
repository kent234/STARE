package scanner

import (
	"fmt"
	"strings"

	"github.com/weppos/publicsuffix-go/publicsuffix"
)

// ExtractRootDomain — извлекает корневой домен из любого имени.
// Пример: "sub.example.co.uk" -> "example.co.uk"
func ExtractRootDomain(domain string) (string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return "", fmt.Errorf("empty domain")
	}

	root, err := publicsuffix.Domain(domain)
	if err != nil {
		return "", fmt.Errorf("publicsuffix: %w", err)
	}
	return root, nil
}
