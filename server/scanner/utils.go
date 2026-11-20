package scanner

import (
	"golang.org/x/net/idna"
	"strings"
)

func ToASCII(domain string) (string, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	return idna.Lookup.ToASCII(domain)
}
