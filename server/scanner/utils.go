package scanner

import (
	"strings"
	"golang.org/x/net/idna"
)

func ToASCII(domain string) (string, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	return idna.Lookup.ToASCII(domain)
}