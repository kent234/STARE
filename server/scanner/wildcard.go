package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"time"
)

// DetectWildcardDNS проверяет, отдаёт ли DNS одинаковый ответ на случайные
// несуществующие поддомены. Нужно, чтобы не считать wildcard-ответы находками.
func DetectWildcardDNS(ctx context.Context, domain string) bool {
	resolver := net.DefaultResolver
	answers := 0
	var first []string
	for i := 0; i < 3; i++ {
		label := randomLabel()
		lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		ips, err := resolver.LookupHost(lctx, label+"."+domain)
		cancel()
		if err != nil || len(ips) == 0 {
			continue
		}
		sortStrings(ips)
		if first == nil {
			first = ips
			answers++
			continue
		}
		if equalStrings(first, ips) {
			answers++
		}
	}
	return answers >= 2
}

func randomLabel() string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return "stare-" + hex.EncodeToString(buf)
}

func sortStrings(items []string) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j] < items[j-1]; j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
