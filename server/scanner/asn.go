package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
)

func GetASN(ctx context.Context, ip string) (string, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", fmt.Errorf("invalid ip")
	}

	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return "IPv6 not supported yet", nil
	}
	reversed := fmt.Sprintf("%s.%s.%s.%s", parts[3], parts[2], parts[1], parts[0])

	query := reversed + ".origin.asn.cymru.com"
	txts, err := net.LookupTXT(query)
	if err != nil || len(txts) == 0 {
		return "Unknown", nil
	}

	// Формат ответа: "12345 | 1.2.3.0/24 | RU | ripencc | 2020-01-01"
	data := strings.Split(txts[0], "|")
	if len(data) >= 3 {
		return fmt.Sprintf("ASN: %s | Country: %s", strings.TrimSpace(data[0]), strings.TrimSpace(data[2])), nil
	}
	return "Unknown", nil
}
