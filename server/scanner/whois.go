package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

func FetchWhois(ctx context.Context, domain string) (map[string]string, error) {
	domain = strings.ToLower(domain)
	server := "whois.iana.org:43" // fallback

	// Поддержка .ru, .su и .рф (в Punycode это .xn--p1ai)
	if strings.HasSuffix(domain, ".ru") || strings.HasSuffix(domain, ".su") || strings.HasSuffix(domain, ".xn--p1ai") {
		if strings.HasSuffix(domain, ".net.ru") || strings.HasSuffix(domain, ".org.ru") || strings.HasSuffix(domain, ".pp.ru") || strings.HasSuffix(domain, ".msk.ru") {
			// Подзоны, обслуживаемые MSK-IX / nic.ru
			server = "whois.nic.ru:43"
		} else {
			// Основная зона (ТЦИ)
			server = "whois.tcinet.ru:43"
		}
	}

	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, fmt.Errorf("whois dial (%s): %w", server, err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "%s\r\n", domain)

	res := make(map[string]string)
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if key != "" && val != "" {
				res[key] = val
			}
		}
	}
	return res, nil
}