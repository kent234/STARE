package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ScanResult — структура, которую мы отдадим в React
type ScanResult struct {
	Target       string              `json:"target"`
	Subdomains   []string            `json:"subdomains"`
	SubdomainIPs map[string][]string `json:"subdomain_ips"`
	IPs          []string            `json:"ips"`
	Ports        map[string][]int    `json:"ports"`
	Banners      map[string]string   `json:"banners"` // НОВОЕ: Баннеры сервисов
	DNS          ExtendedDNS         `json:"dns"`
	Whois        map[string]string   `json:"whois"`
	ASN          map[string]string   `json:"asn"`
	Artifacts    Artifacts           `json:"artifacts"`
	Technologies []string            `json:"technologies"`
	Errors       []string            `json:"errors"`
	Duration     string              `json:"duration"`
}

// RunFullScan — выполняет полный цикл разведки и возвращает результат
func RunFullScan(ctx context.Context, target string) *ScanResult {
	start := time.Now()
	result := &ScanResult{
		Target:       target,
		Ports:        make(map[string][]int),
		Banners:      make(map[string]string),
		ASN:          make(map[string]string),
		SubdomainIPs: make(map[string][]string),
		Errors:       []string{},
	}

	// Очищаем домен (PSL)
	if root, err := ExtractRootDomain(target); err == nil {
		result.Target = root
		target = root
	}

	dns := NewDNSClient()
	var wg sync.WaitGroup
	var mu sync.Mutex

	addSubdomains := func(subs []string) {
		mu.Lock()
		defer mu.Unlock()
		result.Subdomains = append(result.Subdomains, subs...)
	}

	// 1. Пассивный сбор (все источники параллельно)
	sources := []func(context.Context, string) ([]string, error){
		func(c context.Context, d string) ([]string, error) { return NewCRTShClient().FetchSubdomains(c, d) },
		FetchCRTName, FetchRapidDNS, FetchHackerTarget,
		FetchAlienVaultOTX, FetchAnubisDB, FetchThreatMiner, FetchURLScan, FetchTLSCC,
	}

	for _, fn := range sources {
		wg.Add(1)
		go func(f func(context.Context, string) ([]string, error)) {
			defer wg.Done()
			subs, err := f(ctx, target)
			if err != nil {
				mu.Lock()
				result.Errors = append(result.Errors, err.Error())
				mu.Unlock()
				return
			}
			if len(subs) > 0 {
				addSubdomains(subs)
			}
		}(fn)
	}

	// 2. DNS, WHOIS и Технологии
	wg.Add(3)
	go func() {
		defer wg.Done()
		result.DNS = dns.ResolveExtended(ctx, target)
	}()
	go func() {
		defer wg.Done()
		whois, _ := FetchWhoisUniversal(ctx, target)
		result.Whois = whois
	}()
	go func() {
		defer wg.Done()
		arts, techs := AnalyzeArtifacts(ctx, target)
		result.Artifacts = arts
		result.Technologies = techs
	}()

	wg.Wait()
	result.Subdomains = uniqueSorted(result.Subdomains)

	// 3. IP-адреса и связь с поддоменами
	ips := []string{}
	resolved, _ := dns.Resolve(ctx, target)
	ips = append(ips, resolved...)

	for _, sub := range result.Subdomains {
		if subIPs, err := dns.Resolve(ctx, sub); err == nil && len(subIPs) > 0 {
			ips = append(ips, subIPs...)
			result.SubdomainIPs[sub] = subIPs
		}
	}
	result.IPs = uniqueSorted(ips)

	// 4. ASN
	for _, ip := range result.IPs {
		asn, _ := GetASN(ctx, ip)
		result.ASN[ip] = asn
	}

	// 5. Порты и Баннеры
	if len(result.IPs) > 0 {
		portsClient := NewPortsClient()
		result.Ports, _ = portsClient.ScanPortsMany(ctx, result.IPs)

		var wgBanners sync.WaitGroup
		for ip, ports := range result.Ports {
			for _, port := range ports {
				wgBanners.Add(1)
				go func(ipAddr string, p int) {
					defer wgBanners.Done()
					banner := grabBanner(ctx, ipAddr, p)
					if banner != "" {
						mu.Lock()
						result.Banners[fmt.Sprintf("%s:%d", ipAddr, p)] = banner
						mu.Unlock()
					}
				}(ip, port)
			}
		}
		wgBanners.Wait()
	}

	result.Duration = time.Since(start).Round(time.Millisecond).String()
	return result
}

// Встроенная функция для быстрого получения баннера
func grabBanner(ctx context.Context, ip string, port int) string {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: 3 * time.Second}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Если это веб-порт, отправляем HTTP-запрос
	if port == 80 || port == 8080 {
		fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: STARE/1.0\r\nConnection: close\r\n\r\n", ip)
	} else if port == 443 {
		// Для HTTPS нужно TLS-соединение (пока пропустим или используем http.Get)
		return "HTTPS (TLS)"
	}

	reader := bufio.NewReader(conn)
	buffer := make([]byte, 512)
	n, _ := reader.Read(buffer)

	rawBanner := string(buffer[:n])
	cleanBanner := strings.Map(func(r rune) rune {
		if r >= 32 && r <= 126 {
			return r
		}
		return -1
	}, rawBanner)

	// Берем только первую строку (например, "HTTP/1.1 200 OK" или "HTTP/1.1 301 Moved Permanently")
	lines := strings.Split(cleanBanner, "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(lines[0])
	}
	return strings.TrimSpace(cleanBanner)
}

func uniqueSorted(in []string) []string {
	seen := map[string]struct{}{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" {
			seen[s] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	return out
}
