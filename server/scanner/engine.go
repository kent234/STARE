package scanner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ScanResult — итоговая структура, которую мы отдадим в React
type ScanResult struct {
	Target     string              `json:"target"`
	Subdomains []string            `json:"subdomains"`
	IPs        []string            `json:"ips"`
	Ports      map[string][]int    `json:"ports"`
	DNS        ExtendedDNS         `json:"dns"`
	Whois      map[string]string   `json:"whois"`
	ASN        map[string]string   `json:"asn"`
	Artifacts  Artifacts           `json:"artifacts"`
	Errors     []string            `json:"errors"`
	Duration   string              `json:"duration"`
}

// RunFullScan — выполняет полный цикл разведки и возвращает результат
func RunFullScan(ctx context.Context, target string) *ScanResult {
	start := time.Now()
	result := &ScanResult{
		Target: target,
		Ports:  make(map[string][]int),
		ASN:    make(map[string]string),
	}

	// Применяем Public Suffix List (очищаем домен)
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

	// 1. ПАССИВНЫЙ СБОР (Параллельно)
	sources := []struct {
		Name string
		Fn   func(context.Context, string) ([]string, error)
	}{
		{"crt.sh", func(c context.Context, d string) ([]string, error) { return NewCRTShClient().FetchSubdomains(c, d) }},
		{"crt.name", FetchCRTName},
		{"RapidDNS", FetchRapidDNS},
		{"HackerTarget", FetchHackerTarget},
		{"AlienVault", FetchAlienVaultOTX},
		{"AnubisDB", FetchAnubisDB},
		{"ThreatMiner", FetchThreatMiner},
		{"URLScan", FetchURLScan},
	}

	for _, src := range sources {
		wg.Add(1)
		go func(fn func(context.Context, string) ([]string, error)) {
			defer wg.Done()
			subs, err := fn(ctx, target)
			if err != nil {
				mu.Lock()
				result.Errors = append(result.Errors, err.Error())
				mu.Unlock()
				return
			}
			addSubdomains(subs)
		}(src.Fn)
	}

	// 2. DNS и WHOIS (параллельно с поддоменами)
	wg.Add(2)
	go func() {
		defer wg.Done()
		result.DNS = dns.ResolveExtended(ctx, target)
	}()
	go func() {
		defer wg.Done()
		whois, _ := FetchWhoisUniversal(ctx, target)
		result.Whois = whois
	}()

	wg.Wait()
	result.Subdomains = uniqueSorted(result.Subdomains)

	// 3. Резолвинг IP
	ips := []string{}
	resolved, _ := dns.Resolve(ctx, target)
	ips = append(ips, resolved...)
	
	for _, sub := range result.Subdomains {
		if subIPs, err := dns.Resolve(ctx, sub); err == nil {
			ips = append(ips, subIPs...)
		}
	}
	result.IPs = uniqueSorted(ips)

	// 4. ASN
	for _, ip := range result.IPs {
		asn, _ := GetASN(ctx, ip)
		result.ASN[ip] = asn
	}

	// 5. Порты
	if len(result.IPs) > 0 {
		portsClient := NewPortsClient()
		openPorts, _ := portsClient.ScanPortsMany(ctx, result.IPs)
		result.Ports = openPorts
	}

	// 6. Артефакты (robots.txt, заголовки)
	result.Artifacts = CheckArtifacts(ctx, target)

	result.Duration = time.Since(start).Round(time.Millisecond).String()
	return result
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
	// sort.Strings(out) // если нужна сортировка
	return out
}

func init() {
	// Пустая функция init на случай, если fmt не используется
	_ = fmt.Sprint
}