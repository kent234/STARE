package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ScanResult — структура, которую мы отдадим в React
type ScanResult struct {
	Target              string              `json:"target"`
	Subdomains          []string            `json:"subdomains"`
	SubdomainSources    map[string][]string `json:"subdomain_sources,omitempty"`
	SubdomainConfidence map[string]string   `json:"subdomain_confidence,omitempty"`
	SubdomainIPs        map[string][]string `json:"subdomain_ips"`
	IPs                 []string            `json:"ips"`
	Ports               map[string][]int    `json:"ports"`
	Banners             map[string]string   `json:"banners"` // НОВОЕ: Баннеры сервисов
	DNS                 ExtendedDNS         `json:"dns"`
	Whois               map[string]string   `json:"whois"`
	ASN                 map[string]string   `json:"asn"`
	Artifacts           Artifacts           `json:"artifacts"`
	Technologies        []string            `json:"technologies"`
	Observations        []Observation       `json:"observations,omitempty"`
	Vulnerabilities     []NucleiFinding     `json:"vulnerabilities,omitempty"`
	HTTP                []HTTPProbe         `json:"http,omitempty"`
	TLS                 []TLSInfo           `json:"tls,omitempty"`
	Endpoints           []string            `json:"endpoints,omitempty"`
	CloudBuckets        []CloudBucket       `json:"cloud_buckets,omitempty"`
	ThreatHits          []ThreatHit         `json:"threat_hits,omitempty"`
	WildcardDNS         bool                `json:"wildcard_dns,omitempty"`
	// WildcardIPs — адреса, которые DNS отдаёт на случайные имена.
	// SubdomainWildcard — имена, чей резолв целиком попал в этот набор.
	WildcardIPs       []string        `json:"wildcard_ips,omitempty"`
	SubdomainWildcard map[string]bool `json:"subdomain_wildcard,omitempty"`
	// PrivateIPs — адреса из result.IPs, которые нельзя сканировать
	// (RFC1918, loopback, CGNAT, link-local и прочие bogon-диапазоны).
	PrivateIPs []string `json:"private_ips,omitempty"`
	Errors     []string `json:"errors"`
	Duration   string   `json:"duration"`
}

// RunFullScan — выполняет полный цикл разведки и возвращает результат
func RunFullScan(ctx context.Context, target string) *ScanResult {
	start := time.Now()
	result := &ScanResult{
		Target:              target,
		Ports:               make(map[string][]int),
		Banners:             make(map[string]string),
		ASN:                 make(map[string]string),
		SubdomainIPs:        make(map[string][]string),
		SubdomainSources:    make(map[string][]string),
		SubdomainConfidence: make(map[string]string),
		SubdomainWildcard:   make(map[string]bool),
		Errors:              []string{},
	}

	// Очищаем домен (PSL)
	if root, err := ExtractRootDomain(target); err == nil {
		result.Target = root
		target = root
	}

	dns := NewDNSClient()

	// Резолвим апекс заранее: если он указывает только на приватные/bogon
	// адреса, активные стадии (nuclei, httpx, tlsx, katana, порты) запрещены.
	// Это защита от SSRF через A-запись вида 10.0.0.1/127.0.0.1.
	apexIPs := []string{}
	if ip := net.ParseIP(target); ip != nil {
		apexIPs = []string{target}
	} else if resolved, err := dns.Resolve(ctx, target); err == nil {
		apexIPs = resolved
	}
	apexSafe := hostSafeToProbe(apexIPs)

	var wg sync.WaitGroup
	var mu sync.Mutex

	addSubdomains := func(source string, subs []string) {
		mu.Lock()
		defer mu.Unlock()
		for _, sub := range subs {
			if sub == "" {
				continue
			}
			result.Subdomains = append(result.Subdomains, sub)
			if !containsString(result.SubdomainSources[sub], source) {
				result.SubdomainSources[sub] = append(result.SubdomainSources[sub], source)
			}
		}
	}

	// Nuclei: только для доменов, с отдельным таймаутом и изоляцией ошибок.
	var wgNuclei sync.WaitGroup
	wgNuclei.Add(1)
	go func() {
		defer wgNuclei.Done()
		if net.ParseIP(target) != nil {
			return
		}
		if !apexSafe {
			mu.Lock()
			result.Errors = append(result.Errors, "nuclei: skipped: apex resolves only to non-public IPs")
			mu.Unlock()
			return
		}
		nctx, cancel := context.WithTimeout(ctx, nucleiTimeout())
		defer cancel()
		findings, err := RunNuclei(nctx, target)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			result.Errors = append(result.Errors, "nuclei: "+err.Error())
			return
		}
		result.Vulnerabilities = findings
	}()

	// 1. Пассивный сбор (все источники параллельно)
	sources := []struct {
		name string
		fn   func(context.Context, string) ([]string, error)
	}{
		{"crtsh", func(c context.Context, d string) ([]string, error) { return NewCRTShClient().FetchSubdomains(c, d) }},
		{"crt.name", FetchCRTName},
		{"rapiddns", FetchRapidDNS},
		{"hackertarget", FetchHackerTarget},
		{"otx", FetchAlienVaultOTX},
		{"urlscan", FetchURLScan},
		{"tlscc", FetchTLSCC},
		{"subfinder", RunSubfinder},
	}

	for _, source := range sources {
		source := source
		wg.Add(1)
		go func() {
			defer wg.Done()
			subs, err := source.fn(ctx, target)
			if err != nil {
				mu.Lock()
				result.Errors = append(result.Errors, source.name+": "+err.Error())
				mu.Unlock()
				return
			}
			if len(subs) > 0 {
				addSubdomains(source.name, subs)
			}
		}()
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
		if !apexSafe {
			mu.Lock()
			result.Errors = append(result.Errors, "artifacts: skipped: apex resolves only to non-public IPs")
			mu.Unlock()
			return
		}
		arts, techs := AnalyzeArtifacts(ctx, target)
		result.Artifacts = arts
		result.Technologies = techs
	}()

	wg.Wait()
	result.Subdomains = uniqueSorted(result.Subdomains)
	// Источники каждого имени собираются горутинами в произвольном порядке —
	// сортируем, чтобы JSON и diff между прогонами были стабильны.
	for sub := range result.SubdomainSources {
		sort.Strings(result.SubdomainSources[sub])
	}

	// Wildcard проверяется до резолва имён: его IP-набор нужен, чтобы
	// не подтверждать сгенерированные DNS-ответы.
	wildcard := DetectWildcardDNS(ctx, target)
	result.WildcardDNS = wildcard.Detected
	result.WildcardIPs = wildcard.IPs

	// 3. IP-адреса и связь с поддоменами
	ips := append([]string{}, apexIPs...)

	// Резолвим поддомены параллельно: последовательный обход на больших зонах
	// съедал минуты и не оставлял времени на обогащение/Nuclei.
	var (
		dnsWG  sync.WaitGroup
		dnsSem = make(chan struct{}, 20)
	)
	for _, sub := range result.Subdomains {
		sub := sub
		dnsWG.Add(1)
		dnsSem <- struct{}{}
		go func() {
			defer dnsWG.Done()
			defer func() { <-dnsSem }()
			subIPs, err := dns.Resolve(ctx, sub)
			if err != nil || len(subIPs) == 0 {
				return
			}
			mu.Lock()
			ips = append(ips, subIPs...)
			result.SubdomainIPs[sub] = subIPs
			mu.Unlock()
		}()
	}
	dnsWG.Wait()
	result.IPs = uniqueSorted(ips)

	// Confidence считается только после резолва: имя без A-записи не может
	// быть high. Имя, чей резолв целиком совпал с wildcard-набором, понижается
	// до low независимо от числа источников.
	for _, sub := range result.Subdomains {
		subIPs := result.SubdomainIPs[sub]
		wildcardHit := isWildcardResolution(subIPs, wildcard.IPs)
		if wildcardHit {
			result.SubdomainWildcard[sub] = true
		}
		result.SubdomainConfidence[sub] = subdomainConfidence(
			len(result.SubdomainSources[sub]), len(subIPs) > 0, wildcardHit,
		)
	}

	// Публичные адреса можно сканировать, приватные/bogon — только показывать.
	publicIPs, privateIPs := splitPublicPrivateIPs(result.IPs)
	result.PrivateIPs = privateIPs

	// Дополнительные источники: обычные — по домену, batch-источники — по всем IP.
	// Запускаются после DNS, параллельно с ASN/портами; ошибки изолированы per-source.
	obsTargets := append([]string{}, publicIPs...)
	if net.ParseIP(target) != nil {
		obsTargets = append(obsTargets, target)
	}
	var wgObs sync.WaitGroup
	wgObs.Add(1)
	go func() {
		defer wgObs.Done()
		obs, errs := FetchAllSources(ctx, target, obsTargets...)
		mu.Lock()
		result.Observations = append(result.Observations, obs...)
		result.Errors = append(result.Errors, errs...)
		mu.Unlock()
	}()

	// 4. ASN — только публичные адреса (для приватных внешний API бессмысленен).
	for _, ip := range publicIPs {
		asn, _ := GetASN(ctx, ip)
		result.ASN[ip] = asn
	}

	// 4.1. Активные проверки (ProjectDiscovery CLI, если установлены).
	var wgActive sync.WaitGroup
	wgActive.Add(1)
	go func() {
		defer wgActive.Done()
		// В httpx уходят только хосты без приватных адресов: активная
		// проверка не должна касаться внутренней сети.
		hosts := activeProbeTargets(target, apexIPs, result.Subdomains, result.SubdomainIPs)
		probes, err := RunHTTPX(ctx, hosts)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			result.Errors = append(result.Errors, "httpx: "+err.Error())
			return
		}
		result.HTTP = probes
		for _, p := range probes {
			result.Technologies = append(result.Technologies, p.Technologies...)
		}
		result.Technologies = uniqueSorted(result.Technologies)
	}()

	wgActive.Add(1)
	go func() {
		defer wgActive.Done()
		if !apexSafe {
			mu.Lock()
			result.Errors = append(result.Errors, "tlsx: skipped: apex resolves only to non-public IPs")
			mu.Unlock()
			return
		}
		certs, err := RunTLSX(ctx, target)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			result.Errors = append(result.Errors, "tlsx: "+err.Error())
			return
		}
		result.TLS = certs
	}()

	wgActive.Add(1)
	go func() {
		defer wgActive.Done()
		if net.ParseIP(target) != nil {
			return
		}
		if !apexSafe {
			mu.Lock()
			result.Errors = append(result.Errors, "katana: skipped: apex resolves only to non-public IPs")
			mu.Unlock()
			return
		}
		endpoints, err := RunKatana(ctx, "https://"+target)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			result.Errors = append(result.Errors, "katana: "+err.Error())
			return
		}
		result.Endpoints = endpoints
	}()

	wgActive.Add(1)
	go func() {
		defer wgActive.Done()
		hits, err := FetchThreatFeeds(ctx, target, publicIPs, result.Subdomains)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			result.Errors = append(result.Errors, "threat-feeds: "+err.Error())
			return
		}
		result.ThreatHits = hits
	}()

	wgActive.Add(1)
	go func() {
		defer wgActive.Done()
		if net.ParseIP(target) != nil {
			return
		}
		buckets := CheckCloudBuckets(ctx, target)
		mu.Lock()
		result.CloudBuckets = buckets
		mu.Unlock()
	}()

	// 5. Порты: naabu top-1000 + быстрый fallback из 7 частых портов.
	if len(publicIPs) > 0 {
		portsClient := NewPortsClient()
		fallback, _ := portsClient.ScanPortsMany(ctx, publicIPs)
		fast, _ := RunNaabu(ctx, publicIPs, 1000)
		result.Ports = mergePorts(fallback, fast)

		var wgBanners sync.WaitGroup
		bannerSem := make(chan struct{}, 50)
		for ip, ports := range result.Ports {
			for _, port := range ports {
				wgBanners.Add(1)
				bannerSem <- struct{}{}
				go func(ipAddr string, p int) {
					defer wgBanners.Done()
					defer func() { <-bannerSem }()
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

	wgActive.Wait()
	wgObs.Wait()
	wgNuclei.Wait()
	result.Vulnerabilities = EnrichNucleiWithKEV(ctx, result.Vulnerabilities)
	result.Vulnerabilities = EnrichNucleiWithEPSS(ctx, result.Vulnerabilities)

	// Все параллельные стадии пишут срезы в произвольном порядке.
	// Стабилизируем их перед отдачей: иначе diff между прогонами и
	// сохранённые графы сравнивать невозможно.
	sortObservations(result.Observations)
	sortVulnerabilities(result.Vulnerabilities)
	sortHTTPProbes(result.HTTP)
	sortTLSInfos(result.TLS)
	sortThreatHits(result.ThreatHits)
	sortCloudBuckets(result.CloudBuckets)
	result.Errors = uniqueSorted(result.Errors)

	result.Duration = time.Since(start).Round(time.Millisecond).String()
	return result
}

// activeProbeTargets отбирает хосты для httpx: апекс и поддомены,
// у которых нет приватных адресов. Имена без резолва оставляем — решение
// принимает сам httpx; но если хотя бы один адрес приватный, хост запрещён.
func activeProbeTargets(target string, apexIPs, subs []string, subIPs map[string][]string) []string {
	out := make([]string, 0, len(subs)+1)
	if hostSafeToProbe(apexIPs) {
		out = append(out, target)
	}
	for _, sub := range subs {
		if hostSafeToProbe(subIPs[sub]) {
			out = append(out, sub)
		}
	}
	return uniqueSorted(out)
}

// nucleiTimeout — таймаут запуска Nuclei (NUCLEI_TIMEOUT, по умолчанию 5m).
func nucleiTimeout() time.Duration {
	if d, err := time.ParseDuration(envOr("NUCLEI_TIMEOUT", "5m")); err == nil && d > 0 {
		return d
	}
	return 5 * time.Minute
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
	// Без явной сортировки порядок зависел от обхода map и менялся между
	// прогонами — это ломало diff и сравнение сохранённых графов.
	sort.Strings(out)
	return out
}

// mergePorts объединяет результаты naabu и fallback-сканера.
func mergePorts(base, extra map[string][]int) map[string][]int {
	out := make(map[string][]int, len(base)+len(extra))
	for ip, ports := range base {
		out[ip] = uniquePorts(ports)
	}
	for ip, ports := range extra {
		out[ip] = uniquePorts(append(out[ip], ports...))
	}
	return out
}

func containsString(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
