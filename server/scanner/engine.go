package scanner

import (
	"bufio"
	"context"
	"crypto/tls"
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
	SchemaVersion       string              `json:"schema_version"`
	ScanID              string              `json:"scan_id"`
	Meta                ScanMeta            `json:"scan_meta"`
	Target              string              `json:"target"`
	Subdomains          []string            `json:"subdomains"`
	SubdomainsRejected  int                 `json:"subdomains_rejected,omitempty"`
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
	Findings            []Finding           `json:"findings,omitempty"`
	HTTP                []HTTPProbe         `json:"http,omitempty"`
	TLS                 []TLSInfo           `json:"tls,omitempty"`
	Hosts               []HostInfo          `json:"hosts,omitempty"`
	Endpoints           []string            `json:"endpoints,omitempty"`
	EndpointsByHost     map[string][]string `json:"endpoints_by_host,omitempty"`
	DNSChecks           DNSChecks           `json:"dns_checks"`
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
		SchemaVersion:       SchemaVersion,
		ScanID:              NewScanID(),
		Meta:                newScanMeta(),
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
		for _, raw := range subs {
			sub, ok := normalizeSubdomain(raw, target)
			if !ok {
				// Считаем отброшенные имена: это объясняет разницу между
				// «источник вернул 319» и «реально проверено 200».
				result.SubdomainsRejected++
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
		// Пропуск по типу цели/приватному адресу — это skipped, а не missing.
		if net.ParseIP(target) != nil {
			mu.Lock()
			result.Meta.Tools["nuclei"] = ToolStatus{Status: ToolSkipped}
			result.Meta.Coverage["nuclei"] = StageCoverage{Skipped: 1}
			mu.Unlock()
			return
		}
		if !apexSafe {
			mu.Lock()
			result.Errors = append(result.Errors, "nuclei: skipped: apex resolves only to non-public IPs")
			result.Meta.Tools["nuclei"] = ToolStatus{Status: ToolSkipped}
			result.Meta.Coverage["nuclei"] = StageCoverage{Skipped: 1}
			mu.Unlock()
			return
		}
		if _, ok := toolBinary("NUCLEI_BINARY", "nuclei"); !ok {
			mu.Lock()
			result.Meta.Tools["nuclei"] = ToolStatus{Status: ToolMissing}
			result.Meta.Coverage["nuclei"] = StageCoverage{Attempted: 1, Skipped: 1}
			mu.Unlock()
			return
		}

		start := time.Now()
		nctx, cancel := context.WithTimeout(ctx, nucleiTimeout())
		defer cancel()
		findings, err := RunNuclei(nctx, target)
		status := ToolStatus{Status: ToolRan, DurationMS: time.Since(start).Milliseconds(), Input: 1, Items: len(findings)}
		if err != nil {
			status.Status = ToolError
			status.Error = err.Error()
		}
		mu.Lock()
		defer mu.Unlock()
		result.Meta.Tools["nuclei"] = status
		cov := result.Meta.Coverage["nuclei"]
		cov.Attempted = 1
		if err != nil {
			cov.Failed = 1
			result.Errors = append(result.Errors, "nuclei: "+err.Error())
			result.Meta.Coverage["nuclei"] = cov
			return
		}
		cov.Succeeded = 1
		result.Meta.Coverage["nuclei"] = cov
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

			// Subfinder — внешний бинарник; его отсутствие должно быть
			// видно как missing, а не как «источник ничего не нашёл».
			if source.name == "subfinder" {
				if _, ok := toolBinary("SUBFINDER_BIN", "subfinder"); !ok {
					mu.Lock()
					result.Meta.Tools["subfinder"] = ToolStatus{Status: ToolMissing}
					cov := result.Meta.Coverage["subdomains"]
					cov.Skipped++
					result.Meta.Coverage["subdomains"] = cov
					mu.Unlock()
					return
				}
			}

			started := time.Now()
			subs, err := source.fn(ctx, target)
			elapsed := time.Since(started)

			mu.Lock()
			cov := result.Meta.Coverage["subdomains"]
			cov.Attempted++
			if source.name == "subfinder" {
				status := ToolStatus{Status: ToolRan, DurationMS: elapsed.Milliseconds(), Input: 1, Items: len(subs)}
				if err != nil {
					status.Status = ToolError
					status.Error = err.Error()
				}
				result.Meta.Tools["subfinder"] = status
			}
			if err != nil {
				cov.Failed++
				result.Errors = append(result.Errors, source.name+": "+err.Error())
			} else {
				cov.Succeeded++
			}
			result.Meta.Coverage["subdomains"] = cov
			mu.Unlock()

			if err == nil && len(subs) > 0 {
				addSubdomains(source.name, subs)
			}
		}()
	}

	// 2. DNS, WHOIS, DNS-гигиена и Технологии
	wg.Add(4)
	go func() {
		defer wg.Done()
		result.DNS = dns.ResolveExtended(ctx, target)
	}()
	go func() {
		defer wg.Done()
		if net.ParseIP(target) != nil {
			return
		}
		checks, err := CheckEmailDNS(ctx, target)
		mu.Lock()
		defer mu.Unlock()
		result.DNSChecks = checks
		if err != nil {
			result.Errors = append(result.Errors, "dns-checks: "+err.Error())
		}
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

	// DNS coverage: сколько имён реально резолвится, а сколько осталось без A/AAAA.
	dnsAttempted := len(result.Subdomains)
	dnsSucceeded := len(result.SubdomainIPs)
	if net.ParseIP(target) == nil {
		dnsAttempted++
		if len(apexIPs) > 0 {
			dnsSucceeded++
		}
	}
	result.Meta.Coverage["dns"] = StageCoverage{
		Attempted: dnsAttempted,
		Succeeded: dnsSucceeded,
		Failed:    dnsAttempted - dnsSucceeded,
	}

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
		limit := httpxMaxTargets
		truncated := len(hosts) > limit
		if truncated {
			hosts = hosts[:limit]
		}

		if _, ok := toolBinary("HTTPX_BIN", "httpx"); !ok {
			mu.Lock()
			result.Meta.Tools["httpx"] = ToolStatus{Status: ToolMissing, Input: len(hosts)}
			result.Meta.Coverage["http"] = StageCoverage{Attempted: len(hosts), Skipped: len(hosts)}
			mu.Unlock()
			return
		}

		started := time.Now()
		probes, err := RunHTTPX(ctx, hosts)
		status := ToolStatus{
			Status:     ToolRan,
			DurationMS: time.Since(started).Milliseconds(),
			Input:      len(hosts),
			Items:      len(probes),
			Truncated:  truncated,
		}
		if err != nil {
			status.Status = ToolError
			status.Error = err.Error()
		}
		mu.Lock()
		defer mu.Unlock()
		result.Meta.Tools["httpx"] = status
		cov := StageCoverage{Attempted: len(hosts), Succeeded: len(probes)}
		if cov.Succeeded > cov.Attempted {
			cov.Succeeded = cov.Attempted
		}
		cov.Failed = cov.Attempted - cov.Succeeded
		result.Meta.Coverage["http"] = cov
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
		if net.ParseIP(target) != nil {
			mu.Lock()
			result.Meta.Tools["katana"] = ToolStatus{Status: ToolSkipped}
			mu.Unlock()
			return
		}
		if !apexSafe {
			mu.Lock()
			result.Errors = append(result.Errors, "katana: skipped: apex resolves only to non-public IPs")
			result.Meta.Tools["katana"] = ToolStatus{Status: ToolSkipped}
			mu.Unlock()
			return
		}
		if _, ok := toolBinary("KATANA_BIN", "katana"); !ok {
			mu.Lock()
			result.Meta.Tools["katana"] = ToolStatus{Status: ToolMissing, Input: 1}
			mu.Unlock()
			return
		}

		started := time.Now()
		rawEndpoints, err := RunKatana(ctx, "https://"+target)
		endpoints := filterEndpoints(rawEndpoints, target)
		dropped := len(rawEndpoints) - len(endpoints)
		truncated := false
		if len(endpoints) > katanaMaxEndpoints {
			endpoints = endpoints[:katanaMaxEndpoints]
			truncated = true
		}
		status := ToolStatus{
			Status:     ToolRan,
			DurationMS: time.Since(started).Milliseconds(),
			Input:      1,
			Items:      len(endpoints),
			Dropped:    dropped,
			Truncated:  truncated,
		}
		if err != nil {
			status.Status = ToolError
			status.Error = err.Error()
		}
		mu.Lock()
		defer mu.Unlock()
		result.Meta.Tools["katana"] = status
		rawCount := len(rawEndpoints)
		cov := StageCoverage{Attempted: rawCount, Succeeded: len(endpoints), Failed: dropped}
		result.Meta.Coverage["endpoints"] = cov
		if err != nil {
			result.Errors = append(result.Errors, "katana: "+err.Error())
			return
		}
		result.Endpoints = endpoints
		result.EndpointsByHost = groupEndpointsByHost(endpoints)
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

		// naabu — опциональный ускоритель; fallback-скан работает всегда,
		// но отсутствие naabu должно быть видно в scan_meta.
		fast := map[string][]int{}
		naabuStatus := ToolStatus{Status: ToolMissing, Input: len(publicIPs)}
		if _, ok := toolBinary("NAABU_BIN", "naabu"); ok {
			started := time.Now()
			var err error
			fast, err = RunNaabu(ctx, publicIPs, 1000)
			naabuStatus = ToolStatus{
				Status:     ToolRan,
				DurationMS: time.Since(started).Milliseconds(),
				Input:      len(publicIPs),
				Items:      countPorts(fast),
			}
			if err != nil {
				naabuStatus.Status = ToolError
				naabuStatus.Error = err.Error()
			}
		}

		result.Ports = mergePorts(fallback, fast)
		cov := StageCoverage{Attempted: len(publicIPs), Succeeded: len(result.Ports)}
		cov.Failed = cov.Attempted - cov.Succeeded
		mu.Lock()
		result.Meta.Tools["naabu"] = naabuStatus
		result.Meta.Coverage["ports"] = cov
		mu.Unlock()

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

	// TLS проверяется после портов/httpx: tlsx запускается по всем хостам
	// с открытым 443, а не только по апексу.
	tlsHosts := tlsCandidateHosts(target, apexIPs, result.Subdomains, result.SubdomainIPs, result.Ports, result.HTTP)
	result.TLS = mergeTLS(result.TLS, probeTLSInfo(result.HTTP))
	switch {
	case !apexSafe:
		result.Meta.Tools["tlsx"] = ToolStatus{Status: ToolSkipped, Input: len(tlsHosts)}
		result.Meta.Coverage["tls"] = StageCoverage{Attempted: len(tlsHosts), Skipped: len(tlsHosts)}
	case len(tlsHosts) == 0:
		result.Meta.Tools["tlsx"] = ToolStatus{Status: ToolSkipped}
	default:
		if _, ok := toolBinary("TLSX_BIN", "tlsx"); !ok {
			result.Meta.Tools["tlsx"] = ToolStatus{Status: ToolMissing, Input: len(tlsHosts)}
			result.Meta.Coverage["tls"] = StageCoverage{Attempted: len(tlsHosts), Skipped: len(tlsHosts)}
			break
		}
		started := time.Now()
		certs, err := RunTLSXHosts(ctx, tlsHosts)
		status := ToolStatus{
			Status:     ToolRan,
			DurationMS: time.Since(started).Milliseconds(),
			Input:      len(tlsHosts),
			Items:      len(certs),
			Truncated:  len(tlsHosts) >= tlsxMaxHosts,
		}
		cov := StageCoverage{Attempted: len(tlsHosts), Succeeded: len(certs)}
		if cov.Succeeded > cov.Attempted {
			cov.Succeeded = cov.Attempted
		}
		cov.Failed = cov.Attempted - cov.Succeeded
		if err != nil {
			status.Status = ToolError
			status.Error = err.Error()
			result.Errors = append(result.Errors, "tlsx: "+err.Error())
		} else {
			result.TLS = mergeTLS(result.TLS, certs)
		}
		result.Meta.Tools["tlsx"] = status
		result.Meta.Coverage["tls"] = cov
	}

	// Server-заголовки берём с реальных хостов, а не только с апекса.
	if result.Artifacts.ServerHeaders == nil {
		result.Artifacts.ServerHeaders = map[string]string{}
	}
	for _, probe := range result.HTTP {
		host := probeHost(probe.Input)
		if host == "" {
			host = probeHost(probe.URL)
		}
		if host != "" && probe.Webserver != "" {
			result.Artifacts.ServerHeaders[host] = probe.Webserver
		}
	}
	if result.Artifacts.ServerHdr == "" {
		for _, probe := range result.HTTP {
			if probeHost(probe.Input) == target && probe.Webserver != "" {
				result.Artifacts.ServerHdr = probe.Webserver
				break
			}
		}
	}

	result.Hosts = buildHosts(target, apexIPs, result)

	// Nuclei и Shodan обогащаются KEV/EPSS одним прогоном, но остаются
	// разными сущностями: local-подтверждение против observed-заявления.
	observedCVEs := shodanCVEFindings(result.Observations)
	nucleiCount := len(result.Vulnerabilities)
	combined := append([]NucleiFinding{}, result.Vulnerabilities...)
	combined = append(combined, observedCVEs...)
	combined = EnrichNucleiWithKEV(ctx, combined)
	combined = EnrichNucleiWithEPSS(ctx, combined)
	result.Vulnerabilities = append([]NucleiFinding{}, combined[:nucleiCount]...)
	observedCVEs = combined[nucleiCount:]
	for i := range observedCVEs {
		if observedCVEs[i].KEV || observedCVEs[i].EPSS >= 0.1 {
			observedCVEs[i].Severity = "high"
		}
	}
	result.Findings = BuildFindings(target, result.Vulnerabilities, observedCVEs, result.DNSChecks, result.CloudBuckets)

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

	var (
		conn net.Conn
		err  error
	)
	if isTLSPort(port) {
		// Для 443/8443 нужен реальный TLS-handshake, иначе «баннер»
		// был бы фиктивной строкой без единого сетевого запроса.
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
		})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if isWebPort(port) {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: STARE/1.0\r\nConnection: close\r\n\r\n", ip)
	}

	reader := bufio.NewReader(conn)
	buffer := make([]byte, 512)
	n, _ := reader.Read(buffer)
	if n == 0 {
		return ""
	}

	// Берём первую непустую строку, но не удаляем переводы строк из ответа
	// целиком: иначе «первая строка» склеивает весь 512-байтный кусок.
	raw := strings.ReplaceAll(string(buffer[:n]), "\r\n", "\n")
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.Map(func(r rune) rune {
			if r >= 32 && r <= 126 {
				return r
			}
			return -1
		}, line))
		if line == "" {
			continue
		}
		if len(line) > 200 {
			line = line[:200]
		}
		return line
	}
	return ""
}

func isTLSPort(port int) bool {
	switch port {
	case 443, 8443, 9443:
		return true
	default:
		return false
	}
}

func isWebPort(port int) bool {
	switch port {
	case 80, 443, 8000, 8080, 8443, 8888, 9443:
		return true
	default:
		return false
	}
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

// countPorts — число открытых портов во всех IP.
func countPorts(ports map[string][]int) int {
	total := 0
	for _, list := range ports {
		total += len(list)
	}
	return total
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
