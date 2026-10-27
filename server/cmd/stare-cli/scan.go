package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"stare/server/scanner"
)

type ModuleID int

const (
	ModCerts ModuleID = iota + 1
	ModDNS
	ModWordlist
	ModPorts
	ModWhois
	ModFingerprint
	ModDeepScan // Новый модуль
)

// Детальный отчет по каждому поддомену
type SubdomainReport struct {
	IPs       []string `json:"ips,omitempty"`
	Ports     []int    `json:"ports,omitempty"`
	Server    string   `json:"server,omitempty"`
	RobotsTxt []string `json:"robots_txt,omitempty"`
}

type ScanResult struct {
	Target           string                      `json:"target"`
	Timestamp        string                      `json:"timestamp"`
	Subdomains       []string                    `json:"subdomains"`
	IPs              []string                    `json:"ips"`
	Ports            map[string][]int            `json:"ports"`
	DNS              scanner.ExtendedDNS         `json:"dns"`
	Whois            map[string]string           `json:"whois"`
	Artifacts        scanner.Artifacts           `json:"artifacts"`
	ASN              map[string]string           `json:"asn"`
	SubdomainDetails map[string]*SubdomainReport `json:"subdomain_details,omitempty"` // НОВОЕ
	Errors           []string                    `json:"errors"`
	DurationMs       int64                       `json:"duration_ms"`
}

func fakeLogs(ctx context.Context, target string) {
	logs := []string{
		"Initializing S.T.A.R.E engine v0.4...",
		fmt.Sprintf("Target acquired: %s", target),
		"Bypassing local firewall restrictions...",
		"Querying Certificate Transparency logs...",
		"Brute-forcing subdomains...",
		"Resolving DNS records...",
		"Probing TCP ports...",
		"Compiling intelligence report...",
	}
	for _, l := range logs {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(200+rand.Intn(300)) * time.Millisecond):
			LogHack(l)
		}
	}
}

func runScan(ctx context.Context, target string, mods []ModuleID) *ScanResult {
	result := &ScanResult{
		Target:           target,
		Timestamp:        time.Now().Format(time.RFC3339),
		Ports:            map[string][]int{},
		ASN:              map[string]string{},
		SubdomainDetails: make(map[string]*SubdomainReport),
	}
	start := time.Now()

	isIP := net.ParseIP(target) != nil
	dns := scanner.NewDNSClient()

	var runCerts, runWordlist, runPorts, runDNS, runWhois, runFingerprint, runDeep bool
	for _, m := range mods {
		switch m {
		case ModCerts:
			runCerts = true
		case ModWordlist:
			runWordlist = true
		case ModPorts:
			runPorts = true
		case ModDNS:
			runDNS = true
		case ModWhois:
			runWhois = true
		case ModFingerprint:
			runFingerprint = true
		case ModDeepScan:
			runDeep = true
		}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	addSubdomains := func(subs []string) {
		mu.Lock()
		defer mu.Unlock()
		result.Subdomains = append(result.Subdomains, subs...)
	}

	// 1. Сбор поддоменов (если выбраны модули)
	if !isIP {
		if runCerts {
			// crt.sh
			wg.Add(1)
			go func() {
				defer wg.Done()
				sp := NewSpinner("Hunting via crt.sh...")
				subs, err := scanner.NewCRTShClient().FetchSubdomains(ctx, target)
				sp.Stop()
				if err != nil {
					LogError("crt.sh: " + err.Error())
				} else {
					addSubdomains(subs)
					LogSuccess(fmt.Sprintf("crt.sh: +%d subs", len(subs)))
				}
			}()

			// crt.name
			wg.Add(1)
			go func() {
				defer wg.Done()
				sp := NewSpinner("Hunting via crt.name...")
				subs, err := scanner.FetchCRTName(ctx, target)
				sp.Stop()
				if err != nil {
					LogError("crt.name: " + err.Error())
				} else {
					addSubdomains(subs)
					LogSuccess(fmt.Sprintf("crt.name: +%d subs", len(subs)))
				}
			}()

			// RapidDNS
			wg.Add(1)
			go func() {
				defer wg.Done()
				sp := NewSpinner("Hunting via RapidDNS...")
				subs, err := scanner.FetchRapidDNS(ctx, target)
				sp.Stop()
				if err != nil {
					LogError("RapidDNS: " + err.Error())
				} else {
					addSubdomains(subs)
					LogSuccess(fmt.Sprintf("RapidDNS: +%d subs", len(subs)))
				}
			}()
			// TLSCC (Российский CT-лог)
			wg.Add(1)
			go func() {
				defer wg.Done()
				sp := NewSpinner("Hunting via TLSCC (RU)...")
				subs, err := scanner.FetchTLSCC(ctx, target)
				sp.Stop()
				if err != nil {
					LogWarn("TLSCC: " + err.Error()) // Желтое предупреждение, а не красная ошибка
				} else {
					addSubdomains(subs)
					LogSuccess(fmt.Sprintf("TLSCC: +%d subs", len(subs)))
				}
			}()
		}
		if runWordlist {
			wg.Add(1)
			go func() {
				defer wg.Done()
				wl := scanner.NewWordlistClient(dns)
				subs, _ := wl.BruteSubdomains(ctx, target)
				addSubdomains(subs)
				LogSuccess(fmt.Sprintf("Wordlist: +%d subs", len(subs)))
			}()
		}
		wg.Wait()
		mu.Lock()
		result.Subdomains = uniqueSorted(result.Subdomains)
		mu.Unlock()
	}

	// 2. DNS и WHOIS основного домена
	if runWhois && !isIP {
		whois, err := scanner.FetchWhois(ctx, target)
		if err == nil {
			result.Whois = whois
		}
	}
	if runDNS && !isIP {
		result.DNS = dns.ResolveExtended(ctx, target)
	}

	// 3. РЕЗОЛВИНГ IP основного домена и поддоменов
	ips := result.IPs
	if isIP {
		ips = append(ips, target)
	} else {
		resolved, _ := dns.Resolve(ctx, target)
		ips = append(ips, resolved...)
		mu.Lock()
		subsCopy := make([]string, len(result.Subdomains))
		copy(subsCopy, result.Subdomains)
		mu.Unlock()
		for _, sub := range subsCopy {
			if subIPs, err := dns.Resolve(ctx, sub); err == nil {
				ips = append(ips, subIPs...)
			}
		}
	}
	result.IPs = uniqueSorted(ips)

	// 4. ASN для всех IP
	for _, ip := range result.IPs {
		asn, _ := scanner.GetASN(ctx, ip)
		result.ASN[ip] = asn
	}

	// 5. СКАНИРОВАНИЕ ПОРТОВ (основные IP)
	if runPorts && len(result.IPs) > 0 {
		ports, _ := scanner.NewPortsClient().ScanPortsMany(ctx, result.IPs)
		result.Ports = ports
	}

	// 6. Артефакты основного домена
	if runFingerprint && !isIP {
		result.Artifacts = scanner.CheckArtifacts(ctx, target)
	}

	// 7. РЕКУРСИВНЫЙ СКАН (Deep Scan) для поддоменов
	if runDeep && !isIP && len(result.Subdomains) > 0 {
		sp := NewSpinner(fmt.Sprintf("Deep scanning %d subdomains...", len(result.Subdomains)))

		var wgDeep sync.WaitGroup
		var muDeep sync.Mutex
		// Ограничиваем параллельность, чтобы не забанили
		sem := make(chan struct{}, 5)

		for _, sub := range result.Subdomains {
			wgDeep.Add(1)
			go func(subdomain string) {
				defer wgDeep.Done()
				sem <- struct{}{}        // Захватываем слот
				defer func() { <-sem }() // Освобождаем слот

				report := &SubdomainReport{}

				// Резолвим IP поддомена
				subIPs, err := dns.Resolve(ctx, subdomain)
				if err != nil {
					return
				}
				report.IPs = subIPs

				// Сканируем порты (только базовые 80, 443, 8080)
				portsClient := scanner.NewPortsClient()
				openPorts, _ := portsClient.ScanPortsMany(ctx, subIPs)
				for _, ports := range openPorts {
					report.Ports = append(report.Ports, ports...)
				}
				report.Ports = uniqueInts(report.Ports)

				// Снимаем заголовки и robots.txt
				arts := scanner.CheckArtifacts(ctx, subdomain)
				report.Server = arts.ServerHdr
				report.RobotsTxt = arts.RobotsTxt

				// Сохраняем, если есть хоть какая-то инфа
				if len(report.IPs) > 0 || len(report.Ports) > 0 || report.Server != "" {
					muDeep.Lock()
					result.SubdomainDetails[subdomain] = report
					muDeep.Unlock()
				}
			}(sub)
		}
		wgDeep.Wait()
		sp.Stop()
		LogSuccess(fmt.Sprintf("Deep scanned %d subdomains", len(result.SubdomainDetails)))
	}

	result.DurationMs = time.Since(start).Milliseconds()
	return result
}

func saveReport(r *ScanResult) {
	safeName := strings.ReplaceAll(r.Target, ".", "_")
	fileName := fmt.Sprintf("stare_report_%s_%s.json", safeName, time.Now().Format("20060102_150405"))

	file, err := os.Create(fileName)
	if err != nil {
		LogError("Failed to create report: " + err.Error())
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encoder.Encode(r)

	LogSuccess(fmt.Sprintf("Report saved: %s", colorize(fileName, brightCyan)))
}

func printResults(r *ScanResult) {
	BoxedText("INTELLIGENCE REPORT: " + r.Target)

	if len(r.Subdomains) > 0 {
		fmt.Println(colorize(fmt.Sprintf("  [+] SUBDOMAINS (%d):", len(r.Subdomains)), brightWhite))
		for _, s := range r.Subdomains[:min(10, len(r.Subdomains))] {
			fmt.Println(colorize("      ├── ", dim) + s)
		}
		if len(r.Subdomains) > 10 {
			fmt.Println(colorize("      └── ... and more", dim))
		}
	}

	if len(r.IPs) > 0 {
		fmt.Println(colorize("\n  [+] TOP IPs:", brightWhite))
		for _, ip := range r.IPs[:min(5, len(r.IPs))] {
			fmt.Printf("      ├── %s [%s]\n", ip, r.ASN[ip])
		}
	}

	if len(r.Ports) > 0 {
		fmt.Println(colorize("\n  [+] OPEN PORTS:", brightWhite))
		for h, p := range r.Ports {
			if len(p) > 0 {
				fmt.Printf("      ├── %s → %v\n", h, p)
			}
		}
	}

	if len(r.SubdomainDetails) > 0 {
		fmt.Println(colorize("\n  [+] DEEP SCAN RESULTS:", brightWhite))
		for sub, detail := range r.SubdomainDetails {
			fmt.Printf("      ├── %s\n", colorize(sub, brightGreen))
			if detail.Server != "" {
				fmt.Printf("      │   ├── Server: %s\n", detail.Server)
			}
			if len(detail.Ports) > 0 {
				fmt.Printf("      │   ├── Ports: %v\n", detail.Ports)
			}
		}
	}

	fmt.Println()
	fmt.Println(colorize(fmt.Sprintf("  [ Execution time: %s ]", time.Duration(r.DurationMs)*time.Millisecond), dim))
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
	sort.Strings(out)
	return out
}

func uniqueInts(in []int) []int {
	seen := map[int]struct{}{}
	for _, n := range in {
		seen[n] = struct{}{}
	}
	out := make([]int, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
