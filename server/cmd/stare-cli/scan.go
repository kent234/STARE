package main

import (
	"context"
	"encoding/json"
	"fmt"
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
	ModDeepScan
	ModNuclei
)

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
	Technologies     []string                    `json:"technologies"`
	Observations     []scanner.Observation       `json:"observations,omitempty"`
	Vulnerabilities  []scanner.NucleiFinding     `json:"vulnerabilities"`
	ASN              map[string]string           `json:"asn"`
	SubdomainDetails map[string]*SubdomainReport `json:"subdomain_details,omitempty"`
	Errors           []string                    `json:"errors"`
	DurationMs       int64                       `json:"duration_ms"`
}

func runScan(ctx context.Context, target string, mods []ModuleID) *ScanResult {
	result := &ScanResult{
		Target:           target,
		Timestamp:        time.Now().Format(time.RFC3339),
		Ports:            map[string][]int{},
		ASN:              map[string]string{},
		SubdomainDetails: make(map[string]*SubdomainReport),
		Technologies:     []string{},
		Vulnerabilities:  []scanner.NucleiFinding{},
	}
	start := time.Now()

	if root, err := scanner.ExtractRootDomain(target); err == nil {
		result.Target = root
		target = root
	}

	isIP := net.ParseIP(target) != nil
	dns := scanner.NewDNSClient()

	var runCerts, runWordlist, runPorts, runDNS, runWhois, runFingerprint, runDeep, runNuclei bool
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
		case ModNuclei:
			runNuclei = true
		}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	addSubdomains := func(subs []string) {
		mu.Lock()
		defer mu.Unlock()
		result.Subdomains = append(result.Subdomains, subs...)
	}

	// 1. Сбор поддоменов
	if !isIP {
		isRF := strings.HasSuffix(target, ".xn--p1ai")

		if runCerts {
			LogInfo("Starting passive subdomain enumeration...")
			if isRF {
				wg.Add(1)
				go func() {
					defer wg.Done()
					LogInfo("Querying TLSCC (RU)...")
					subs, err := scanner.FetchTLSCC(ctx, target)
					if err != nil {
						LogWarn("TLSCC: " + err.Error())
					} else {
						addSubdomains(subs)
						LogSuccess(fmt.Sprintf("TLSCC: +%d subdomains", len(subs)))
					}
				}()
			} else {
				sources := []struct {
					Name string
					Fn   func(context.Context, string) ([]string, error)
				}{
					{"crt.sh", func(c context.Context, d string) ([]string, error) {
						return scanner.NewCRTShClient().FetchSubdomains(c, d)
					}},
					{"crt.name", scanner.FetchCRTName},
					{"RapidDNS", scanner.FetchRapidDNS},
					{"TLSCC", scanner.FetchTLSCC},
					{"HackerTarget", scanner.FetchHackerTarget},
					{"AlienVault OTX", scanner.FetchAlienVaultOTX},
					{"URLScan.io", scanner.FetchURLScan},
				}

				for _, src := range sources {
					wg.Add(1)
					go func(name string, fn func(context.Context, string) ([]string, error)) {
						defer wg.Done()
						LogInfo(fmt.Sprintf("Querying %s...", name))
						subs, err := fn(ctx, target)
						if err != nil {
							LogWarn(name + ": " + err.Error())
						} else {
							addSubdomains(subs)
							LogSuccess(fmt.Sprintf("%s: +%d subdomains", name, len(subs)))
						}
					}(src.Name, src.Fn)
				}
			}
		}

		if runWordlist {
			wg.Add(1)
			go func() {
				defer wg.Done()
				LogInfo("Starting wordlist brute-force...")
				wl := scanner.NewWordlistClient(dns)
				subs, err := wl.BruteSubdomains(ctx, target)
				if err != nil {
					LogWarn("Wordlist: " + err.Error())
				} else {
					addSubdomains(subs)
					LogSuccess(fmt.Sprintf("Wordlist: +%d subdomains", len(subs)))
				}
			}()
		}
		wg.Wait()
		mu.Lock()
		result.Subdomains = uniqueSorted(result.Subdomains)
		LogInfo(fmt.Sprintf("Total unique subdomains found: %d", len(result.Subdomains)))
		mu.Unlock()
	}

	// 2. WHOIS и DNS
	if runWhois && !isIP {
		LogInfo("Fetching WHOIS/RDAP data...")
		whoisData, err := scanner.FetchWhoisUniversal(ctx, target)
		if err == nil {
			result.Whois = whoisData
			LogSuccess("WHOIS/RDAP data retrieved")
		} else {
			LogWarn("WHOIS: " + err.Error())
		}
	}

	if runDNS && !isIP {
		LogInfo("Fetching extended DNS records (MX, TXT, NS)...")
		result.DNS = dns.ResolveExtended(ctx, target)
		LogSuccess("DNS records retrieved")
	}

	// 3. Резолвинг IP
	if isIP {
		result.IPs = append(result.IPs, target)
	} else {
		LogInfo("Resolving IPs for base domain and subdomains...")
		resolved, _ := dns.Resolve(ctx, target)
		ips := append(result.IPs, resolved...)

		mu.Lock()
		subsCopy := make([]string, len(result.Subdomains))
		copy(subsCopy, result.Subdomains)
		mu.Unlock()

		for _, sub := range subsCopy {
			if subIPs, err := dns.Resolve(ctx, sub); err == nil {
				ips = append(ips, subIPs...)
			}
		}
		result.IPs = uniqueSorted(ips)
		LogSuccess(fmt.Sprintf("Resolved %d unique IP addresses", len(result.IPs)))
	}

	// 4. ASN
	if len(result.IPs) > 0 {
		LogInfo("Fetching ASN information...")
		for _, ip := range result.IPs {
			asn, _ := scanner.GetASN(ctx, ip)
			result.ASN[ip] = asn
		}
		LogSuccess("ASN data retrieved")
	}

	// 5. Порты
	if runPorts && len(result.IPs) > 0 {
		sp := NewSpinner(fmt.Sprintf("Scanning ports on %d hosts...", len(result.IPs)))
		ports, _ := scanner.NewPortsClient().ScanPortsMany(ctx, result.IPs)
		sp.Stop()
		result.Ports = ports

		totalPorts := 0
		for _, p := range ports {
			totalPorts += len(p)
		}
		LogSuccess(fmt.Sprintf("Found %d open ports", totalPorts))
	}

	// 6. Артефакты и Фингерпринт (Wappalyzer)
	if runFingerprint && !isIP {
		sp := NewSpinner("Fingerprinting technologies (Wappalyzer)...")
		arts, techs := scanner.AnalyzeArtifacts(ctx, target)
		sp.Stop()
		result.Artifacts = arts
		result.Technologies = techs
		LogSuccess(fmt.Sprintf("Technologies detected: %v", techs))
	}

	// 7. Deep Scan
	if runDeep && !isIP && len(result.Subdomains) > 0 {
		sp := NewSpinner(fmt.Sprintf("Deep scanning %d subdomains...", len(result.Subdomains)))
		var wgDeep sync.WaitGroup
		var muDeep sync.Mutex
		sem := make(chan struct{}, 15) // Увеличили для скорости

		for _, sub := range result.Subdomains {
			wgDeep.Add(1)
			go func(subdomain string) {
				defer wgDeep.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				report := &SubdomainReport{}
				subIPs, err := dns.Resolve(ctx, subdomain)
				if err != nil {
					return
				}
				report.IPs = subIPs

				portsClient := scanner.NewPortsClient()
				openPorts, _ := portsClient.ScanPortsMany(ctx, subIPs)
				for _, ports := range openPorts {
					report.Ports = append(report.Ports, ports...)
				}
				report.Ports = uniqueInts(report.Ports)

				arts := scanner.CheckArtifacts(ctx, subdomain)
				report.Server = arts.ServerHdr
				report.RobotsTxt = arts.RobotsTxt

				if len(report.IPs) > 0 || len(report.Ports) > 0 || report.Server != "" {
					muDeep.Lock()
					result.SubdomainDetails[subdomain] = report
					muDeep.Unlock()
				}
			}(sub)
		}
		wgDeep.Wait()
		sp.Stop()
		LogSuccess(fmt.Sprintf("Deep Scan complete: analyzed %d responsive subdomains", len(result.SubdomainDetails)))
	}

	// 8. Nuclei (Уязвимости)
	if runNuclei && !isIP {
		sp := NewSpinner("Running Nuclei vulnerability scanner (this may take a while)...")
		findings, err := scanner.RunNuclei(ctx, target)
		sp.Stop()
		if err != nil {
			LogWarn("Nuclei: " + err.Error())
		} else {
			result.Vulnerabilities = findings
			LogSuccess(fmt.Sprintf("Nuclei: Found %d vulnerabilities", len(findings)))
		}
	}

	sp := NewSpinner("Querying threat intelligence sources...")
	obs, errs := scanner.FetchAllSources(ctx, target, result.IPs...)
	sp.Stop()
	result.Observations = obs
	result.Errors = append(result.Errors, errs...)
	if len(obs) > 0 {
		LogSuccess(fmt.Sprintf("Threat intel: %d observations", len(obs)))
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

	if len(r.Technologies) > 0 {
		fmt.Println(colorize("\n  [+] TECHNOLOGIES (Wappalyzer):", brightWhite))
		fmt.Printf("      ├── %s\n", strings.Join(r.Technologies, ", "))
	}

	if len(r.Vulnerabilities) > 0 {
		fmt.Println(colorize("\n  [!] VULNERABILITIES (Nuclei):", brightRed))
		for _, v := range r.Vulnerabilities {
			fmt.Printf("      ├── [%s] %s (%s)\n", strings.ToUpper(v.Severity), v.Name, v.MatchedAt)
		}
	}

	if len(r.Observations) > 0 {
		fmt.Println(colorize("\n  [+] THREAT INTEL:", brightWhite))
		counts := map[string]int{}
		for _, o := range r.Observations {
			counts[o.Source]++
		}
		for src, n := range counts {
			fmt.Printf("      ├── %s: %d observations\n", src, n)
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
