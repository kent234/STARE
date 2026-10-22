package main

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
	"time"

	"stare/server/scanner"
)

type ModuleID int

const (
	ModCerts ModuleID = iota + 1
	ModDNS
	ModWordlist
	ModPorts
)

type ScanResult struct {
	Target     string
	Subdomains []string
	IPs        []string
	Ports      map[string][]int
	Errors     []string
	Duration   time.Duration
}

func fakeLogs(ctx context.Context, target string) {
	logs := []string{
		"Initializing S.T.A.R.E engine v0.1...",
		"Loading target modules...",
		fmt.Sprintf("Target acquired: %s", target),
		"Bypassing local firewall restrictions...",
		"Establishing secure tunnel...",
		"Querying Certificate Transparency logs...",
		"Resolving DNS A/AAAA records...",
		"Brute-forcing subdomains via built-in wordlist...",
		"Probing TCP ports [stealth mode]...",
		"Analyzing responses...",
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
	result := &ScanResult{Target: target, Ports: map[string][]int{}}
	start := time.Now()

	isIP := net.ParseIP(target) != nil
	dns := scanner.NewDNSClient()

	for _, m := range mods {
		switch m {
		case ModCerts:
			if isIP {
				continue
			}
			sp := NewSpinner("Hunting for SSL certificates...")
			subs, err := scanner.NewCRTShClient().FetchSubdomains(ctx, target)
			sp.Stop()
			if err != nil {
				LogError("crt.sh: " + err.Error())
			} else {
				result.Subdomains = append(result.Subdomains, subs...)
				LogSuccess(fmt.Sprintf("Found %d subdomains via crt.sh", len(subs)))
			}
		case ModDNS:
			if isIP {
				result.IPs = append(result.IPs, target)
				LogSuccess("Target is IP: " + target)
				continue
			}
			sp := NewSpinner("Resolving target IPs...")
			ips, err := dns.Resolve(ctx, target)
			sp.Stop()
			if err != nil {
				LogError("DNS: " + err.Error())
			} else {
				result.IPs = append(result.IPs, ips...)
				LogSuccess(fmt.Sprintf("Resolved %d IP(s)", len(ips)))
			}
		case ModWordlist:
			if isIP {
				continue
			}
			sp := NewSpinner("Brute-forcing subdomains...")
			subs, err := scanner.NewWordlistClient(dns).BruteSubdomains(ctx, target)
			sp.Stop()
			if err != nil {
				LogError("Wordlist: " + err.Error())
			} else {
				result.Subdomains = append(result.Subdomains, subs...)
				LogSuccess(fmt.Sprintf("Found %d subdomains via wordlist", len(subs)))
			}
		case ModPorts:
			ips := result.IPs
			if !isIP && len(ips) == 0 {
				resolved, _ := dns.Resolve(ctx, target)
				ips = resolved
				result.IPs = append(result.IPs, resolved...)
			}
			if len(ips) > 0 {
				sp := NewSpinner(fmt.Sprintf("Scanning ports on %d host(s)...", len(ips)))
				ports, err := scanner.NewPortsClient().ScanPortsMany(ctx, ips)
				sp.Stop()
				if err != nil {
					LogError("Ports: " + err.Error())
				} else {
					result.Ports = ports
					total := 0
					for _, p := range ports {
						total += len(p)
					}
					LogSuccess(fmt.Sprintf("Found %d open ports", total))
				}
			}
		}
	}

	result.Duration = time.Since(start)
	return result
}

func printResults(r *ScanResult) {
	r.Subdomains = uniqueSorted(r.Subdomains)
	r.IPs = uniqueSorted(r.IPs)

	BoxedText("INTELLIGENCE REPORT: " + r.Target)

	if len(r.Subdomains) > 0 {
		fmt.Println(colorize("  [+] SUBDOMAINS FOUND:", brightWhite))
		for _, s := range r.Subdomains {
			fmt.Println(colorize("      ├── ", dim) + s)
		}
	}

	if len(r.IPs) > 0 {
		fmt.Println()
		fmt.Println(colorize("  [+] IP ADDRESSES:", brightWhite))
		for _, ip := range r.IPs {
			fmt.Println(colorize("      ├── ", dim) + ip)
		}
	}

	if len(r.Ports) > 0 {
		fmt.Println()
		fmt.Println(colorize("  [+] OPEN PORTS (TCP):", brightWhite))
		for h, p := range r.Ports {
			for _, port := range p {
				state := colorize("OPEN", brightGreen)
				if isRisky(port) {
					state = colorize("OPEN [RISKY]", blink+brightRed)
				}
				fmt.Printf("      ├── %s:%d  →  %s\n", h, port, state)
			}
		}
	}

	if len(r.Errors) > 0 {
		fmt.Println()
		for _, e := range r.Errors {
			LogError(e)
		}
	}

	fmt.Println()
	fmt.Println(colorize(fmt.Sprintf("  [ Execution time: %s ]", r.Duration.Round(time.Millisecond)), dim))
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

func isRisky(port int) bool {
	risky := map[int]bool{22: true, 3306: true, 3389: true, 6379: true}
	return risky[port]
}
