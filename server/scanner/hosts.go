package scanner

import (
	"net/url"
	"sort"
	"strings"
)

// HostInfo — нормализованная модель хоста: вместо ручного join
// subdomain_ips + ports + http + tls потребитель получает одну запись.
type HostInfo struct {
	Host     string     `json:"host"`
	IPs      []string   `json:"ips,omitempty"`
	Resolved bool       `json:"resolved"`
	Wildcard bool       `json:"wildcard,omitempty"`
	Private  bool       `json:"private,omitempty"`
	Ports    []int      `json:"ports,omitempty"`
	HTTP     *HTTPProbe `json:"http,omitempty"`
	TLS      []TLSInfo  `json:"tls,omitempty"`
}

// buildHosts собирает hosts[] после всех активных стадий.
func buildHosts(target string, apexIPs []string, result *ScanResult) []HostInfo {
	hosts := uniqueSorted(append([]string{target}, result.Subdomains...))
	out := make([]HostInfo, 0, len(hosts))
	for _, host := range hosts {
		ips := result.SubdomainIPs[host]
		if host == target {
			ips = apexIPs
		}
		info := HostInfo{
			Host:     host,
			IPs:      uniqueSorted(ips),
			Resolved: len(ips) > 0,
			Wildcard: result.SubdomainWildcard[host],
			Private:  len(ips) > 0 && !hostSafeToProbe(ips),
			Ports:    hostPorts(ips, result.Ports),
			HTTP:     bestHTTPProbe(host, result.HTTP),
			TLS:      certsForHost(host, ips, result.TLS),
		}
		out = append(out, info)
	}
	return out
}

func hostPorts(ips []string, ports map[string][]int) []int {
	seen := map[int]struct{}{}
	out := []int{}
	for _, ip := range ips {
		for _, port := range ports[ip] {
			if _, ok := seen[port]; ok {
				continue
			}
			seen[port] = struct{}{}
			out = append(out, port)
		}
	}
	sort.Ints(out)
	return out
}

func bestHTTPProbe(host string, probes []HTTPProbe) *HTTPProbe {
	host = strings.TrimPrefix(strings.ToLower(host), "www.")
	var best *HTTPProbe
	bestScore := -1
	for i := range probes {
		probe := &probes[i]
		if probeHost(probe.Input) != host && probeHost(probe.URL) != host {
			continue
		}
		score := 0
		switch {
		case probe.StatusCode >= 200 && probe.StatusCode < 400:
			score += 100
		case probe.StatusCode >= 400:
			score += 10
		}
		if strings.HasPrefix(strings.ToLower(probe.URL), "https://") {
			score += 10
		}
		if score > bestScore {
			best, bestScore = probe, score
		}
	}
	return best
}

func probeTLSInfo(probes []HTTPProbe) []TLSInfo {
	out := []TLSInfo{}
	for _, probe := range probes {
		if probe.TLS == nil {
			continue
		}
		cert := *probe.TLS
		if cert.Host == "" {
			cert.Host = probeHost(probe.URL)
		}
		if cert.Port == "" {
			cert.Port = "443"
		}
		out = append(out, cert)
	}
	return out
}

func mergeTLS(left, right []TLSInfo) []TLSInfo {
	seen := map[string]struct{}{}
	out := make([]TLSInfo, 0, len(left)+len(right))
	for _, cert := range append(append([]TLSInfo{}, left...), right...) {
		key := cert.Host + "|" + cert.Port + "|" + cert.SubjectCN + "|" + cert.NotAfter
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, cert)
	}
	sortTLSInfos(out)
	return out
}

func probeHost(value string) string {
	if value == "" {
		return ""
	}
	if u, err := url.Parse(value); err == nil && u.Hostname() != "" {
		return strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
	}
	return strings.TrimPrefix(strings.ToLower(value), "www.")
}

func certsForHost(host string, ips []string, certs []TLSInfo) []TLSInfo {
	host = strings.TrimPrefix(strings.ToLower(host), "www.")
	ipSet := map[string]struct{}{}
	for _, ip := range ips {
		ipSet[ip] = struct{}{}
	}
	seen := map[string]struct{}{}
	out := []TLSInfo{}
	for _, cert := range certs {
		certHost := strings.TrimPrefix(strings.ToLower(cert.Host), "www.")
		matches := certHost == host
		if _, ok := ipSet[cert.Host]; ok {
			matches = true
		}
		if !matches {
			for _, san := range cert.SAN {
				if sanMatchesHost(san, host) {
					matches = true
					break
				}
			}
		}
		if !matches {
			continue
		}
		key := cert.Host + "|" + cert.Port + "|" + cert.SubjectCN
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, cert)
	}
	sortTLSInfos(out)
	return out
}

func sanMatchesHost(san, host string) bool {
	san = strings.TrimPrefix(strings.ToLower(san), "www.")
	if san == host {
		return true
	}
	if strings.HasPrefix(san, "*.") {
		suffix := san[1:] // ".example.com"
		return strings.HasSuffix(host, suffix) && strings.Count(host, ".") == strings.Count(suffix, ".")
	}
	return false
}

// tlsCandidateHosts выбирает хосты для tlsx: те, у кого реально открыт 443
// (по naabu/fallback) или есть HTTPS-проба httpx. Иначе tlsx по всем именам
// бессмысленно замедляет скан.
func tlsCandidateHosts(target string, apexIPs []string, subs []string, subIPs map[string][]string, ports map[string][]int, probes []HTTPProbe) []string {
	set := map[string]struct{}{}
	ip443 := map[string]struct{}{}
	for ip, list := range ports {
		for _, port := range list {
			if port == 443 {
				ip443[ip] = struct{}{}
				break
			}
		}
	}
	for _, host := range append([]string{target}, subs...) {
		ips := subIPs[host]
		if host == target {
			ips = apexIPs
		}
		for _, ip := range ips {
			if _, ok := ip443[ip]; ok {
				set[host] = struct{}{}
				break
			}
		}
	}
	for _, probe := range probes {
		if !strings.HasPrefix(strings.ToLower(probe.URL), "https://") {
			continue
		}
		if host := probeHost(probe.URL); host != "" {
			set[host] = struct{}{}
		}
	}
	// Если порты не собрались, но апекс публичный — хотя бы проверим его.
	if len(set) == 0 && hostSafeToProbe(apexIPs) {
		set[target] = struct{}{}
	}

	out := make([]string, 0, len(set))
	for host := range set {
		out = append(out, host)
	}
	sort.Strings(out)
	if len(out) > tlsxMaxHosts {
		out = out[:tlsxMaxHosts]
	}
	return out
}
