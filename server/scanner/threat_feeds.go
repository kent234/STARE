package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ThreatHit — совпадение актива с бесплатным threat-feed.
type ThreatHit struct {
	Source    string `json:"source"`
	Indicator string `json:"indicator"`
	Detail    string `json:"detail,omitempty"`
}

// CloudBucket — облачное хранилище с доказательством, а не «кандидат».
type CloudBucket struct {
	Provider   string `json:"provider"`
	Name       string `json:"name"`
	URL        string `json:"url"`
	Status     int    `json:"status"`
	Public     bool   `json:"public"`
	Confidence string `json:"confidence,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
}

func httpGetBody(ctx context.Context, link string, limit int64) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "Stare/1.0 (+osint)")
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	return body, resp.StatusCode, err
}

// FetchThreatFeeds проверяет цель и её IP/поддомены по бесплатным фидам.
func FetchThreatFeeds(ctx context.Context, target string, ips, subdomains []string) ([]ThreatHit, error) {
	type feed struct {
		name string
		url  string
		kind string
	}
	feeds := []feed{
		{"openphish", "https://openphish.com/feed.txt", "url"},
		{"spamhaus-drop", "https://www.spamhaus.org/drop/drop.txt", "cidr"},
		{"tor-exits", "https://check.torproject.org/torbulkexitlist", "ip"},
	}

	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		hits []ThreatHit
	)
	for _, f := range feeds {
		f := f
		wg.Add(1)
		go func() {
			defer wg.Done()
			body, status, err := httpGetBody(ctx, f.url, 16<<20)
			if err != nil || status != http.StatusOK {
				return
			}
			found := matchFeed(f.kind, string(body), target, ips, subdomains)
			if len(found) == 0 {
				return
			}
			mu.Lock()
			for _, hit := range found {
				hit.Source = f.name
				hits = append(hits, hit)
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return hits, nil
}

func matchFeed(kind, body, target string, ips, subdomains []string) []ThreatHit {
	var hits []ThreatHit
	switch kind {
	case "url":
		known := map[string]struct{}{target: {}}
		for _, sub := range subdomains {
			known[strings.ToLower(sub)] = struct{}{}
		}
		for _, line := range strings.Split(body, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			u, err := url.Parse(line)
			if err != nil {
				continue
			}
			host := strings.ToLower(u.Hostname())
			if _, ok := known[host]; ok {
				hits = append(hits, ThreatHit{Indicator: host, Detail: line})
			}
		}
	case "ip":
		known := map[string]struct{}{}
		for _, ip := range ips {
			known[ip] = struct{}{}
		}
		for _, line := range strings.Split(body, "\n") {
			line = strings.TrimSpace(line)
			if _, ok := known[line]; ok {
				hits = append(hits, ThreatHit{Indicator: line})
			}
		}
	case "cidr":
		for _, netblock := range ips {
			ip := net.ParseIP(netblock)
			if ip == nil {
				continue
			}
			for _, line := range strings.Split(body, "\n") {
				line = strings.TrimSpace(strings.SplitN(line, ";", 2)[0])
				_, cidr, err := net.ParseCIDR(line)
				if err == nil && cidr.Contains(ip) {
					hits = append(hits, ThreatHit{Indicator: netblock, Detail: line})
				}
			}
		}
	}
	return hits
}

// EnrichNucleiWithKEV/EPSS добавляет приоритет уязвимостям (бесплатные CISA KEV + EPSS).
func EnrichNucleiWithKEV(ctx context.Context, findings []NucleiFinding) []NucleiFinding {
	if len(findings) == 0 {
		return findings
	}
	body, status, err := httpGetBody(ctx,
		"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", 32<<20)
	if err != nil || status != http.StatusOK {
		return findings
	}
	var kev struct {
		Vulnerabilities []struct {
			CVE string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if json.Unmarshal(body, &kev) != nil {
		return findings
	}
	known := map[string]struct{}{}
	for _, v := range kev.Vulnerabilities {
		known[v.CVE] = struct{}{}
	}
	for i := range findings {
		if _, ok := known[findings[i].TemplateID]; ok {
			findings[i].KEV = true
		}
	}
	return findings
}

func EnrichNucleiWithEPSS(ctx context.Context, findings []NucleiFinding) []NucleiFinding {
	var cves []string
	for _, f := range findings {
		if strings.HasPrefix(f.TemplateID, "CVE-") {
			cves = append(cves, f.TemplateID)
		}
	}
	if len(cves) == 0 {
		return findings
	}
	link := "https://api.first.org/data/v1/epss?cve=" + url.QueryEscape(strings.Join(cves, ","))
	body, status, err := httpGetBody(ctx, link, 4<<20)
	if err != nil || status != http.StatusOK {
		return findings
	}
	var resp struct {
		Data []struct {
			CVE  string `json:"cve"`
			EPSS string `json:"epss"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return findings
	}
	scores := map[string]float64{}
	for _, row := range resp.Data {
		var score float64
		fmt.Sscanf(row.EPSS, "%f", &score)
		scores[row.CVE] = score
	}
	for i := range findings {
		if score, ok := scores[findings[i].TemplateID]; ok {
			findings[i].EPSS = score
		}
	}
	return findings
}

// CheckCloudBuckets ищет публичные/существующие S3/GCS/Azure buckets по имени домена.
func CheckCloudBuckets(ctx context.Context, domain string) []CloudBucket {
	names := bucketNames(domain)
	providers := []struct {
		name string
		url  func(string) string
	}{
		{"aws", func(n string) string { return "https://" + n + ".s3.amazonaws.com/" }},
		{"gcs", func(n string) string { return "https://storage.googleapis.com/" + n }},
		{"azure", func(n string) string { return "https://" + n + ".blob.core.windows.net/" }},
	}

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		buckets []CloudBucket
		sem     = make(chan struct{}, 8)
	)
	client := &http.Client{Timeout: 8 * time.Second}
	for _, provider := range providers {
		for _, name := range names {
			provider, name := provider, name
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				link := provider.url(name)
				// GET, а не HEAD: публичность подтверждается телом листинга.
				// 403/404 — не доказательство существования и не попадают в отчёт.
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
				if err != nil {
					return
				}
				resp, err := client.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					return
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
				evidence := "HTTP 200"
				confidence := "medium"
				if bucketListing(body) {
					evidence = "public listing marker"
					confidence = "high"
				}
				mu.Lock()
				buckets = append(buckets, CloudBucket{
					Provider:   provider.name,
					Name:       name,
					URL:        link,
					Status:     resp.StatusCode,
					Public:     true,
					Confidence: confidence,
					Evidence:   evidence,
				})
				mu.Unlock()
			}()
		}
	}
	wg.Wait()
	return buckets
}

func bucketNames(domain string) []string {
	base := strings.Split(domain, ".")[0]
	if base == "" {
		return nil
	}
	return uniqueSorted([]string{
		base,
		"www-" + base,
		base + "-dev",
		base + "-prod",
		base + "-backup",
		base + "-data",
		base + "-assets",
		base + "-static",
	})
}

func bucketListing(body []byte) bool {
	lower := strings.ToLower(string(body))
	for _, marker := range []string{"<listbucketresult", "<enumerationresults", "<contents>", `"items":`} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
