package scanner

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Artifacts struct {
	RobotsTxt     []string          `json:"robots_txt"`
	Allow         []string          `json:"allow,omitempty"`
	Sitemaps      []string          `json:"sitemaps,omitempty"`
	ServerHdr     string            `json:"server_header"`
	ServerHeaders map[string]string `json:"server_headers,omitempty"`
	FaviconMD5    string            `json:"favicon_md5"`
}

func CheckArtifacts(ctx context.Context, domain string) Artifacts {
	var last Artifacts
	for _, baseURL := range []string{"https://" + domain, "http://" + domain} {
		res, ok := fetchArtifactsBase(ctx, baseURL)
		if res.ServerHdr != "" {
			last.ServerHdr = res.ServerHdr
		}
		if ok {
			if last.ServerHdr != "" {
				res.ServerHdr = last.ServerHdr
			}
			return res
		}
	}
	return last
}

// fetchArtifactsBase собирает robots/sitemap/Allow/favicon с одного origin.
// HTTPS→HTTP fallback делает проверку рабочей и для доменов без TLS.
func fetchArtifactsBase(ctx context.Context, baseURL string) (Artifacts, bool) {
	var res Artifacts
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get(baseURL)
	if err != nil {
		return res, false
	}
	res.ServerHdr = resp.Header.Get("Server")
	status := resp.StatusCode
	resp.Body.Close()
	if status >= 400 {
		return res, false
	}

	if robots, ok := fetchText(ctx, client, baseURL+"/robots.txt"); ok {
		res.RobotsTxt, res.Allow, res.Sitemaps = parseRobots(robots)
	}

	if body, ok := fetchBytes(ctx, client, baseURL+"/favicon.ico", 100<<10); ok {
		res.FaviconMD5 = fmt.Sprintf("%x", md5.Sum(body))
	}
	return res, true
}

func parseRobots(body string) (disallow, allow, sitemaps []string) {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "disallow:"):
			if value := strings.TrimSpace(line[len("disallow:"):]); value != "" {
				disallow = append(disallow, value)
			}
		case strings.HasPrefix(lower, "allow:"):
			if value := strings.TrimSpace(line[len("allow:"):]); value != "" {
				allow = append(allow, value)
			}
		case strings.HasPrefix(lower, "sitemap:"):
			if value := strings.TrimSpace(line[len("sitemap:"):]); value != "" {
				sitemaps = append(sitemaps, value)
			}
		}
	}
	return disallow, allow, sitemaps
}

func fetchText(ctx context.Context, client *http.Client, link string) (string, bool) {
	body, ok := fetchBytes(ctx, client, link, 500<<10)
	return string(body), ok
}

func fetchBytes(ctx context.Context, client *http.Client, link string, limit int64) ([]byte, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return nil, false
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, false
	}
	return body, true
}
