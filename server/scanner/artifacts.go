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
	RobotsTxt  []string `json:"robots_txt"`
	ServerHdr  string   `json:"server_header"`
	FaviconMD5 string   `json:"favicon_md5"`
}

func CheckArtifacts(ctx context.Context, domain string) Artifacts {
	var res Artifacts
	client := &http.Client{Timeout: 10 * time.Second}
	baseURL := fmt.Sprintf("https://%s", domain)

	if resp, err := client.Get(baseURL); err == nil {
		res.ServerHdr = resp.Header.Get("Server")
		resp.Body.Close()
	}

	if resp, err := client.Get(baseURL + "/robots.txt"); err == nil && resp.StatusCode == 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 500<<10))
		resp.Body.Close()
		for _, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(line, "Disallow:") {
				res.RobotsTxt = append(res.RobotsTxt, strings.TrimSpace(strings.TrimPrefix(line, "Disallow:")))
			}
		}
	}

	if resp, err := client.Get(baseURL + "/favicon.ico"); err == nil && resp.StatusCode == 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 100<<10))
		resp.Body.Close()
		res.FaviconMD5 = fmt.Sprintf("%x", md5.Sum(body))
	}
	return res
}
