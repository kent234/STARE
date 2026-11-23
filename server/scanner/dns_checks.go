package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DNSChecks — минимальная проверка почтовой/DNS-гигиены домена.
// Это не полноценный SPF-evaluator, но он ловит типовые ошибки:
// несколько SPF-записей (PermError), отсутствие DMARC/CAA, выключенный DNSSEC.
type DNSChecks struct {
	SPF         []string `json:"spf,omitempty"`
	SPFStatus   string   `json:"spf_status,omitempty"` // ok|missing|permerror
	DMARC       string   `json:"dmarc,omitempty"`
	DMARCPolicy string   `json:"dmarc_policy,omitempty"`
	DMARCStatus string   `json:"dmarc_status,omitempty"` // ok|missing
	CAA         []string `json:"caa,omitempty"`
	DNSSEC      bool     `json:"dnssec"`
	Issues      []string `json:"issues,omitempty"`
}

type dohAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	Data string `json:"data"`
}

type dohResponse struct {
	Status int         `json:"Status"`
	AD     bool        `json:"AD"`
	Answer []dohAnswer `json:"Answer"`
}

type dohClient struct {
	endpoints []string
	client    *http.Client
}

func newDOHClient() *dohClient {
	endpoints := []string{"https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"}
	if custom := os.Getenv("STARE_DOH_URL"); custom != "" {
		endpoints = []string{custom}
	}
	return &dohClient{
		endpoints: endpoints,
		client:    &http.Client{Timeout: 8 * time.Second},
	}
}

func (c *dohClient) query(ctx context.Context, name string, qtype int) (dohResponse, error) {
	var lastErr error
	for _, endpoint := range c.endpoints {
		sep := "?"
		if strings.Contains(endpoint, "?") {
			sep = "&"
		}
		link := endpoint + sep + "name=" + url.QueryEscape(name) + "&type=" + strconv.Itoa(qtype)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Accept", "application/dns-json")
		req.Header.Set("User-Agent", "Stare/1.0 (+osint)")
		resp, err := c.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("doh status: %d", resp.StatusCode)
			continue
		}
		var parsed dohResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			lastErr = err
			continue
		}
		if parsed.Status != 0 {
			lastErr = fmt.Errorf("dns rcode: %d", parsed.Status)
			continue
		}
		return parsed, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no doh endpoint configured")
	}
	return dohResponse{}, lastErr
}

// CheckEmailDNS проверяет SPF/DMARC/CAA/DNSSEC через DoH (без ключей).
func CheckEmailDNS(ctx context.Context, domain string) (DNSChecks, error) {
	return checkEmailDNSWith(ctx, domain, newDOHClient())
}

func checkEmailDNSWith(ctx context.Context, domain string, client *dohClient) (DNSChecks, error) {
	checks := DNSChecks{}

	spfAnswers, err := client.query(ctx, domain, 16)
	if err != nil {
		return checks, err
	}
	for _, answer := range spfAnswers.Answer {
		txt := cleanTXT(answer.Data)
		if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
			checks.SPF = append(checks.SPF, txt)
		}
	}
	switch {
	case len(checks.SPF) == 0:
		checks.SPFStatus = "missing"
		checks.Issues = append(checks.Issues, "SPF record is missing")
	case len(checks.SPF) > 1:
		checks.SPFStatus = "permerror"
		checks.Issues = append(checks.Issues, "multiple SPF records (PermError)")
	default:
		checks.SPFStatus = "ok"
	}

	dmarcAnswers, err := client.query(ctx, "_dmarc."+domain, 16)
	if err != nil {
		return checks, err
	}
	for _, answer := range dmarcAnswers.Answer {
		txt := cleanTXT(answer.Data)
		if strings.HasPrefix(strings.ToLower(txt), "v=dmarc1") {
			checks.DMARC = txt
			checks.DMARCStatus = "ok"
			if m := dmarcPolicyRe.FindStringSubmatch(txt); len(m) == 2 {
				checks.DMARCPolicy = strings.ToLower(m[1])
				if checks.DMARCPolicy == "none" {
					checks.Issues = append(checks.Issues, "DMARC policy is p=none")
				}
			}
			break
		}
	}
	if checks.DMARCStatus == "" {
		checks.DMARCStatus = "missing"
		checks.Issues = append(checks.Issues, "DMARC record is missing")
	}

	caaAnswers, err := client.query(ctx, domain, 257)
	if err != nil {
		return checks, err
	}
	for _, answer := range caaAnswers.Answer {
		if strings.TrimSpace(answer.Data) != "" {
			checks.CAA = append(checks.CAA, strings.TrimSpace(answer.Data))
		}
	}
	if len(checks.CAA) == 0 {
		checks.Issues = append(checks.Issues, "no CAA records")
	}

	dnssecAnswers, err := client.query(ctx, domain, 48)
	if err != nil {
		return checks, err
	}
	checks.DNSSEC = dnssecAnswers.AD && len(dnssecAnswers.Answer) > 0
	if !checks.DNSSEC {
		checks.Issues = append(checks.Issues, "DNSSEC is not enabled")
	}
	return checks, nil
}

var dmarcPolicyRe = regexp.MustCompile(`(?i)\bp\s*=\s*(none|quarantine|reject)`)

func cleanTXT(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"`)
	value = strings.ReplaceAll(value, `\"`, `"`)
	return strings.TrimSpace(value)
}
