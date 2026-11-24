package scanner

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Finding — единая сущность для отчёта. Nuclei, Shodan, DNS-гигиена и
// публичные bucket'ы больше не живут в разных форматах: у каждой находки
// есть severity, source (local/observed) и confidence.
type Finding struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Severity   string   `json:"severity"`
	Source     string   `json:"source"`
	Confidence string   `json:"confidence"`
	Host       string   `json:"host,omitempty"`
	URL        string   `json:"url,omitempty"`
	Evidence   string   `json:"evidence,omitempty"`
	CVE        []string `json:"cve,omitempty"`
	TemplateID string   `json:"template_id,omitempty"`
	KEV        bool     `json:"kev,omitempty"`
	EPSS       float64  `json:"epss,omitempty"`
}

// shodanCVEFindings превращает observations Shodan в CVE-записи для findings.
// Это observed-данные: они не доказывают эксплуатацию локально.
func shodanCVEFindings(observations []Observation) []NucleiFinding {
	var out []NucleiFinding
	seen := map[string]struct{}{}
	for _, obs := range observations {
		if obs.Source != "shodan" {
			continue
		}
		var payload struct {
			Indicator string   `json:"indicator"`
			Vulns     []string `json:"vulns"`
		}
		if json.Unmarshal(obs.Payload, &payload) != nil {
			continue
		}
		for _, cve := range payload.Vulns {
			cve = strings.TrimSpace(cve)
			if cve == "" {
				continue
			}
			key := cve + "|" + payload.Indicator
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, NucleiFinding{
				TemplateID: cve,
				Name:       "Shodan observed " + cve,
				Severity:   "medium",
				MatchedAt:  payload.Indicator,
			})
		}
	}
	return out
}

func BuildFindings(target string, nuclei, observed []NucleiFinding, dns DNSChecks, buckets []CloudBucket) []Finding {
	findings := make([]Finding, 0, len(nuclei)+len(observed)+len(dns.Issues)+len(buckets))
	seen := map[string]struct{}{}

	add := func(f Finding) {
		if f.ID == "" {
			return
		}
		if _, ok := seen[f.ID]; ok {
			return
		}
		seen[f.ID] = struct{}{}
		f.Severity = normalizeSeverity(f.Severity)
		findings = append(findings, f)
	}

	for _, item := range nuclei {
		finding := Finding{
			ID:         fmt.Sprintf("nuclei:%s:%s", item.TemplateID, item.MatchedAt),
			Title:      firstNonEmpty(item.Name, item.TemplateID, "Nuclei finding"),
			Severity:   item.Severity,
			Source:     "local",
			Confidence: "high",
			Host:       findingHost(item.MatchedAt),
			URL:        item.MatchedAt,
			Evidence:   "Nuclei template match",
			TemplateID: item.TemplateID,
			KEV:        item.KEV,
			EPSS:       item.EPSS,
		}
		if strings.HasPrefix(strings.ToUpper(item.TemplateID), "CVE-") {
			finding.CVE = []string{item.TemplateID}
		}
		add(finding)
	}

	for _, item := range observed {
		host := findingHost(item.MatchedAt)
		add(Finding{
			ID:         fmt.Sprintf("shodan:%s:%s", item.TemplateID, item.MatchedAt),
			Title:      fmt.Sprintf("Shodan reports %s", item.TemplateID),
			Severity:   item.Severity,
			Source:     "observed",
			Confidence: "medium",
			Host:       host,
			Evidence:   "Shodan vulns list",
			CVE:        []string{item.TemplateID},
			KEV:        item.KEV,
			EPSS:       item.EPSS,
		})
	}

	for _, issue := range dns.Issues {
		add(Finding{
			ID:         "dns:" + slug(issue),
			Title:      issue,
			Severity:   dnsIssueSeverity(issue),
			Source:     "local",
			Confidence: "high",
			Host:       target,
			Evidence:   "SPF/DMARC/CAA/DNSSEC check over DoH",
		})
	}

	for _, bucket := range buckets {
		if !bucket.Public {
			continue
		}
		add(Finding{
			ID:         fmt.Sprintf("cloud:%s:%s", bucket.Provider, bucket.Name),
			Title:      fmt.Sprintf("Public %s bucket: %s", bucket.Provider, bucket.Name),
			Severity:   "high",
			Source:     "local",
			Confidence: firstNonEmpty(bucket.Confidence, "medium"),
			Host:       bucket.Provider,
			URL:        bucket.URL,
			Evidence:   bucket.Evidence,
		})
	}

	sort.Slice(findings, func(i, j int) bool {
		left, right := severityRank(findings[i].Severity), severityRank(findings[j].Severity)
		if left != right {
			return left > right
		}
		return findings[i].ID < findings[j].ID
	})
	return findings
}

func normalizeSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "unknown"
	}
}

func severityRank(value string) int {
	switch value {
	case "critical":
		return 6
	case "high":
		return 5
	case "medium":
		return 4
	case "low":
		return 3
	case "info":
		return 2
	default:
		return 1
	}
}

func dnsIssueSeverity(issue string) string {
	lower := strings.ToLower(issue)
	switch {
	case strings.Contains(lower, "permerror"), strings.Contains(lower, "multiple spf"):
		return "high"
	case strings.Contains(lower, "spf record is missing"), strings.Contains(lower, "dmarc record is missing"):
		return "medium"
	case strings.Contains(lower, "p=none"), strings.Contains(lower, "caa"), strings.Contains(lower, "dnssec"):
		return "low"
	default:
		return "info"
	}
}

func findingHost(value string) string {
	if u, err := url.Parse(value); err == nil && u.Hostname() != "" {
		return strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
	}
	return strings.TrimPrefix(strings.ToLower(value), "www.")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func slug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	dash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			b.WriteRune(r)
			dash = false
		} else {
			dash = true
		}
	}
	if b.Len() == 0 {
		return "issue"
	}
	return b.String()
}
