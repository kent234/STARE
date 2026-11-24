package scanner

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestShodanCVEFindings(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{"indicator": "1.2.3.4", "vulns": []string{"CVE-2024-1111", "CVE-2024-2222"}})
	obs := []Observation{{Source: "shodan", Payload: payload}}
	got := shodanCVEFindings(obs)
	if len(got) != 2 || got[0].TemplateID != "CVE-2024-1111" || got[0].MatchedAt != "1.2.3.4" {
		t.Fatalf("shodan findings = %+v", got)
	}
}

func TestBuildFindings(t *testing.T) {
	nuclei := []NucleiFinding{
		{TemplateID: "CVE-2024-1111", Name: "RCE", Severity: "critical", MatchedAt: "https://api.example.com/x", KEV: true, EPSS: 0.9},
	}
	observed := []NucleiFinding{
		{TemplateID: "CVE-2024-2222", Severity: "medium", MatchedAt: "1.2.3.4"},
	}
	dns := DNSChecks{Issues: []string{
		"multiple SPF records (PermError)",
		"DMARC policy is p=none",
		"no CAA records",
	}}
	buckets := []CloudBucket{
		{Provider: "aws", Name: "example-assets", URL: "https://example-assets.s3.amazonaws.com/", Public: true, Confidence: "high", Evidence: "public listing marker"},
		{Provider: "gcs", Name: "example-private", Public: false},
	}

	got := BuildFindings("example.com", nuclei, observed, dns, buckets)
	if len(got) != 6 {
		t.Fatalf("findings = %+v", got)
	}
	if got[0].Severity != "critical" || got[0].Source != "local" || got[0].KEV != true {
		t.Fatalf("first finding = %+v", got[0])
	}
	var shodan *Finding
	var dnsHigh, dnsLow, bucket *Finding
	for i := range got {
		switch {
		case got[i].Source == "observed":
			shodan = &got[i]
		case strings.HasPrefix(got[i].ID, "dns:"):
			if got[i].Severity == "high" {
				dnsHigh = &got[i]
			} else {
				dnsLow = &got[i]
			}
		case strings.HasPrefix(got[i].ID, "cloud:"):
			bucket = &got[i]
		}
	}
	if shodan == nil || shodan.Confidence != "medium" || len(shodan.CVE) != 1 {
		t.Fatalf("shodan finding = %+v", shodan)
	}
	if dnsHigh == nil || dnsLow == nil {
		t.Fatalf("dns findings = %+v", got)
	}
	if bucket == nil || bucket.Severity != "high" || bucket.Confidence != "high" {
		t.Fatalf("bucket finding = %+v", bucket)
	}
}

func TestDedupFindings(t *testing.T) {
	nuclei := []NucleiFinding{{TemplateID: "t", Name: "same", Severity: "high", MatchedAt: "x"}, {TemplateID: "t", Name: "same", Severity: "high", MatchedAt: "x"}}
	got := BuildFindings("example.com", nuclei, nil, DNSChecks{}, nil)
	if len(got) != 1 {
		t.Fatalf("duplicates not removed: %+v", got)
	}
}

func TestBucketNamesAndListing(t *testing.T) {
	names := bucketNames("example.com")
	want := []string{"example", "example-assets", "example-backup", "example-data", "example-dev", "example-prod", "example-static", "www-example"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("names = %v, want %v", names, want)
	}
	if !bucketListing([]byte(`<?xml version="1.0"?><ListBucketResult><Contents></Contents></ListBucketResult>`)) {
		t.Fatal("listing not detected")
	}
	if bucketListing([]byte(`<html>Access denied</html>`)) {
		t.Fatal("html must not be a listing")
	}
}

func TestFindingHost(t *testing.T) {
	if got := findingHost("https://www.api.example.com/x"); got != "api.example.com" {
		t.Fatalf("host = %q", got)
	}
	if got := findingHost("1.2.3.4"); got != "1.2.3.4" {
		t.Fatalf("host = %q", got)
	}
}
