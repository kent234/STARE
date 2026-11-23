package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeSubdomain(t *testing.T) {
	tests := []struct {
		raw  string
		root string
		want string
		ok   bool
	}{
		{"HTTPS://WWW.Example.com/path?x=1", "example.com", "www.example.com", true},
		{"*.api.example.com.", "example.com", "api.example.com", true},
		{"example.com", "example.com", "example.com", true},
		{"a_b.example.com", "example.com", "a_b.example.com", true},
		{"u003ewww.nmap.org", "nmap.org", "", false},
		{"evil.example.net", "example.com", "", false},
		{"-bad.example.com", "example.com", "", false},
		{"api.example.com:443", "example.com", "api.example.com", true},
	}
	for _, tt := range tests {
		got, ok := normalizeSubdomain(tt.raw, tt.root)
		if got != tt.want || ok != tt.ok {
			t.Errorf("normalizeSubdomain(%q,%q) = (%q,%v), want (%q,%v)", tt.raw, tt.root, got, ok, tt.want, tt.ok)
		}
	}
}

func TestFilterEndpoints(t *testing.T) {
	raw := []string{
		"https://api.example.com/v1/users",
		"https://cdn.example.net/app.js",
		"https://example.com/assets/app.js",
		"https://www.w3.org/2000/svg",
		"https://example.com/$%7Bthis.questionData.pageUrl%7D",
		"https://example.com/login",
		"https://example.com/login",
		"ftp://example.com/file",
		"https://example.com/logo.png",
	}
	got := filterEndpoints(raw, "example.com")
	want := []string{"https://api.example.com/v1/users", "https://example.com/login"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filtered = %v, want %v", got, want)
	}
}

func TestGroupEndpointsByHost(t *testing.T) {
	grouped := groupEndpointsByHost([]string{"https://api.example.com/a", "https://example.com/b", "https://api.example.com/c"})
	if len(grouped["api.example.com"]) != 2 || len(grouped["example.com"]) != 1 {
		t.Fatalf("grouped = %v", grouped)
	}
}

func TestParseRobots(t *testing.T) {
	body := "User-agent: *\nDisallow: /admin # comment\nAllow: /public\nSitemap: https://example.com/sitemap.xml\n"
	disallow, allow, sitemaps := parseRobots(body)
	if !reflect.DeepEqual(disallow, []string{"/admin"}) ||
		!reflect.DeepEqual(allow, []string{"/public"}) ||
		!reflect.DeepEqual(sitemaps, []string{"https://example.com/sitemap.xml"}) {
		t.Fatalf("robots parsed: %v %v %v", disallow, allow, sitemaps)
	}
}

func TestFetchArtifactsBase(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Server", "nginx-test")
			_, _ = w.Write([]byte("ok"))
		case "/robots.txt":
			_, _ = w.Write([]byte("Disallow: /private\nAllow: /open\nSitemap: /sitemap.xml\n"))
		case "/favicon.ico":
			_, _ = w.Write([]byte("icon-bytes"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	got, ok := fetchArtifactsBase(context.Background(), srv.URL)
	if !ok {
		t.Fatal("artifacts fetch failed")
	}
	if got.ServerHdr != "nginx-test" || len(got.RobotsTxt) != 1 || len(got.Allow) != 1 || len(got.Sitemaps) != 1 {
		t.Fatalf("artifacts = %+v", got)
	}
	if got.FaviconMD5 == "" {
		t.Fatal("favicon hash missing")
	}
}

func TestCheckEmailDNS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		qtype := r.URL.Query().Get("type")
		w.Header().Set("Content-Type", "application/dns-json")
		switch {
		case name == "example.com" && qtype == "16":
			_, _ = w.Write([]byte(`{"Status":0,"Answer":[{"data":"\"v=spf1 include:_spf.example.net ~all\""},{"data":"\"v=spf1 include:other.example.net ~all\""}]}`))
		case name == "_dmarc.example.com" && qtype == "16":
			_, _ = w.Write([]byte(`{"Status":0,"Answer":[{"data":"\"v=DMARC1; p=none; rua=mailto:dmarc@example.com\""}]}`))
		case name == "example.com" && qtype == "257":
			_, _ = w.Write([]byte(`{"Status":0,"Answer":[{"data":"0 issue \"letsencrypt.org\""}]}`))
		case name == "example.com" && qtype == "48":
			_, _ = w.Write([]byte(`{"Status":0,"AD":false,"Answer":[]}`))
		default:
			_, _ = fmt.Fprintf(w, `{"Status":0,"Answer":[]}`)
		}
	}))
	defer srv.Close()

	client := &dohClient{endpoints: []string{srv.URL}, client: srv.Client()}
	checks, err := checkEmailDNSWith(context.Background(), "example.com", client)
	if err != nil {
		t.Fatalf("dns checks: %v", err)
	}
	if checks.SPFStatus != "permerror" || len(checks.SPF) != 2 {
		t.Fatalf("spf = %+v", checks)
	}
	if checks.DMARCStatus != "ok" || checks.DMARCPolicy != "none" {
		t.Fatalf("dmarc = %+v", checks)
	}
	if len(checks.CAA) != 1 || checks.DNSSEC {
		t.Fatalf("caa/dnssec = %+v", checks)
	}
	joined := strings.Join(checks.Issues, "; ")
	for _, want := range []string{"multiple SPF", "p=none", "DNSSEC"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("issues missing %q: %s", want, joined)
		}
	}
}
