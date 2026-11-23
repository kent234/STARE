package scanner

import (
	"context"
	"net"
	"reflect"
	"strconv"
	"testing"
)

func TestBuildHosts(t *testing.T) {
	result := &ScanResult{
		Target:            "example.com",
		Subdomains:        []string{"api.example.com", "wild.example.com"},
		SubdomainIPs:      map[string][]string{"api.example.com": {"8.8.8.8"}, "wild.example.com": {"1.1.1.1"}},
		SubdomainWildcard: map[string]bool{"wild.example.com": true},
		Ports:             map[string][]int{"8.8.8.8": {80, 443}, "1.1.1.1": {443}},
		HTTP: []HTTPProbe{
			{Input: "api.example.com", URL: "https://api.example.com", StatusCode: 200, Title: "API"},
		},
		TLS: []TLSInfo{{Host: "api.example.com", Port: "443", SubjectCN: "api.example.com"}},
	}

	hosts := buildHosts("example.com", []string{"8.8.8.8"}, result)
	if len(hosts) != 3 {
		t.Fatalf("hosts = %+v", hosts)
	}
	var api HostInfo
	for _, host := range hosts {
		if host.Host == "api.example.com" {
			api = host
		}
	}
	if !api.Resolved || !reflect.DeepEqual(api.Ports, []int{80, 443}) {
		t.Fatalf("api host = %+v", api)
	}
	if api.HTTP == nil || api.HTTP.StatusCode != 200 {
		t.Fatalf("http probe not attached: %+v", api.HTTP)
	}
	if len(api.TLS) != 1 {
		t.Fatalf("tls not attached: %+v", api.TLS)
	}
	if !result.SubdomainWildcard["wild.example.com"] {
		t.Fatal("wildcard flag lost")
	}
}

func TestBestHTTPProbePrefersHTTPS200(t *testing.T) {
	probes := []HTTPProbe{
		{Input: "example.com", URL: "http://example.com", StatusCode: 403},
		{Input: "example.com", URL: "https://example.com", StatusCode: 200},
	}
	best := bestHTTPProbe("example.com", probes)
	if best == nil || best.URL != "https://example.com" {
		t.Fatalf("best = %+v", best)
	}
}

func TestCertsForHostSAN(t *testing.T) {
	certs := []TLSInfo{
		{Host: "1.1.1.1", SubjectCN: "*.example.com", SAN: []string{"*.example.com"}},
		{Host: "2.2.2.2", SubjectCN: "other.example.net"},
	}
	got := certsForHost("api.example.com", []string{"1.1.1.1"}, certs)
	if len(got) != 1 || got[0].SubjectCN != "*.example.com" {
		t.Fatalf("certs = %+v", got)
	}
}

func TestTLSCandidateHosts(t *testing.T) {
	hosts := tlsCandidateHosts(
		"example.com", []string{"8.8.8.8"}, []string{"api.example.com", "no443.example.com"},
		map[string][]string{"api.example.com": {"8.8.8.8"}, "no443.example.com": {"9.9.9.9"}},
		map[string][]int{"8.8.8.8": {443}, "9.9.9.9": {80}},
		[]HTTPProbe{{Input: "api.example.com", URL: "https://api.example.com"}},
	)
	want := []string{"api.example.com", "example.com"}
	if !reflect.DeepEqual(hosts, want) {
		t.Fatalf("tls hosts = %v, want %v", hosts, want)
	}
}

func TestMergeTLS(t *testing.T) {
	a := []TLSInfo{{Host: "a", Port: "443", SubjectCN: "a"}}
	b := []TLSInfo{{Host: "a", Port: "443", SubjectCN: "a"}, {Host: "b", Port: "443", SubjectCN: "b"}}
	if got := mergeTLS(a, b); len(got) != 2 {
		t.Fatalf("merged = %+v", got)
	}
}

func TestIsTLSPort(t *testing.T) {
	for _, port := range []int{443, 8443, 9443} {
		if !isTLSPort(port) {
			t.Errorf("port %d must be TLS", port)
		}
	}
	if isTLSPort(80) {
		t.Fatal("80 must not be TLS")
	}
}

func TestGrabBannerPlain(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			conn.Close()
		}
	}()
	_, portStr, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	if banner := grabBanner(context.Background(), "127.0.0.1", port); banner != "SSH-2.0-OpenSSH_9.6" {
		t.Fatalf("banner = %q", banner)
	}
}
