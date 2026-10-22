//go:build integration

package scanner

import (
	"context"
	"testing"
	"time"
)

func TestFetchSubdomains_RealCRTSh(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := NewCRTShClient()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	subs, err := client.FetchSubdomains(ctx, "uni-dubna.ru")
	if err != nil {
		t.Fatalf("crtsh failed: %v", err)
	}

	if len(subs) == 0 {
		t.Fatal("expected subdomains, got none")
	}

	t.Logf("found %d subdomains", len(subs))
	for i, s := range subs {
		if i >= 5 {
			break
		}
		t.Logf("  - %s", s)
	}
}

func TestResolve_RealDNS(t *testing.T) {
	client := NewDNSClient()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ips, err := client.Resolve(ctx, "uni-dubna.ru")
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}

	if len(ips) == 0 {
		t.Fatal("expected IPs, got none")
	}

	t.Logf("uni-dubna.ru resolved to %d IPs:", len(ips))
	for _, ip := range ips {
		t.Logf("  - %s", ip)
	}
}

func TestResolve_InvalidDomain(t *testing.T) {
	client := NewDNSClient()

	_, err := client.Resolve(context.Background(), "not a domain!")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestBruteSubdomains_RealDNS(t *testing.T) {
	dns := NewDNSClient()
	client := NewWordlistClient(dns)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	start := time.Now()
	subs, err := client.BruteSubdomains(ctx, "uni-dubna.ru")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("brute failed: %v", err)
	}

	t.Logf("found %d subdomains in %v", len(subs), elapsed)
	for _, s := range subs {
		t.Logf("  - %s", s)
	}
}

func TestScanPorts_RealHost(t *testing.T) {
	client := NewPortsClient()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	ports, err := client.ScanPorts(ctx, "159.93.168.194") // uni-dubna.ru
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	t.Logf("open ports in %v: %v", elapsed, ports)
}

func TestScanPorts_InvalidIP(t *testing.T) {
	client := NewPortsClient()

	_, err := client.ScanPorts(context.Background(), "not an ip")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestScanPortsMany_RealHosts(t *testing.T) {
	client := NewPortsClient()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	ips := []string{"159.93.168.194", "1.1.1.1"}
	result, err := client.ScanPortsMany(ctx, ips)
	if err != nil {
		t.Fatalf("scan many failed: %v", err)
	}

	for ip, ports := range result {
		t.Logf("%s: %v", ip, ports)
	}
}
