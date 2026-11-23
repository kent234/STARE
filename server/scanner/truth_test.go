package scanner

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"2606:4700:4700::1111", true},
		{"10.0.0.1", false},
		{"172.16.5.4", false},
		{"192.168.1.10", false},
		{"127.0.0.1", false},
		{"169.254.169.254", false},
		{"100.64.0.1", false}, // CGNAT
		{"192.0.2.10", false}, // TEST-NET-1
		{"198.18.0.1", false}, // benchmark
		{"203.0.113.7", false},
		{"224.0.0.1", false},
		{"0.0.0.0", false},
		{"fc00::1", false},
		{"fe80::1", false},
		{"::1", false},
		{"2001:db8::1", false},
	}
	for _, tt := range tests {
		if got := isPublicIPString(tt.ip); got != tt.want {
			t.Errorf("isPublicIPString(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestSplitPublicPrivateIPs(t *testing.T) {
	public, private := splitPublicPrivateIPs([]string{
		"8.8.8.8", "10.0.0.1", "1.1.1.1", "192.168.0.5", "8.8.8.8",
	})
	if !reflect.DeepEqual(public, []string{"1.1.1.1", "8.8.8.8"}) {
		t.Fatalf("public = %v", public)
	}
	if !reflect.DeepEqual(private, []string{"10.0.0.1", "192.168.0.5"}) {
		t.Fatalf("private = %v", private)
	}
}

func TestHostSafeToProbe(t *testing.T) {
	if !hostSafeToProbe(nil) {
		t.Fatal("unknown resolution must stay allowed")
	}
	if !hostSafeToProbe([]string{"8.8.8.8", "1.1.1.1"}) {
		t.Fatal("all-public host must be allowed")
	}
	if hostSafeToProbe([]string{"8.8.8.8", "10.0.0.1"}) {
		t.Fatal("mixed host must be blocked")
	}
}

func TestDetectWildcard(t *testing.T) {
	ctx := context.Background()

	t.Run("same answers", func(t *testing.T) {
		info := detectWildcardDNS(ctx, "example.com", func(context.Context, string) ([]string, error) {
			return []string{"5.6.7.8", "1.2.3.4"}, nil
		})
		if !info.Detected {
			t.Fatal("wildcard not detected")
		}
		if !reflect.DeepEqual(info.IPs, []string{"1.2.3.4", "5.6.7.8"}) {
			t.Fatalf("ips = %v", info.IPs)
		}
	})

	t.Run("rotating answers", func(t *testing.T) {
		call := 0
		info := detectWildcardDNS(ctx, "example.com", func(context.Context, string) ([]string, error) {
			call++
			return []string{"10.0.0." + string(rune('0'+call))}, nil
		})
		if !info.Detected || len(info.IPs) != 3 {
			t.Fatalf("rotating wildcard = %+v", info)
		}
	})

	t.Run("nxdomain", func(t *testing.T) {
		info := detectWildcardDNS(ctx, "example.com", func(context.Context, string) ([]string, error) {
			return nil, errors.New("no such host")
		})
		if info.Detected || len(info.IPs) != 0 {
			t.Fatalf("unexpected wildcard: %+v", info)
		}
	})

	t.Run("ip target", func(t *testing.T) {
		called := false
		info := detectWildcardDNS(ctx, "8.8.8.8", func(context.Context, string) ([]string, error) {
			called = true
			return nil, nil
		})
		if called || info.Detected {
			t.Fatalf("wildcard must be skipped for IP: %+v", info)
		}
	})
}

func TestIsWildcardResolution(t *testing.T) {
	wildcard := []string{"1.2.3.4", "5.6.7.8"}
	if !isWildcardResolution([]string{"1.2.3.4"}, wildcard) {
		t.Fatal("subset must be wildcard")
	}
	if isWildcardResolution([]string{"1.2.3.4", "9.9.9.9"}, wildcard) {
		t.Fatal("extra address is not wildcard")
	}
	if isWildcardResolution(nil, wildcard) || isWildcardResolution([]string{"1.2.3.4"}, nil) {
		t.Fatal("empty input is not proof")
	}
}

func TestSubdomainConfidence(t *testing.T) {
	tests := []struct {
		sources  int
		resolved bool
		wildcard bool
		want     string
	}{
		{2, true, false, "high"},
		{1, true, false, "medium"},
		{0, true, false, "low"},
		{3, false, false, "low"},
		{4, true, true, "low"}, // wildcard никогда не подтверждается
	}
	for _, tt := range tests {
		if got := subdomainConfidence(tt.sources, tt.resolved, tt.wildcard); got != tt.want {
			t.Errorf("confidence(%d,%v,%v) = %q, want %q", tt.sources, tt.resolved, tt.wildcard, got, tt.want)
		}
	}
}

func TestActiveProbeTargets(t *testing.T) {
	subs := []string{"pub.example.com", "priv.example.com", "mixed.example.com", "unresolved.example.com"}
	subIPs := map[string][]string{
		"pub.example.com":        {"8.8.8.8"},
		"priv.example.com":       {"10.0.0.5"},
		"mixed.example.com":      {"8.8.8.8", "192.168.0.1"},
		"unresolved.example.com": nil,
	}
	got := activeProbeTargets("example.com", []string{"1.1.1.1"}, subs, subIPs)
	want := []string{"example.com", "pub.example.com", "unresolved.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("active targets = %v, want %v", got, want)
	}

	// Апекс, указывающий в приватную сеть, не должен попадать в активные проверки.
	got = activeProbeTargets("internal.example.com", []string{"10.0.0.10"}, nil, nil)
	if len(got) != 0 {
		t.Fatalf("private apex must be excluded: %v", got)
	}
}

func TestUniqueSortedIsSorted(t *testing.T) {
	got := uniqueSorted([]string{"b", "a", "b", " c ", ""})
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("uniqueSorted = %v, want %v", got, want)
	}
}

func TestSortHelpersDeterministic(t *testing.T) {
	obs := []Observation{
		{Source: "b", Confidence: ConfidenceLow, Payload: []byte(`{"x":2}`)},
		{Source: "a", Confidence: ConfidenceHigh, Payload: []byte(`{"x":1}`)},
		{Source: "a", Confidence: ConfidenceHigh, Payload: []byte(`{"x":0}`)},
	}
	sortObservations(obs)
	if obs[0].Source != "a" || obs[1].Source != "a" || obs[2].Source != "b" {
		t.Fatalf("observations not sorted: %+v", obs)
	}
	if string(obs[0].Payload) != `{"x":0}` || string(obs[1].Payload) != `{"x":1}` {
		t.Fatalf("payload tie-break not stable: %+v", obs)
	}
}
