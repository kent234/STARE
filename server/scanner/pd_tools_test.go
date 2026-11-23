package scanner

import "testing"

func TestMatchFeed(t *testing.T) {
	subs := []string{"api.example.com", "dev.example.com"}
	ips := []string{"159.93.168.194"}

	urlHits := matchFeed("url", "https://evil.example.net/x\nhttps://api.example.com/login\n", "example.com", ips, subs)
	if len(urlHits) != 1 || urlHits[0].Indicator != "api.example.com" {
		t.Fatalf("url hits = %+v", urlHits)
	}

	ipHits := matchFeed("ip", "1.1.1.1\n159.93.168.194\n", "example.com", ips, subs)
	if len(ipHits) != 1 || ipHits[0].Indicator != "159.93.168.194" {
		t.Fatalf("ip hits = %+v", ipHits)
	}

	cidrHits := matchFeed("cidr", "159.93.0.0/16 ; RU block\n", "example.com", ips, subs)
	if len(cidrHits) != 1 {
		t.Fatalf("cidr hits = %+v", cidrHits)
	}
}

func TestMergePorts(t *testing.T) {
	merged := mergePorts(
		map[string][]int{"1.1.1.1": {80, 443}},
		map[string][]int{"1.1.1.1": {443, 8080}, "2.2.2.2": {22}},
	)
	if len(merged["1.1.1.1"]) != 3 {
		t.Fatalf("ports for 1.1.1.1 = %v", merged["1.1.1.1"])
	}
	if len(merged["2.2.2.2"]) != 1 {
		t.Fatalf("ports for 2.2.2.2 = %v", merged["2.2.2.2"])
	}
}

func TestParseHTTPXRow(t *testing.T) {
	row := map[string]any{
		"input": "example.com", "url": "https://example.com", "status_code": float64(200),
		"title": "Example", "tech": []any{"nginx", "React"},
		"tls": map[string]any{"issuer_cn": "R3", "subject_an": []any{"example.com"}},
	}
	if got := intVal(row["status_code"]); got != 200 {
		t.Fatalf("status = %d", got)
	}
	if techs := stringSlice(row["tech"]); len(techs) != 2 || techs[0] != "nginx" {
		t.Fatalf("tech = %v", techs)
	}
}
