package people

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"stare/server/scanner"
)

func TestParseProfileURL(t *testing.T) {
	tests := []struct {
		input    string
		platform string
		handle   string
		ok       bool
	}{
		{"https://vk.com/durov", "vk", "durov", true},
		{"vk.com/durov", "vk", "durov", true},
		{"https://www.instagram.com/john_doe/", "instagram", "john_doe", true},
		{"https://github.com/torvalds", "github", "torvalds", true},
		{"https://x.com/jack", "x", "jack", true},
		{"https://t.me/durov", "t", "durov", true},
		{"https://youtube.com/@MrBeast", "youtube", "MrBeast", true},
		{"https://reddit.com/user/spez", "reddit", "spez", true},
		{"https://ok.ru/profile/123456", "ok", "123456", true},
		{"example.com", "", "", false},
		{"not a url", "", "", false},
	}
	for _, tt := range tests {
		platform, handle, ok := ParseProfileURL(tt.input)
		if ok != tt.ok || platform != tt.platform || handle != tt.handle {
			t.Errorf("ParseProfileURL(%q) = (%q,%q,%v), want (%q,%q,%v)",
				tt.input, platform, handle, ok, tt.platform, tt.handle, tt.ok)
		}
	}
}

func TestDetectProfileURL(t *testing.T) {
	if got := Detect("https://vk.com/durov"); got != KindProfileURL {
		t.Fatalf("Detect = %q, want profile_url", got)
	}
}

func TestProfileMetaParsing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><head>
			<title>Fallback Title</title>
			<meta property="og:title" content="John &amp; Doe">
			<meta property="og:description" content="Public bio">
			<meta property="og:image" content="https://cdn.example/avatar.jpg">
			</head><body><a href="https://other.example/link">x</a></body></html>`))
	}))
	defer srv.Close()

	meta := fetchProfileMeta(context.Background(), srv.URL)
	if meta.Title != "John & Doe" || meta.Description != "Public bio" || meta.Avatar != "https://cdn.example/avatar.jpg" {
		t.Fatalf("bad meta: %+v", meta)
	}
	if len(meta.Links) == 0 || meta.Links[0] != "https://other.example/link" {
		t.Fatalf("links = %v", meta.Links)
	}
}

func TestNormalizeProfileFields(t *testing.T) {
	obs := []scanner.Observation{
		Observation("profile", scanner.ConfidenceHigh, map[string]any{
			"kind": "profile", "platform": "vk", "handle": "durov", "url": "https://vk.com/durov",
			"name": "Pavel Durov", "bio": "Bio", "avatar": "https://cdn/avatar.jpg",
			"links": []string{"https://t.me/durov"},
		}),
	}
	accounts, _, _, _ := Normalize(obs)
	if len(accounts) != 1 {
		t.Fatalf("accounts = %d", len(accounts))
	}
	acc := accounts[0]
	if acc.Name != "Pavel Durov" || acc.Bio != "Bio" || acc.Avatar == "" || len(acc.Links) != 1 {
		t.Fatalf("bad account: %+v", acc)
	}
}
