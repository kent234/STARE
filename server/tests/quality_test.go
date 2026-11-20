package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"stare/server/people"
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
		{"https://instagram.com/john_doe/", "instagram", "john_doe", true},
		{"https://github.com/torvalds", "github", "torvalds", true},
		{"https://x.com/jack", "x", "jack", true},
		{"https://t.me/durov", "t", "durov", true},
		{"https://youtube.com/@MrBeast", "youtube", "MrBeast", true},
		{"https://reddit.com/user/spez", "reddit", "spez", true},
		{"https://ok.ru/profile/123456", "ok", "123456", true},
		{"https://instagram.com/p/abc", "", "", false},
		{"example.com", "", "", false},
		{"not a url", "", "", false},
	}
	for _, tt := range tests {
		platform, handle, ok := people.ParseProfileURL(tt.input)
		if ok != tt.ok || platform != tt.platform || handle != tt.handle {
			t.Errorf("ParseProfileURL(%q) = (%q,%q,%v), want (%q,%q,%v)",
				tt.input, platform, handle, ok, tt.platform, tt.handle, tt.ok)
		}
	}
}

func TestApplyProfileMatchUsesProfileSemantics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><head>
			<meta property="og:title" content="Linus Torvalds">
			<meta property="og:description" content="Linux kernel maintainer and open source developer">
		</head></html>`))
	}))
	defer srv.Close()

	accounts := []people.Account{
		{
			ID: "account:github:torvalds", Platform: "github", Handle: "torvalds",
			URL: "https://github.com/torvalds", Name: "Linus Torvalds",
			Bio: "Linux kernel maintainer", Verified: true,
		},
		{
			ID: "account:random:torvalds", Platform: "random", Handle: "torvalds",
			URL: srv.URL, Confidence: "medium",
		},
	}

	matched := people.ApplyProfileMatch(context.Background(), "https://github.com/torvalds", accounts)
	if matched[0].MatchScore != 100 || matched[0].MatchReason != "input profile" {
		t.Fatalf("source account not marked as input profile: %+v", matched[0])
	}
	if matched[1].MatchScore < 50 {
		t.Fatalf("candidate should match by name/bio, got score=%d reason=%q", matched[1].MatchScore, matched[1].MatchReason)
	}
	if !matched[1].Verified {
		t.Fatal("semantically matched candidate must be verified")
	}
}
