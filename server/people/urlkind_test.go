package people

import (
	"testing"

	"stare/server/scanner"
)

func TestClassifyURLKind(t *testing.T) {
	tests := []struct {
		link string
		want URLKind
	}{
		{"https://www.chess.com/member/Yamickuru", URLKindProfile},
		{"https://api.chess.com/pub/player/Yamickuru", URLKindAPI},
		{"https://web.archive.org/web/2024/https://example.com", URLKindArchive},
		{"https://twitterarchivedtweets.com/user/yamickuru", URLKindArchive},
		{"https://mcuuid.net/?q=Notch", URLKindUtility},
		{"https://playerdb.co/api/player/minecraft/Notch", URLKindUtility},
		{"https://gdbrowser.com/u/abc", URLKindUtility},
		{"https://namemc.com/profile/Notch", URLKindProfile},
	}
	for _, tt := range tests {
		if got := classifyURLKind(tt.link); got != tt.want {
			t.Errorf("classifyURLKind(%q) = %q, want %q", tt.link, got, tt.want)
		}
	}
}

func TestNormalizeRejectsArchiveAccountAndKeepsMention(t *testing.T) {
	obs := []scanner.Observation{
		Observation("maigret", scanner.ConfidenceMedium, map[string]any{
			"platform": "Twitter Archived Tweets",
			"handle":   "yamickuru",
			"url":      "https://twitterarchivedtweets.com/user/yamickuru",
		}),
	}
	accounts, _, _, _ := Normalize(obs)
	if len(accounts) != 0 {
		t.Fatalf("archive must not be an account: %+v", accounts)
	}
	mentions := ExtractMentions(obs)
	if len(mentions) != 1 || mentions[0].Source != "archive" {
		t.Fatalf("archive mention = %+v", mentions)
	}
}

func TestNormalizeMinecraftUtilityMerge(t *testing.T) {
	obs := []scanner.Observation{
		Observation("maigret", scanner.ConfidenceMedium, map[string]any{
			"platform": "mcuuid", "handle": "Notch", "url": "https://mcuuid.net/?q=Notch",
		}),
		Observation("maigret", scanner.ConfidenceMedium, map[string]any{
			"platform": "playerdb", "handle": "Notch", "url": "https://playerdb.co/api/player/minecraft/Notch",
		}),
	}
	accounts, _, _, _ := Normalize(obs)
	if len(accounts) != 1 {
		t.Fatalf("accounts = %+v", accounts)
	}
	acc := accounts[0]
	if acc.Platform != "minecraft" {
		t.Fatalf("platform = %q", acc.Platform)
	}
	if acc.URL != "https://namemc.com/profile/Notch" {
		t.Fatalf("canonical URL = %q", acc.URL)
	}
	if acc.URLKind != URLKindProfile {
		t.Fatalf("url kind = %q", acc.URLKind)
	}
	for _, evidence := range []string{"https://mcuuid.net/?q=Notch", "https://playerdb.co/api/player/minecraft/Notch"} {
		if !contains(acc.EvidenceURLs, evidence) {
			t.Fatalf("evidence %q missing: %v", evidence, acc.EvidenceURLs)
		}
	}
}

func TestNormalizeGdbrowserMapsToGeometryDash(t *testing.T) {
	accounts, _, _, _ := Normalize([]scanner.Observation{
		Observation("maigret", scanner.ConfidenceMedium, map[string]any{
			"platform": "gdbrowser", "handle": "abc", "url": "https://gdbrowser.com/u/abc",
		}),
	})
	if len(accounts) != 1 {
		t.Fatalf("accounts = %+v", accounts)
	}
	acc := accounts[0]
	if acc.Platform != "geometrydash" || acc.ProviderName != "gdbrowser" {
		t.Fatalf("account = %+v", acc)
	}
	if acc.URLKind != URLKindUtility {
		t.Fatalf("url kind = %q", acc.URLKind)
	}
}

func TestAPIHTML200NotConfirmed(t *testing.T) {
	account := Account{Handle: "john", Platform: "example", URLKind: URLKindAPI}
	html := profileFetch{Status: 200, ContentType: "text/html", Body: `<title>john profile</title>`}
	if got := evaluateProfilePage(&account, html); got == ExistenceConfirmed {
		t.Fatalf("API HTML 200 must not confirm, got %q", got)
	}
	json := profileFetch{Status: 200, ContentType: "application/json", Body: `{"username":"john"}`}
	if got := evaluateProfilePage(&account, json); got != ExistenceConfirmed {
		t.Fatalf("API JSON semantics must confirm, got %q", got)
	}
}
