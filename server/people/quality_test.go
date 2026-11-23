package people

import (
	"testing"

	"stare/server/scanner"
)

func TestNormalizeCanonicalAndRegistrations(t *testing.T) {
	obs := []scanner.Observation{
		Observation("sherlock", scanner.ConfidenceMedium, map[string]any{
			"platform": "github", "handle": "john", "url": "https://github.com/john",
		}),
		Observation("maigret", scanner.ConfidenceHigh, map[string]any{
			"platform": "GitHub (user)", "handle": "John", "url": "https://github.com/John",
		}),
		Observation("holehe", scanner.ConfidenceLow, map[string]any{
			"kind": "registration", "platform": "office365.com", "email": "john@example.com",
		}),
	}
	accounts, _, _, registrations := Normalize(obs)
	if len(accounts) != 1 {
		t.Fatalf("accounts = %d, want 1 canonical github account", len(accounts))
	}
	acc := accounts[0]
	if acc.Platform != "github" || len(acc.Sources) != 2 {
		t.Fatalf("bad merged account: %+v", acc)
	}
	if len(registrations) != 1 || registrations[0].Platform != "office365.com" {
		t.Fatalf("registrations = %+v", registrations)
	}
	if acc.Score <= 0 || acc.Score > 100 {
		t.Fatalf("score = %d", acc.Score)
	}
}

func TestVerifiedScoresHigher(t *testing.T) {
	unverified := accountScore(scanner.ConfidenceMedium, false, "https://site.example/john", "john", "sherlock")
	verified := accountScore(scanner.ConfidenceMedium, true, "https://site.example/john", "john", "githubuser")
	if verified <= unverified {
		t.Fatalf("verified score %d should exceed unverified %d", verified, unverified)
	}
}

func TestIsValidProfileURL(t *testing.T) {
	tests := []struct {
		platform, handle, link string
		want                   bool
	}{
		{"chess", "Yamickuru", "https://www.chess.com/member/Yamickuru", true},
		{"chess.com", "Yamickuru", "https://api.chess.com/pub/player/Yamickuru", true},
		{"dota2", "Yamickuru", "https://dota2.ru/forum/search?type=user&keywords=Yamickuru", false},
		{"twitch", "Yamickuru", "https://twitchtracker.com/Yamickuru", false},
		{"kvinneguiden", "Yamickuru", "https://forum.kvinneguiden.no", false},
		{"rajce.net", "Yamickuru", "https://Yamickuru.rajce.idnes.cz/", true},
		{"github", "torvalds", "https://github.com/torvalds", true},
		{"github", "torvalds", "https://github.com/", false},
	}
	for _, tt := range tests {
		if got := isValidProfileURL(tt.platform, tt.handle, tt.link); got != tt.want {
			t.Errorf("isValidProfileURL(%q,%q,%q) = %v, want %v", tt.platform, tt.handle, tt.link, got, tt.want)
		}
	}
}

func TestNormalizeRejectsGarbageAndCanonicalizes(t *testing.T) {
	obs := []scanner.Observation{
		Observation("maigret", scanner.ConfidenceHigh, map[string]any{
			"platform": "Chess", "handle": "Yamickuru", "url": "https://www.chess.com/member/Yamickuru",
		}),
		Observation("blackbird", scanner.ConfidenceMedium, map[string]any{
			"platform": "Chess.com", "handle": "Yamickuru", "url": "https://api.chess.com/pub/player/Yamickuru",
		}),
		Observation("maigret", scanner.ConfidenceHigh, map[string]any{
			"platform": "Dota2", "handle": "Yamickuru", "url": "https://dota2.ru/forum/search?type=user&keywords=Yamickuru",
		}),
		Observation("sherlock", scanner.ConfidenceMedium, map[string]any{
			"platform": "kvinneguiden", "handle": "Yamickuru", "url": "https://forum.kvinneguiden.no",
		}),
	}
	accounts, _, _, _ := Normalize(obs)
	if len(accounts) != 1 {
		t.Fatalf("accounts = %+v, want one canonical chess.com", accounts)
	}
	if accounts[0].Platform != "chess.com" || !accounts[0].MultiSource || !accounts[0].URLValid {
		t.Fatalf("bad canonical account: %+v", accounts[0])
	}
}
