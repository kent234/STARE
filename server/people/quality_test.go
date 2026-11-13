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
