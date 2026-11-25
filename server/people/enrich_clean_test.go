package people

import (
	"testing"

	"stare/server/scanner"
)

func TestCleanMetaTitleSuffixes(t *testing.T) {
	tests := []struct {
		title  string
		handle string
		want   string
	}{
		{"Alice - Wattpad", "x", "Alice"},
		{"Stare - Profile | OpenSea", "x", "Stare"},
		{"bob's Profile", "x", "bob"},
		{"Bob Smith's Profile", "x", "Bob Smith"},
		{"Alice | SoundCloud", "x", "Alice"},
		{"Alice — Last.fm", "x", "Alice"},
		{"Alice · GitHub", "x", "Alice"},
		{"alice", "alice", ""},
		{"Alice (@alice) • Instagram photos and videos", "x", "Alice"},
	}
	for _, tt := range tests {
		if got := cleanMetaTitle(tt.title, tt.handle); got != tt.want {
			t.Errorf("cleanMetaTitle(%q,%q) = %q, want %q", tt.title, tt.handle, got, tt.want)
		}
	}
}

func TestGenericBioRejected(t *testing.T) {
	for _, bio := range []string{
		"Best place for your photos and more",
		"One of the millions of people using this network",
		"Check out my profile!",
		"Best place to share your moments",
		"The world's largest professional network",
	} {
		if !isGenericBio(bio) {
			t.Errorf("bio %q must be generic", bio)
		}
	}
	for _, bio := range []string{
		"Security researcher, CTF player",
		"Backend developer. Coffee and Go.",
	} {
		if isGenericBio(bio) {
			t.Errorf("bio %q must be personal", bio)
		}
	}
}

func TestNormalizeDropsGenericBio(t *testing.T) {
	obs := []scanner.Observation{Observation("maigret", scanner.ConfidenceMedium, map[string]any{
		"platform": "pinterest", "handle": "yamickuru", "url": "https://pinterest.com/yamickuru",
		"bio": "Best place for your photos and more",
	})}
	accounts, _, _, _ := Normalize(obs)
	if len(accounts) != 1 {
		t.Fatalf("accounts = %+v", accounts)
	}
	if accounts[0].Bio != "" {
		t.Fatalf("generic bio kept: %q", accounts[0].Bio)
	}
}

func TestEnrichmentTitlesAreCleaned(t *testing.T) {
	if got := cleanMetaTitle("Yamickuru - Wattpad", "other_handle"); got != "Yamickuru" {
		t.Fatalf("got %q", got)
	}
	if got := cleanMetaTitle("yamickuru's Profile | OpenSea", "other_handle"); got != "yamickuru" {
		t.Fatalf("got %q", got)
	}
}
