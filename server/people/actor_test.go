package people

import (
	"testing"

	"stare/server/scanner"
)

func TestSharedLinkRequiresTwoAccounts(t *testing.T) {
	// Ссылка дважды внутри одного аккаунта — не сигнал.
	single := []Account{
		{ID: "account:github:yamickuru", Existence: ExistenceConfirmed, Handle: "yamickuru",
			Links: []string{"https://matrix.to/@yamickuru", "https://matrix.to/@yamickuru"}},
	}
	if signals := actorSignals(single, "yamickuru"); len(signals) != 0 {
		t.Fatalf("single-account duplicate must not be a signal: %v", signals)
	}

	// Одна и та же внешняя ссылка у двух разных аккаунтов — сигнал.
	shared := []Account{
		{ID: "account:github:yamickuru", Existence: ExistenceConfirmed, Handle: "yamickuru",
			Links: []string{"https://example.dev/me"}},
		{ID: "account:reddit:yamickuru", Existence: ExistenceConfirmed, Handle: "yamickuru",
			Links: []string{"https://example.dev/me"}},
	}
	if signals := actorSignals(shared, "yamickuru"); len(signals) != 1 || signals[0] != "shared_link" {
		t.Fatalf("shared link across accounts must be a signal: %v", signals)
	}
}

func TestBoilerplateLinksIgnored(t *testing.T) {
	links := []string{
		"https://fonts.gstatic.com/s/roboto.woff2",
		"https://cdn.jsdelivr.net/npm/x",
		"https://support.github.com/contact",
		"https://github.com/features",
		"https://github.com/yamickuru/following",
		"https://t.me/yamickuru",
		"https://example.dev/me",
		"https://second.example/me",
	}
	got := filteredPersonalLinks(links, "github")
	if len(got) != 3 {
		t.Fatalf("links = %v", got)
	}
	for _, want := range []string{"https://example.dev/me", "https://second.example/me", "https://t.me/yamickuru"} {
		if !contains(got, want) {
			t.Fatalf("links = %v, missing %q", got, want)
		}
	}
}

func TestActorLabelHandleByDefault(t *testing.T) {
	base := Account{ID: "account:github:yamickuru", Existence: ExistenceConfirmed, Handle: "yamickuru", Platform: "github"}

	// Имя из 5+ токенов — описательная фраза, не имя человека.
	verbose := base
	verbose.Name = "Yamickuru profile page on Chess.com"
	if actor := BuildActor("yamickuru", []Account{verbose}); actor.Label != "yamickuru" {
		t.Fatalf("verbose name accepted: %q", actor.Label)
	}

	// Имя, равное платформе, не принимается.
	platformName := base
	platformName.Name = "GitHub"
	if actor := BuildActor("yamickuru", []Account{platformName}); actor.Label != "yamickuru" {
		t.Fatalf("platform name accepted: %q", actor.Label)
	}

	// Нормальное имя из 2 токенов принимается.
	named := base
	named.Name = "Yami Kuru"
	if actor := BuildActor("yamickuru", []Account{named}); actor.Label != "Yami Kuru" {
		t.Fatalf("valid name rejected: %q", actor.Label)
	}
}

func TestDefaultAvatarIgnored(t *testing.T) {
	for _, avatar := range []string{
		"https://www.notion.so/images/default.png",
		"https://t.me/i/userpic/320/placeholder.svg",
		"https://abs.twimg.com/sticky/default_profile_images/default_profile.png",
	} {
		if !isDefaultAvatar(avatar) {
			t.Errorf("avatar %q must be default", avatar)
		}
	}
	if isDefaultAvatar("https://cdn.example/u/1234.jpg") {
		t.Error("real avatar must not be default")
	}
}

func TestNormalizeDedupsLinksWithinAccount(t *testing.T) {
	obs := []scanner.Observation{
		Observation("maigret", scanner.ConfidenceMedium, map[string]any{
			"platform": "github", "handle": "yamickuru", "url": "https://github.com/yamickuru",
			"links": []any{
				"https://example.dev/me",
				"https://example.dev/me",
				"https://fonts.gstatic.com/x.woff2",
			},
		}),
	}
	accounts, _, _, _ := Normalize(obs)
	if len(accounts) != 1 {
		t.Fatalf("accounts = %+v", accounts)
	}
	if got := accounts[0].Links; len(got) != 1 || got[0] != "https://example.dev/me" {
		t.Fatalf("links = %v", got)
	}
}
