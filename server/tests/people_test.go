package tests

import (
	"testing"

	"stare/server/people"
	"stare/server/scanner"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		input string
		want  people.Kind
	}{
		{"john_doe", people.KindUsername},
		{"john@example.com", people.KindEmail},
		{"+7 (900) 123-45-67", people.KindPhone},
		{"79001234567", people.KindPhone},
		{"John Doe", people.KindRealName},
		{"", ""},
	}
	for _, tt := range tests {
		if got := people.Detect(tt.input); got != tt.want {
			t.Errorf("people.Detect(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalizeDedupAndConfidence(t *testing.T) {
	obs := []scanner.Observation{
		people.Observation("sherlock", scanner.ConfidenceMedium, map[string]any{
			"platform": "GitHub", "handle": "John", "url": "https://github.com/John",
		}),
		people.Observation("maigret", scanner.ConfidenceHigh, map[string]any{
			"platform": "github", "handle": "john", "url": "https://github.com/John",
		}),
		people.Observation("holehe", scanner.ConfidenceLow, map[string]any{
			"platform": "twitter", "handle": "john", "url": "https://twitter.com/john",
		}),
		people.Observation("sherlock", scanner.ConfidenceMedium, map[string]any{
			"platform": "twitter", "handle": "john", "url": "https://twitter.com/john",
		}),
	}

	accounts, breaches, phone, _ := people.Normalize(obs)
	if len(breaches) != 0 || phone != nil {
		t.Fatalf("unexpected breach/phone: %v %v", breaches, phone)
	}
	if len(accounts) != 2 {
		t.Fatalf("got %d accounts, want 2", len(accounts))
	}

	var github *people.Account
	for i := range accounts {
		if accounts[i].Platform == "github" {
			github = &accounts[i]
		}
	}
	if github == nil {
		t.Fatal("github account not found")
	}
	if !github.MultiSource || len(github.Sources) != 2 {
		t.Fatalf("expected multi_source with 2 sources, got %+v", github)
	}
	// Без HTTP-подтверждения источник не делает аккаунт доказанным:
	// existence=unknown, tier=low (см. verification/existence в Account).
	if github.Confidence != scanner.ConfidenceLow {
		t.Fatalf("confidence = %q, want low before HTTP verification", github.Confidence)
	}
	if github.Existence != people.ExistenceUnknown || github.Verification != people.VerificationNone {
		t.Fatalf("verification state = %q/%q", github.Verification, github.Existence)
	}
}

func TestNormalizeBreachAndPhone(t *testing.T) {
	obs := []scanner.Observation{
		people.Observation("xposedornot", scanner.ConfidenceHigh, map[string]any{
			"kind": "breach", "breach_name": "Example", "email": "a@b.c", "date": "2024-01-01",
			"data_classes": []string{"emails"},
		}),
		people.Observation("phone", scanner.ConfidenceMedium, map[string]any{
			"kind": "phone", "indicator": "+79001234567", "country": "RU", "country_code": "7", "valid": true,
		}),
	}
	_, breaches, phone, _ := people.Normalize(obs)
	if len(breaches) != 1 || breaches[0].Name != "Example" {
		t.Fatalf("breaches = %+v", breaches)
	}
	if phone == nil || phone.Country != "RU" {
		t.Fatalf("phone = %+v", phone)
	}
}

func TestBuildActorConfidence(t *testing.T) {
	// Без кросс-сигналов кластер не может быть high, даже если источники разные.
	noSignals := people.BuildActor("John", []people.Account{
		{ID: "account:github:john", Existence: people.ExistenceConfirmed},
		{ID: "account:reddit:john", Existence: people.ExistenceConfirmed},
	})
	if noSignals == nil || noSignals.Confidence != scanner.ConfidenceMedium {
		t.Fatalf("no-signal actor = %+v", noSignals)
	}

	// Два независимых сигнала (имя + аватар) дают high.
	withSignals := people.BuildActor("John", []people.Account{
		{ID: "account:github:john", Existence: people.ExistenceConfirmed, Name: "John Smith", Avatar: "https://cdn.example/a.png"},
		{ID: "account:reddit:john", Existence: people.ExistenceConfirmed, Name: "John Smith", Avatar: "https://cdn.example/a.png"},
	})
	if withSignals == nil || withSignals.Confidence != scanner.ConfidenceHigh {
		t.Fatalf("signal actor = %+v", withSignals)
	}
	if len(withSignals.Signals) < 2 {
		t.Fatalf("signals = %v", withSignals.Signals)
	}
	if len(withSignals.Accounts) != 2 {
		t.Fatalf("accounts = %v", withSignals.Accounts)
	}
	if withSignals.ID != "actor:john" {
		t.Fatalf("actor id = %q", withSignals.ID)
	}
}

func TestBuildActorExcludesSensitive(t *testing.T) {
	actor := people.BuildActor("John", []people.Account{
		{ID: "account:github:john", Existence: people.ExistenceConfirmed, Name: "John Smith"},
		{ID: "account:pornhub:john", Existence: people.ExistenceConfirmed, Name: "John Smith", Sensitive: true},
	})
	if actor == nil {
		t.Fatal("actor is nil")
	}
	if len(actor.Accounts) != 1 || actor.Accounts[0] != "account:github:john" {
		t.Fatalf("accounts = %v", actor.Accounts)
	}
	if len(actor.SensitiveAccounts) != 1 || actor.SensitiveAccounts[0] != "account:pornhub:john" {
		t.Fatalf("sensitive = %v", actor.SensitiveAccounts)
	}
	if actor.Confidence == scanner.ConfidenceHigh {
		t.Fatal("sensitive account must not raise actor confidence")
	}
}

func TestActorIDFromProfileURL(t *testing.T) {
	actor := people.BuildActor("https://vk.com/john_doe", []people.Account{
		{ID: "account:vk:john_doe", Existence: people.ExistenceConfirmed},
	})
	if actor == nil || actor.ID != "actor:john_doe" {
		t.Fatalf("actor = %+v", actor)
	}
}
