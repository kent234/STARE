package people

import (
	"testing"

	"stare/server/scanner"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		input string
		want  Kind
	}{
		{"john_doe", KindUsername},
		{"john@example.com", KindEmail},
		{"+7 (900) 123-45-67", KindPhone},
		{"79001234567", KindPhone},
		{"John Doe", KindRealName},
		{"", ""},
	}
	for _, tt := range tests {
		if got := Detect(tt.input); got != tt.want {
			t.Errorf("Detect(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalizeDedupAndConfidence(t *testing.T) {
	obs := []scanner.Observation{
		Observation("sherlock", scanner.ConfidenceMedium, map[string]any{
			"platform": "GitHub", "handle": "John", "url": "https://github.com/John",
		}),
		Observation("maigret", scanner.ConfidenceHigh, map[string]any{
			"platform": "github", "handle": "john", "url": "https://github.com/John",
		}),
		Observation("holehe", scanner.ConfidenceLow, map[string]any{
			"platform": "twitter", "handle": "john", "url": "https://twitter.com/john",
		}),
	}

	accounts, breaches, phone, _ := Normalize(obs)
	if len(breaches) != 0 || phone != nil {
		t.Fatalf("unexpected breach/phone: %v %v", breaches, phone)
	}
	if len(accounts) != 2 {
		t.Fatalf("got %d accounts, want 2", len(accounts))
	}

	var github *Account
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
	if github.Confidence != scanner.ConfidenceHigh {
		t.Fatalf("confidence = %q, want high", github.Confidence)
	}
}

func TestNormalizeBreachAndPhone(t *testing.T) {
	obs := []scanner.Observation{
		Observation("xposedornot", scanner.ConfidenceHigh, map[string]any{
			"kind": "breach", "breach_name": "Example", "email": "a@b.c", "date": "2024-01-01",
			"data_classes": []string{"emails"},
		}),
		Observation("phone", scanner.ConfidenceMedium, map[string]any{
			"kind": "phone", "indicator": "+79001234567", "country": "RU", "country_code": "7", "valid": true,
		}),
	}
	_, breaches, phone, _ := Normalize(obs)
	if len(breaches) != 1 || breaches[0].Name != "Example" {
		t.Fatalf("breaches = %+v", breaches)
	}
	if phone == nil || phone.Country != "RU" {
		t.Fatalf("phone = %+v", phone)
	}
}

func TestBuildActorConfidence(t *testing.T) {
	actor := BuildActor("John", []Account{
		{ID: "account:github:john", Confidence: scanner.ConfidenceMedium},
		{ID: "account:reddit:john", Confidence: scanner.ConfidenceHigh},
	})
	if actor == nil {
		t.Fatal("actor is nil")
	}
	if actor.Confidence != scanner.ConfidenceHigh {
		t.Fatalf("actor confidence = %q, want high", actor.Confidence)
	}
	if len(actor.Accounts) != 2 {
		t.Fatalf("accounts = %v", actor.Accounts)
	}
}
