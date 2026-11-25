package people

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPlatformVerifiers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/chess":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"player_id":42,"username":"yamickuru"}`))
		case "/pinterest":
			_, _ = w.Write([]byte(`<html><title>Pinterest</title><body>Log in to continue</body></html>`))
		case "/tweakers":
			_, _ = w.Write([]byte(`<html><head><title>yamickuru - Tweakers</title><meta property="og:title" content="yamickuru"></head><body>profiel</body></html>`))
		case "/sketchfab":
			_, _ = w.Write([]byte(`<html><title>Sketchfab</title><body>models</body></html>`))
		case "/telegram-user":
			_, _ = w.Write([]byte(`<html><title>yamickuru</title><body><div class="tgme_page_title">yamickuru</div></body></html>`))
		case "/telegram-placeholder":
			_, _ = w.Write([]byte(`<html><title>Telegram: Contact @yamickuru</title><div class="tgme_page_photo_image"><img src="/img/placeholder.svg"></div></body></html>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	accounts := []Account{
		{ID: "a:chess", Platform: "chess.com", Handle: "yamickuru", URL: srv.URL + "/chess", URLValid: true, URLKind: URLKindAPI, Confidence: "low", Existence: ExistenceUnknown, Sources: []string{"maigret"}},
		{ID: "a:pinterest", Platform: "pinterest", Handle: "yamickuru", URL: srv.URL + "/pinterest", URLValid: true, URLKind: URLKindProfile, Confidence: "medium", Existence: ExistenceUnknown, Sources: []string{"sherlock"}},
		{ID: "a:tweakers", Platform: "tweakers", Handle: "yamickuru", URL: srv.URL + "/tweakers", URLValid: true, URLKind: URLKindProfile, Confidence: "medium", Existence: ExistenceUnknown, Sources: []string{"sherlock"}},
		{ID: "a:sketchfab", Platform: "sketchfab", Handle: "yamickuru", URL: srv.URL + "/sketchfab", URLValid: true, URLKind: URLKindProfile, Confidence: "medium", Existence: ExistenceUnknown, Sources: []string{"sherlock"}},
		{ID: "a:tg", Platform: "telegram", Handle: "yamickuru", URL: srv.URL + "/telegram-user", URLValid: true, URLKind: URLKindProfile, Confidence: "low", Existence: ExistenceUnknown, Sources: []string{"whatsmyname"}},
		{ID: "a:tg-ph", Platform: "telegram", Handle: "placeholder", URL: srv.URL + "/telegram-placeholder", URLValid: true, URLKind: URLKindProfile, Confidence: "low", Existence: ExistenceUnknown, Sources: []string{"whatsmyname"}},
	}

	got, _ := VerifyAccountURLs(context.Background(), accounts)
	byID := map[string]Account{}
	for _, acc := range got {
		byID[acc.ID] = acc
	}

	if byID["a:chess"].Existence != ExistenceConfirmed {
		t.Fatalf("chess player_id must confirm: %+v", byID["a:chess"])
	}
	if byID["a:pinterest"].Existence != ExistenceBlocked {
		t.Fatalf("pinterest login wall must be blocked: %+v", byID["a:pinterest"])
	}
	if byID["a:tweakers"].Existence != ExistenceConfirmed {
		t.Fatalf("tweakers profile title must confirm: %+v", byID["a:tweakers"])
	}
	if byID["a:sketchfab"].Existence == ExistenceConfirmed {
		t.Fatalf("single-source sketchfab without marker must stay candidate: %+v", byID["a:sketchfab"])
	}
	if byID["a:sketchfab"].Confidence != "low" {
		t.Fatalf("candidate confidence must be low: %+v", byID["a:sketchfab"])
	}
	if byID["a:tg"].Existence != ExistenceConfirmed {
		t.Fatalf("telegram user page must confirm: %+v", byID["a:tg"])
	}
	if byID["a:tg-ph"].Existence == ExistenceConfirmed {
		t.Fatalf("telegram placeholder must not confirm: %+v", byID["a:tg-ph"])
	}
}

func TestSingleSourceWithoutMarkerStaysCandidate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><title>Some Page</title><body>nothing here</body></html>`))
	}))
	defer srv.Close()

	accounts := []Account{{
		ID: "a:generic", Platform: "generic.example", Handle: "yamickuru",
		URL: srv.URL, URLValid: true, URLKind: URLKindProfile,
		Confidence: "medium", Existence: ExistenceUnknown, Sources: []string{"sherlock"},
	}}
	got, _ := VerifyAccountURLs(context.Background(), accounts)
	if len(got) != 1 {
		t.Fatalf("accounts = %+v", got)
	}
	if got[0].Existence != ExistenceUnknown || got[0].Confidence != "low" || got[0].Verified {
		t.Fatalf("single-source without marker must stay candidate: %+v", got[0])
	}
}
