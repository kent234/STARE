package people

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyAccountURLs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user/john":
			_, _ = w.Write([]byte(`<html><head><title>John (@john) · Profile</title></head><body>about john</body></html>`))
		case "/marker":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><title>Welcome</title><body>member-card john</body></html>`))
		case "/soft":
			_, _ = w.Write([]byte(`<html><title>Page not found</title><body>try another user</body></html>`))
		case "/login":
			_, _ = w.Write([]byte(`<html><title>Log in to continue</title><body>login</body></html>`))
		case "/blocked":
			w.WriteHeader(http.StatusForbidden)
		case "/missing":
			w.WriteHeader(http.StatusNotFound)
		case "/error":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	accounts := []Account{
		{ID: "a:ok", Platform: "ok", Handle: "john", URL: srv.URL + "/user/john", URLValid: true, Confidence: "medium", Verification: VerificationNone, Existence: ExistenceUnknown, Score: 50},
		{ID: "a:marker", Platform: "marker", Handle: "john", URL: srv.URL + "/marker", URLValid: true, Confidence: "low", Verification: VerificationCollector, Existence: ExistenceUnknown, PageMarker: "member-card", Score: 45, Sources: []string{"whatsmyname"}},
		{ID: "a:soft", Platform: "soft", Handle: "john", URL: srv.URL + "/soft", URLValid: true, Confidence: "medium", Verification: VerificationNone, Existence: ExistenceUnknown, Score: 50},
		{ID: "a:login", Platform: "login", Handle: "john", URL: srv.URL + "/login", URLValid: true, Confidence: "medium", Verification: VerificationNone, Existence: ExistenceUnknown, Score: 50},
		{ID: "a:blocked", Platform: "blocked", Handle: "john", URL: srv.URL + "/blocked", URLValid: true, Confidence: "medium", Verification: VerificationNone, Existence: ExistenceUnknown, Score: 50},
		{ID: "a:missing", Platform: "missing", Handle: "john", URL: srv.URL + "/missing", URLValid: true, Confidence: "medium", Verification: VerificationNone, Existence: ExistenceUnknown, Score: 50},
		{ID: "a:error", Platform: "error", Handle: "john", URL: srv.URL + "/error", URLValid: true, Confidence: "medium", Verification: VerificationNone, Existence: ExistenceUnknown, Score: 50},
		{ID: "a:provider", Platform: "microsoft", Handle: "john@example.com", URL: "https://login.microsoftonline.com/", URLValid: true, Confidence: "high", Verification: VerificationCollector, Existence: ExistenceConfirmed, Provider: true, Score: 95},
	}

	got, removed := VerifyAccountURLs(context.Background(), accounts)
	byPlatform := map[string]Account{}
	for _, acc := range got {
		byPlatform[acc.Platform] = acc
	}

	if _, ok := byPlatform["missing"]; ok {
		t.Fatal("404 account must be removed from results")
	}
	if len(removed) != 2 {
		t.Fatalf("removed = %+v", removed)
	}
	removedByPlatform := map[string]RemovedAccount{}
	for _, item := range removed {
		removedByPlatform[item.Platform] = item
	}
	if removedByPlatform["missing"].Status != http.StatusNotFound {
		t.Fatalf("missing removed = %+v", removedByPlatform["missing"])
	}
	if _, ok := removedByPlatform["soft"]; !ok {
		t.Fatalf("strong-negative soft-404 must be removed: %+v", removed)
	}

	ok := byPlatform["ok"]
	if ok.Existence != ExistenceConfirmed || ok.Verification != VerificationHTTP || !ok.Verified {
		t.Fatalf("confirmed account = %+v", ok)
	}
	if ok.HTTPStatus != http.StatusOK || !ok.HTTPAttempted || !ok.URLReachable {
		t.Fatalf("http fields = %+v", ok)
	}

	marker := byPlatform["marker"]
	if marker.Existence != ExistenceConfirmed || marker.Verification != VerificationHTTP {
		t.Fatalf("page marker account = %+v", marker)
	}

	for _, platform := range []string{"login", "blocked", "error"} {
		acc := byPlatform[platform]
		if acc.Verified {
			t.Fatalf("%s must not be verified: %+v", platform, acc)
		}
		if acc.Confidence != "low" {
			t.Fatalf("%s confidence = %q, want low", platform, acc.Confidence)
		}
	}
	if byPlatform["blocked"].Existence != ExistenceBlocked {
		t.Fatalf("403 existence = %q", byPlatform["blocked"].Existence)
	}
	if byPlatform["login"].Existence != ExistenceBlocked {
		t.Fatalf("login wall existence = %q", byPlatform["login"].Existence)
	}

	provider := byPlatform["microsoft"]
	if !provider.Verified || provider.Existence != ExistenceConfirmed || provider.HTTPAttempted {
		t.Fatalf("provider must be confirmed without HTTP: %+v", provider)
	}
}

func TestVerifyNetworkErrorIsUnknown(t *testing.T) {
	accounts := []Account{{
		ID: "a:net", Platform: "net", Handle: "john",
		// Закрытый порт: сеть недоступна, но это не доказательство отсутствия.
		URL: "http://127.0.0.1:1/user/john", URLValid: true, Confidence: "medium",
		Verification: VerificationNone, Existence: ExistenceUnknown, Score: 50,
	}}
	got, removed := VerifyAccountURLs(context.Background(), accounts)
	if len(removed) != 0 || len(got) != 1 {
		t.Fatalf("got %d accounts, %d removed", len(got), len(removed))
	}
	acc := got[0]
	if acc.Existence != ExistenceUnknown || acc.HTTPError == "" || acc.Verified {
		t.Fatalf("network error account = %+v", acc)
	}
}

func TestEvaluateProfilePage(t *testing.T) {
	base := Account{Handle: "john"}
	tests := []struct {
		name    string
		fetch   profileFetch
		account Account
		want    ExistenceState
	}{
		{
			name:  "og title",
			fetch: profileFetch{Status: 200, Body: `<meta property="og:title" content="John Doe">`},
			want:  ExistenceConfirmed,
		},
		{
			name:  "api json",
			fetch: profileFetch{Status: 200, ContentType: "application/json", Body: `{"username":"john"}`},
			want:  ExistenceConfirmed,
		},
		{
			name:  "soft 404 body",
			fetch: profileFetch{Status: 200, Body: `<title>Profile</title>user not found`},
			want:  ExistenceAbsent,
		},
		{
			name:    "site negative marker",
			account: Account{Handle: "john", PageNegative: "not here"},
			fetch:   profileFetch{Status: 200, Body: `<title>John</title>not here`},
			want:    ExistenceUnknown,
		},
		{
			name:  "login redirect",
			fetch: profileFetch{Status: 200, FinalURL: "https://site.example/login", Body: `<title>Welcome</title>`},
			want:  ExistenceBlocked,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acc := base
			if tt.account.Handle != "" {
				acc = tt.account
			}
			if got := evaluateProfilePage(&acc, tt.fetch); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
