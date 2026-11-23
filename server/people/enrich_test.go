package people

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnrichProfiles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><head>
			<title>John Doe · Example</title>
			<meta property="og:description" content="Security researcher">
			<meta property="og:image" content="https://cdn.example/avatar.png">
		</head><body><a href="https://matrix.to/@john">matrix</a></body></html>`))
	}))
	defer srv.Close()

	accounts := []Account{
		{ID: "a:ok", Platform: "example", Handle: "john", URL: srv.URL + "/john",
			URLValid: true, Existence: ExistenceConfirmed, Score: 60},
		{ID: "a:sensitive", Platform: "pornhub", Handle: "john", URL: srv.URL + "/s",
			URLValid: true, Existence: ExistenceConfirmed, Sensitive: true, Score: 90},
		{ID: "a:blocked", Platform: "blocked", Handle: "john", URL: srv.URL + "/b",
			URLValid: true, Existence: ExistenceBlocked, Score: 50},
	}
	got, enriched, _ := EnrichProfiles(context.Background(), accounts, 10)
	if enriched != 1 {
		t.Fatalf("enriched = %d, want 1", enriched)
	}
	if got[0].Name != "John Doe" || got[0].Bio != "Security researcher" || got[0].Avatar != "https://cdn.example/avatar.png" {
		t.Fatalf("enriched account = %+v", got[0])
	}
	if len(got[0].Links) == 0 {
		t.Fatal("links not enriched")
	}
	// sensitive и blocked не должны обогащаться (могут раскрыть лишнее/не существуют).
	if got[1].Name != "" || got[2].Name != "" {
		t.Fatalf("skipped accounts changed: %+v %+v", got[1], got[2])
	}
}
