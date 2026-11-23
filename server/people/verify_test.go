package people

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVerifyAccountURLs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/u/Yamickuru":
			_, _ = w.Write([]byte("<html>profile Yamickuru</html>"))
		case "/blocked":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	accounts := []Account{
		{ID: "a:ok", Platform: "ok", Handle: "Yamickuru", URL: srv.URL + "/u/Yamickuru", URLValid: true, Score: 50, Confidence: "medium", Sources: []string{"maigret"}},
		{ID: "a:missing", Platform: "missing", Handle: "Yamickuru", URL: srv.URL + "/missing", URLValid: true, Score: 50, Sources: []string{"maigret"}},
		{ID: "a:blocked", Platform: "blocked", Handle: "Yamickuru", URL: srv.URL + "/blocked", URLValid: true, Score: 50, Sources: []string{"maigret"}},
	}
	got := VerifyAccountURLs(context.Background(), accounts)
	if len(got) != 2 {
		t.Fatalf("got %d accounts, want 2 (404 dropped): %+v", len(got), got)
	}
	var ok, blocked *Account
	for i := range got {
		switch got[i].Platform {
		case "ok":
			ok = &got[i]
		case "blocked":
			blocked = &got[i]
		}
	}
	if ok == nil || !ok.Verified || ok.HTTPStatus != http.StatusOK {
		t.Fatalf("ok account not verified: %+v", ok)
	}
	if blocked == nil || blocked.Verified || blocked.HTTPStatus != http.StatusForbidden {
		t.Fatalf("blocked account must stay unverified: %+v", blocked)
	}
}

func TestMaigretArgs(t *testing.T) {
	full := strings.Join(maigretArgs("user", "0"), " ")
	if strings.Contains(full, "--top-sites") {
		t.Fatalf("0 must mean no limit: %s", full)
	}
	limited := strings.Join(maigretArgs("user", "500"), " ")
	if !strings.Contains(limited, "--top-sites 500") {
		t.Fatalf("expected --top-sites 500: %s", limited)
	}
}
