package people

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"stare/server/scanner"
)

// scenarioServer отдаёт ответы для двух разборов Yamickuru/Lowstander.
func scenarioServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/notion":
			_, _ = w.Write([]byte(`<html><title>Notion</title><body>Notion – The all-in-one workspace</body></html>`))
		case "/wordpress":
			_, _ = w.Write([]byte(`<html><title>WordPress.com</title><body>Create a free website</body></html>`))
		case "/user/yamickuru":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"player_id":1,"username":"yamickuru"}`))
		case "/u/yamickuru":
			_, _ = w.Write([]byte(`<html><title>Pinterest</title><body>Log in to continue</body></html>`))
		case "/g/yamickuru":
			_, _ = w.Write([]byte(`<html><title>yamickuru - Tweakers</title><body>profiel</body></html>`))
		case "/p/lowstander":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"users" : []}`))
		case "/lowstander":
			_, _ = w.Write([]byte(`<html><head><title>Lowstander</title></head><body>profile</body></html>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func runScenario(t *testing.T, target string, observations []scanner.Observation, base string) Result {
	t.Helper()
	accounts, breaches, phone, regs := Normalize(observations)
	accounts, removed := VerifyAccountURLs(context.Background(), accounts)
	refreshAccountEvidence(accounts)
	return Result{
		Target:        target,
		InputType:     KindUsername,
		Accounts:      accounts,
		Removed:       removed,
		Breaches:      breaches,
		Phone:         phone,
		Registrations: regs,
		Actor:         BuildActor(target, accounts),
	}
}

func TestScenarioYamickuru(t *testing.T) {
	srv := scenarioServer(t)
	defer srv.Close()
	obs := []scanner.Observation{
		Observation("subdomain_patterns", scanner.ConfidenceLow, map[string]any{
			"platform": "notion.site", "handle": "yamickuru", "url": srv.URL + "/notion",
			"verified": false, "candidate": true, "page_negative": "Notion",
		}),
		Observation("subdomain_patterns", scanner.ConfidenceLow, map[string]any{
			"platform": "wordpress.com", "handle": "yamickuru", "url": srv.URL + "/wordpress",
			"verified": false, "candidate": true, "page_negative": "WordPress.com",
		}),
		Observation("maigret", scanner.ConfidenceMedium, map[string]any{
			"platform": "chess.com", "handle": "yamickuru", "url": srv.URL + "/user/yamickuru",
		}),
		Observation("sherlock", scanner.ConfidenceMedium, map[string]any{
			"platform": "pinterest", "handle": "yamickuru", "url": srv.URL + "/u/yamickuru",
		}),
		Observation("sherlock", scanner.ConfidenceMedium, map[string]any{
			"platform": "tweakers", "handle": "yamickuru", "url": srv.URL + "/g/yamickuru",
		}),
	}
	res := runScenario(t, "yamickuru", obs, srv.URL)

	byPlatform := map[string]Account{}
	for _, acc := range res.Accounts {
		byPlatform[acc.Platform] = acc
	}
	for _, platform := range []string{"notion.site", "wordpress.com"} {
		acc := byPlatform[platform]
		if acc.Existence == ExistenceConfirmed {
			t.Fatalf("%s generic landing confirmed: %+v", platform, acc)
		}
	}
	if byPlatform["chess.com"].Existence != ExistenceConfirmed {
		t.Fatalf("chess must be confirmed: %+v", byPlatform["chess.com"])
	}
	if got := byPlatform["pinterest"].Existence; got != ExistenceBlocked {
		t.Fatalf("pinterest must be blocked, got %q", got)
	}
	if byPlatform["tweakers"].Existence != ExistenceConfirmed {
		t.Fatalf("tweakers must be confirmed: %+v", byPlatform["tweakers"])
	}

	if res.Actor == nil || res.Actor.Label != "yamickuru" {
		t.Fatalf("actor label = %+v", res.Actor)
	}
	for _, signal := range res.Actor.Signals {
		if signal == "shared_link" {
			t.Fatalf("false shared_link: %v", res.Actor.Signals)
		}
	}
	for _, id := range res.Actor.Accounts {
		for _, platform := range []string{"notion.site", "wordpress.com"} {
			if id == "account:"+platform+":yamickuru" {
				t.Fatalf("pattern page leaked into actor: %v", res.Actor.Accounts)
			}
		}
	}
}

func TestScenarioLowstander(t *testing.T) {
	srv := scenarioServer(t)
	defer srv.Close()
	obs := []scanner.Observation{
		Observation("subdomain_patterns", scanner.ConfidenceLow, map[string]any{
			"platform": "notion.site", "handle": "lowstander", "url": srv.URL + "/notion",
			"verified": false, "candidate": true, "page_negative": "Notion",
		}),
		Observation("subdomain_patterns", scanner.ConfidenceLow, map[string]any{
			"platform": "wordpress.com", "handle": "lowstander", "url": srv.URL + "/wordpress",
			"verified": false, "candidate": true, "page_negative": "WordPress.com",
		}),
		Observation("maigret", scanner.ConfidenceMedium, map[string]any{
			"platform": "duolingo", "handle": "lowstander", "url": srv.URL + "/p/lowstander",
		}),
		Observation("maigret", scanner.ConfidenceMedium, map[string]any{
			"platform": "mcuuid", "handle": "lowstander", "url": "https://mcuuid.net/?q=lowstander",
		}),
		Observation("maigret", scanner.ConfidenceMedium, map[string]any{
			"platform": "twitterarchivedtweets", "handle": "lowstander",
			"url": "https://twitterarchivedtweets.com/user/lowstander",
		}),
		Observation("githubuser", scanner.ConfidenceHigh, map[string]any{
			"platform": "github", "handle": "lowstander", "url": srv.URL + "/lowstander", "name": "Lowstander",
		}),
	}
	res := runScenario(t, "Lowstander", obs, srv.URL)

	byPlatform := map[string]Account{}
	for _, acc := range res.Accounts {
		byPlatform[acc.Platform] = acc
	}
	for _, platform := range []string{"notion.site", "wordpress.com"} {
		if byPlatform[platform].Existence == ExistenceConfirmed {
			t.Fatalf("%s generic landing confirmed", platform)
		}
	}
	if _, ok := byPlatform["twitterarchivedtweets"]; ok {
		t.Fatal("archive platform must not be an account")
	}
	if _, ok := byPlatform["mcuuid"]; ok {
		t.Fatal("mcuuid must merge into minecraft, not be its own account")
	}
	if res.Actor == nil || res.Actor.Label != "Lowstander" {
		t.Fatalf("actor label = %+v", res.Actor)
	}
	for _, signal := range res.Actor.Signals {
		if signal == "shared_link" {
			t.Fatalf("false shared_link: %v", res.Actor.Signals)
		}
	}
	removedDuolingo := false
	for _, item := range res.Removed {
		if item.Platform == "duolingo" {
			removedDuolingo = true
		}
	}
	if !removedDuolingo {
		t.Fatalf("duolingo absent must be recorded in removed: %+v", res.Removed)
	}
}
