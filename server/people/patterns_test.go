package people

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"stare/server/scanner"
)

func TestClassifySitePage(t *testing.T) {
	tests := []struct {
		name    string
		suffix  string
		body    string
		verdict sitePatternVerdict
		site    string
	}{
		{
			name:    "notion generic landing",
			suffix:  "notion.site",
			body:    `<html><head><title>Notion – The all-in-one workspace for your notes</title></head><body>Notion</body></html>`,
			verdict: siteCandidate,
		},
		{
			name:    "wordpress generic landing",
			suffix:  "wordpress.com",
			body:    `<html><head><title>WordPress.com</title></head><body>Create a free website</body></html>`,
			verdict: siteCandidate,
		},
		{
			name:    "notion unique page",
			suffix:  "notion.site",
			body:    `<html><head><title>Security Notes</title><meta property="og:title" content="Security Notes"></head><body>notes</body></html>`,
			verdict: siteConfirmed,
			site:    "Security Notes",
		},
		{
			name:    "wordpress unique blog",
			suffix:  "wordpress.com",
			body:    `<html><head><title>My Security Blog – WordPress.com</title></head><body>posts</body></html>`,
			verdict: siteConfirmed,
			site:    "My Security Blog",
		},
		{
			name:    "github pages missing",
			suffix:  "github.io",
			body:    `<html><head><title>Site not found</title></head><body>There isn't a GitHub Pages site here.</body></html>`,
			verdict: siteAbsent,
		},
		{
			name:    "gitlab pages missing",
			suffix:  "gitlab.io",
			body:    `<html><head><title>Project not found</title></head><body>404</body></html>`,
			verdict: siteAbsent,
		},
		{
			name:    "vercel deployment missing",
			suffix:  "vercel.app",
			body:    `<html><head><title>Deployment Not Found</title></head><body>DEPLOYMENT_NOT_FOUND</body></html>`,
			verdict: siteAbsent,
		},
		{
			name:    "netlify site missing",
			suffix:  "netlify.app",
			body:    `<html><head><title>Site not found</title></head><body>Not Found</body></html>`,
			verdict: siteAbsent,
		},
		{
			name:    "pages dev project missing",
			suffix:  "pages.dev",
			body:    `<html><head><title>Project not found</title></head><body>Project not found</body></html>`,
			verdict: siteAbsent,
		},
		{
			name:    "firebase site missing",
			suffix:  "web.app",
			body:    `<html><head><title>Site Not Found</title></head><body>Firebase Hosting</body></html>`,
			verdict: siteAbsent,
		},
		{
			name:    "vercel unique app",
			suffix:  "vercel.app",
			body:    `<html><head><title>Alice Portfolio</title></head><body>portfolio</body></html>`,
			verdict: siteConfirmed,
			site:    "Alice Portfolio",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict, site := classifySitePage(tt.suffix, "alice", tt.body)
			if verdict != tt.verdict {
				t.Fatalf("verdict = %v, want %v", verdict, tt.verdict)
			}
			if tt.site != "" && site != tt.site {
				t.Fatalf("site = %q, want %q", site, tt.site)
			}
		})
	}
}

func TestBuildSiteObservation(t *testing.T) {
	generic := buildSiteObservation("notion.site", "alice", "https://alice.notion.site", `<title>Notion</title><body>app</body>`)
	if generic == nil {
		t.Fatal("generic landing should be candidate, not dropped silently")
	}
	var payload map[string]any
	if err := json.Unmarshal(generic.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["kind"] == "provider" || payload["verified"] == true {
		t.Fatalf("generic landing confirmed: %s", generic.Payload)
	}
	if marker, _ := payload["page_marker"].(string); marker == "</html>" {
		t.Fatalf("generic </html> marker must not be used: %s", generic.Payload)
	}

	unique := buildSiteObservation("notion.site", "alice", "https://alice.notion.site", `<title>Alice Notes</title><body>notes</body>`)
	if unique == nil {
		t.Fatal("unique page must produce observation")
	}
	if err := json.Unmarshal(unique.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["kind"] != "provider" || payload["platform"] != "personal_site" {
		t.Fatalf("unique page not a personal_site provider: %s", unique.Payload)
	}
	if payload["provider_name"] != "notion.site" {
		t.Fatalf("provider_name missing: %s", unique.Payload)
	}
	if marker, _ := payload["page_marker"].(string); marker == "</html>" {
		t.Fatalf("</html> marker must be removed: %s", unique.Payload)
	}
}

func TestGenericLandingNotConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><head><title>Notion</title></head><body>Notion – The all-in-one workspace</body></html>`))
	}))
	defer srv.Close()

	accounts := []Account{{
		ID: "account:notion.site:alice", Platform: "notion.site", Handle: "alice",
		URL: srv.URL, URLValid: true, Confidence: scanner.ConfidenceLow,
		Verification: VerificationCollector, Existence: ExistenceUnknown,
		PageNegative: "Notion", Score: 20,
	}}
	got, _ := VerifyAccountURLs(context.Background(), accounts)
	if len(got) != 1 {
		t.Fatalf("accounts = %+v", got)
	}
	if got[0].Existence == ExistenceConfirmed || got[0].Verified {
		t.Fatalf("generic landing confirmed: %+v", got[0])
	}
}

func TestNormalizePersonalSiteProvider(t *testing.T) {
	obs := []scanner.Observation{
		Observation("subdomain_patterns", scanner.ConfidenceMedium, map[string]any{
			"kind":          "provider",
			"platform":      "personal_site",
			"handle":        "alice",
			"url":           "https://alice.notion.site",
			"verified":      true,
			"provider_name": "notion.site",
			"name":          "Alice Notes",
		}),
	}
	accounts, _, _, _ := Normalize(obs)
	if len(accounts) != 1 {
		t.Fatalf("accounts = %+v", accounts)
	}
	acc := accounts[0]
	if acc.Platform != "personal_site" || !acc.Provider || acc.ProviderName != "notion.site" {
		t.Fatalf("account = %+v", acc)
	}
	if acc.Existence != ExistenceConfirmed || !acc.Verified {
		t.Fatalf("personal site not confirmed: %+v", acc)
	}
	if strings.Contains(acc.URL, "notion.site") == false {
		t.Fatalf("url lost: %+v", acc)
	}
}
