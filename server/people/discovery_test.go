package people

import (
	"testing"

	"stare/server/scanner"
)

func TestExtractMentions(t *testing.T) {
	obs := []scanner.Observation{
		Observation("grepapp", scanner.ConfidenceLow, map[string]any{
			"kind": "mention", "mention_source": "grepapp", "url": "https://github.com/a/b/blob/HEAD/x",
			"title": "a/b/x", "context": "found yamikuru",
		}),
		Observation("grepapp", scanner.ConfidenceLow, map[string]any{
			"kind": "mention", "mention_source": "grepapp", "url": "https://github.com/a/b/blob/HEAD/x",
			"title": "duplicate",
		}),
		Observation("hn_algolia", scanner.ConfidenceLow, map[string]any{
			"kind": "mention", "mention_source": "hn_algolia", "url": "https://news.ycombinator.com/item?id=1",
			"title": "comment",
		}),
		Observation("registry", scanner.ConfidenceHigh, map[string]any{"platform": "github", "handle": "x", "url": "https://github.com/x"}),
	}
	mentions := ExtractMentions(obs)
	if len(mentions) != 2 {
		t.Fatalf("mentions = %+v", mentions)
	}
	if mentions[0].Source != "grepapp" && mentions[1].Source != "grepapp" {
		t.Fatalf("grepapp mention lost: %+v", mentions)
	}
	for _, mention := range mentions {
		if mention.ID == "" || mention.URL == "" {
			t.Fatalf("bad mention: %+v", mention)
		}
	}
}

func TestSafePublicURL(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1/x", "http://localhost/x", "file:///etc/passwd", "ftp://example.com/x"} {
		if safePublicURL(raw) {
			t.Errorf("%q must be rejected", raw)
		}
	}
}

func TestSearchAPIKeysPresent(t *testing.T) {
	t.Setenv("BRAVE_API_KEY", "")
	t.Setenv("SERPAPI_KEY", "")
	if searchAPIKeysPresent() {
		t.Fatal("no keys must mean missing")
	}
	t.Setenv("BRAVE_API_KEY", "test")
	if !searchAPIKeysPresent() {
		t.Fatal("brave key not detected")
	}
}
