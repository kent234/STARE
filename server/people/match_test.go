package people

import "testing"

func TestSemanticScoreNameAndHandle(t *testing.T) {
	src := profileMeta{
		Title:       "Linus Torvalds",
		Description: "Linux kernel maintainer",
		Links:       []string{"https://example.org/blog"},
	}
	cand := Account{Handle: "torvalds", Platform: "github", Verified: true}
	meta := profileMeta{
		Title:       "Linus Torvalds",
		Description: "Linux kernel maintainer and open source developer",
		Links:       []string{"https://example.org/blog"},
	}
	score, reasons := semanticScore(src, "torvalds", cand, meta)
	if score < 70 {
		t.Fatalf("score=%d reasons=%v, want >=70", score, reasons)
	}
}

func TestSemanticScoreRejectsDifferentPerson(t *testing.T) {
	src := profileMeta{Title: "Linus Torvalds", Description: "Linux kernel"}
	cand := Account{Handle: "torvalds", Platform: "twitter"}
	meta := profileMeta{Title: "Bob Smith", Description: "Sales manager in London"}
	score, _ := semanticScore(src, "torvalds", cand, meta)
	if score >= 50 {
		t.Fatalf("score=%d, want <50 for a different person", score)
	}
}
