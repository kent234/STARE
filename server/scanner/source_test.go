package scanner

import (
	"context"
	"testing"
	"time"
)

type recordingSource struct {
	calls []string
}

func (s *recordingSource) Name() string { return "recording" }

func (s *recordingSource) Fetch(_ context.Context, target string) ([]Observation, error) {
	s.calls = append(s.calls, target)
	return []Observation{{
		Source:     "recording",
		FetchedAt:  time.Now(),
		Confidence: ConfidenceLow,
		Payload:    []byte(`{"indicator":"` + target + `"}`),
	}}, nil
}

func TestFetchBatchDeduplicates(t *testing.T) {
	src := &recordingSource{}
	obs, err := fetchBatch(context.Background(), src, []string{"1.1.1.1", "1.1.1.1", "", "2.2.2.2"})
	if err != nil {
		t.Fatalf("fetchBatch: %v", err)
	}
	if len(obs) != 2 {
		t.Fatalf("got %d observations, want 2", len(obs))
	}
	if len(src.calls) != 2 || src.calls[0] != "1.1.1.1" || src.calls[1] != "2.2.2.2" {
		t.Fatalf("unexpected calls: %v", src.calls)
	}
}
