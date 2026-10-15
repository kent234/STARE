//go:build integration

package scanner

import (
	"context"
	"testing"
	"time"
)

func TestFetchSubdomains_RealCRTSh(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := NewCRTShClient()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	subs, err := client.FetchSubdomains(ctx, "uni-dubna.ru")
	if err != nil {
		t.Fatalf("crtsh failed: %v", err)
	}

	if len(subs) == 0 {
		t.Fatal("expected subdomains, got none")
	}

	t.Logf("found %d subdomains", len(subs))
	for i, s := range subs {
		if i >= 5 {
			break
		}
		t.Logf("  - %s", s)
	}
}
