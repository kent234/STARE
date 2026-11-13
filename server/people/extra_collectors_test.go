package people

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"stare/server/scanner"
)

func TestParseJSONAccounts(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want int
	}{
		{
			name: "array",
			raw:  `[{"platform":"GitHub","handle":"john","url":"https://github.com/john"},{"site":"reddit","username":"john","profile":"https://reddit.com/user/john"}]`,
			want: 2,
		},
		{
			name: "object results",
			raw:  `{"results":[{"name":"vk","username":"john","url":"https://vk.com/john"}]}`,
			want: 1,
		},
		{
			name: "empty",
			raw:  `not json`,
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obs := parseJSONAccounts(tt.raw, "blackbird", "john", scanner.ConfidenceMedium)
			if len(obs) != tt.want {
				t.Fatalf("got %d observations, want %d", len(obs), tt.want)
			}
			for _, o := range obs {
				if o.Source != "blackbird" || o.Confidence != scanner.ConfidenceMedium {
					t.Fatalf("bad observation meta: %+v", o)
				}
			}
		})
	}
}

func TestParseGHunt(t *testing.T) {
	obs := parseGHunt(`{"name":"Test User","profile_picture":"https://img/avatar.jpg"}`, "test@example.com")
	if len(obs) != 1 {
		t.Fatalf("got %d observations", len(obs))
	}
	var payload map[string]any
	if err := json.Unmarshal(obs[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["platform"] != "google" || payload["name"] != "Test User" || payload["verified"] != true {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestWMNProfileExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>profile: john</html>`))
	}))
	defer srv.Close()

	if !wmnProfileExists(context.Background(), srv.Client(), srv.URL, "john", "not-found") {
		t.Fatal("expected profile match")
	}
	if wmnProfileExists(context.Background(), srv.Client(), srv.URL, "other", "") {
		t.Fatal("expected no match for missing e_string")
	}
}
