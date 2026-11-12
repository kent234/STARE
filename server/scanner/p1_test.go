package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mustIndicators(t *testing.T, obs []Observation) []string {
	t.Helper()
	out := make([]string, 0, len(obs))
	for _, o := range obs {
		var p map[string]any
		if err := json.Unmarshal(o.Payload, &p); err != nil {
			t.Fatalf("payload: %v", err)
		}
		ind, _ := p["indicator"].(string)
		out = append(out, ind)
	}
	return out
}

func TestShodanSource_Mock(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		lookup  func(context.Context, string) ([]string, error)
		status  int
		want    int
		wantErr bool
	}{
		{name: "ip", target: "1.2.3.4", want: 1},
		{
			name:   "domain resolves to two ips",
			target: "example.com",
			lookup: func(context.Context, string) ([]string, error) {
				return []string{"1.1.1.1", "2.2.2.2"}, nil
			},
			want: 2,
		},
		{name: "not found", target: "1.2.3.4", status: http.StatusNotFound, want: 0},
		{name: "http error", target: "1.2.3.4", status: http.StatusInternalServerError, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.status != 0 {
					w.WriteHeader(tt.status)
					return
				}
				if r.URL.Query().Get("key") != "test-key" {
					t.Errorf("missing shodan key")
				}
				ip := strings.TrimPrefix(r.URL.Path, "/shodan/host/")
				_, _ = fmt.Fprintf(w, `{"ip_str":%q,"org":"Example","ports":[80,443],"data":[{"port":80,"product":"nginx","version":"1.24"}],"vulns":["CVE-2021-1234"]}`, ip)
			}))
			defer srv.Close()

			src := NewShodanSource().(*shodanSource)
			src.apiKey = "test-key"
			src.baseURL = srv.URL
			src.client = srv.Client()
			if tt.lookup != nil {
				src.lookup = tt.lookup
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			obs, err := src.Fetch(ctx, tt.target)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("fetch: %v", err)
			}
			if len(obs) != tt.want {
				t.Fatalf("got %d observations, want %d", len(obs), tt.want)
			}
			for _, o := range obs {
				if o.Source != "shodan" || o.Confidence != ConfidenceHigh || !json.Valid(o.Payload) {
					t.Errorf("bad observation: %+v", o)
				}
			}
		})
	}
}

func TestGreyNoiseSource_Mock(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		status  int
		want    int
		wantErr bool
	}{
		{name: "classified ip", target: "1.2.3.4", want: 1},
		{name: "not observed", target: "1.2.3.4", status: http.StatusNotFound, want: 0},
		{name: "http error", target: "1.2.3.4", status: http.StatusTooManyRequests, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.status != 0 {
					w.WriteHeader(tt.status)
					return
				}
				if r.Header.Get("key") != "test-key" {
					t.Errorf("missing greynoise key")
				}
				ip := strings.TrimPrefix(r.URL.Path, "/v3/community/")
				_, _ = fmt.Fprintf(w, `{"ip":%q,"noise":true,"classification":"malicious","name":"scanner","last_seen":"2026-01-01"}`, ip)
			}))
			defer srv.Close()

			src := NewGreyNoiseSource().(*greynoiseSource)
			src.apiKey = "test-key"
			src.baseURL = srv.URL
			src.client = srv.Client()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			obs, err := src.Fetch(ctx, tt.target)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("fetch: %v", err)
			}
			if len(obs) != tt.want {
				t.Fatalf("got %d observations, want %d", len(obs), tt.want)
			}
			if tt.want > 0 {
				var p map[string]any
				if err := json.Unmarshal(obs[0].Payload, &p); err != nil {
					t.Fatalf("payload: %v", err)
				}
				if p["classification"] != "malicious" {
					t.Errorf("classification = %v", p["classification"])
				}
			}
		})
	}
}

func TestAbuseIPDBSource_Mock(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		lookup  func(context.Context, string) ([]string, error)
		status  int
		want    int
		wantErr bool
	}{
		{name: "ip", target: "1.2.3.4", want: 1},
		{
			name:   "domain resolves to two ips",
			target: "example.com",
			lookup: func(context.Context, string) ([]string, error) {
				return []string{"1.1.1.1", "2.2.2.2"}, nil
			},
			want: 2,
		},
		{name: "http error", target: "1.2.3.4", status: http.StatusTooManyRequests, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.status != 0 {
					w.WriteHeader(tt.status)
					return
				}
				if r.Header.Get("Key") != "test-key" {
					t.Errorf("missing abuseipdb key")
				}
				ip := r.URL.Query().Get("ipAddress")
				_, _ = fmt.Fprintf(w, `{"data":{"ipAddress":%q,"abuseConfidenceScore":87,"totalReports":10,"countryCode":"DE","isp":"Example"}}`, ip)
			}))
			defer srv.Close()

			src := NewAbuseIPDBSource().(*abuseIPDBSource)
			src.apiKey = "test-key"
			src.baseURL = srv.URL
			src.client = srv.Client()
			if tt.lookup != nil {
				src.lookup = tt.lookup
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			obs, err := src.Fetch(ctx, tt.target)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("fetch: %v", err)
			}
			if len(obs) != tt.want {
				t.Fatalf("got %d observations, want %d", len(obs), tt.want)
			}
			inds := mustIndicators(t, obs)
			if len(inds) != tt.want {
				t.Fatalf("got indicators %v", inds)
			}
		})
	}
}
