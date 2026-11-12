package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIPinfoSource_Mock(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		lookup  func(context.Context, string) ([]string, error)
		status  int
		want    int
		wantErr bool
	}{
		{
			name:   "ip target",
			target: "1.2.3.4",
			want:   1,
		},
		{
			name:   "domain resolves to two ips",
			target: "example.com",
			lookup: func(context.Context, string) ([]string, error) {
				return []string{"1.1.1.1", "2.2.2.2"}, nil
			},
			want: 2,
		},
		{
			name:   "lookup fails",
			target: "example.com",
			lookup: func(context.Context, string) ([]string, error) {
				return nil, fmt.Errorf("dns boom")
			},
			wantErr: true,
		},
		{
			name:    "http error",
			target:  "1.2.3.4",
			status:  http.StatusInternalServerError,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.status != 0 {
					w.WriteHeader(tt.status)
					return
				}
				ip := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/json")
				_, _ = fmt.Fprintf(w, `{"ip":%q,"org":"AS15169 Google LLC","country":"DE"}`, ip)
			}))
			defer srv.Close()

			src := NewIPinfoSource().(*ipinfoSource)
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
				if o.Source != "ipinfo" || o.Confidence != ConfidenceHigh || o.FetchedAt.IsZero() {
					t.Errorf("bad observation meta: %+v", o)
				}
				var payload map[string]any
				if err := json.Unmarshal(o.Payload, &payload); err != nil {
					t.Fatalf("payload: %v", err)
				}
				if payload["asn"] != "AS15169" {
					t.Errorf("asn = %v, want AS15169", payload["asn"])
				}
			}
		})
	}
}

func TestOSVSource_Mock(t *testing.T) {
	const vulnJSON = `{"id":"CVE-2024-1234","summary":"bad thing","aliases":["GHSA-aaaa-bbbb-cccc"],"severity":[{"type":"CVSS_V3","score":"9.8"}],"affected":[{"package":{"name":"lodash","ecosystem":"npm"}}],"published":"2024-01-01T00:00:00Z"}`

	tests := []struct {
		name    string
		target  string
		query   string
		want    int
		wantReq int32
	}{
		{
			name:    "cve id",
			target:  "CVE-2024-1234",
			want:    1,
			wantReq: 1,
		},
		{
			name:    "package with version",
			target:  "npm/lodash@4.17.20",
			query:   `{"vulns":[` + vulnJSON + `]}`,
			want:    1,
			wantReq: 1,
		},
		{
			name:    "package no vulns",
			target:  "PyPI/requests@2.31.0",
			query:   `{"vulns":[]}`,
			want:    0,
			wantReq: 1,
		},
		{
			name:    "unsupported domain target",
			target:  "example.com",
			want:    0,
			wantReq: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var hits int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&hits, 1)
				switch {
				case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
					_, _ = w.Write([]byte(vulnJSON))
				case r.Method == http.MethodPost && r.URL.Path == "/v1/query":
					_, _ = w.Write([]byte(tt.query))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer srv.Close()

			src := NewOSVSource().(*osvSource)
			src.baseURL = srv.URL
			src.client = srv.Client()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			obs, err := src.Fetch(ctx, tt.target)
			if err != nil {
				t.Fatalf("fetch: %v", err)
			}
			if len(obs) != tt.want {
				t.Fatalf("got %d observations, want %d", len(obs), tt.want)
			}
			if got := atomic.LoadInt32(&hits); got != tt.wantReq {
				t.Fatalf("got %d http requests, want %d", got, tt.wantReq)
			}
			for _, o := range obs {
				if o.Source != "osv" || o.Confidence != ConfidenceHigh || o.FetchedAt.IsZero() || !json.Valid(o.Payload) {
					t.Errorf("bad observation: %+v", o)
				}
			}
		})
	}
}

func TestParseOSVTarget(t *testing.T) {
	tests := []struct {
		target  string
		isID    bool
		id      string
		eco     string
		pkg     string
		version string
		ok      bool
	}{
		{"CVE-2024-1234", true, "CVE-2024-1234", "", "", "", true},
		{"GHSA-aaaa-bbbb-cccc", true, "GHSA-aaaa-bbbb-cccc", "", "", "", true},
		{"npm/lodash@4.17.20", false, "", "npm", "lodash", "4.17.20", true},
		{"PyPI/requests@2.31.0", false, "", "PyPI", "requests", "2.31.0", true},
		{"lodash@4.17.20", false, "", "npm", "lodash", "4.17.20", true},
		{"example.com", false, "", "", "", "", false},
		{"", false, "", "", "", "", false},
	}
	for _, tt := range tests {
		isID, id, eco, pkg, version, ok := parseOSVTarget(tt.target)
		if isID != tt.isID || id != tt.id || eco != tt.eco || pkg != tt.pkg || version != tt.version || ok != tt.ok {
			t.Errorf("parseOSVTarget(%q) = (%v,%q,%q,%q,%q,%v), want (%v,%q,%q,%q,%q,%v)",
				tt.target, isID, id, eco, pkg, version, ok,
				tt.isID, tt.id, tt.eco, tt.pkg, tt.version, tt.ok)
		}
	}
}
