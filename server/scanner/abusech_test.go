package scanner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAbuseCHSources_Mock(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		body       string
		source     string
		confidence ConfidenceTier
		parse      func(target string, body []byte) ([]map[string]any, error)
		want       int
	}{
		{
			name:       "urlhaus matches subdomain",
			target:     "example.com",
			source:     "urlhaus",
			confidence: ConfidenceHigh,
			parse:      parseURLhaus,
			body: "# comment\n" +
				`1,2026-01-01 00:00:00,http://evil.example.com/a,online,,malware_download,tag1,tag2,link,reporter` + "\n" +
				`2,2026-01-01 00:00:00,http://other.org/b,offline,,malware_download,,link,reporter` + "\n",
			want: 1,
		},
		{
			name:       "threatfox array format",
			target:     "example.com",
			source:     "threatfox",
			confidence: ConfidenceMedium,
			parse:      parseThreatFox,
			body: `[{"ioc":"bad.example.com","ioc_type":"domain","malware":"m1","confidence_level":75},
			        {"ioc":"9.9.9.9:443","ioc_type":"ip:port","malware":"m2"}]`,
			want: 1,
		},
		{
			name:       "threatfox object format",
			target:     "1.2.3.4",
			source:     "threatfox",
			confidence: ConfidenceMedium,
			parse:      parseThreatFox,
			body:       `{"101":[{"ioc":"1.2.3.4:8080","ioc_type":"ip:port","malware":"m3"}]}`,
			want:       1,
		},
		{
			name:       "feodo matches ip",
			target:     "1.2.3.4",
			source:     "feodo",
			confidence: ConfidenceHigh,
			parse:      parseFeodo,
			body:       `[{"ip_address":"1.2.3.4","port":443,"status":"online","malware":"Emotet"},{"ip_address":"5.6.7.8","port":80}]`,
			want:       1,
		},
		{
			name:       "feodo matches hostname",
			target:     "c2.example.com",
			source:     "feodo",
			confidence: ConfidenceHigh,
			parse:      parseFeodo,
			body:       `[{"ip_address":"1.1.1.1","hostname":"c2.example.com","status":"online"}]`,
			want:       1,
		},
		{
			name:       "no match",
			target:     "example.com",
			source:     "urlhaus",
			confidence: ConfidenceHigh,
			parse:      parseURLhaus,
			body:       `1,2026-01-01,http://other.org/b,online,,malware,,link,reporter` + "\n",
			want:       0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			src := &abuseCHSource{
				name:       tt.source,
				url:        srv.URL,
				confidence: tt.confidence,
				parse:      tt.parse,
				client:     srv.Client(),
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			obs, err := src.Fetch(ctx, tt.target)
			if err != nil {
				t.Fatalf("fetch: %v", err)
			}
			if len(obs) != tt.want {
				t.Fatalf("got %d observations, want %d", len(obs), tt.want)
			}
			for _, o := range obs {
				if o.Source != tt.source || o.Confidence != tt.confidence || o.FetchedAt.IsZero() {
					t.Errorf("bad observation meta: %+v", o)
				}
				if !json.Valid(o.Payload) {
					t.Errorf("payload is not valid JSON: %s", o.Payload)
				}
			}
		})
	}
}

func TestAbuseCHSource_PostAuthHeader(t *testing.T) {
	const apiResp = `{"query_status":"ok","data":[{"ioc":"bad.example.com","ioc_type":"domain","malware":"m1"}]}`
	var gotMethod, gotKey, gotBody string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotKey = r.Header.Get("Auth-Key")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = w.Write([]byte(apiResp))
	}))
	defer srv.Close()

	src := &abuseCHSource{
		name:       "threatfox",
		url:        srv.URL,
		method:     http.MethodPost,
		body:       []byte(`{"query":"get_iocs","days":7}`),
		headers:    map[string]string{"Auth-Key": "test-key", "Content-Type": "application/json"},
		confidence: ConfidenceMedium,
		parse:      parseThreatFox,
		client:     srv.Client(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	obs, err := src.Fetch(ctx, "example.com")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("got %d observations, want 1", len(obs))
	}
	if gotMethod != http.MethodPost || gotKey != "test-key" || gotBody != `{"query":"get_iocs","days":7}` {
		t.Fatalf("bad request: method=%q key=%q body=%q", gotMethod, gotKey, gotBody)
	}
}

func TestIndicatorMatches(t *testing.T) {
	tests := []struct {
		target, indicator string
		want              bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "a.example.com", true},
		{"example.com", "notexample.com", false},
		{"example.com", "http://a.example.com/x", true},
		{"1.2.3.4", "1.2.3.4:443", true},
		{"1.2.3.4", "1.2.3.5", false},
		{"", "example.com", false},
	}
	for _, tt := range tests {
		if got := indicatorMatches(tt.target, tt.indicator); got != tt.want {
			t.Errorf("indicatorMatches(%q, %q) = %v, want %v", tt.target, tt.indicator, got, tt.want)
		}
	}
}
