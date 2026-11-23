package people

import (
	"testing"

	"stare/server/scanner"
)

func TestParseMicrosoftExists(t *testing.T) {
	tests := []struct {
		body   string
		exists bool
		ok     bool
	}{
		{`{"IfExistsResult":0,"ThrottleStatus":0}`, true, true},
		{`{"IfExistsResult":5,"ThrottleStatus":0}`, true, true},
		{`{"IfExistsResult":6,"ThrottleStatus":0}`, true, true},
		{`{"IfExistsResult":1,"ThrottleStatus":0}`, false, true},
		{`{"IfExistsResult":0,"ThrottleStatus":1}`, false, false},
		{`not json`, false, false},
	}
	for _, tt := range tests {
		exists, ok := parseMicrosoftExists([]byte(tt.body))
		if exists != tt.exists || ok != tt.ok {
			t.Errorf("parseMicrosoftExists(%s) = (%v,%v), want (%v,%v)", tt.body, exists, ok, tt.exists, tt.ok)
		}
	}
}

func TestParseDisify(t *testing.T) {
	body := []byte(`{"email":"a@b.c","format":true,"domain":"b.c","disposable":false,"dns":true,"role":false,"free":true,"whitelist":false,"mx_info":["mx.b.c"]}`)
	info := parseDisify("a@b.c", body)
	if info == nil || !info.Format || !info.DNS || len(info.MX) != 1 || info.MX[0] != "mx.b.c" {
		t.Fatalf("bad disify info: %+v", info)
	}
}

func TestExtractEmailIntel(t *testing.T) {
	obs := []scanner.Observation{
		Observation("disify", scanner.ConfidenceHigh, map[string]any{
			"kind": "email_intel",
			"info": map[string]any{"email": "a@b.c", "format": true, "mx": []string{"mx.b.c"}},
		}),
	}
	info := ExtractEmailIntel(obs)
	if info == nil || info.Email != "a@b.c" || len(info.MX) != 1 {
		t.Fatalf("email intel = %+v", info)
	}
}
