package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNewScanID(t *testing.T) {
	first, second := NewScanID(), NewScanID()
	if len(first) != 24 {
		t.Fatalf("scan id length = %d, want 24", len(first))
	}
	if first == second {
		t.Fatal("scan ids must differ")
	}
}

func TestNewScanMetaMaps(t *testing.T) {
	meta := newScanMeta()
	if meta.Tools == nil || meta.Coverage == nil || meta.Versions == nil {
		t.Fatalf("meta maps must be initialized: %+v", meta)
	}
	meta.Tools["httpx"] = ToolStatus{Status: ToolMissing}
	meta.Coverage["http"] = StageCoverage{Attempted: 10, Succeeded: 4, Failed: 6}

	raw, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	encoded := string(raw)
	for _, want := range []string{`"httpx"`, `"missing"`, `"attempted":10`, `"succeeded":4`, `"failed":6`} {
		if !strings.Contains(encoded, want) {
			t.Fatalf("meta JSON missing %s: %s", want, encoded)
		}
	}
}

func TestToolStatusJSONOmitsZeroes(t *testing.T) {
	raw, _ := json.Marshal(ToolStatus{Status: ToolRan, Items: 3})
	encoded := string(raw)
	if strings.Contains(encoded, "duration_ms") || strings.Contains(encoded, "error") {
		t.Fatalf("zero fields must be omitted: %s", encoded)
	}
}
