package people

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRunEmptyTargetHasMeta(t *testing.T) {
	res := Run(context.Background(), "")
	if res.SchemaVersion == "" || res.ScanID == "" {
		t.Fatalf("schema/scan id missing: %+v", res)
	}
	if len(res.Errors) == 0 {
		t.Fatal("empty target must produce an error")
	}
	if res.DurationMS < 0 {
		t.Fatalf("duration = %d", res.DurationMS)
	}
}

func TestCollectorRequirement(t *testing.T) {
	tests := []struct {
		name   string
		ok     bool
		envKey string
	}{
		{"sherlock", true, "SHERLOCK_BIN"},
		{"maigret", true, "MAIGRET_BIN"},
		{"blackbird", true, "BLACKBIRD_BIN"},
		{"holehe", true, "HOLEHE_BIN"},
		{"ghunt", true, "GHUNT_BIN"},
		{"phoneinfoga", true, "PHONEINFOGA_BIN"},
		{"whatsmyname", false, ""},
		{"microsoft", false, ""},
	}
	for _, tt := range tests {
		envKey, _, ok := collectorRequirement(tt.name)
		if ok != tt.ok || envKey != tt.envKey {
			t.Errorf("collectorRequirement(%q) = (%q,%v), want (%q,%v)", tt.name, envKey, ok, tt.envKey, tt.ok)
		}
	}
}

func TestCollectorVersionsMissingBinary(t *testing.T) {
	t.Setenv("PATH", "")
	t.Setenv("SHERLOCK_BIN", filepath.Join(t.TempDir(), "no-sherlock"))
	// Нет бинарников — карта версий не должна появляться с пустыми значениями.
	if got := collectorVersions([]string{"sherlock"}); len(got) != 0 {
		t.Fatalf("versions = %v", got)
	}
}

func TestBinaryVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stub is POSIX-only")
	}
	path := filepath.Join(t.TempDir(), "tool")
	script := "#!/bin/sh\necho 'tool 1.2.3'\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	if got := binaryVersion(path); got != "tool 1.2.3" {
		t.Fatalf("version = %q", got)
	}
}
