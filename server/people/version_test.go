package people

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestBinaryVersionUsageRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stub is POSIX-only")
	}
	tests := []struct {
		name   string
		script string
		want   string
	}{
		{"semver", "#!/bin/sh\necho 'blackbird 2.0.1'\n", "blackbird 2.0.1"},
		{"version flag", "#!/bin/sh\necho '0.9.2'\n", "0.9.2"},
		{"usage", "#!/bin/sh\necho 'usage: blackbird [-h] -u USERNAME [email]'\n", ""},
		{"unknown option", "#!/bin/sh\necho '--version: unrecognized argument' >&2\nexit 2\n", ""},
		{"help table", "#!/bin/sh\necho 'positional arguments:'\necho '  username'\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tool")
			if err := os.WriteFile(path, []byte(tt.script), 0o755); err != nil {
				t.Fatal(err)
			}
			if got := binaryVersion(path); got != tt.want {
				t.Fatalf("binaryVersion = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCollectorVersionsSkipsUsage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stub is POSIX-only")
	}
	stub := filepath.Join(t.TempDir(), "blackbird")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\necho 'usage: blackbird [-h] -u USERNAME'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BLACKBIRD_BIN", stub)
	t.Setenv("SHERLOCK_BIN", filepath.Join(t.TempDir(), "missing"))
	versions := collectorVersions([]string{"blackbird", "sherlock"})
	if _, ok := versions["blackbird"]; ok {
		t.Fatalf("usage must not be a version: %v", versions)
	}
}
