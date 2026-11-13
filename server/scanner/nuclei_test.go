//go:build !nuclei

package scanner

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRunNucleiExec(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stub is POSIX-only")
	}

	bin := filepath.Join(t.TempDir(), "nuclei")
	script := "#!/bin/sh\n" +
		"echo '{\"template-id\":\"CVE-2024-0001\",\"matched-at\":\"https://example.com/x\",\"info\":{\"name\":\"Test vuln\",\"severity\":\"high\"}}'\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	t.Setenv("NUCLEI_BINARY", bin)
	t.Setenv("NUCLEI_SEVERITY", "critical,high")

	findings, err := RunNuclei(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("RunNuclei: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	got := findings[0]
	if got.TemplateID != "CVE-2024-0001" || got.Name != "Test vuln" || got.Severity != "high" || got.MatchedAt != "https://example.com/x" {
		t.Fatalf("bad finding: %+v", got)
	}
}

func TestRunNucleiMissingBinary(t *testing.T) {
	t.Setenv("NUCLEI_BINARY", filepath.Join(t.TempDir(), "nuclei-does-not-exist"))

	findings, err := RunNuclei(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("missing binary should not fail scan: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}
