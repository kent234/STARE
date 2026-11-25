package people

import (
	"context"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Состояния коллектора. missing (нет бинарника) и ran (запущен, но ничего
// не нашёл) должны быть различимы в отчёте.
const (
	CollectorRan     = "ran"
	CollectorMissing = "missing"
	CollectorError   = "error"
	CollectorSkipped = "skipped"
)

// CollectorStatus — телеметрия одного коллектора.
type CollectorStatus struct {
	Name         string `json:"name"`
	Status       string `json:"status"`
	Observations int    `json:"observations"`
	Kept         int    `json:"kept"`
	DurationMS   int64  `json:"duration_ms,omitempty"`
	Error        string `json:"error,omitempty"`
}

// collectorRequirement сопоставляет коллектор с внешним бинарником.
// HTTP-коллекторы в этот список не входят: они всегда доступны.
func collectorRequirement(name string) (envKey string, binaries []string, ok bool) {
	switch name {
	case "sherlock":
		return "SHERLOCK_BIN", []string{"sherlock"}, true
	case "maigret":
		return "MAIGRET_BIN", []string{"maigret"}, true
	case "blackbird":
		return "BLACKBIRD_BIN", []string{"blackbird", "blackbird.py"}, true
	case "holehe":
		return "HOLEHE_BIN", []string{"holehe"}, true
	case "ghunt":
		return "GHUNT_BIN", []string{"ghunt"}, true
	case "phoneinfoga":
		return "PHONEINFOGA_BIN", []string{"phoneinfoga"}, true
	default:
		return "", nil, false
	}
}

// collectorVersions фиксирует версии CLI, реально установленных в окружении.
// Нужно для воспроизводимости отчёта: «sherlock 0.15.0» ≠ «sherlock latest».
func collectorVersions(names []string) map[string]string {
	out := map[string]string{}
	for _, name := range names {
		envKey, binaries, ok := collectorRequirement(name)
		if !ok {
			continue
		}
		path, found := lookBinary(envKey, binaries...)
		if !found {
			continue
		}
		if version := binaryVersion(path); version != "" {
			out[name] = version
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// versionRe принимает строку только если в ней есть похожий на версию токен.
var versionRe = regexp.MustCompile(`(?i)\bv?\d+\.\d+(\.\d+)?([-.+][0-9A-Za-z.]+)?\b`)

// usageMarkers — вывод справки, а не версии: CLI не понимает --version.
var usageMarkers = []string{
	"usage:",
	"usage :",
	"positional arguments",
	"optional arguments",
	"options:",
	"unrecognized arguments",
	"unknown option",
	"invalid option",
	"no such option",
	"error:",
	"traceback (most recent call last)",
}

func isVersionLine(line string) bool {
	lower := strings.ToLower(line)
	for _, marker := range usageMarkers {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return versionRe.MatchString(line)
}

// binaryVersion возвращает версию CLI только при валидном ответе.
// Usage/help/ошибка не должны попадать в versions[].
func binaryVersion(path string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	if err != nil && len(out) == 0 {
		return ""
	}
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || !isVersionLine(line) {
			continue
		}
		if len(line) > 200 {
			line = line[:200]
		}
		return line
	}
	return ""
}
