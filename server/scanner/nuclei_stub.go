//go:build !nuclei

package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// NucleiFinding — результат проверки Nuclei.
type NucleiFinding struct {
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	MatchedAt  string `json:"matched_at"`
}

// RunNuclei запускает внешний бинарник nuclei (JSONL) и маппит его вывод.
// Если бинарник не установлен — возвращает пустой список без ошибки,
// чтобы скан продолжал работать (nuclei подключается опционально).
//
// Переменные окружения: NUCLEI_BINARY, NUCLEI_TEMPLATES, NUCLEI_SEVERITY.
func RunNuclei(ctx context.Context, target string) ([]NucleiFinding, error) {
	bin := os.Getenv("NUCLEI_BINARY")
	if bin == "" {
		bin = "nuclei"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return []NucleiFinding{}, nil
	}

	severity := os.Getenv("NUCLEI_SEVERITY")
	if severity == "" {
		severity = "critical,high"
	}
	args := []string{
		"-u", target,
		"-severity", severity,
		"-jsonl", "-silent", "-no-color", "-disable-update-check",
	}
	if dir := os.Getenv("NUCLEI_TEMPLATES"); dir != "" {
		args = append(args, "-t", dir)
	}

	cmd := exec.CommandContext(ctx, path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return nil, fmt.Errorf("nuclei: %w", err)
		}
		return nil, fmt.Errorf("nuclei: %w: %s", err, msg)
	}

	type result struct {
		TemplateID string `json:"template-id"`
		MatchedAt  string `json:"matched-at"`
		Info       struct {
			Name     string `json:"name"`
			Severity string `json:"severity"`
		} `json:"info"`
	}

	findings := []NucleiFinding{}
	sc := bufio.NewScanner(&stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var r result
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		if r.TemplateID == "" && r.Info.Name == "" {
			continue
		}
		findings = append(findings, NucleiFinding{
			TemplateID: r.TemplateID,
			Name:       r.Info.Name,
			Severity:   r.Info.Severity,
			MatchedAt:  r.MatchedAt,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("nuclei output: %w", err)
	}
	return findings, nil
}
