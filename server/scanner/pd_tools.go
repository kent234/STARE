package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ProjectDiscovery-инструменты опциональны: если бинарника нет, сканер
// продолжает работу без них. Путь можно переопределить через *_BIN.

var errToolNotInstalled = errors.New("tool not installed")

const (
	// httpxMaxTargets — предел хостов на один запуск httpx.
	httpxMaxTargets = 500
	// katanaMaxEndpoints — предел сохраняемых URL после краулинга.
	katanaMaxEndpoints = 2000
)

// HTTPProbe — результат httpx (живой HTTP-сервис и его атрибуты).
type HTTPProbe struct {
	Input        string   `json:"input"`
	URL          string   `json:"url"`
	Title        string   `json:"title,omitempty"`
	Webserver    string   `json:"webserver,omitempty"`
	StatusCode   int      `json:"status_code,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
	CDN          string   `json:"cdn,omitempty"`
	Favicon      string   `json:"favicon,omitempty"`
	TLS          *TLSInfo `json:"tls,omitempty"`
}

// TLSInfo — данные сертификата (tlsx/httpx).
type TLSInfo struct {
	Host      string   `json:"host"`
	Port      string   `json:"port,omitempty"`
	SubjectCN string   `json:"subject_cn,omitempty"`
	IssuerCN  string   `json:"issuer_cn,omitempty"`
	SAN       []string `json:"san,omitempty"`
	NotAfter  string   `json:"not_after,omitempty"`
	Expired   bool     `json:"expired,omitempty"`
	Version   string   `json:"tls_version,omitempty"`
}

func toolBinary(envKey, name string) (string, bool) {
	if bin := os.Getenv(envKey); bin != "" {
		if path, err := exec.LookPath(bin); err == nil {
			return path, true
		}
	}
	path, err := exec.LookPath(name)
	return path, err == nil
}

func runPDTool(ctx context.Context, envKey, name string, args []string, stdin string, timeout time.Duration) ([]byte, error) {
	bin, ok := toolBinary(envKey, name)
	if !ok {
		return nil, errToolNotInstalled
	}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(tctx, bin, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if tctx.Err() != nil {
			return nil, tctx.Err()
		}
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return nil, fmt.Errorf("%s: %w: %s", name, err, msg)
		}
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return stdout.Bytes(), nil
}

func scanJSONLines(data []byte, fn func(map[string]any)) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var row map[string]any
		if json.Unmarshal([]byte(line), &row) == nil {
			fn(row)
		}
	}
}

// RunSubfinder — пассивные поддомены из десятков источников.
func RunSubfinder(ctx context.Context, domain string) ([]string, error) {
	out, err := runPDTool(ctx, "SUBFINDER_BIN", "subfinder",
		[]string{"-d", domain, "-silent", "-all", "-no-color"}, "", 120*time.Second)
	if errors.Is(err, errToolNotInstalled) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var subs []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" || strings.ContainsAny(line, " \t") {
			continue
		}
		if line == domain || strings.HasSuffix(line, "."+domain) {
			subs = append(subs, line)
		}
	}
	return uniqueSorted(subs), nil
}

// RunHTTPX — активная проверка HTTP(S), технологии, TLS, CDN.
func RunHTTPX(ctx context.Context, targets []string) ([]HTTPProbe, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	if len(targets) > httpxMaxTargets {
		targets = targets[:httpxMaxTargets]
	}
	out, err := runPDTool(ctx, "HTTPX_BIN", "httpx", []string{
		"-json", "-silent", "-no-color", "-status-code", "-title", "-tech-detect",
		"-tls-grab", "-favicon", "-cdn", "-timeout", "10", "-retries", "1",
	}, strings.Join(targets, "\n"), 180*time.Second)
	if errors.Is(err, errToolNotInstalled) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var probes []HTTPProbe
	scanJSONLines(out, func(row map[string]any) {
		p := HTTPProbe{
			Input:        strVal(row["input"]),
			URL:          strVal(row["url"]),
			Title:        strVal(row["title"]),
			Webserver:    strVal(row["webserver"]),
			StatusCode:   intVal(row["status_code"]),
			CDN:          strVal(row["cdn_name"]),
			Favicon:      strVal(row["favicon"]),
			Technologies: stringSlice(row["tech"]),
		}
		if tls, ok := row["tls"].(map[string]any); ok {
			p.TLS = &TLSInfo{
				Host:      p.Input,
				SubjectCN: strVal(tls["subject_cn"]),
				IssuerCN:  strVal(tls["issuer_cn"]),
				SAN:       stringSlice(tls["subject_an"]),
				NotAfter:  strVal(tls["not_after"]),
				Expired:   boolValAny(tls["expired"]),
				Version:   strVal(tls["tls_version"]),
			}
		}
		probes = append(probes, p)
	})
	return probes, nil
}

// RunNaabu — быстрый TCP-скан top-N портов.
func RunNaabu(ctx context.Context, ips []string, topPorts int) (map[string][]int, error) {
	if len(ips) == 0 {
		return nil, nil
	}
	if topPorts <= 0 {
		topPorts = 1000
	}
	out, err := runPDTool(ctx, "NAABU_BIN", "naabu", []string{
		"-json", "-silent", "-no-color", "-top-ports", strconv.Itoa(topPorts),
		"-rate", "1000", "-timeout", "5",
	}, strings.Join(ips, "\n"), 240*time.Second)
	if errors.Is(err, errToolNotInstalled) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	result := make(map[string][]int)
	scanJSONLines(out, func(row map[string]any) {
		ip := strVal(row["ip"])
		if ip == "" {
			ip = strVal(row["host"])
		}
		port := intVal(row["port"])
		if ip != "" && port > 0 {
			result[ip] = append(result[ip], port)
		}
	})
	for ip, ports := range result {
		result[ip] = uniquePorts(ports)
	}
	return result, nil
}

// RunTLSX — сертификаты, SAN и срок действия для хоста.
func RunTLSX(ctx context.Context, host string) ([]TLSInfo, error) {
	// ВАЖНО: -san/-cn/-expired — взаимоисключающие probe-флаги tlsx.
	// JSON-вывод по умолчанию уже содержит subject_cn, subject_an и not_after.
	out, err := runPDTool(ctx, "TLSX_BIN", "tlsx", []string{
		"-u", host, "-json", "-silent", "-no-color",
	}, "", 90*time.Second)
	if errors.Is(err, errToolNotInstalled) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var certs []TLSInfo
	scanJSONLines(out, func(row map[string]any) {
		certs = append(certs, TLSInfo{
			Host:      strVal(row["host"]),
			Port:      strVal(row["port"]),
			SubjectCN: strVal(row["subject_cn"]),
			IssuerCN:  strVal(row["issuer_cn"]),
			SAN:       stringSlice(row["subject_an"]),
			NotAfter:  strVal(row["not_after"]),
			Expired:   boolValAny(row["expired"]),
			Version:   strVal(row["tls_version"]),
		})
	})
	return certs, nil
}

// RunKatana — краулинг и извлечение URL/эндпоинтов.
func RunKatana(ctx context.Context, target string) ([]string, error) {
	out, err := runPDTool(ctx, "KATANA_BIN", "katana", []string{
		"-u", target, "-silent", "-no-color", "-jsonl", "-d", "2", "-jc",
	}, "", 180*time.Second)
	if errors.Is(err, errToolNotInstalled) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var endpoints []string
	scanJSONLines(out, func(row map[string]any) {
		if req, ok := row["request"].(map[string]any); ok {
			if ep := strVal(req["endpoint"]); ep != "" {
				endpoints = append(endpoints, ep)
			}
			if u := strVal(req["url"]); u != "" {
				endpoints = append(endpoints, u)
			}
		}
		if u := strVal(row["url"]); u != "" {
			endpoints = append(endpoints, u)
		}
	})
	return uniqueSorted(endpoints), nil
}

func strVal(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func intVal(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case string:
		i, _ := strconv.Atoi(n)
		return i
	default:
		return 0
	}
}

func boolValAny(v any) bool {
	b, _ := v.(bool)
	return b
}

func stringSlice(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s := strVal(item); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func uniquePorts(in []int) []int {
	seen := make(map[int]struct{}, len(in))
	out := make([]int, 0, len(in))
	for _, p := range in {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}
