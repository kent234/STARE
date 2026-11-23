package scanner

import (
	"net/url"
	"path"
	"sort"
	"strings"
)

// namespaceHosts — URL из XML/JSON-схем, которые katana вытаскивает из HTML.
var namespaceHosts = map[string]struct{}{
	"w3.org":         {},
	"www.w3.org":     {},
	"schema.org":     {},
	"www.schema.org": {},
	"ns.adobe.com":   {},
	"purl.org":       {},
	"xmlns.com":      {},
}

var staticExtensions = map[string]struct{}{
	".js": {}, ".mjs": {}, ".css": {}, ".map": {},
	".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {}, ".svg": {}, ".webp": {}, ".ico": {},
	".woff": {}, ".woff2": {}, ".ttf": {}, ".eot": {},
	".mp4": {}, ".webm": {}, ".mp3": {}, ".wav": {},
	".pdf": {}, ".zip": {}, ".gz": {},
}

// filterEndpoints оставляет только HTTP(S)-URL в scope root, без шаблонов
// и статики. Это убирает из отчёта тысячи JS-чанков и $%7B...%7D.
func filterEndpoints(raw []string, root string) []string {
	root = strings.ToLower(strings.TrimSpace(root))
	seen := map[string]struct{}{}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		cleaned, host, ok := cleanEndpoint(item)
		if !ok || !hostInScope(host, root) {
			continue
		}
		ext := strings.ToLower(path.Ext(hostPath(cleaned)))
		if _, bad := staticExtensions[ext]; bad {
			continue
		}
		if _, ok := seen[cleaned]; ok {
			continue
		}
		seen[cleaned] = struct{}{}
		out = append(out, cleaned)
	}
	sort.Strings(out)
	return out
}

func cleanEndpoint(raw string) (string, string, bool) {
	value := strings.TrimSpace(raw)
	lower := strings.ToLower(value)
	// Шаблоны и плейсхолдеры не являются эндпоинтами.
	if strings.Contains(lower, "$%7b") || strings.Contains(lower, "%7b") ||
		strings.Contains(lower, "${") || strings.Contains(lower, "{{") ||
		strings.ContainsAny(lower, "<>") {
		return "", "", false
	}
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" {
		return "", "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", false
	}
	host := strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
	if _, bad := namespaceHosts[u.Hostname()]; bad {
		return "", "", false
	}
	if _, bad := namespaceHosts[host]; bad {
		return "", "", false
	}
	u.Scheme = scheme
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	return u.String(), host, true
}

func hostInScope(host, root string) bool {
	if host == "" || root == "" {
		return false
	}
	host = strings.TrimPrefix(strings.ToLower(host), "www.")
	root = strings.TrimPrefix(strings.ToLower(root), "www.")
	return host == root || strings.HasSuffix(host, "."+root)
}

func hostPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Path
}

// groupEndpointsByHost — удобная проекция endpoints[] для отчёта и UI.
func groupEndpointsByHost(endpoints []string) map[string][]string {
	out := map[string][]string{}
	for _, endpoint := range endpoints {
		u, err := url.Parse(endpoint)
		if err != nil || u.Hostname() == "" {
			continue
		}
		host := strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
		out[host] = append(out[host], endpoint)
	}
	for host := range out {
		sort.Strings(out[host])
	}
	return out
}
