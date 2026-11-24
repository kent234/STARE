package people

import (
	"context"
	"strings"
	"testing"
)

func TestLoadPlatforms(t *testing.T) {
	defs := loadPlatforms()
	if len(defs) < 15 {
		t.Fatalf("registry too small: %d", len(defs))
	}
	seen := map[string]struct{}{}
	for _, def := range defs {
		if def.Name == "" || def.URL == "" {
			t.Fatalf("invalid platform: %+v", def)
		}
		if _, ok := seen[def.Name]; ok {
			t.Fatalf("duplicate platform %q", def.Name)
		}
		seen[def.Name] = struct{}{}
		switch def.Detector {
		case "status", "json_path", "body_contains", "body_absent":
		default:
			t.Fatalf("unknown detector %q for %s", def.Detector, def.Name)
		}
		if def.RequiresAuth {
			t.Fatalf("%s requires auth, keyless registry expected", def.Name)
		}
	}
}

func TestLookupJSONPath(t *testing.T) {
	payload := map[string]any{
		"data": []any{map[string]any{"name": "john"}},
		"ok":   true,
		"zero": float64(0),
	}
	if !lookupJSONPath(payload, "data.0.name") {
		t.Fatal("array path not found")
	}
	if !lookupJSONPath(payload, "ok") {
		t.Fatal("bool true not detected")
	}
	if lookupJSONPath(payload, "zero") {
		t.Fatal("zero must be treated as empty")
	}
	if lookupJSONPath(payload, "data.1.name") {
		t.Fatal("out-of-range index must fail")
	}
}

func TestDetectRegistry(t *testing.T) {
	if !detectRegistry(200, "", platformDef{Detector: "status"}) {
		t.Fatal("status detector failed")
	}
	if detectRegistry(404, "", platformDef{Detector: "status"}) {
		t.Fatal("404 must not match")
	}
	if !detectRegistry(200, `{"username":"john"}`, platformDef{Detector: "json_path", Path: "username"}) {
		t.Fatal("json detector failed")
	}
	if !detectRegistry(200, "tgme_page_title", platformDef{Detector: "body_contains", Contains: "tgme_page_title"}) {
		t.Fatal("body_contains failed")
	}
	if !detectRegistry(200, "welcome", platformDef{Detector: "body_absent", Contains: "sign in"}) {
		t.Fatal("body_absent failed")
	}
}

func TestRegistryBuilders(t *testing.T) {
	if got := buildRegistryURL("https://x/{handle}", "john doe"); !strings.Contains(got, "john%20doe") {
		t.Fatalf("url = %q", got)
	}
	body := buildRegistryBody(`{"usernames":["{handle}"]}`, `jo"hn`)
	if !strings.Contains(body, `jo\"hn`) {
		t.Fatalf("body = %q", body)
	}
	if got := registryHandle("https://vk.com/john_doe"); got != "john_doe" {
		t.Fatalf("handle = %q", got)
	}
	if got := registryHandle("john@example.com"); got != "" {
		t.Fatalf("email must not be registry handle: %q", got)
	}
}

func TestExpandVariants(t *testing.T) {
	got := expandVariants("yami_kuru")
	if len(got) == 0 || len(got) > 4 {
		t.Fatalf("variants = %v", got)
	}
	for _, variant := range got {
		if variant == "yami_kuru" {
			t.Fatalf("base handle must be excluded: %v", got)
		}
	}
	joined := strings.Join(got, ",")
	if !strings.Contains(joined, "yami-kuru") || !strings.Contains(joined, "yamikuru") {
		t.Fatalf("expected dash/compact variants: %v", got)
	}
}

func TestSanitizeDNSLabel(t *testing.T) {
	if got := sanitizeDNSLabel("John_Doe!"); got != "johndoe" {
		t.Fatalf("label = %q", got)
	}
	if got := sanitizeDNSLabel("---"); got != "" {
		t.Fatalf("empty label = %q", got)
	}
}

func TestMaigretArgsModes(t *testing.T) {
	t.Setenv("PEOPLE_DEEP", "0")
	if args := strings.Join(maigretArgs("john", "0"), " "); strings.Contains(args, "--all-sites") || strings.Contains(args, "--top-sites") {
		t.Fatalf("normal args = %s", args)
	}
	if args := strings.Join(maigretArgs("john", "500"), " "); !strings.Contains(args, "--top-sites 500") {
		t.Fatalf("limited args = %s", args)
	}
}

func TestDeepModeSwitches(t *testing.T) {
	t.Setenv("PEOPLE_DEEP", "1")
	args := strings.Join(maigretArgs("john", "0"), " ")
	if !strings.Contains(args, "--all-sites") {
		t.Fatalf("deep maigret args = %s", args)
	}
	if got := verifyLimit(); got != 100000 {
		t.Fatalf("deep verify limit = %d", got)
	}
}

func TestRegistryCollectorEmptyHandle(t *testing.T) {
	obs, err := (&RegistryCollector{}).Collect(context.Background(), "john@example.com")
	if err != nil || len(obs) != 0 {
		t.Fatalf("obs=%v err=%v", obs, err)
	}
}
