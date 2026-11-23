package people

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"stare/server/scanner"
)

// EmailIntel — бесплатная валидация email (Disify): формат, MX, disposable, role.
type EmailIntel struct {
	Email      string   `json:"email"`
	Domain     string   `json:"domain,omitempty"`
	Format     bool     `json:"format"`
	Disposable bool     `json:"disposable"`
	DNS        bool     `json:"dns"`
	Role       bool     `json:"role"`
	Free       bool     `json:"free"`
	Whitelist  bool     `json:"whitelist"`
	MX         []string `json:"mx,omitempty"`
}

// MicrosoftCollector — бесплатная проверка существования Microsoft/Office365 аккаунта.
type MicrosoftCollector struct{}

func (c *MicrosoftCollector) Name() string { return "microsoft" }

func (c *MicrosoftCollector) Collect(ctx context.Context, email string) ([]scanner.Observation, error) {
	if !strings.Contains(email, "@") {
		return nil, nil
	}
	body, _ := json.Marshal(map[string]any{
		"username":             email,
		"isOtherIdpSupported":  true,
		"checkPhones":          false,
		"isRemoteNGCSupported": true,
		"isCookieBannerShown":  false,
		"isFidoSupported":      false,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://login.microsoftonline.com/common/GetCredentialType", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36")

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("microsoft status: %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	exists, ok := parseMicrosoftExists(data)
	if !ok || !exists {
		return nil, nil
	}
	return []scanner.Observation{Observation("microsoft", scanner.ConfidenceHigh, map[string]any{
		"kind":     "provider",
		"platform": "microsoft",
		"handle":   email,
		"url":      "https://login.microsoftonline.com/",
		"verified": true,
		"evidence": "GetCredentialType: account exists",
	})}, nil
}

// parseMicrosoftExists: 0/5/6 — аккаунт есть, 1 — нет, иное — неизвестно.
func parseMicrosoftExists(data []byte) (exists bool, ok bool) {
	var payload struct {
		IfExistsResult int `json:"IfExistsResult"`
		ThrottleStatus int `json:"ThrottleStatus"`
	}
	if json.Unmarshal(data, &payload) != nil || payload.ThrottleStatus != 0 {
		return false, false
	}
	switch payload.IfExistsResult {
	case 0, 5, 6:
		return true, true
	case 1:
		return false, true
	default:
		return false, false
	}
}

// PGPCollector — подтверждённый email в keys.openpgp.org (бесплатно, без ключа).
type PGPCollector struct{}

func (c *PGPCollector) Name() string { return "pgp" }

func (c *PGPCollector) Collect(ctx context.Context, email string) ([]scanner.Observation, error) {
	if !strings.Contains(email, "@") {
		return nil, nil
	}
	link := "https://keys.openpgp.org/vks/v1/by-email/" + url.PathEscape(email)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Stare/1.0 (+osint)")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pgp status: %d", resp.StatusCode)
	}
	return []scanner.Observation{Observation("pgp", scanner.ConfidenceHigh, map[string]any{
		"kind":     "provider",
		"platform": "pgp",
		"handle":   email,
		"url":      link,
		"verified": true,
		"evidence": "keys.openpgp.org has verified key for email",
	})}, nil
}

// DisifyCollector — бесплатная валидация/disposable/MX без ключа.
type DisifyCollector struct{}

func (c *DisifyCollector) Name() string { return "disify" }

func (c *DisifyCollector) Collect(ctx context.Context, email string) ([]scanner.Observation, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://disify.com/api/email/"+url.PathEscape(email), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Stare/1.0 (+osint)")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("disify status: %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	info := parseDisify(email, data)
	if info == nil {
		return nil, nil
	}
	return []scanner.Observation{Observation("disify", scanner.ConfidenceHigh, map[string]any{
		"kind": "email_intel",
		"info": info,
	})}, nil
}

func parseDisify(email string, data []byte) *EmailIntel {
	var payload struct {
		Email      string   `json:"email"`
		Format     bool     `json:"format"`
		Domain     string   `json:"domain"`
		Disposable bool     `json:"disposable"`
		DNS        bool     `json:"dns"`
		Role       bool     `json:"role"`
		Free       bool     `json:"free"`
		Whitelist  bool     `json:"whitelist"`
		MXInfo     []string `json:"mx_info"`
	}
	if json.Unmarshal(data, &payload) != nil {
		return nil
	}
	if payload.Email == "" {
		payload.Email = email
	}
	return &EmailIntel{
		Email:      payload.Email,
		Domain:     payload.Domain,
		Format:     payload.Format,
		Disposable: payload.Disposable,
		DNS:        payload.DNS,
		Role:       payload.Role,
		Free:       payload.Free,
		Whitelist:  payload.Whitelist,
		MX:         payload.MXInfo,
	}
}

// ExtractEmailIntel достаёт результат Disify из наблюдений.
func ExtractEmailIntel(observations []scanner.Observation) *EmailIntel {
	for _, obs := range observations {
		var payload struct {
			Kind string      `json:"kind"`
			Info *EmailIntel `json:"info"`
		}
		if json.Unmarshal(obs.Payload, &payload) == nil && payload.Kind == "email_intel" && payload.Info != nil {
			return payload.Info
		}
	}
	return nil
}
