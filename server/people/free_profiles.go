package people

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"stare/server/scanner"
)

// ---------- Gravatar ----------

type GravatarCollector struct{}

func (c *GravatarCollector) Name() string { return "gravatar" }

func (c *GravatarCollector) Collect(ctx context.Context, target string) ([]scanner.Observation, error) {
	if !strings.Contains(target, "@") {
		return nil, nil
	}
	sum := md5.Sum([]byte(strings.ToLower(strings.TrimSpace(target))))
	hash := hex.EncodeToString(sum[:])
	link := "https://gravatar.com/" + hash + ".json"

	body, status, err := httpGetJSON(ctx, link)
	if err != nil || status != http.StatusOK {
		return nil, err
	}
	var payload struct {
		Entry []struct {
			DisplayName  string `json:"displayName"`
			AboutMe      string `json:"aboutMe"`
			ProfileURL   string `json:"profileUrl"`
			ThumbnailURL string `json:"thumbnailUrl"`
			Accounts     []struct {
				Shortname string `json:"shortname"`
				Username  string `json:"username"`
				URL       string `json:"url"`
				Verified  bool   `json:"verified"`
			} `json:"accounts"`
		} `json:"entry"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || len(payload.Entry) == 0 {
		return nil, nil
	}
	entry := payload.Entry[0]
	profileURL := entry.ProfileURL
	if profileURL == "" {
		profileURL = "https://gravatar.com/" + hash
	}
	obs := []scanner.Observation{Observation("gravatar", scanner.ConfidenceHigh, map[string]any{
		"platform": "gravatar",
		"handle":   strings.ToLower(target),
		"url":      profileURL,
		"name":     entry.DisplayName,
		"bio":      entry.AboutMe,
		"avatar":   entry.ThumbnailURL,
		"verified": true,
	})}
	for _, acc := range entry.Accounts {
		if acc.Shortname == "" || acc.Username == "" {
			continue
		}
		obs = append(obs, Observation("gravatar", scanner.ConfidenceHigh, map[string]any{
			"platform": acc.Shortname,
			"handle":   acc.Username,
			"url":      acc.URL,
			"verified": acc.Verified,
		}))
	}
	return obs, nil
}

// ---------- GitHub user ----------

type GitHubUserCollector struct{}

func (c *GitHubUserCollector) Name() string { return "githubuser" }

func (c *GitHubUserCollector) Collect(ctx context.Context, target string) ([]scanner.Observation, error) {
	handle := strings.TrimPrefix(strings.TrimSpace(target), "@")
	if handle == "" {
		return nil, nil
	}
	body, status, err := httpGetJSON(ctx, "https://api.github.com/users/"+url.PathEscape(handle))
	if err != nil || status != http.StatusOK {
		return nil, err
	}
	var user struct {
		Login     string `json:"login"`
		Name      string `json:"name"`
		Bio       string `json:"bio"`
		AvatarURL string `json:"avatar_url"`
		HTMLURL   string `json:"html_url"`
		Blog      string `json:"blog"`
		Location  string `json:"location"`
		Company   string `json:"company"`
		Twitter   string `json:"twitter_username"`
	}
	if err := json.Unmarshal(body, &user); err != nil || user.Login == "" {
		return nil, nil
	}
	payload := map[string]any{
		"platform": "github",
		"handle":   user.Login,
		"url":      user.HTMLURL,
		"name":     user.Name,
		"bio":      user.Bio,
		"avatar":   user.AvatarURL,
		"verified": true,
	}
	var links []string
	if user.Blog != "" {
		links = append(links, user.Blog)
	}
	if user.Location != "" {
		payload["location"] = user.Location
	}
	if user.Company != "" {
		payload["company"] = user.Company
	}
	if len(links) > 0 {
		payload["links"] = links
	}
	obs := []scanner.Observation{Observation("githubuser", scanner.ConfidenceHigh, payload)}
	if user.Twitter != "" {
		obs = append(obs, Observation("githubuser", scanner.ConfidenceHigh, map[string]any{
			"platform": "twitter",
			"handle":   user.Twitter,
			"url":      "https://x.com/" + user.Twitter,
			"verified": true,
		}))
	}
	return obs, nil
}

// ---------- GitLab user ----------

type GitLabUserCollector struct{}

func (c *GitLabUserCollector) Name() string { return "gitlab" }

func (c *GitLabUserCollector) Collect(ctx context.Context, target string) ([]scanner.Observation, error) {
	handle := strings.TrimPrefix(strings.TrimSpace(target), "@")
	body, status, err := httpGetJSON(ctx, "https://gitlab.com/api/v4/users?username="+url.QueryEscape(handle))
	if err != nil || status != http.StatusOK {
		return nil, err
	}
	var users []struct {
		Username  string `json:"username"`
		Name      string `json:"name"`
		Bio       string `json:"bio"`
		AvatarURL string `json:"avatar_url"`
		WebURL    string `json:"web_url"`
	}
	if err := json.Unmarshal(body, &users); err != nil || len(users) == 0 {
		return nil, nil
	}
	u := users[0]
	return []scanner.Observation{Observation("gitlab", scanner.ConfidenceHigh, map[string]any{
		"platform": "gitlab",
		"handle":   u.Username,
		"url":      u.WebURL,
		"name":     u.Name,
		"bio":      u.Bio,
		"avatar":   u.AvatarURL,
		"verified": true,
	})}, nil
}

// ---------- Keybase ----------

type KeybaseCollector struct{}

func (c *KeybaseCollector) Name() string { return "keybase" }

func (c *KeybaseCollector) Collect(ctx context.Context, target string) ([]scanner.Observation, error) {
	handle := strings.TrimPrefix(strings.TrimSpace(target), "@")
	endpoint := "https://keybase.io/_/api/1.0/user/lookup.json?username=" + url.QueryEscape(handle) + "&fields=profile,proofs_summary"
	body, status, err := httpGetJSON(ctx, endpoint)
	if err != nil || status != http.StatusOK {
		return nil, err
	}
	var payload struct {
		Them json.RawMessage `json:"them"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || len(payload.Them) == 0 {
		return nil, nil
	}

	type kbUser struct {
		Profile struct {
			FullName string `json:"full_name"`
			Bio      string `json:"bio"`
			Avatar   string `json:"avatar"`
		} `json:"profile"`
		Proofs struct {
			All []struct {
				ProofType string `json:"proof_type"`
				Nametag   string `json:"nametag"`
				Service   string `json:"service_url"`
				Human     string `json:"human_url"`
			} `json:"all"`
		} `json:"proofs_summary"`
	}
	var them kbUser
	if err := json.Unmarshal(payload.Them, &them); err != nil {
		var list []kbUser
		if err := json.Unmarshal(payload.Them, &list); err != nil || len(list) == 0 {
			return nil, nil
		}
		them = list[0]
	}
	if them.Profile.FullName == "" && them.Profile.Bio == "" && len(them.Proofs.All) == 0 {
		return nil, nil
	}
	obs := []scanner.Observation{Observation("keybase", scanner.ConfidenceHigh, map[string]any{
		"platform": "keybase",
		"handle":   handle,
		"url":      "https://keybase.io/" + handle,
		"name":     them.Profile.FullName,
		"bio":      them.Profile.Bio,
		"avatar":   them.Profile.Avatar,
		"verified": true,
	})}
	for _, proof := range them.Proofs.All {
		platform := strings.ToLower(proof.ProofType)
		if platform == "" || platform == "dns" || platform == "http" || platform == "https" {
			continue
		}
		link := proof.Human
		if link == "" {
			link = proof.Service
		}
		obs = append(obs, Observation("keybase", scanner.ConfidenceHigh, map[string]any{
			"platform": platform,
			"handle":   proof.Nametag,
			"url":      link,
			"verified": true,
		}))
	}
	return obs, nil
}

func httpGetJSON(ctx context.Context, link string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "Stare/1.0 (+osint)")
	req.Header.Set("Accept", "application/json")
	if strings.Contains(link, "api.github.com") {
		if token := os.Getenv("GITHUB_TOKEN"); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusTooManyRequests {
		return nil, resp.StatusCode, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return body, resp.StatusCode, err
}
