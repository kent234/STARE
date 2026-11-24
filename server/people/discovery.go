package people

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"stare/server/scanner"
)

// Mention — найденное упоминание ника вне профиля: код, форумы, поиск,
// архивы. Это не аккаунт и не доказательство личности, поэтому живёт отдельно.
type Mention struct {
	ID      string `json:"id"`
	Source  string `json:"source"`
	URL     string `json:"url"`
	Title   string `json:"title,omitempty"`
	Context string `json:"context,omitempty"`
}

func ExtractMentions(observations []scanner.Observation) []Mention {
	seen := map[string]struct{}{}
	var out []Mention
	for _, obs := range observations {
		var payload struct {
			Kind    string `json:"kind"`
			Source  string `json:"mention_source"`
			URL     string `json:"url"`
			Title   string `json:"title"`
			Context string `json:"context"`
		}
		if json.Unmarshal(obs.Payload, &payload) != nil || payload.Kind != "mention" || payload.URL == "" {
			continue
		}
		source := payload.Source
		if source == "" {
			source = obs.Source
		}
		key := source + "|" + payload.URL
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, Mention{
			ID:      "mention:" + slugify(source) + ":" + slugify(payload.URL),
			Source:  source,
			URL:     payload.URL,
			Title:   cleanText(payload.Title),
			Context: cleanText(payload.Context),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].URL < out[j].URL
	})
	return out
}

// URLScanCollector — публичный поиск urlscan.io по вхождениям ника в URL.
// Это discovery, а не подтверждение профиля.
type URLScanCollector struct{}

func (c *URLScanCollector) Name() string { return "urlscan_search" }

func (c *URLScanCollector) Collect(ctx context.Context, target string) ([]scanner.Observation, error) {
	handle := registryHandle(target)
	if handle == "" {
		return nil, nil
	}
	query := url.QueryEscape("page.url:*" + handle + "*")
	link := "https://urlscan.io/api/v1/search/?q=" + query + "&size=20"
	status, body, err := fetchRegistryPage(ctx, discoveryClient(), http.MethodGet, link, "")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("urlscan search status: %d", status)
	}
	var payload struct {
		Results []struct {
			Page struct {
				URL    string `json:"url"`
				Domain string `json:"domain"`
			} `json:"page"`
			Task struct {
				URL string `json:"url"`
			} `json:"task"`
		} `json:"results"`
	}
	if json.Unmarshal([]byte(body), &payload) != nil {
		return nil, nil
	}
	seen := map[string]struct{}{}
	var obs []scanner.Observation
	for _, row := range payload.Results {
		found := row.Page.URL
		if found == "" {
			found = row.Task.URL
		}
		if found == "" || !strings.Contains(strings.ToLower(found), strings.ToLower(handle)) {
			continue
		}
		if _, ok := seen[found]; ok {
			continue
		}
		seen[found] = struct{}{}
		obs = append(obs, Observation("urlscan_search", scanner.ConfidenceLow, map[string]any{
			"platform":  firstNonEmptyString(row.Page.Domain, hostOfURL(found)),
			"handle":    handle,
			"url":       found,
			"verified":  false,
			"discovery": "urlscan",
		}))
	}
	return obs, nil
}

// HNMentionsCollector — комментарии/посты автора на Hacker News через Algolia.
type HNMentionsCollector struct{}

func (c *HNMentionsCollector) Name() string { return "hn_algolia" }

func (c *HNMentionsCollector) Collect(ctx context.Context, target string) ([]scanner.Observation, error) {
	handle := registryHandle(target)
	if handle == "" {
		return nil, nil
	}
	link := "https://hn.algolia.com/api/v1/search?tags=author_" + url.QueryEscape(handle) + "&hitsPerPage=10"
	status, body, err := fetchRegistryPage(ctx, discoveryClient(), http.MethodGet, link, "")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("hn algolia status: %d", status)
	}
	var payload struct {
		Hits []struct {
			ObjectID   string `json:"objectID"`
			Comment    string `json:"comment_text"`
			Title      string `json:"title"`
			StoryTitle string `json:"story_title"`
		} `json:"hits"`
	}
	if json.Unmarshal([]byte(body), &payload) != nil {
		return nil, nil
	}
	var obs []scanner.Observation
	for _, hit := range payload.Hits {
		if hit.ObjectID == "" {
			continue
		}
		title := firstNonEmptyString(hit.Title, hit.StoryTitle, "Hacker News mention")
		obs = append(obs, Observation("hn_algolia", scanner.ConfidenceLow, map[string]any{
			"kind":           "mention",
			"mention_source": "hn_algolia",
			"url":            "https://news.ycombinator.com/item?id=" + hit.ObjectID,
			"title":          title,
			"context":        truncateText(hit.Comment, 240),
		}))
	}
	return obs, nil
}

// GrepAppCollector — упоминания ника в публичном коде/конфигах.
type GrepAppCollector struct{}

func (c *GrepAppCollector) Name() string { return "grepapp" }

func (c *GrepAppCollector) Collect(ctx context.Context, target string) ([]scanner.Observation, error) {
	handle := registryHandle(target)
	if handle == "" {
		return nil, nil
	}
	link := "https://grep.app/api/search?q=" + url.QueryEscape(handle)
	status, body, err := fetchRegistryPage(ctx, discoveryClient(), http.MethodGet, link, "")
	if err != nil {
		return nil, err
	}
	if status == http.StatusForbidden || status == http.StatusTooManyRequests {
		return nil, fmt.Errorf("grep.app blocked: status %d", status)
	}
	if status != http.StatusOK {
		return nil, nil
	}
	var payload struct {
		Hits struct {
			Hits []struct {
				Repo struct {
					Raw string `json:"raw"`
				} `json:"repo"`
				Path struct {
					Raw string `json:"raw"`
				} `json:"path"`
				Content struct {
					Snippet string `json:"snippet"`
				} `json:"content"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if json.Unmarshal([]byte(body), &payload) != nil {
		return nil, nil
	}
	var obs []scanner.Observation
	for i, hit := range payload.Hits.Hits {
		if i >= 10 || hit.Repo.Raw == "" || hit.Path.Raw == "" {
			continue
		}
		link := "https://github.com/" + hit.Repo.Raw + "/blob/HEAD/" + hit.Path.Raw
		obs = append(obs, Observation("grepapp", scanner.ConfidenceLow, map[string]any{
			"kind":           "mention",
			"mention_source": "grepapp",
			"url":            link,
			"title":          hit.Repo.Raw + "/" + hit.Path.Raw,
			"context":        truncateText(stripTags(hit.Content.Snippet), 240),
		}))
	}
	return obs, nil
}

// SearchAPICollector — опциональный поиск (Brave/SerpAPI). Без ключа
// коллектор помечается missing и не влияет на результат.
type SearchAPICollector struct{}

func (c *SearchAPICollector) Name() string { return "search_api" }

func (c *SearchAPICollector) Collect(ctx context.Context, target string) ([]scanner.Observation, error) {
	handle := registryHandle(target)
	if handle == "" {
		return nil, nil
	}
	query := `"` + handle + `"`
	if key := os.Getenv("BRAVE_API_KEY"); key != "" {
		return braveSearch(ctx, key, query, handle)
	}
	if key := os.Getenv("SERPAPI_KEY"); key != "" {
		return serpAPISearch(ctx, key, query, handle)
	}
	return nil, nil
}

func braveSearch(ctx context.Context, key, query, handle string) ([]scanner.Observation, error) {
	link := "https://api.search.brave.com/res/v1/web/search?q=" + url.QueryEscape(query) + "&count=10"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Subscription-Token", key)
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("brave status: %d", resp.StatusCode)
	}
	var payload struct {
		Web struct {
			Results []struct {
				Title       string `json:"title"`
				URL         string `json:"url"`
				Description string `json:"description"`
			} `json:"results"`
		} `json:"web"`
	}
	if json.NewDecoder(resp.Body).Decode(&payload) != nil {
		return nil, nil
	}
	return searchMentions("brave", payload.Web.Results, handle), nil
}

func serpAPISearch(ctx context.Context, key, query, handle string) ([]scanner.Observation, error) {
	link := "https://serpapi.com/search.json?q=" + url.QueryEscape(query) +
		"&num=10&api_key=" + url.QueryEscape(key)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Get(link)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("serpapi status: %d", resp.StatusCode)
	}
	var payload struct {
		Organic []struct {
			Title   string `json:"title"`
			Link    string `json:"link"`
			Snippet string `json:"snippet"`
		} `json:"organic_results"`
	}
	if json.NewDecoder(resp.Body).Decode(&payload) != nil {
		return nil, nil
	}
	results := make([]struct {
		Title       string `json:"title"`
		URL         string `json:"url"`
		Description string `json:"description"`
	}, 0, len(payload.Organic))
	for _, item := range payload.Organic {
		results = append(results, struct {
			Title       string `json:"title"`
			URL         string `json:"url"`
			Description string `json:"description"`
		}{Title: item.Title, URL: item.Link, Description: item.Snippet})
	}
	return searchMentions("serpapi", results, handle), nil
}

func searchMentions(source string, results []struct {
	Title       string `json:"title"`
	URL         string `json:"url"`
	Description string `json:"description"`
}, handle string) []scanner.Observation {
	var obs []scanner.Observation
	for i, item := range results {
		if i >= 10 || item.URL == "" {
			continue
		}
		haystack := strings.ToLower(item.URL + " " + item.Title + " " + item.Description)
		if !strings.Contains(haystack, strings.ToLower(handle)) {
			continue
		}
		obs = append(obs, Observation(source, scanner.ConfidenceLow, map[string]any{
			"kind":           "mention",
			"mention_source": source,
			"url":            item.URL,
			"title":          item.Title,
			"context":        truncateText(item.Description, 240),
		}))
	}
	return obs
}

func discoveryClient() *http.Client {
	return &http.Client{Timeout: 12 * time.Second}
}

func hostOfURL(value string) string {
	if u, err := url.Parse(value); err == nil {
		return strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
	}
	return ""
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func truncateText(value string, limit int) string {
	value = cleanText(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}

func stripTags(value string) string {
	var b strings.Builder
	inTag := false
	for _, r := range value {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
		case !inTag:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func slugify(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	dash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			b.WriteRune(r)
			dash = false
		} else {
			dash = true
		}
	}
	if b.Len() == 0 {
		return "x"
	}
	return b.String()
}

// searchAPIKeysPresent — используется для статуса missing без вызова сети.
func searchAPIKeysPresent() bool {
	return os.Getenv("BRAVE_API_KEY") != "" || os.Getenv("SERPAPI_KEY") != ""
}
