package people

import (
	"strings"
	"time"

	"stare/server/scanner"
)

// Fixture — детерминированные данные для тестов и PEOPLE_FIXTURE=1.
func Fixture(target string) Result {
	target = strings.TrimSpace(target)
	if target == "" {
		target = "test"
	}
	handle := target
	if i := strings.IndexByte(target, '@'); i > 0 {
		handle = target[:i]
	}

	observations := []scanner.Observation{
		Observation("sherlock", scanner.ConfidenceMedium, map[string]any{
			"platform": "github", "handle": handle, "url": "https://github.com/" + handle,
		}),
		Observation("maigret", scanner.ConfidenceHigh, map[string]any{
			"platform": "github", "handle": handle, "url": "https://github.com/" + handle,
		}),
		Observation("sherlock", scanner.ConfidenceMedium, map[string]any{
			"platform": "reddit", "handle": handle, "url": "https://reddit.com/user/" + handle,
		}),
		Observation("maigret", scanner.ConfidenceHigh, map[string]any{
			"platform": "vk", "handle": handle, "url": "https://vk.com/" + handle,
		}),
	}

	if strings.Contains(target, "@") {
		observations = append(observations, Observation("xposedornot", scanner.ConfidenceHigh, map[string]any{
			"kind":         "breach",
			"breach_name":  "ExampleBreach",
			"email":        target,
			"date":         "2024-01-01",
			"data_classes": []string{"emails", "usernames"},
		}))
	}
	if isPhone(target) {
		observations = append(observations, Observation("phone", scanner.ConfidenceMedium, map[string]any{
			"kind": "phone", "indicator": target, "e164": target, "country": "RU", "country_code": "7", "valid": true,
		}))
	}

	accounts, breaches, phone, registrations := Normalize(observations)
	return Result{
		Target:        target,
		Kind:          "people",
		InputType:     Detect(target),
		FetchedAt:     time.Now().UTC(),
		Observations:  observations,
		Accounts:      accounts,
		Actor:         BuildActor(target, accounts),
		Breaches:      breaches,
		Phone:         phone,
		Registrations: registrations,
	}
}
