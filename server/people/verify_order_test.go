package people

import "testing"

func TestChessPlayerIDPositive(t *testing.T) {
	acc := Account{Handle: "Yamickuru", Platform: "chess.com"}
	got := evaluateProfilePage(&acc, profileFetch{
		Status:      200,
		ContentType: "application/json",
		Body:        `{"player_id":123456,"code":0,"status":"ok"}`,
	})
	if got != ExistenceConfirmed {
		t.Fatalf("player_id must confirm chess profile, got %q", got)
	}
}

func TestDuolingoEmptyUsersAbsent(t *testing.T) {
	acc := Account{Handle: "lowstander", Platform: "duolingo"}
	got := evaluateProfilePage(&acc, profileFetch{
		Status:      200,
		ContentType: "application/json",
		Body:        `{"users" : []}`,
	})
	if got != ExistenceAbsent {
		t.Fatalf("empty users must be absent, got %q", got)
	}
}

func TestGenericJSONNegativesIgnored(t *testing.T) {
	acc := Account{Handle: "yamickuru", Platform: "example"}
	got := evaluateProfilePage(&acc, profileFetch{
		Status:      200,
		ContentType: "text/html",
		Body: `<html><head><title>yamickuru profile</title></head>` +
			`<body>{"code":0,"error":0,"status":"ok","success":true}</body></html>`,
	})
	if got != ExistenceConfirmed {
		t.Fatalf("generic JSON flags must not block confirmation, got %q", got)
	}
}

func TestPositiveMarkerBeatsNegative(t *testing.T) {
	acc := Account{Handle: "yamickuru", Platform: "example", PageMarker: "profile-card"}
	got := evaluateProfilePage(&acc, profileFetch{
		Status: 200,
		Body:   `<html><title>Profile</title><body>profile-card user not found</body></html>`,
	})
	if got != ExistenceConfirmed {
		t.Fatalf("positive marker must win over negative, got %q", got)
	}
}

func TestStrongNegativeIsAbsent(t *testing.T) {
	acc := Account{Handle: "yamickuru", Platform: "example"}
	got := evaluateProfilePage(&acc, profileFetch{
		Status: 200,
		Body:   `<html><title>Profile</title><body>user not found</body></html>`,
	})
	if got != ExistenceAbsent {
		t.Fatalf("strong negative without positive must be absent, got %q", got)
	}
}

func TestWeakNegativeStaysUnknown(t *testing.T) {
	acc := Account{Handle: "yamickuru", Platform: "example", PageNegative: "not here"}
	got := evaluateProfilePage(&acc, profileFetch{
		Status: 200,
		Body:   `<html><title>Profile</title><body>not here</body></html>`,
	})
	if got != ExistenceUnknown {
		t.Fatalf("weak negative must stay unknown, got %q", got)
	}
}
