package provider

import (
	"net/url"
	"slices"
	"testing"
)

func TestBuiltin(t *testing.T) {
	want := []string{"github", "linear", "slack", "asana", "google", "jira", "zoom"}
	if got := Names(); !slices.Equal(got, want) {
		t.Fatalf("Names() = %v, want OAuthService's seven: %v", got, want)
	}
	for _, p := range Builtin {
		for _, raw := range []string{p.AuthorizeURL, p.TokenURL} {
			u, err := url.Parse(raw)
			if err != nil || u.Scheme != "https" || u.Host == "" {
				t.Errorf("%s: %q isn't an https URL", p.Name, raw)
			}
		}
		if p.Title == "" || p.Setup == "" {
			t.Errorf("%s: no title or setup text", p.Name)
		}
		if got, ok := Lookup(p.Name); !ok || got.Name != p.Name {
			t.Errorf("Lookup(%q) = %v, %v", p.Name, got, ok)
		}
	}
	if _, ok := Lookup("gitlab"); ok {
		t.Error("Lookup found gitlab")
	}
}

// The providers OAuthService (in @raycast/utils 2.3.3) talks to directly have
// these defaults there; the relay talks to the same endpoints.
func TestDirectProvidersMatchOAuthService(t *testing.T) {
	for name, authorize := range map[string]string{
		"google": "https://accounts.google.com/o/oauth2/v2/auth",
		"jira":   "https://auth.atlassian.com/authorize",
		"zoom":   "https://zoom.us/oauth/authorize",
	} {
		if p, _ := Lookup(name); p.AuthorizeURL != authorize {
			t.Errorf("%s: %q, want %q", name, p.AuthorizeURL, authorize)
		}
	}
	for name, token := range map[string]string{
		"google": "https://oauth2.googleapis.com/token",
		"jira":   "https://auth.atlassian.com/oauth/token",
		"zoom":   "https://zoom.us/oauth/token",
	} {
		if p, _ := Lookup(name); p.TokenURL != token {
			t.Errorf("%s: %q, want %q", name, p.TokenURL, token)
		}
	}
}

func TestOnlyGitHubLacksRefresh(t *testing.T) {
	for _, p := range Builtin {
		if p.Refresh == (p.Name == "github") {
			t.Errorf("%s: Refresh = %v", p.Name, p.Refresh)
		}
	}
}
