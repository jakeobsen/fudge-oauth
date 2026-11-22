package provider

import (
	"net/url"
	"slices"
	"testing"
)

func TestBuiltin(t *testing.T) {
	want := []string{
		"github", "linear", "slack", "asana", "google", "atlassian", "zoom",
		"notion", "todoist", "basecamp", "gumroad", "moneybird",
	}
	if got := Names(); !slices.Equal(got, want) {
		t.Fatalf("Names() = %v, want OAuthService's seven, then the five behind Raycast's other sign-in servers: %v", got, want)
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
		"google":    "https://accounts.google.com/o/oauth2/v2/auth",
		"atlassian": "https://auth.atlassian.com/authorize",
		"zoom":      "https://zoom.us/oauth/authorize",
	} {
		if p, _ := Lookup(name); p.AuthorizeURL != authorize {
			t.Errorf("%s: %q, want %q", name, p.AuthorizeURL, authorize)
		}
	}
	for name, token := range map[string]string{
		"google":    "https://oauth2.googleapis.com/token",
		"atlassian": "https://auth.atlassian.com/oauth/token",
		"zoom":      "https://zoom.us/oauth/token",
	} {
		if p, _ := Lookup(name); p.TokenURL != token {
			t.Errorf("%s: %q, want %q", name, p.TokenURL, token)
		}
	}
}

// The five services store extensions reach through Raycast's other sign-in
// servers (FUD-166), as each service documents them.
func TestServicesBehindRaycastsOtherSignInServers(t *testing.T) {
	for _, want := range []Provider{
		// https://developers.notion.com/guides/authorization/overview and
		// https://developers.notion.com/reference/create-a-token: HTTP Basic, a JSON
		// body, refresh tokens, no PKCE.
		{
			Name: "notion", AuthorizeURL: "https://api.notion.com/v1/oauth/authorize",
			TokenURL: "https://api.notion.com/v1/oauth/token", PKCE: false, Refresh: true,
			ClientAuth: ClientAuthBasic, TokenBody: BodyJSON,
		},
		// https://developer.todoist.com/api/v1/: credentials in a form body, refresh
		// tokens (on by default for new apps, rotated), PKCE only for public clients.
		{
			Name: "todoist", AuthorizeURL: "https://app.todoist.com/oauth/authorize",
			TokenURL: "https://api.todoist.com/oauth/access_token", PKCE: false, Refresh: true,
			ClientAuth: ClientAuthBody, TokenBody: BodyForm,
		},
		// https://github.com/basecamp/bc3-api/blob/master/sections/authentication.md:
		// credentials as parameters, refresh tokens always issued, no PKCE.
		{
			Name: "basecamp", AuthorizeURL: "https://launchpad.37signals.com/authorization/new",
			TokenURL: "https://launchpad.37signals.com/authorization/token", PKCE: false, Refresh: true,
			ClientAuth: ClientAuthBody, TokenBody: BodyForm,
		},
		// Gumroad's own OmniAuth strategy (antiwork/omniauth-gumroad) for the URLs, and
		// its Doorkeeper settings (antiwork/gumroad, config/initializers/doorkeeper.rb):
		// refresh tokens on, PKCE not forced.
		{
			Name: "gumroad", AuthorizeURL: "https://gumroad.com/oauth/authorize",
			TokenURL: "https://gumroad.com/oauth/token", PKCE: false, Refresh: true,
			ClientAuth: ClientAuthBody, TokenBody: BodyForm,
		},
		// https://developer.moneybird.com/authentication/: client_id and client_secret
		// in the body, a refresh token in the example answer, no PKCE.
		{
			Name: "moneybird", AuthorizeURL: "https://moneybird.com/oauth/authorize",
			TokenURL: "https://moneybird.com/oauth/token", PKCE: false, Refresh: true,
			ClientAuth: ClientAuthBody, TokenBody: BodyForm,
		},
	} {
		got, ok := Lookup(want.Name)
		if !ok {
			t.Errorf("%s: not built in", want.Name)
			continue
		}
		if got.AuthorizeURL != want.AuthorizeURL || got.TokenURL != want.TokenURL || got.PKCE != want.PKCE ||
			got.Refresh != want.Refresh || got.ClientAuth != want.ClientAuth || got.TokenBody != want.TokenBody {
			t.Errorf("%s: %+v, want %+v", want.Name, got, want)
		}
		if len(got.AuthorizeDefaults) != 0 {
			t.Errorf("%s: AuthorizeDefaults %v, want none", want.Name, got.AuthorizeDefaults)
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
