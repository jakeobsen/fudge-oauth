package provider

import (
	"maps"
	"net/url"
	"slices"
	"testing"
)

func TestBuiltin(t *testing.T) {
	want := []string{
		"github", "linear", "slack", "asana", "google", "atlassian", "zoom",
		"notion", "todoist", "basecamp", "gumroad", "moneybird",
		"freeagent", "mollie", "plane", "homey", "figma",
		"intra42", "ticktick", "zoho", "webflow",
	}
	if got := Names(); !slices.Equal(got, want) {
		t.Fatalf("Names() = %v, want OAuthService's seven, then the fourteen behind Raycast's other sign-in servers: %v", got, want)
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

// The fourteen services store extensions reach through Raycast's other sign-in
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
		// https://dev.freeagent.com/docs/oauth: HTTP Basic, refresh tokens, no PKCE.
		// Its examples label a form body as JSON, so the form body is inferred: FreeAgent
		// implements OAuth 2.0 Draft 22, whose token requests are form-encoded, and its
		// quick start drives it from Google's OAuth 2.0 Playground.
		{
			Name: "freeagent", AuthorizeURL: "https://api.freeagent.com/v2/approve_app",
			TokenURL: "https://api.freeagent.com/v2/token_endpoint", PKCE: false, Refresh: true,
			ClientAuth: ClientAuthBasic, TokenBody: BodyForm,
		},
		// https://docs.mollie.com/reference/authorize-endpoint and
		// https://docs.mollie.com/reference/oauth-generate-tokens: HTTP Basic, a form
		// body (or JSON), refresh tokens that don't expire, no PKCE.
		{
			Name: "mollie", AuthorizeURL: "https://my.mollie.com/oauth2/authorize",
			TokenURL: "https://api.mollie.com/oauth2/tokens", PKCE: false, Refresh: true,
			ClientAuth: ClientAuthBasic, TokenBody: BodyForm,
		},
		// https://developers.plane.so/dev-tools/build-plane-app/choose-token-flow: the
		// user-token flow, client_id and client_secret in a form body, refresh tokens,
		// no PKCE.
		{
			Name: "plane", AuthorizeURL: "https://api.plane.so/auth/o/authorize-app/",
			TokenURL: "https://api.plane.so/auth/o/token/", PKCE: false, Refresh: true,
			ClientAuth: ClientAuthBody, TokenBody: BodyForm,
		},
		// https://api.developer.homey.app/http-and-socket.io/http-specification.md: HTTP
		// Basic, a form body, refresh tokens, no PKCE.
		{
			Name: "homey", AuthorizeURL: "https://api.athom.com/oauth2/authorise",
			TokenURL: "https://api.athom.com/oauth2/token", PKCE: false, Refresh: true,
			ClientAuth: ClientAuthBasic, TokenBody: BodyForm,
		},
		// https://developers.figma.com/docs/rest-api/oauth-apps/: HTTP Basic, a form
		// body, refresh tokens, PKCE (S256) recommended. That page refreshes at
		// /v1/oauth/refresh; the changelog of May 16, 2025
		// (https://developers.figma.com/docs/rest-api/changelog/) says to refresh at the
		// token URL, as the relay does.
		{
			Name: "figma", AuthorizeURL: "https://www.figma.com/oauth",
			TokenURL: "https://api.figma.com/v1/oauth/token", PKCE: true, Refresh: true,
			ClientAuth: ClientAuthBasic, TokenBody: BodyForm,
		},
		// 42's own guides need a 42 login, so the URLs come from an unofficial public copy
		// of them, last updated in 2021: credentials as parameters, a form body (its code
		// exchange is multipart, its other example form-encoded), no PKCE mentioned.
		// Refresh is inferred: no public 42 page documents it, but the extension sets a
		// refresh URL, and third-party code refreshes at the token URL.
		{
			Name: "intra42", AuthorizeURL: "https://api.intra.42.fr/oauth/authorize",
			TokenURL: "https://api.intra.42.fr/oauth/token", PKCE: false, Refresh: true,
			ClientAuth: ClientAuthBody, TokenBody: BodyForm,
		},
		// https://developer.ticktick.com/docs/openapi.md: HTTP Basic, a form body, no PKCE.
		// It documents only the code grant, so refresh is inferred: the extension's author
		// writes that TickTick's refresh-token grant is unreliable.
		{
			Name: "ticktick", AuthorizeURL: "https://ticktick.com/oauth/authorize",
			TokenURL: "https://ticktick.com/oauth/token", PKCE: false, Refresh: true,
			ClientAuth: ClientAuthBasic, TokenBody: BodyForm,
		},
		// https://www.zoho.com/developer/oauth/web-server-apps/get-access-token.html and
		// https://www.zoho.com/developer/oauth/web-server-apps/refresh-access-token.html,
		// at the US data center: credentials as parameters, refresh tokens, no PKCE for
		// server-based apps. The code exchange's form body is Zoho's own CRM SDK's
		// (zoho/zohocrm-python-sdk-8.0). prompt=consent, since otherwise Zoho gives a
		// refresh token only at a user's first consent.
		{
			Name: "zoho", AuthorizeURL: "https://accounts.zoho.com/oauth/v2/auth",
			TokenURL: "https://accounts.zoho.com/oauth/v2/token", PKCE: false, Refresh: true,
			ClientAuth: ClientAuthBody, TokenBody: BodyForm,
			AuthorizeDefaults: map[string]string{"prompt": "consent"},
		},
		// https://developers.webflow.com/data/reference/oauth-app.md: credentials in the
		// body, no refresh tokens, no PKCE. The JSON body with grant_type is its EU hosting
		// page's (https://developers.webflow.com/data/reference/eu-hosting.md) and its
		// SDK's (webflow-api 3.3.4, the version the extension locks).
		{
			Name: "webflow", AuthorizeURL: "https://webflow.com/oauth/authorize",
			TokenURL: "https://api.webflow.com/oauth/access_token", PKCE: false, Refresh: false,
			ClientAuth: ClientAuthBody, TokenBody: BodyJSON,
		},
	} {
		got, ok := Lookup(want.Name)
		if !ok {
			t.Errorf("%s: not built in", want.Name)
			continue
		}
		if got.AuthorizeURL != want.AuthorizeURL || got.TokenURL != want.TokenURL || got.PKCE != want.PKCE ||
			got.Refresh != want.Refresh || got.ClientAuth != want.ClientAuth || got.TokenBody != want.TokenBody ||
			got.RefreshRedirectURI != want.RefreshRedirectURI || !maps.Equal(got.CodeParams, want.CodeParams) ||
			!maps.Equal(got.RefreshParams, want.RefreshParams) {
			t.Errorf("%s: %+v, want %+v", want.Name, got, want)
		}
		if !maps.Equal(got.AuthorizeDefaults, want.AuthorizeDefaults) {
			t.Errorf("%s: AuthorizeDefaults %v, want %v", want.Name, got.AuthorizeDefaults, want.AuthorizeDefaults)
		}
	}
}

// Each token parameter field is set only for the services whose docs ask for it, and never names a parameter the
// relay sets itself.
func TestOnlyTheirProvidersAddTokenParameters(t *testing.T) {
	refreshRedirectURI := []string{"bangumi", "wave"}
	refreshParams := map[string]map[string]string{"whoop": {"scope": "offline"}}
	codeParams := map[string]map[string]string{}
	relaysOwn := []string{"grant_type", "code", "code_verifier", "redirect_uri", "refresh_token", "client_id", "client_secret"}
	for _, p := range Builtin {
		if p.RefreshRedirectURI != slices.Contains(refreshRedirectURI, p.Name) {
			t.Errorf("%s: RefreshRedirectURI = %v", p.Name, p.RefreshRedirectURI)
		}
		if !maps.Equal(p.RefreshParams, refreshParams[p.Name]) {
			t.Errorf("%s: RefreshParams %v, want %v", p.Name, p.RefreshParams, refreshParams[p.Name])
		}
		if !maps.Equal(p.CodeParams, codeParams[p.Name]) {
			t.Errorf("%s: CodeParams %v, want %v", p.Name, p.CodeParams, codeParams[p.Name])
		}
		for _, params := range []map[string]string{p.CodeParams, p.RefreshParams} {
			for name := range params {
				if slices.Contains(relaysOwn, name) {
					t.Errorf("%s: adds %s, which the relay sets itself", p.Name, name)
				}
			}
		}
	}
}

func TestOnlyGitHubAndWebflowLackRefresh(t *testing.T) {
	for _, p := range Builtin {
		if p.Refresh == (p.Name == "github" || p.Name == "webflow") {
			t.Errorf("%s: Refresh = %v", p.Name, p.Refresh)
		}
	}
}
