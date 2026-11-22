// Package provider holds the built-in OAuth providers: the seven that
// @raycast/utils' OAuthService knows (GitHub, Linear, Slack, Asana, Google,
// Atlassian for Jira and Confluence, and Zoom), fourteen that store extensions
// reach through Raycast's other sign-in servers (Notion, Todoist, Basecamp,
// Gumroad, Moneybird, FreeAgent, Mollie, Plane, Homey, Figma, 42, TickTick, Zoho
// and Webflow), and how the relay talks to each.
package provider

import "slices"

// ClientAuth says how the relay sends its client credentials with a token request.
type ClientAuth int

const (
	// ClientAuthBody puts client_id and client_secret in the request body.
	ClientAuthBody ClientAuth = iota
	// ClientAuthBasic sends them as HTTP Basic authentication.
	ClientAuthBasic
)

// BodyEncoding is how a token request's body is encoded.
type BodyEncoding int

const (
	// BodyForm is application/x-www-form-urlencoded.
	BodyForm BodyEncoding = iota
	// BodyJSON is application/json.
	BodyJSON
)

// Provider describes one OAuth provider.
type Provider struct {
	// Name is the provider's path segment: /<name>/authorize.
	Name string
	// Title is the provider's name for people.
	Title string
	// AuthorizeURL is the provider's authorization endpoint.
	AuthorizeURL string
	// TokenURL is the provider's token endpoint, used for refreshing too.
	TokenURL string
	// PKCE says whether the relay uses PKCE with the provider as well.
	PKCE bool
	// Refresh says whether the provider issues refresh tokens.
	Refresh bool
	// ClientAuth is how client credentials go with token requests.
	ClientAuth ClientAuth
	// TokenBody is how token requests are encoded.
	TokenBody BodyEncoding
	// AuthorizeDefaults are authorize parameters the relay adds when the extension didn't send them: what
	// Raycast's proxy adds for the provider (Atlassian's), or what the relay's own app needs (Zoho's).
	AuthorizeDefaults map[string]string
	// CodeParams are parameters the relay adds to every code exchange (Tesla's audience). The relay's own always win.
	CodeParams map[string]string
	// RefreshParams are parameters the relay adds to every refresh grant (WHOOP's scope=offline). The relay's own
	// always win.
	RefreshParams map[string]string
	// RefreshRedirectURI says whether a refresh grant carries the relay's callback as redirect_uri, as Bangumi and
	// Wave require.
	RefreshRedirectURI bool
	// Setup says where the provider's OAuth apps are registered, for the front page.
	Setup string
}

// Builtin lists the providers in a stable order.
var Builtin = []Provider{
	{
		Name:         "github",
		Title:        "GitHub",
		AuthorizeURL: "https://github.com/login/oauth/authorize",
		TokenURL:     "https://github.com/login/oauth/access_token",
		PKCE:         true,
		// OAuth apps' tokens don't expire and come without a refresh token.
		Refresh: false,
		Setup:   "GitHub → Settings → Developer settings → OAuth Apps",
	},
	{
		Name:         "linear",
		Title:        "Linear",
		AuthorizeURL: "https://linear.app/oauth/authorize",
		TokenURL:     "https://api.linear.app/oauth/token",
		PKCE:         true,
		Refresh:      true,
		Setup:        "Linear → Settings → API → OAuth applications",
	},
	{
		Name:         "slack",
		Title:        "Slack",
		AuthorizeURL: "https://slack.com/oauth/v2/authorize",
		TokenURL:     "https://slack.com/api/oauth.v2.access",
		PKCE:         false,
		Refresh:      true,
		Setup:        "api.slack.com/apps → your app → OAuth & Permissions → Redirect URLs",
	},
	{
		Name:         "asana",
		Title:        "Asana",
		AuthorizeURL: "https://app.asana.com/-/oauth_authorize",
		TokenURL:     "https://app.asana.com/-/oauth_token",
		PKCE:         true,
		Refresh:      true,
		Setup:        "Asana developer console → your app → OAuth → Redirect URLs",
	},
	{
		Name:         "google",
		Title:        "Google",
		AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		PKCE:         true,
		Refresh:      true,
		Setup:        "Google Cloud console → APIs & Services → Credentials → OAuth client ID (Web application) → Authorized redirect URIs",
	},
	{
		// One Atlassian app covers Jira and Confluence. Until v0.3.0 this was "jira", which stays an alias.
		Name:         "atlassian",
		Title:        "Atlassian (Jira, Confluence)",
		AuthorizeURL: "https://auth.atlassian.com/authorize",
		TokenURL:     "https://auth.atlassian.com/oauth/token",
		PKCE:         false,
		Refresh:      true,
		TokenBody:    BodyJSON,
		// Atlassian's 3LO needs both. Raycast's Jira proxy adds them, so the Jira extension doesn't send them.
		AuthorizeDefaults: map[string]string{"audience": "api.atlassian.com", "prompt": "consent"},
		Setup: "developer.atlassian.com → Developer console → your app → Authorization → OAuth 2.0 (3LO) → Callback URL; " +
			"Permissions → the Jira and Confluence API scopes your extensions ask for",
	},
	{
		Name:         "zoom",
		Title:        "Zoom",
		AuthorizeURL: "https://zoom.us/oauth/authorize",
		TokenURL:     "https://zoom.us/oauth/token",
		PKCE:         true,
		Refresh:      true,
		ClientAuth:   ClientAuthBasic,
		Setup:        "Zoom App Marketplace → Develop → your app → OAuth Redirect URL and OAuth allow list",
	},
	{
		Name:         "notion",
		Title:        "Notion",
		AuthorizeURL: "https://api.notion.com/v1/oauth/authorize",
		TokenURL:     "https://api.notion.com/v1/oauth/token",
		PKCE:         false,
		Refresh:      true,
		ClientAuth:   ClientAuthBasic,
		TokenBody:    BodyJSON,
		Setup:        "Notion developer portal → Developer connections → New connection (OAuth, installable in any workspace) → OAuth Domain & URIs",
	},
	{
		Name:         "todoist",
		Title:        "Todoist",
		AuthorizeURL: "https://app.todoist.com/oauth/authorize",
		TokenURL:     "https://api.todoist.com/oauth/access_token",
		PKCE:         false,
		Refresh:      true,
		Setup:        "Todoist → Settings → Integrations → App Management → your app → OAuth redirect URL",
	},
	{
		Name:         "basecamp",
		Title:        "Basecamp",
		AuthorizeURL: "https://launchpad.37signals.com/authorization/new",
		TokenURL:     "https://launchpad.37signals.com/authorization/token",
		PKCE:         false,
		Refresh:      true,
		Setup:        "launchpad.37signals.com/integrations → your application → Redirect URI",
	},
	{
		Name:         "gumroad",
		Title:        "Gumroad",
		AuthorizeURL: "https://gumroad.com/oauth/authorize",
		TokenURL:     "https://gumroad.com/oauth/token",
		PKCE:         false,
		// Its access tokens don't expire, so they're never refreshed, but it issues refresh tokens all the same.
		Refresh: true,
		Setup:   "Gumroad → Settings → Advanced → Applications → your application → Redirect URI",
	},
	{
		Name:         "moneybird",
		Title:        "Moneybird",
		AuthorizeURL: "https://moneybird.com/oauth/authorize",
		TokenURL:     "https://moneybird.com/oauth/token",
		PKCE:         false,
		Refresh:      true,
		Setup:        "moneybird.com/user/applications/new → External OAuth application → Redirect URI",
	},
	{
		Name:         "freeagent",
		Title:        "FreeAgent",
		AuthorizeURL: "https://api.freeagent.com/v2/approve_app",
		TokenURL:     "https://api.freeagent.com/v2/token_endpoint",
		PKCE:         false,
		Refresh:      true,
		ClientAuth:   ClientAuthBasic,
		Setup:        "FreeAgent Developer Dashboard (dev.freeagent.com) → My Apps → your app → Redirect URIs",
	},
	{
		Name:         "mollie",
		Title:        "Mollie",
		AuthorizeURL: "https://my.mollie.com/oauth2/authorize",
		TokenURL:     "https://api.mollie.com/oauth2/tokens",
		PKCE:         false,
		Refresh:      true,
		ClientAuth:   ClientAuthBasic,
		Setup:        "Mollie → Developers → Your apps → Create application → Redirect URL",
	},
	{
		Name:         "plane",
		Title:        "Plane",
		AuthorizeURL: "https://api.plane.so/auth/o/authorize-app/",
		TokenURL:     "https://api.plane.so/auth/o/token/",
		PKCE:         false,
		Refresh:      true,
		Setup:        "Plane → Workspace settings → Integrations → Build your own → Redirect URI; Scopes & Permissions → the scopes your extensions ask for",
	},
	{
		Name:         "homey",
		Title:        "Homey",
		AuthorizeURL: "https://api.athom.com/oauth2/authorise",
		TokenURL:     "https://api.athom.com/oauth2/token",
		PKCE:         false,
		Refresh:      true,
		ClientAuth:   ClientAuthBasic,
		Setup:        "Homey Developer Tools (tools.developer.homey.app/api/clients) → your Web API client → Redirect URI",
	},
	{
		Name:         "figma",
		Title:        "Figma",
		AuthorizeURL: "https://www.figma.com/oauth",
		TokenURL:     "https://api.figma.com/v1/oauth/token",
		PKCE:         true,
		Refresh:      true,
		ClientAuth:   ClientAuthBasic,
		Setup:        "figma.com/developers/apps → your app → OAuth credentials → Redirect URLs; OAuth scopes → the scopes your extensions ask for",
	},
	{
		Name:         "intra42",
		Title:        "42",
		AuthorizeURL: "https://api.intra.42.fr/oauth/authorize",
		TokenURL:     "https://api.intra.42.fr/oauth/token",
		PKCE:         false,
		Refresh:      true,
		Setup:        "profile.intra.42.fr/oauth/applications → your application → Redirect URI; Scopes → the scopes your extensions ask for",
	},
	{
		Name:         "ticktick",
		Title:        "TickTick",
		AuthorizeURL: "https://ticktick.com/oauth/authorize",
		TokenURL:     "https://ticktick.com/oauth/token",
		PKCE:         false,
		// TickTick documents only the code grant, but its answers can carry a refresh token, so a refresh goes on
		// and TickTick decides.
		Refresh:    true,
		ClientAuth: ClientAuthBasic,
		Setup:      "TickTick Developer Center (developer.ticktick.com/manage) → your app → Redirect URL",
	},
	{
		Name:         "zoho",
		Title:        "Zoho",
		AuthorizeURL: "https://accounts.zoho.com/oauth/v2/auth",
		TokenURL:     "https://accounts.zoho.com/oauth/v2/token",
		PKCE:         false,
		Refresh:      true,
		// Zoho gives a refresh token only at a user's first consent unless the sign-in asks for consent again, so
		// through one app a user's next sign-in would get none.
		AuthorizeDefaults: map[string]string{"prompt": "consent"},
		Setup:             "Zoho API Console (api-console.zoho.com) → Server-based Applications → Authorized Redirect URIs",
	},
	{
		Name:         "webflow",
		Title:        "Webflow",
		AuthorizeURL: "https://webflow.com/oauth/authorize",
		TokenURL:     "https://api.webflow.com/oauth/access_token",
		PKCE:         false,
		// Its access tokens come without a refresh token.
		Refresh:   false,
		TokenBody: BodyJSON,
		Setup:     "Webflow → Workspace settings → Apps & Integrations → App Development → your App → Data Client → Redirect URI and scopes",
	},
	{
		Name:         "bangumi",
		Title:        "Bangumi",
		AuthorizeURL: "https://bgm.tv/oauth/authorize",
		TokenURL:     "https://bgm.tv/oauth/access_token",
		PKCE:         false,
		Refresh:      true,
		// Bangumi wants the app's callback with a refresh too.
		RefreshRedirectURI: true,
		Setup:              "bgm.tv/dev/app → your app → callback URL",
	},
	{
		Name:         "wave",
		Title:        "Wave",
		AuthorizeURL: "https://api.waveapps.com/oauth2/authorize/",
		TokenURL:     "https://api.waveapps.com/oauth2/token/",
		PKCE:         false,
		Refresh:      true,
		// Wave wants the sign-in's redirect URI with a refresh too.
		RefreshRedirectURI: true,
		Setup:              "Wave Developer Portal → Manage Applications → your application → Redirect URIs",
	},
	{
		Name:         "whoop",
		Title:        "WHOOP",
		AuthorizeURL: "https://api.prod.whoop.com/oauth/oauth2/auth",
		TokenURL:     "https://api.prod.whoop.com/oauth/oauth2/token",
		PKCE:         false,
		Refresh:      true,
		// A refresh asks for the offline scope again, so that WHOOP's answer carries the next refresh token.
		RefreshParams: map[string]string{"scope": "offline"},
		Setup:         "WHOOP Developer Dashboard (developer-dashboard.whoop.com) → your app → Redirect URLs; Scopes → the scopes your extensions ask for",
	},
	{
		Name:         "miro",
		Title:        "Miro",
		AuthorizeURL: "https://miro.com/oauth/authorize",
		TokenURL:     "https://api.miro.com/v1/oauth/token",
		PKCE:         false,
		// Only an app created with expiring tokens gets refresh tokens; the others' tokens don't expire.
		Refresh: true,
		Setup:   "Miro → Settings → Your apps → Create new app (Expire user authorization token on) → Redirect URI; Permissions → boards:read and boards:write",
	},
}

// Aliases maps a deprecated path name to the provider it now stands for. They work for one release, and the
// relay logs that they're deprecated.
var Aliases = map[string]string{"jira": "atlassian"}

// Canonical returns the provider name a path name stands for: an alias's provider, else the name itself.
func Canonical(name string) string {
	if canonical, ok := Aliases[name]; ok {
		return canonical
	}
	return name
}

// AliasesOf lists the deprecated names that stand for name, sorted.
func AliasesOf(name string) []string {
	var aliases []string
	for alias, canonical := range Aliases {
		if canonical == name {
			aliases = append(aliases, alias)
		}
	}
	slices.Sort(aliases)
	return aliases
}

// Lookup returns the built-in provider with this name.
func Lookup(name string) (Provider, bool) {
	i := slices.IndexFunc(Builtin, func(p Provider) bool { return p.Name == name })
	if i < 0 {
		return Provider{}, false
	}
	return Builtin[i], true
}

// Names lists the built-in providers' names, in Builtin's order.
func Names() []string {
	names := make([]string, len(Builtin))
	for i, p := range Builtin {
		names[i] = p.Name
	}
	return names
}
