package relay

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jakeobsen/fudge-oauth/internal/config"
	"github.com/jakeobsen/fudge-oauth/internal/provider"
)

// What Fudge and @raycast/utils 2.3.3 send. OAuthService.fetchTokens and
// OAuthService.refreshTokens build the token bodies below, field for field and
// in this order, as JSON or with URLSearchParams (which Node's fetch sends as
// "application/x-www-form-urlencoded;charset=UTF-8"). The authorize URL is
// Raycast's AuthorizationRequest.toURL(), which Fudge's OAuth.PKCEClient builds
// (SPEC-056).

const (
	extensionClientID = "extension-client-id"
	fudgeRedirect     = "http://127.0.0.1:53682/oauth/callback/k3l9xq"
)

// extension is a sign-in as an extension starts it through OAuthService's
// built-in provider: its scope and extraParameters.
type extension struct {
	scope  string
	extras map[string]string
}

var extensions = map[string]extension{
	"github": {scope: "repo read:user"},
	"linear": {scope: "read write", extras: map[string]string{"actor": "user"}},
	// OAuthService.slack sets scope to "" and moves the scope to user_scope.
	"slack":     {scope: "", extras: map[string]string{"user_scope": "emoji:read"}},
	"asana":     {scope: "default"},
	"google":    {scope: "https://www.googleapis.com/auth/drive.readonly", extras: map[string]string{"access_type": "offline", "prompt": "consent"}},
	"atlassian": {scope: "read:jira-work offline_access", extras: map[string]string{"audience": "api.atlassian.com", "prompt": "consent"}},
	"zoom":      {scope: "meeting:write"},
	// The store's notion extension (notion/src/utils/notion/oauth.ts) sends no scope and owner=user.
	"notion": {scope: "", extras: map[string]string{"owner": "user"}},
	// The store's todoist extension (todoist/src/helpers/withTodoistApi.tsx), comma-separated as Todoist wants.
	"todoist": {scope: "data:read_write,data:delete,project:delete"},
	// The store's trek extension (trek/src/oauth/auth.tsx) sends no scope and Basecamp's legacy type=web_server.
	"basecamp": {scope: "", extras: map[string]string{"type": "web_server"}},
	// The store's gumroad extension (gumroad/src/oauth.ts).
	"gumroad": {scope: "view_profile view_sales"},
	// The store's moneybird extension (moneybird/src/oauth/client.ts).
	"moneybird": {scope: "time_entries sales_invoices settings"},
	// The store's freeagent extension (freeagent/src/oauth.ts).
	"freeagent": {scope: "read write"},
	// The store's mollie-for-raycast extension (mollie-for-raycast/src/oauth.ts). It builds its token bodies itself,
	// with the fields OAuthService sends as JSON, so exchangeFields and refreshFields are its bodies too.
	"mollie": {scope: "organizations.read profiles.read payments.read payments.write sales-invoices.read sales-invoices.write balances.read settlements.read payment-links.read payment-links.write subscriptions.read subscriptions.write refunds.write refunds.read"},
	// The store's plane extension (plane/src/api/auth.ts).
	"plane": {scope: "read write"},
	// The store's homey extension (homey/src/lib/Homey.ts) sends no scope.
	"homey": {scope: ""},
	// The store's figma-files extension (figma-files/src/oauth.ts), comma-separated, which Figma takes.
	"figma": {scope: "file_content:read,file_metadata:read,file_versions:read,projects:read"},
	// The store's 42-api extension (42-api/src/lib/auth.ts).
	"intra42": {scope: "public profile"},
	// The store's ticktick-plus extension (ticktick-plus/src/api/oauth.ts).
	"ticktick": {scope: "tasks:read tasks:write"},
	// The store's zoho-mail extension (zoho-mail/src/oauth.ts): space-separated, though Zoho documents commas,
	// and access_type=offline for a refresh token. It sends no prompt.
	"zoho": {scope: "ZohoMail.accounts.READ ZohoMail.folders.READ ZohoMail.messages.READ ZohoMail.messages.UPDATE ZohoMail.organization.accounts.READ ZohoMail.organization.domains.READ ZohoMail.partner.organization.READ", extras: map[string]string{"access_type": "offline"}},
	// The store's webflow-sites extension (webflow-sites/src/oauth.ts).
	"webflow": {scope: "sites:read assets:read"},
}

var encodings = []string{"json", "url-encoded"}

// fudgeSignIn is what Fudge keeps while a sign-in runs.
type fudgeSignIn struct {
	verifier string
	state    string
}

func randomVerifier(t *testing.T) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func (h *harness) authorizeURL(name string, si fudgeSignIn, change func(url.Values)) string {
	ext := extensions[name]
	q := url.Values{
		"client_id":             {extensionClientID},
		"redirect_uri":          {fudgeRedirect},
		"response_type":         {"code"},
		"scope":                 {ext.scope},
		"state":                 {si.state},
		"code_challenge":        {s256(si.verifier)},
		"code_challenge_method": {"S256"},
	}
	for k, v := range ext.extras {
		q.Set(k, v)
	}
	if change != nil {
		change(q)
	}
	return h.relay.URL + "/" + name + "/authorize?" + q.Encode()
}

func (h *harness) newSignIn(t *testing.T) fudgeSignIn {
	si := fudgeSignIn{verifier: randomVerifier(t), state: "FUDGE-STATE-" + randomVerifier(t)[:16]}
	h.remember(si.verifier, si.state)
	return si
}

// signIn runs the browser's part: Fudge's authorize URL, the provider, the
// relay's callback, and back to Fudge's loopback redirect. It returns the code Fudge gets.
func (h *harness) signIn(t *testing.T, name string) (fudgeSignIn, string) {
	t.Helper()
	si := h.newSignIn(t)
	toProvider := location(t, h.get(t, h.authorizeURL(name, si, nil)))
	toRelay := location(t, h.get(t, toProvider.String()))
	toFudge := location(t, h.get(t, toRelay.String()))

	if got := toFudge.Scheme + "://" + toFudge.Host + toFudge.Path; got != fudgeRedirect {
		t.Fatalf("%s: back to %s, want %s", name, got, fudgeRedirect)
	}
	q := toFudge.Query()
	if q.Get("state") != si.state {
		t.Fatalf("%s: state %q, want Fudge's %q", name, q.Get("state"), si.state)
	}
	if q.Get("error") != "" || q.Get("code") == "" {
		t.Fatalf("%s: back to Fudge with %v", name, q)
	}
	h.remember(q.Get("code"))
	return si, q.Get("code")
}

// post sends a token request as OAuthService does, and reads the JSON answer.
func (h *harness) post(t *testing.T, path, encoding string, fields [][2]string) (int, map[string]any) {
	t.Helper()
	var body, contentType string
	if encoding == "json" {
		obj := map[string]string{}
		for _, f := range fields {
			obj[f[0]] = f[1]
		}
		b, _ := json.Marshal(obj)
		body, contentType = string(b), "application/json"
	} else {
		var parts []string
		for _, f := range fields {
			parts = append(parts, url.QueryEscape(f[0])+"="+url.QueryEscape(f[1]))
		}
		body, contentType = strings.Join(parts, "&"), "application/x-www-form-urlencoded;charset=UTF-8"
	}
	resp, err := http.Post(h.relay.URL+path, contentType, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("%s: Content-Type %q", path, ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("%s: Cache-Control %q", path, cc)
	}
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return resp.StatusCode, obj
}

func exchangeFields(code, verifier string) [][2]string {
	return [][2]string{
		{"client_id", extensionClientID},
		{"code", code},
		{"code_verifier", verifier},
		{"grant_type", "authorization_code"},
		{"redirect_uri", fudgeRedirect},
	}
}

func refreshFields(token string) [][2]string {
	return [][2]string{
		{"client_id", extensionClientID},
		{"refresh_token", token},
		{"grant_type", "refresh_token"},
	}
}

// accessTokenFor reads the token as each provider's default tokenResponseParser in OAuthService does.
func accessTokenFor(name string, body map[string]any) string {
	if name == "slack" {
		user, _ := body["authed_user"].(map[string]any)
		s, _ := user["access_token"].(string)
		return s
	}
	s, _ := body["access_token"].(string)
	return s
}

func TestSignInWithEveryProvider(t *testing.T) {
	h := newHarness(t)
	for _, name := range provider.Names() {
		for _, enc := range encodings {
			t.Run(name+"/"+enc, func(t *testing.T) {
				fp := h.providers[name]
				si, code := h.signIn(t, name)

				seen := fp.seen()
				ext := extensions[name]
				if ext.scope == "" {
					if seen.Has("scope") {
						t.Errorf("an empty scope went on as %q", seen.Get("scope"))
					}
				} else if seen.Get("scope") != ext.scope {
					t.Errorf("scope %q, want %q", seen.Get("scope"), ext.scope)
				}
				for k, v := range ext.extras {
					if seen.Get(k) != v {
						t.Errorf("extra %s = %q, want %q", k, seen.Get(k), v)
					}
				}
				if seen.Get("fixed") != "kept" {
					t.Errorf("the configured authorize URL's own query was dropped: %v", seen)
				}
				if seen.Get("state") == si.state || strings.Contains(seen.Get("state"), si.state) {
					t.Error("Fudge's state reached the provider in the clear")
				}

				status, body := h.post(t, "/"+name+"/token", enc, exchangeFields(code, si.verifier))
				if status != http.StatusOK {
					t.Fatalf("token: %d %v", status, body)
				}
				if want := fp.lastAnswer(); !reflect.DeepEqual(body, want) {
					t.Fatalf("token: the provider's answer changed on the way:\n got %v\nwant %v", body, want)
				}
				access := accessTokenFor(name, body)
				if !strings.HasPrefix(access, "ACCESS-TOKEN-"+name) {
					t.Fatalf("token: no access token where OAuthService reads it: %v", body)
				}
				if name == "linear" {
					if _, isArray := body["scope"].([]any); !isArray {
						t.Errorf("Linear's scope array changed: %v", body["scope"])
					}
				}
				if exp, ok := body["expires_in"]; ok {
					if _, isNumber := exp.(json.Number); !isNumber {
						t.Errorf("expires_in isn't a number: %#v", exp)
					}
				}

				if !fp.def.Refresh {
					return
				}
				refresh, _ := body["refresh_token"].(string)
				if name == "slack" {
					refresh, _ = body["authed_user"].(map[string]any)["refresh_token"].(string)
				}
				// OAuthService refreshes at /refresh-token, or at the token URL
				// for Google, Jira, Zoom and Notion; both work.
				for _, path := range []string{"/refresh-token", "/token"} {
					status, body = h.post(t, "/"+name+path, enc, refreshFields(refresh))
					if status != http.StatusOK {
						t.Fatalf("refresh at %s: %d %v", path, status, body)
					}
					if want := fp.lastAnswer(); !reflect.DeepEqual(body, want) {
						t.Fatalf("refresh at %s: the provider's answer changed:\n got %v\nwant %v", path, body, want)
					}
					got, _ := body["access_token"].(string)
					if !strings.HasPrefix(got, "ACCESS-TOKEN-"+name) || got == access {
						t.Fatalf("refresh at %s: access_token %q", path, got)
					}
					access = got
					if next, ok := body["refresh_token"].(string); ok {
						refresh = next
					}
				}
			})
		}
	}
	h.checkLogs(t)
}

func TestRefreshWithoutRefreshTokens(t *testing.T) {
	h := newHarness(t, "github", "webflow")
	for _, p := range []struct{ name, says string }{
		{"github", "GitHub doesn't issue refresh tokens"},
		{"webflow", "Webflow doesn't issue refresh tokens"},
	} {
		for _, enc := range encodings {
			status, body := h.post(t, "/"+p.name+"/refresh-token", enc, refreshFields("anything"))
			if status != http.StatusBadRequest || body["error"] != "unsupported_grant_type" {
				t.Fatalf("%s %s: %d %v", p.name, enc, status, body)
			}
			if desc, _ := body["error_description"].(string); !strings.Contains(desc, p.says) {
				t.Fatalf("%s %s: %q", p.name, enc, desc)
			}
		}
	}
	status, body := h.post(t, "/linear/refresh-token", "json", refreshFields("x"))
	if status != http.StatusNotFound {
		t.Fatalf("an unconfigured provider: %d %v", status, body)
	}
}

func TestZohoGetsPromptConsentOnce(t *testing.T) {
	h := newHarness(t, "zoho", "github")
	authorize := func(name string, change func(url.Values)) url.Values {
		t.Helper()
		si := h.newSignIn(t)
		return location(t, h.get(t, h.authorizeURL(name, si, change))).Query()
	}

	// The zoho-mail extension sends access_type=offline and no prompt: the relay adds prompt=consent, so a
	// user's every sign-in through the relay's one app gets a refresh token, not only their first.
	q := authorize("zoho", nil)
	if !slices.Equal(q["prompt"], []string{"consent"}) || !slices.Equal(q["access_type"], []string{"offline"}) {
		t.Errorf("prompt %q access_type %q, want consent and offline once each", q["prompt"], q["access_type"])
	}
	// An extension that sends its own prompt keeps it, once.
	q = authorize("zoho", func(q url.Values) { q.Set("prompt", "login") })
	if !slices.Equal(q["prompt"], []string{"login"}) {
		t.Errorf("prompt %q, want the extension's own, once", q["prompt"])
	}
	// Nobody else gets it.
	q = authorize("github", nil)
	if q.Has("prompt") {
		t.Errorf("github got Zoho's prompt: %v", q)
	}
	h.checkLogs(t)
}

func TestLoopbackRedirect(t *testing.T) {
	good := []string{
		"http://127.0.0.1:53682/oauth/callback/abc",
		"http://127.0.0.1:1",
		"http://[::1]:65535/x?y=z",
	}
	bad := []string{
		"",
		"https://127.0.0.1:53682/cb",
		"http://localhost:53682/cb",
		"http://127.0.0.1/cb",
		"http://127.0.0.1:/cb",
		"http://127.0.0.1:0/cb",
		"http://127.0.0.1:65536/cb",
		"http://127.0.0.1:0080/cb",
		"http://127.0.0.2:53682/cb",
		"http://[::2]:53682/cb",
		"http://user@127.0.0.1:53682/cb",
		"http://127.0.0.1:53682/cb#frag",
		"http://evil.example:53682/cb",
		"http://127.0.0.1.evil.example:53682/cb",
		"//127.0.0.1:53682/cb",
		"raycast://oauth?package_name=x",
		"https://raycast.com/redirect?packageName=x",
		"http:127.0.0.1:53682",
		"http://127.0.0.1@evil.com/",
		"http://127.0.0.1:53682@evil.com:53682/",
		"http://127.0.0.1.evil.com/",
		"http://evil.com/#@127.0.0.1",
		"http://evil.com:53682/#@127.0.0.1:53682",
		"https://127.0.0.1/",
		"http://localhost/",
		"javascript:alert(1)",
		"http://0x7f000001:53682/cb",
		"http://2130706433:53682/cb",
		"http://[::ffff:127.0.0.1]:53682/cb",
		" http://127.0.0.1:53682/cb",
	}
	for _, s := range good {
		if !LoopbackRedirect(s) {
			t.Errorf("refused %q", s)
		}
	}
	for _, s := range bad {
		if LoopbackRedirect(s) {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestAuthorizeRefuses(t *testing.T) {
	h := newHarness(t, "github")
	si := h.newSignIn(t)
	cases := map[string]func(url.Values){
		"a redirect off this Mac":    func(q url.Values) { q.Set("redirect_uri", "https://evil.example/cb") },
		"localhost by name":          func(q url.Values) { q.Set("redirect_uri", "http://localhost:53682/cb") },
		"Raycast's redirect":         func(q url.Values) { q.Set("redirect_uri", "https://raycast.com/redirect?packageName=Extension") },
		"no redirect":                func(q url.Values) { q.Del("redirect_uri") },
		"no challenge":               func(q url.Values) { q.Del("code_challenge"); q.Del("code_challenge_method") },
		"no challenge method":        func(q url.Values) { q.Del("code_challenge_method") },
		"a plain challenge":          func(q url.Values) { q.Set("code_challenge_method", "plain") },
		"a challenge that isn't one": func(q url.Values) { q.Set("code_challenge", "too-short") },
		"no state":                   func(q url.Values) { q.Del("state") },
		"another response type":      func(q url.Values) { q.Set("response_type", "token") },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			resp := h.get(t, h.authorizeURL("github", si, change))
			if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
				t.Fatalf("status %d, Location %q", resp.StatusCode, resp.Header.Get("Location"))
			}
			if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				t.Fatalf("Content-Type %q", ct)
			}
		})
	}
	if h.providers["github"].seen() != nil {
		t.Fatal("a refused sign-in reached the provider")
	}
}

// A link can't override what the relay sends the provider: its client ID and
// callback, the state, the response type and the PKCE parameters.
func TestOwnParametersCantBeOverridden(t *testing.T) {
	h := newHarness(t, "github", "slack")
	for _, name := range []string{"github", "slack"} {
		si := h.newSignIn(t)
		u := h.authorizeURL(name, si, nil) + "&" + url.Values{
			"client_id":             {"evil-client"},
			"redirect_uri":          {"https://evil.example/cb"},
			"state":                 {"evil-state"},
			"response_type":         {"token"},
			"code_challenge":        {s256("evil-verifier-evil-verifier-evil-verifier-1")},
			"code_challenge_method": {"plain"},
			"scope":                 {"admin"},
		}.Encode()
		toProvider := location(t, h.get(t, u))
		h.get(t, toProvider.String())
		seen := h.providers[name].seen()
		for _, k := range []string{"client_id", "redirect_uri", "state", "response_type", "code_challenge", "code_challenge_method", "scope"} {
			if len(seen[k]) > 1 {
				t.Errorf("%s: %s reached the provider %d times: %v", name, k, len(seen[k]), seen[k])
			}
		}
		if seen.Get("client_id") != "relay-id-"+name || seen.Get("response_type") != "code" ||
			!strings.HasSuffix(seen.Get("redirect_uri"), "/"+name+"/callback") || seen.Get("state") == "evil-state" {
			t.Errorf("%s: the provider saw %v", name, seen)
		}
		switch name {
		case "github": // PKCE: the relay's own challenge
			if c := seen.Get("code_challenge"); c == s256(si.verifier) || c == s256("evil-verifier-evil-verifier-evil-verifier-1") || seen.Get("code_challenge_method") != "S256" {
				t.Errorf("github: challenge %q method %q", c, seen.Get("code_challenge_method"))
			}
			if seen.Get("scope") != extensions["github"].scope {
				t.Errorf("github: scope %q", seen.Get("scope"))
			}
		case "slack": // no PKCE: none at all
			if seen.Has("code_challenge") || seen.Has("code_challenge_method") {
				t.Errorf("slack: PKCE parameters reached it: %v", seen)
			}
		}
	}
}

func TestCallbackRefuses(t *testing.T) {
	h := newHarness(t, "github", "linear")
	si := h.newSignIn(t)
	toProvider := location(t, h.get(t, h.authorizeURL("github", si, nil)))
	sealedState := toProvider.Query().Get("state")
	callback := func(name, state string) *http.Response {
		return h.get(t, h.relay.URL+"/"+name+"/callback?"+url.Values{"code": {"PROVIDER-CODE-x"}, "state": {state}}.Encode())
	}
	tampered := []byte(sealedState)
	tampered[len(tampered)/2] ^= 0x01

	cases := map[string]struct {
		resp *http.Response
		want string
	}{
		"a tampered state":   {callback("github", string(tampered)), "isn't valid"},
		"no state":           {callback("github", ""), "isn't valid"},
		"another provider's": {callback("linear", sealedState), "isn't valid"},
		"Fudge's own state":  {callback("github", si.state), "isn't valid"},
	}
	h.advance(StateLifetime)
	cases["an expired state"] = struct {
		resp *http.Response
		want string
	}{callback("github", sealedState), "took too long"}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if c.resp.StatusCode != http.StatusBadRequest || c.resp.Header.Get("Location") != "" {
				t.Fatalf("status %d, Location %q", c.resp.StatusCode, c.resp.Header.Get("Location"))
			}
			body, _ := io.ReadAll(c.resp.Body)
			if !strings.Contains(html.UnescapeString(string(body)), c.want) {
				t.Fatalf("page doesn't say %q: %s", c.want, body)
			}
		})
	}
}

func TestCallbackPassesProviderErrors(t *testing.T) {
	h := newHarness(t, "google")
	si := h.newSignIn(t)
	sealedState := location(t, h.get(t, h.authorizeURL("google", si, nil))).Query().Get("state")

	back := location(t, h.get(t, h.relay.URL+"/google/callback?"+url.Values{
		"error": {"access_denied"}, "error_description": {"The user said no."}, "state": {sealedState},
	}.Encode()))
	q := back.Query()
	if q.Get("error") != "access_denied" || q.Get("error_description") != "The user said no." || q.Get("state") != si.state || q.Has("code") {
		t.Fatalf("back to Fudge with %v", q)
	}

	back = location(t, h.get(t, h.relay.URL+"/google/callback?"+url.Values{"state": {sealedState}}.Encode()))
	q = back.Query()
	if q.Get("error") != "invalid_request" || q.Get("state") != si.state || q.Has("code") {
		t.Fatalf("no code: back to Fudge with %v", q)
	}
}

func TestCallbackKeepsFudgesQuery(t *testing.T) {
	h := newHarness(t, "zoom")
	si := h.newSignIn(t)
	redirect := "http://[::1]:4000/oauth/callback/x?keep=1"
	toProvider := location(t, h.get(t, h.authorizeURL("zoom", si, func(q url.Values) { q.Set("redirect_uri", redirect) })))
	toRelay := location(t, h.get(t, toProvider.String()))
	back := location(t, h.get(t, toRelay.String()))
	if back.Host != "[::1]:4000" || back.Query().Get("keep") != "1" || back.Query().Get("code") == "" {
		t.Fatalf("back to %s", back)
	}
}

func TestTokenRefuses(t *testing.T) {
	h := newHarness(t, "github", "linear")
	si, code := h.signIn(t, "github")
	tampered := []byte(code)
	tampered[len(tampered)/2] ^= 0x01
	otherSignIn := h.newSignIn(t)
	sealedState := location(t, h.get(t, h.authorizeURL("github", otherSignIn, nil))).Query().Get("state")

	cases := []struct {
		name   string
		path   string
		fields [][2]string
		status int
		error  string
		want   string
	}{
		{"a wrong verifier", "/github/token", exchangeFields(code, randomVerifier(t)), 400, "invalid_grant", "code_verifier"},
		{"no verifier", "/github/token", exchangeFields(code, ""), 400, "invalid_grant", "code_verifier"},
		{"a short verifier", "/github/token", exchangeFields(code, "abc"), 400, "invalid_grant", "code_verifier"},
		{"another provider", "/linear/token", exchangeFields(code, si.verifier), 400, "invalid_grant", "isn't valid"},
		{"a tampered code", "/github/token", exchangeFields(string(tampered), si.verifier), 400, "invalid_grant", "isn't valid"},
		{"the provider's raw code", "/github/token", exchangeFields("PROVIDER-CODE-github-1", si.verifier), 400, "invalid_grant", "isn't valid"},
		{"a sealed state as the code", "/github/token", exchangeFields(sealedState, si.verifier), 400, "invalid_grant", "isn't valid"},
		{"another redirect_uri", "/github/token", [][2]string{
			{"code", code}, {"code_verifier", si.verifier}, {"grant_type", "authorization_code"}, {"redirect_uri", "http://127.0.0.1:1/other"},
		}, 400, "invalid_grant", "redirect_uri"},
		{"a refresh grant for GitHub", "/github/token", refreshFields("x"), 400, "unsupported_grant_type", "GitHub doesn't issue refresh tokens"},
		{"a password grant", "/github/token", [][2]string{{"grant_type", "password"}, {"username", "a"}, {"password", "b"}}, 400, "unsupported_grant_type", "authorization_code or refresh_token"},
		{"a code at refresh-token", "/linear/refresh-token", exchangeFields(code, si.verifier), 400, "unsupported_grant_type", "refresh_token"},
		{"an unconfigured provider", "/zoom/token", exchangeFields(code, si.verifier), 404, "invalid_request", "doesn't offer Zoom"},
	}
	for _, c := range cases {
		for _, enc := range encodings {
			t.Run(c.name+"/"+enc, func(t *testing.T) {
				status, body := h.post(t, c.path, enc, c.fields)
				desc, _ := body["error_description"].(string)
				if status != c.status || body["error"] != c.error || !strings.Contains(desc, c.want) {
					t.Fatalf("got %d %v, want %d %s saying %q", status, body, c.status, c.error, c.want)
				}
			})
		}
	}
	// Nothing above reached the provider, so the code still works, once.
	status, body := h.post(t, "/github/token", "json", exchangeFields(code, si.verifier))
	if status != http.StatusOK || accessTokenFor("github", body) == "" {
		t.Fatalf("the code after the refusals: %d %v", status, body)
	}

	h.advance(CodeLifetime)
	status, body = h.post(t, "/github/token", "json", exchangeFields(code, si.verifier))
	if desc, _ := body["error_description"].(string); status != 400 || !strings.Contains(desc, "expired") {
		t.Fatalf("an expired code: %d %v", status, body)
	}
	h.checkLogs(t)
}

func TestTokenBodies(t *testing.T) {
	h := newHarness(t, "github")
	send := func(contentType, body string) (int, map[string]any) {
		resp, err := http.Post(h.relay.URL+"/github/token", contentType, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var obj map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&obj)
		return resp.StatusCode, obj
	}
	cases := []struct {
		contentType, body string
		status            int
	}{
		{"text/plain", "code=x", http.StatusUnsupportedMediaType},
		{"", "code=x", http.StatusUnsupportedMediaType},
		{"application/json", "[1,2]", http.StatusBadRequest},
		{"application/json", "not json", http.StatusBadRequest},
		{"application/json", `{"code": 5}`, http.StatusBadRequest},
		{"application/json", "{\"code\":\"" + strings.Repeat("x", maxRequestBody) + "\"}", http.StatusBadRequest},
		{"application/x-www-form-urlencoded", "code=%zz", http.StatusBadRequest},
	}
	for _, c := range cases {
		if status, body := send(c.contentType, c.body); status != c.status || body["error"] == nil {
			t.Errorf("%s %.30q: %d %v, want %d", c.contentType, c.body, status, body, c.status)
		}
	}
}

func TestProviderRefusals(t *testing.T) {
	t.Run("a code used twice (GitHub answers 200 with an error)", func(t *testing.T) {
		h := newHarness(t, "github")
		si, code := h.signIn(t, "github")
		if status, _ := h.post(t, "/github/token", "json", exchangeFields(code, si.verifier)); status != 200 {
			t.Fatal(status)
		}
		status, body := h.post(t, "/github/token", "json", exchangeFields(code, si.verifier))
		if status != 400 || body["error"] != "invalid_grant" || body["error_description"] != "The code passed is incorrect or expired." || body["access_token"] != nil {
			t.Fatalf("%d %v", status, body)
		}
		h.checkLogs(t)
	})
	t.Run("Slack's ok false", func(t *testing.T) {
		h := newHarness(t, "slack")
		si, code := h.signIn(t, "slack")
		h.post(t, "/slack/token", "json", exchangeFields(code, si.verifier))
		status, body := h.post(t, "/slack/token", "json", exchangeFields(code, si.verifier))
		if status != 400 || body["error"] != "invalid_code" || body["authed_user"] != nil {
			t.Fatalf("%d %v", status, body)
		}
	})
	t.Run("a refused refresh", func(t *testing.T) {
		h := newHarness(t, "zoom")
		status, body := h.post(t, "/zoom/refresh-token", "url-encoded", refreshFields("REFRESH-TOKEN-unknown"))
		if status != 400 || body["error"] != "invalid_grant" {
			t.Fatalf("%d %v", status, body)
		}
	})
	t.Run("a provider failing", func(t *testing.T) {
		h := newHarness(t, "asana")
		si, code := h.signIn(t, "asana")
		h.providers["asana"].setRefuse(func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("<html>down</html>"))
		})
		status, body := h.post(t, "/asana/token", "json", exchangeFields(code, si.verifier))
		if status != http.StatusBadGateway || body["error"] != "temporarily_unavailable" {
			t.Fatalf("%d %v", status, body)
		}
	})
	t.Run("a provider answering 200 with no tokens", func(t *testing.T) {
		h := newHarness(t, "asana")
		si, code := h.signIn(t, "asana")
		h.providers["asana"].setRefuse(func(w http.ResponseWriter) { _, _ = w.Write([]byte("<html>login</html>")) })
		status, _ := h.post(t, "/asana/token", "json", exchangeFields(code, si.verifier))
		if status != http.StatusBadGateway {
			t.Fatal(status)
		}
	})
	t.Run("a provider out of reach", func(t *testing.T) {
		h := newHarness(t, "atlassian")
		si, code := h.signIn(t, "atlassian")
		h.providers["atlassian"].srv.Close()
		status, body := h.post(t, "/atlassian/token", "json", exchangeFields(code, si.verifier))
		if desc, _ := body["error_description"].(string); status != http.StatusBadGateway || !strings.Contains(desc, "Atlassian (Jira, Confluence) couldn't be reached") {
			t.Fatalf("%d %v", status, body)
		}
		h.checkLogs(t)
	})
	t.Run("a provider redirecting", func(t *testing.T) {
		h := newHarness(t, "linear")
		si, code := h.signIn(t, "linear")
		h.providers["linear"].setRefuse(func(w http.ResponseWriter) {
			w.Header().Set("Location", "https://elsewhere.example/token")
			w.WriteHeader(http.StatusTemporaryRedirect)
		})
		status, body := h.post(t, "/linear/token", "json", exchangeFields(code, si.verifier))
		if status != http.StatusBadGateway || body["error"] != "temporarily_unavailable" {
			t.Fatalf("%d %v", status, body)
		}
	})
}

func TestFormEncodedTokenResponse(t *testing.T) {
	obj, ok := parseTokenResponse("application/x-www-form-urlencoded; charset=utf-8", []byte("access_token=gho_x&scope=repo%2Cuser&token_type=bearer&expires_in=28800&refresh_token_expires_in=15897600"))
	if !ok || obj["access_token"] != "gho_x" || obj["scope"] != "repo,user" || obj["expires_in"] != json.Number("28800") || obj["refresh_token_expires_in"] != json.Number("15897600") {
		t.Fatalf("%v %v", ok, obj)
	}
	if _, ok := parseTokenResponse("text/html", []byte("<html></html>")); ok {
		t.Fatal("parsed HTML")
	}
}

func TestUnconfiguredProviders(t *testing.T) {
	h := newHarness(t, "github")
	for path, want := range map[string]string{
		"/zoom/authorize":         "doesn&#39;t offer Zoom.",
		"/slack/callback":         "doesn&#39;t offer Slack.",
		"/gitlab/authorize":       "doesn&#39;t offer gitlab.",
		"/%3Cscript%3E/authorize": "doesn&#39;t offer &lt;script&gt;.",
	} {
		resp := h.get(t, h.relay.URL+path)
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusNotFound || !strings.Contains(string(body), want) {
			t.Errorf("%s: %d %s", path, resp.StatusCode, body)
		}
		if bytes.Contains(body, []byte("<script>")) {
			t.Errorf("%s: unescaped", path)
		}
	}
	status, body := h.post(t, "/zoom/token", "json", exchangeFields("x", "y"))
	if status != http.StatusNotFound || body["error_description"] != "This sign-in server doesn't offer Zoom." {
		t.Fatalf("%d %v", status, body)
	}
}

func TestIndexHealthAndMethods(t *testing.T) {
	h := newHarness(t, "github", "atlassian")
	resp := h.get(t, h.relay.URL+"/")
	body, _ := io.ReadAll(resp.Body)
	for _, want := range []string{h.relay.URL + "/github/callback", h.relay.URL + "/atlassian/callback", "GitHub", "Atlassian (Jira, Confluence)"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("the index page doesn't show %q", want)
		}
	}
	if strings.Contains(string(body), "zoom") {
		t.Error("the index page shows an unconfigured provider")
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" || resp.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("headers %v", resp.Header)
	}

	resp = h.get(t, h.relay.URL+"/healthz")
	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.StatusCode)
	}
	if strings.Contains(h.logs.String(), "/healthz") {
		t.Error("a health check was logged")
	}

	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/github/token"},
		{http.MethodGet, "/github/refresh-token"},
		{http.MethodPost, "/github/authorize"},
		{http.MethodPost, "/github/callback"},
	} {
		req, _ := http.NewRequest(c.method, h.relay.URL+c.path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: %d", c.method, c.path, resp.StatusCode)
		}
	}
}

func TestInfoPageOff(t *testing.T) {
	hidden := newHarnessWith(t, func(c *config.Config) { c.HideInfoPage = true }, "github")
	shown := newHarness(t, "github")

	type answer struct {
		status      int
		contentType string
		body        string
	}
	ask := func(h *harness, method, path string) answer {
		t.Helper()
		req, _ := http.NewRequest(method, h.relay.URL+path, nil)
		resp, err := noRedirects.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return answer{resp.StatusCode, resp.Header.Get("Content-Type"), string(body)}
	}

	// / answers exactly as a path that was never there, whatever the method.
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
		front, unknown := ask(hidden, method, "/"), ask(hidden, method, "/no-such-page")
		if front != unknown || front.status != http.StatusNotFound {
			t.Errorf("%s /: %+v; an unknown path: %+v", method, front, unknown)
		}
	}
	if got := ask(shown, http.MethodGet, "/"); got.status != http.StatusOK || !strings.Contains(got.body, "/github/callback") {
		t.Errorf("with the page on, / answers %+v", got)
	}

	// Nothing else changes.
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/healthz"},
		{http.MethodGet, "/github/authorize"},
		{http.MethodGet, "/github/callback?state=not-sealed&code=x"},
		{http.MethodGet, "/github/token"},
		{http.MethodPost, "/github/token"},
		{http.MethodPost, "/github/refresh-token"},
		{http.MethodGet, "/zoom/authorize"},
	} {
		if off, on := ask(hidden, c.method, c.path), ask(shown, c.method, c.path); off != on {
			t.Errorf("%s %s: %+v with the page off, %+v with it on", c.method, c.path, off, on)
		}
	}
	si, code := hidden.signIn(t, "github")
	if status, body := hidden.post(t, "/github/token", "json", exchangeFields(code, si.verifier)); status != http.StatusOK || body["access_token"] == nil {
		t.Errorf("a sign-in with the page off: %d %v", status, body)
	}
	hidden.checkLogs(t)
}

func TestLogLines(t *testing.T) {
	h := newHarness(t, "linear")
	si, code := h.signIn(t, "linear")
	h.post(t, "/linear/token", "url-encoded", exchangeFields(code, si.verifier))
	h.post(t, "/linear/token", "url-encoded", exchangeFields(code, "wrong"))

	allowed := []string{"time", "level", "msg", "path", "status", "duration_ms", "provider"}
	lines := strings.Split(strings.TrimSpace(h.logs.String()), "\n")
	if len(lines) < 4 {
		t.Fatalf("%d log lines", len(lines))
	}
	for _, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		if entry["msg"] != "request" {
			continue
		}
		for k := range entry {
			if !slices.Contains(allowed, k) {
				t.Errorf("a request log carries %q: %s", k, line)
			}
		}
		if entry["provider"] != "linear" || strings.Contains(line, "?") {
			t.Errorf("%s", line)
		}
	}
	h.checkLogs(t)
}

func TestSealedValuesExpire(t *testing.T) {
	if StateLifetime != 10*time.Minute || CodeLifetime != 5*time.Minute {
		t.Fatal("SPEC-055 §2: 10 minutes for the state, 5 for the code")
	}
}
