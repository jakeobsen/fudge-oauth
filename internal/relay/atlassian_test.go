package relay

import (
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/jakeobsen/fudge-oauth/internal/seal"
)

func TestAtlassianGetsAudienceAndPromptOnce(t *testing.T) {
	h := newHarness(t, "atlassian", "github")
	authorize := func(name string, change func(url.Values)) url.Values {
		t.Helper()
		si := h.newSignIn(t)
		return location(t, h.get(t, h.authorizeURL(name, si, change))).Query()
	}

	// The Jira extension, through Raycast's proxy, sends neither: the relay adds both.
	q := authorize("atlassian", func(q url.Values) {
		q.Del("audience")
		q.Del("prompt")
	})
	if !slices.Equal(q["audience"], []string{"api.atlassian.com"}) || !slices.Equal(q["prompt"], []string{"consent"}) {
		t.Errorf("audience %q prompt %q, want api.atlassian.com and consent once each", q["audience"], q["prompt"])
	}
	// confluence-search sends its own: they go on once, as sent.
	q = authorize("atlassian", func(q url.Values) { q.Set("prompt", "login") })
	if !slices.Equal(q["audience"], []string{"api.atlassian.com"}) || !slices.Equal(q["prompt"], []string{"login"}) {
		t.Errorf("audience %q prompt %q, want the extension's own, once", q["audience"], q["prompt"])
	}
	// Nobody else gets them.
	q = authorize("github", nil)
	if q.Has("audience") || q.Has("prompt") {
		t.Errorf("github got Atlassian's parameters: %v", q)
	}
	h.checkLogs(t)
}

func TestJiraIsAnAliasForAtlassian(t *testing.T) {
	h := newHarness(t, "atlassian")
	si := h.newSignIn(t)
	start := strings.Replace(h.authorizeURL("atlassian", si, nil), "/atlassian/authorize", "/jira/authorize", 1)
	toProvider := location(t, h.get(t, start))
	// Atlassian compares the callback exactly with the registered one, whichever path the sign-in came in at.
	if got := toProvider.Query().Get("redirect_uri"); got != h.relay.URL+"/atlassian/callback" {
		t.Fatalf("redirect_uri %q, want the atlassian callback", got)
	}
	toRelay := location(t, h.get(t, toProvider.String()))
	toFudge := location(t, h.get(t, toRelay.String()))
	code := toFudge.Query().Get("code")
	h.remember(code)
	if toFudge.Query().Get("state") != si.state || code == "" {
		t.Fatalf("back to Fudge with %v", toFudge.Query())
	}

	status, body := h.post(t, "/jira/token", "json", exchangeFields(code, si.verifier))
	if status != http.StatusOK || !strings.HasPrefix(accessTokenFor("atlassian", body), "ACCESS-TOKEN-atlassian") {
		t.Fatalf("token at /jira/token: %d %v", status, body)
	}
	refresh, _ := body["refresh_token"].(string)
	status, body = h.post(t, "/jira/refresh-token", "json", refreshFields(refresh))
	if status != http.StatusOK {
		t.Fatalf("refresh at /jira/refresh-token: %d %v", status, body)
	}
	// Atlassian rotates refresh tokens: the new one comes back as Atlassian sent it.
	if want := h.providers["atlassian"].lastAnswer(); !reflect.DeepEqual(body, want) || body["refresh_token"] == refresh {
		t.Errorf("refresh: got %v, want Atlassian's answer with a new refresh token %v", body, want)
	}
	h.checkLogs(t)
}

func TestASignInBegunUnderJiraBeforeAnUpgradeCompletes(t *testing.T) {
	h := newHarness(t, "atlassian")
	fp := h.providers["atlassian"]
	sealer, err := seal.New(testKey)
	if err != nil {
		t.Fatal(err)
	}
	// Before the upgrade, the relay sent Atlassian /jira/callback, so the exchange must send that one too.
	fp.wantCallback = h.relay.URL + "/jira/callback"

	// A state the old relay sealed at /jira/authorize comes back to /jira/callback.
	si := h.newSignIn(t)
	state, err := sealer.Seal(purpose(kindState, "jira"), statePayload{
		Provider: "jira", RedirectURI: fudgeRedirect, State: si.state, Challenge: s256(si.verifier),
	}, h.clock().Add(StateLifetime))
	if err != nil {
		t.Fatal(err)
	}
	h.remember(state)
	back := url.Values{"code": {fp.issue()}, "state": {state}}
	toFudge := location(t, h.get(t, h.relay.URL+"/jira/callback?"+back.Encode()))
	code := toFudge.Query().Get("code")
	h.remember(code)
	if toFudge.Query().Get("state") != si.state || code == "" {
		t.Fatalf("back to Fudge with %v", toFudge.Query())
	}
	if status, body := h.post(t, "/atlassian/token", "url-encoded", exchangeFields(code, si.verifier)); status != http.StatusOK {
		t.Fatalf("token: %d %v", status, body)
	}

	// A code the old relay sealed itself redeems too, at either path.
	for _, path := range []string{"/jira/token", "/atlassian/token"} {
		si := h.newSignIn(t)
		old, err := sealer.Seal(purpose(kindCode, "jira"), codePayload{
			Provider: "jira", Code: fp.issue(), RedirectURI: fudgeRedirect, Challenge: s256(si.verifier),
		}, h.clock().Add(CodeLifetime))
		if err != nil {
			t.Fatal(err)
		}
		h.remember(old)
		if status, body := h.post(t, path, "json", exchangeFields(old, si.verifier)); status != http.StatusOK {
			t.Fatalf("an old code at %s: %d %v", path, status, body)
		}
	}

	// An old state or code never opens anywhere but Atlassian's paths.
	h2 := newHarness(t, "atlassian", "github")
	h2.remember(state)
	resp := h2.get(t, h2.relay.URL+"/github/callback?"+back.Encode())
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a jira state at /github/callback: %d", resp.StatusCode)
	}
	h.checkLogs(t)
	h2.checkLogs(t)
}

func TestSlackUserTokenComesThroughBesideABotToken(t *testing.T) {
	h := newHarness(t, "slack")
	fp := h.providers["slack"]
	si, code := h.signIn(t, "slack")
	// An app with bot scopes too answers with the bot token at the top, and the user's in authed_user.
	answer := map[string]any{
		"ok": true, "access_token": "xoxb-BOT-TOKEN", "token_type": "bot", "scope": "chat:write",
		"authed_user": map[string]any{
			"id": "U0", "access_token": "xoxp-USER-TOKEN", "token_type": "user", "scope": "emoji:read",
		},
	}
	h.remember("xoxb-BOT-TOKEN", "xoxp-USER-TOKEN")
	fp.setRefuse(func(w http.ResponseWriter) { writeShape(w, "slack", answer) })
	status, body := h.post(t, "/slack/token", "json", exchangeFields(code, si.verifier))
	if status != http.StatusOK || !reflect.DeepEqual(body, answer) {
		t.Fatalf("token: %d %v, want Slack's answer unchanged", status, body)
	}
	// OAuthService.slack's parser reads the user's token, never the bot's.
	if got := accessTokenFor("slack", body); got != "xoxp-USER-TOKEN" {
		t.Errorf("the extension gets %q, want the user token", got)
	}
	h.checkLogs(t)
}
