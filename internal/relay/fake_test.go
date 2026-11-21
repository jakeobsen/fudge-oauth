package relay

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jakeobsen/fudge-oauth/internal/config"
	"github.com/jakeobsen/fudge-oauth/internal/provider"
)

// testKey is the relay's sealing key in the tests: bytes 0…31.
var testKey = func() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}()

// harness runs the relay against fake providers and records every sensitive
// value that passes through, so a test can check none of them reached the log.
// Its t is the top-level test's: the fake providers report to it from their
// own goroutines, while helpers take the running (sub)test's t.
type harness struct {
	t         *testing.T
	relay     *httptest.Server
	cfg       *config.Config
	providers map[string]*fakeProvider
	logs      *syncBuffer

	mu        sync.Mutex
	now       time.Time
	sensitive []string
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// newHarness configures the named providers (all seven when none are named).
func newHarness(t *testing.T, names ...string) *harness {
	t.Helper()
	return newHarnessWith(t, nil, names...)
}

// newHarnessWith is newHarness, with change applied to the config before the relay is made.
func newHarnessWith(t *testing.T, change func(*config.Config), names ...string) *harness {
	t.Helper()
	if len(names) == 0 {
		names = provider.Names()
	}
	h := &harness{t: t, providers: map[string]*fakeProvider{}, logs: &syncBuffer{}, now: time.Unix(1_800_000_000, 0)}
	var handler http.Handler
	h.relay = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(h.relay.Close)

	h.cfg = &config.Config{Listen: ":0", PublicURL: h.relay.URL, Key: testKey, Providers: map[string]config.Provider{}}
	for _, name := range names {
		def, ok := provider.Lookup(name)
		if !ok {
			t.Fatalf("no provider %q", name)
		}
		fp := newFakeProvider(h, def)
		h.providers[name] = fp
		p := config.Provider{Provider: def, ClientID: "relay-id-" + name, ClientSecret: "RELAY-SECRET-" + strings.ToUpper(name)}
		p.AuthorizeURL = fp.srv.URL + "/oauth/authorize?fixed=kept"
		p.TokenURL = fp.srv.URL + "/oauth/token"
		h.cfg.Providers[name] = p
		h.remember(p.ClientSecret)
	}
	h.remember(base64.StdEncoding.EncodeToString(testKey))
	if change != nil {
		change(h.cfg)
	}

	log := slog.New(slog.NewJSONHandler(h.logs, nil))
	s, err := New(h.cfg, log, WithClock(h.clock))
	if err != nil {
		t.Fatal(err)
	}
	handler = s.Handler()
	return h
}

func (h *harness) clock() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.now
}

func (h *harness) advance(d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.now = h.now.Add(d)
}

func (h *harness) remember(values ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, v := range values {
		if v != "" {
			h.sensitive = append(h.sensitive, v)
		}
	}
}

// checkLogs fails if any recorded secret, code, state, verifier or token is in the log.
func (h *harness) checkLogs(t *testing.T) {
	t.Helper()
	logs := h.logs.String()
	if !strings.Contains(logs, `"msg":"request"`) {
		t.Fatalf("no request was logged:\n%s", logs)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, v := range h.sensitive {
		if strings.Contains(logs, v) {
			t.Errorf("the log contains %q:\n%s", v, logs)
		}
	}
}

// noRedirects is a client that stops at each redirect, as the tests follow them by hand.
var noRedirects = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (h *harness) get(t *testing.T, raw string) *http.Response {
	t.Helper()
	resp, err := noRedirects.Get(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func location(t *testing.T, resp *http.Response) *url.URL {
	t.Helper()
	if resp.StatusCode != http.StatusFound {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(resp.Body)
		t.Fatalf("status %d, want a redirect: %s", resp.StatusCode, body)
	}
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// --- the fake provider ---

// fakeProvider plays one provider's authorize and token endpoints, and checks
// every request the way that provider would.
type fakeProvider struct {
	h   *harness
	def provider.Provider
	srv *httptest.Server

	mu            sync.Mutex
	authorizeSeen url.Values
	challenge     string
	codes         map[string]bool
	refreshTokens map[string]bool
	issued        int
	// refuse makes the token endpoint answer like this instead, when set.
	refuse func(w http.ResponseWriter)
	// last is the token endpoint's last answer.
	last map[string]any
	// wantCallback is the redirect_uri a code exchange must carry, when it isn't the relay's callback for this
	// provider (a sign-in begun under a deprecated name).
	wantCallback string
}

// issue makes a code the token endpoint accepts, as if the provider had sent the browser back with it.
func (fp *fakeProvider) issue() string {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.issued++
	code := fmt.Sprintf("PROVIDER-CODE-%s-%d", fp.def.Name, fp.issued)
	fp.codes[code] = true
	fp.h.remember(code)
	return code
}

// lastAnswer is the token endpoint's last answer, as JSON decodes it.
func (fp *fakeProvider) lastAnswer() map[string]any {
	fp.mu.Lock()
	b, _ := json.Marshal(fp.last)
	fp.mu.Unlock()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var obj map[string]any
	_ = dec.Decode(&obj)
	return obj
}

func (fp *fakeProvider) seen() url.Values {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	return fp.authorizeSeen
}

func (fp *fakeProvider) setRefuse(f func(w http.ResponseWriter)) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.refuse = f
}

func newFakeProvider(h *harness, def provider.Provider) *fakeProvider {
	fp := &fakeProvider{h: h, def: def, codes: map[string]bool{}, refreshTokens: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oauth/authorize", fp.authorize)
	mux.HandleFunc("POST /oauth/token", fp.token)
	fp.srv = httptest.NewServer(mux)
	h.t.Cleanup(fp.srv.Close)
	return fp
}

func (fp *fakeProvider) clientID() string { return "relay-id-" + fp.def.Name }
func (fp *fakeProvider) secret() string   { return "RELAY-SECRET-" + strings.ToUpper(fp.def.Name) }
func (fp *fakeProvider) callback() string { return fp.h.relay.URL + "/" + fp.def.Name + "/callback" }

func (fp *fakeProvider) authorize(w http.ResponseWriter, r *http.Request) {
	t := fp.h.t
	q := r.URL.Query()
	fp.mu.Lock()
	fp.authorizeSeen = q
	fp.challenge = q.Get("code_challenge")
	fp.issued++
	code := fmt.Sprintf("PROVIDER-CODE-%s-%d", fp.def.Name, fp.issued)
	fp.codes[code] = true
	fp.mu.Unlock()
	fp.h.remember(code, q.Get("state"))

	if q.Get("client_id") != fp.clientID() {
		t.Errorf("%s authorize: client_id %q, want the relay's", fp.def.Name, q.Get("client_id"))
	}
	if q.Get("redirect_uri") != fp.callback() {
		t.Errorf("%s authorize: redirect_uri %q, want %q", fp.def.Name, q.Get("redirect_uri"), fp.callback())
	}
	if q.Get("response_type") != "code" {
		t.Errorf("%s authorize: response_type %q", fp.def.Name, q.Get("response_type"))
	}
	if fp.def.PKCE != (q.Get("code_challenge") != "") || (fp.def.PKCE && q.Get("code_challenge_method") != "S256") {
		t.Errorf("%s authorize: PKCE is %v but got challenge %q method %q", fp.def.Name, fp.def.PKCE, q.Get("code_challenge"), q.Get("code_challenge_method"))
	}
	dest, _ := url.Parse(q.Get("redirect_uri"))
	back := url.Values{"code": {code}, "state": {q.Get("state")}}
	dest.RawQuery = back.Encode()
	http.Redirect(w, r, dest.String(), http.StatusFound)
}

func (fp *fakeProvider) token(w http.ResponseWriter, r *http.Request) {
	t := fp.h.t
	name := fp.def.Name
	fp.mu.Lock()
	refuse := fp.refuse
	fp.mu.Unlock()
	if refuse != nil {
		refuse(w)
		return
	}

	if !strings.Contains(r.Header.Get("Accept"), "application/json") {
		t.Errorf("%s token: Accept %q doesn't ask for JSON", name, r.Header.Get("Accept"))
	}
	form := map[string]string{}
	switch ct := r.Header.Get("Content-Type"); fp.def.TokenBody {
	case provider.BodyJSON:
		if ct != "application/json" {
			t.Errorf("%s token: Content-Type %q, want JSON", name, ct)
		}
		if err := json.NewDecoder(r.Body).Decode(&form); err != nil {
			t.Errorf("%s token: %v", name, err)
		}
	default:
		if ct != "application/x-www-form-urlencoded" {
			t.Errorf("%s token: Content-Type %q, want form encoding", name, ct)
		}
		_ = r.ParseForm()
		for k, v := range r.PostForm {
			form[k] = v[0]
		}
	}

	user, pass, basic := r.BasicAuth()
	switch fp.def.ClientAuth {
	case provider.ClientAuthBasic:
		if !basic || user != fp.clientID() || pass != fp.secret() {
			t.Errorf("%s token: Basic auth %q/%q, want the relay's", name, user, pass)
		}
		if _, ok := form["client_secret"]; ok {
			t.Errorf("%s token: client_secret in the body as well as Basic auth", name)
		}
	default:
		if basic {
			t.Errorf("%s token: unexpected Basic auth", name)
		}
		if form["client_id"] != fp.clientID() || form["client_secret"] != fp.secret() {
			t.Errorf("%s token: client_id %q client_secret %q, want the relay's", name, form["client_id"], form["client_secret"])
		}
	}

	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.issued++
	access := fmt.Sprintf("ACCESS-TOKEN-%s-%d", name, fp.issued)
	refresh := fmt.Sprintf("REFRESH-TOKEN-%s-%d", name, fp.issued)
	fp.h.remember(access, refresh)

	switch form["grant_type"] {
	case "authorization_code":
		if !fp.codes[form["code"]] {
			providerRefusal(w, name, "invalid_grant", "The code passed is incorrect or expired.")
			return
		}
		delete(fp.codes, form["code"])
		want := fp.callback()
		if fp.wantCallback != "" {
			want = fp.wantCallback
		}
		if form["redirect_uri"] != want {
			t.Errorf("%s token: redirect_uri %q, want %q", name, form["redirect_uri"], want)
		}
		if fp.def.PKCE {
			if s256(form["code_verifier"]) != fp.challenge {
				t.Errorf("%s token: code_verifier doesn't match the relay's challenge", name)
			}
			fp.h.remember(form["code_verifier"])
		} else if _, ok := form["code_verifier"]; ok {
			t.Errorf("%s token: code_verifier sent to a provider without PKCE", name)
		}
		if fp.def.Refresh {
			fp.refreshTokens[refresh] = true
		}
		fp.last = codeShape(name, access, refresh)
		writeShape(w, name, fp.last)
	case "refresh_token":
		if !fp.def.Refresh {
			t.Errorf("%s token: the relay asked to refresh a provider without refresh tokens", name)
		}
		if !fp.refreshTokens[form["refresh_token"]] {
			providerRefusal(w, name, "invalid_grant", "Bad refresh token.")
			return
		}
		fp.refreshTokens[refresh] = true
		fp.last = refreshShape(name, access, refresh)
		writeShape(w, name, fp.last)
	default:
		t.Errorf("%s token: grant_type %q", name, form["grant_type"])
		providerRefusal(w, name, "unsupported_grant_type", "")
	}
}

// providerRefusal answers as each provider does: GitHub and Slack with a 200.
func providerRefusal(w http.ResponseWriter, name, code, desc string) {
	switch name {
	case "github":
		writeShape(w, name, map[string]any{"error": code, "error_description": desc, "error_uri": "https://docs.github.com/"})
	case "slack":
		writeShape(w, name, map[string]any{"ok": false, "error": "invalid_code"})
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": code, "error_description": desc})
	}
}

func writeShape(w http.ResponseWriter, _ string, body map[string]any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(body)
}

// codeShape is each provider's answer to an authorization code, as documented.
func codeShape(name, access, refresh string) map[string]any {
	switch name {
	case "github":
		return map[string]any{"access_token": access, "token_type": "bearer", "scope": "repo,user"}
	case "slack":
		return map[string]any{
			"ok":     true,
			"app_id": "A0",
			"authed_user": map[string]any{
				"id": "U0", "scope": "emoji:read", "access_token": access, "token_type": "user",
				"refresh_token": refresh, "expires_in": 43200,
			},
			"team": map[string]any{"id": "T0", "name": "Team"},
		}
	case "linear":
		return map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 86399, "scope": []string{"read", "write"}, "refresh_token": refresh}
	case "asana":
		return map[string]any{"access_token": access, "token_type": "bearer", "expires_in": 3600, "refresh_token": refresh, "data": map[string]any{"id": "1", "name": "A"}}
	case "google":
		return map[string]any{"access_token": access, "expires_in": 3599, "refresh_token": refresh, "scope": "https://www.googleapis.com/auth/drive.readonly", "token_type": "Bearer", "id_token": "eyJ.fake"}
	case "atlassian":
		return map[string]any{"access_token": access, "expires_in": 3600, "token_type": "Bearer", "refresh_token": refresh, "scope": "read:jira-work offline_access"}
	case "zoom":
		return map[string]any{"access_token": access, "token_type": "bearer", "refresh_token": refresh, "expires_in": 3599, "scope": "meeting:write"}
	}
	panic(name)
}

func refreshShape(name, access, refresh string) map[string]any {
	if name == "slack" {
		return map[string]any{"ok": true, "access_token": access, "token_type": "user", "refresh_token": refresh, "expires_in": 43200}
	}
	return codeShape(name, access, refresh)
}
