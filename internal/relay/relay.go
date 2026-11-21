// Package relay is the sign-in relay's HTTP side. It stands in for the OAuth
// proxies that @raycast/utils' OAuthService talks to, at
// /<provider>/{authorize,callback,token,refresh-token}, with this relay's own
// OAuth apps. It keeps nothing: what a sign-in needs between requests travels
// sealed inside the state and the code.
package relay

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jakeobsen/fudge-oauth/internal/config"
	"github.com/jakeobsen/fudge-oauth/internal/provider"
	"github.com/jakeobsen/fudge-oauth/internal/seal"
)

const (
	// StateLifetime is how long a sign-in may take in the browser.
	StateLifetime = 10 * time.Minute
	// CodeLifetime is how long Fudge has to exchange the code it was given.
	CodeLifetime = 5 * time.Minute

	purposeState = "state"
	purposeCode  = "code"

	maxParamLen = 2048
)

// Server is the relay.
type Server struct {
	cfg    *config.Config
	sealer *seal.Sealer
	log    *slog.Logger
	client *http.Client
	now    func() time.Time
}

// Option changes a Server, for tests.
type Option func(*Server)

// WithClock replaces time.Now.
func WithClock(now func() time.Time) Option { return func(s *Server) { s.now = now } }

// WithHTTPClient replaces the client the relay talks to providers with.
func WithHTTPClient(c *http.Client) Option { return func(s *Server) { s.client = c } }

// New returns a relay for cfg, logging to log.
func New(cfg *config.Config, log *slog.Logger, opts ...Option) (*Server, error) {
	sealer, err := seal.New(cfg.Key)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:    cfg,
		sealer: sealer,
		log:    log,
		client: &http.Client{
			Timeout: 15 * time.Second,
			// A token endpoint never redirects; following one could send the secret elsewhere.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now: time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// Handler serves every route, with request logging and the headers every response gets.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /{provider}/authorize", s.authorize)
	mux.HandleFunc("GET /{provider}/callback", s.callback)
	mux.HandleFunc("POST /{provider}/token", s.token)
	mux.HandleFunc("POST /{provider}/refresh-token", s.refresh)
	return s.logged(secured(mux))
}

func secured(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// --- authorize ---

// statePayload is what the provider carries for the relay as its state.
type statePayload struct {
	Provider    string `json:"p"`
	RedirectURI string `json:"r"` // Fudge's loopback redirect
	State       string `json:"s"` // Fudge's state
	Challenge   string `json:"c"` // Fudge's S256 challenge
	Verifier    string `json:"v,omitempty"`
}

// The parameters the relay sets itself; every other one goes on to the provider.
var ownParams = map[string]bool{
	"client_id":             true,
	"redirect_uri":          true,
	"response_type":         true,
	"state":                 true,
	"scope":                 true,
	"code_challenge":        true,
	"code_challenge_method": true,
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	p, ok := s.providerPage(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	redirect := q.Get("redirect_uri")
	if !LoopbackRedirect(redirect) {
		s.page(w, http.StatusBadRequest, "Can't sign in", "This sign-in server only sends you back to Fudge on this Mac: redirect_uri must be http://127.0.0.1:<port>/… or http://[::1]:<port>/….")
		return
	}
	if q.Get("response_type") != "code" {
		s.page(w, http.StatusBadRequest, "Can't sign in", "response_type must be code.")
		return
	}
	challenge := q.Get("code_challenge")
	if challenge == "" || q.Get("code_challenge_method") != "S256" {
		s.page(w, http.StatusBadRequest, "Can't sign in", "Signing in needs PKCE: a code_challenge with code_challenge_method S256.")
		return
	}
	if !validChallenge(challenge) {
		s.page(w, http.StatusBadRequest, "Can't sign in", "code_challenge must be a base64url SHA-256 hash.")
		return
	}
	state := q.Get("state")
	if state == "" || len(state) > maxParamLen {
		s.page(w, http.StatusBadRequest, "Can't sign in", "state is missing or too long.")
		return
	}

	payload := statePayload{Provider: p.Name, RedirectURI: redirect, State: state, Challenge: challenge}
	if p.PKCE {
		payload.Verifier = newVerifier()
	}
	sealed, err := s.sealer.Seal(purposeState, payload, s.now().Add(StateLifetime))
	if err != nil {
		s.log.Error("sealing the state failed", "provider", p.Name)
		s.page(w, http.StatusInternalServerError, "Can't sign in", "Something went wrong on the sign-in server. Try again.")
		return
	}

	dest, err := url.Parse(p.AuthorizeURL)
	if err != nil {
		s.page(w, http.StatusInternalServerError, "Can't sign in", "The sign-in server's address for "+p.Title+" isn't valid.")
		return
	}
	params := dest.Query()
	for name, values := range q {
		if !ownParams[name] {
			params[name] = values
		}
	}
	params.Set("client_id", p.ClientID)
	params.Set("redirect_uri", s.cfg.CallbackURL(p.Name))
	params.Set("response_type", "code")
	params.Set("state", sealed)
	if scope := q.Get("scope"); scope != "" {
		params.Set("scope", scope)
	}
	if p.PKCE {
		params.Set("code_challenge", challengeFor(payload.Verifier))
		params.Set("code_challenge_method", "S256")
	}
	dest.RawQuery = params.Encode()
	http.Redirect(w, r, dest.String(), http.StatusFound)
}

// LoopbackRedirect says whether raw is a redirect to Fudge on this Mac:
// http on 127.0.0.1 or [::1], with a port, and no user or fragment.
func LoopbackRedirect(raw string) bool {
	if raw == "" || len(raw) > maxParamLen {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || (host != "127.0.0.1" && host != "::1") {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n < 65536 && strconv.Itoa(n) == port
}

// --- callback ---

// codePayload is the code Fudge gets: the provider's code, sealed.
type codePayload struct {
	Provider    string `json:"p"`
	Code        string `json:"x"`
	RedirectURI string `json:"r"`
	Challenge   string `json:"c"`
	Verifier    string `json:"v,omitempty"`
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	p, ok := s.providerPage(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	var st statePayload
	if err := s.sealer.Open(purposeState, q.Get("state"), s.now(), &st); err != nil || st.Provider != p.Name {
		msg := "This sign-in link isn't valid. Start signing in again from Fudge."
		if errors.Is(err, seal.ErrExpired) {
			msg = "This sign-in took too long. Start signing in again from Fudge."
		}
		s.page(w, http.StatusBadRequest, "Can't sign in", msg)
		return
	}

	dest, err := url.Parse(st.RedirectURI)
	if err != nil {
		s.page(w, http.StatusBadRequest, "Can't sign in", "This sign-in link isn't valid. Start signing in again from Fudge.")
		return
	}
	params := dest.Query()
	params.Set("state", st.State)
	switch code := q.Get("code"); {
	case q.Get("error") != "":
		params.Set("error", clip(q.Get("error")))
		if d := q.Get("error_description"); d != "" {
			params.Set("error_description", clip(d))
		}
	case code == "" || len(code) > maxParamLen:
		params.Set("error", "invalid_request")
		params.Set("error_description", p.Title+" sent no code back.")
	default:
		sealed, err := s.sealer.Seal(purposeCode, codePayload{
			Provider:    p.Name,
			Code:        code,
			RedirectURI: st.RedirectURI,
			Challenge:   st.Challenge,
			Verifier:    st.Verifier,
		}, s.now().Add(CodeLifetime))
		if err != nil {
			s.log.Error("sealing the code failed", "provider", p.Name)
			params.Set("error", "server_error")
			params.Set("error_description", "Something went wrong on the sign-in server. Try again.")
		} else {
			params.Set("code", sealed)
		}
	}
	dest.RawQuery = params.Encode()
	http.Redirect(w, r, dest.String(), http.StatusFound)
}

func clip(s string) string {
	if len(s) > 512 {
		return s[:512]
	}
	return s
}

// --- token and refresh-token ---

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	p, ok := s.providerJSON(w, r)
	if !ok {
		return
	}
	form, ok := readForm(w, r)
	if !ok {
		return
	}
	if form["grant_type"] != "authorization_code" {
		writeError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be authorization_code.")
		return
	}
	var c codePayload
	if err := s.sealer.Open(purposeCode, form["code"], s.now(), &c); err != nil {
		msg := "The code isn't valid. Sign in again."
		if errors.Is(err, seal.ErrExpired) {
			msg = "The code has expired. Sign in again."
		}
		writeError(w, http.StatusBadRequest, "invalid_grant", msg)
		return
	}
	if c.Provider != p.Name {
		writeError(w, http.StatusBadRequest, "invalid_grant", "The code is for another provider.")
		return
	}
	if ru := form["redirect_uri"]; ru != "" && ru != c.RedirectURI {
		writeError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri isn't the one signing in started with.")
		return
	}
	verifier := form["code_verifier"]
	if !validVerifier(verifier) || subtle.ConstantTimeCompare([]byte(challengeFor(verifier)), []byte(c.Challenge)) != 1 {
		writeError(w, http.StatusBadRequest, "invalid_grant", "code_verifier doesn't match the sign-in.")
		return
	}

	params := map[string]string{
		"grant_type":   "authorization_code",
		"code":         c.Code,
		"redirect_uri": s.cfg.CallbackURL(p.Name),
	}
	if c.Verifier != "" {
		params["code_verifier"] = c.Verifier
	}
	s.exchange(w, r, p, params)
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	p, ok := s.providerJSON(w, r)
	if !ok {
		return
	}
	form, ok := readForm(w, r)
	if !ok {
		return
	}
	if form["grant_type"] != "refresh_token" {
		writeError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be refresh_token.")
		return
	}
	if !p.Refresh {
		writeError(w, http.StatusBadRequest, "unsupported_grant_type", p.Title+" doesn't issue refresh tokens, so there's nothing to refresh. Sign in again.")
		return
	}
	token := form["refresh_token"]
	if token == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "refresh_token is missing.")
		return
	}
	s.exchange(w, r, p, map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": token,
	})
}

// --- helpers ---

func newVerifier() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	return base64.RawURLEncoding.EncodeToString(b)
}

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// validVerifier follows RFC 7636 §4.1: 43–128 unreserved characters.
func validVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for _, c := range v {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~') {
			return false
		}
	}
	return true
}

// validChallenge accepts an S256 challenge: 32 bytes in unpadded base64url.
func validChallenge(c string) bool {
	if len(c) != 43 {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(c)
	return err == nil && len(b) == sha256.Size
}

// providerName returns the {provider} path segment.
func providerName(r *http.Request) string { return r.PathValue("provider") }

func (s *Server) lookup(r *http.Request) (config.Provider, bool) {
	p, ok := s.cfg.Providers[providerName(r)]
	return p, ok
}

func (s *Server) providerPage(w http.ResponseWriter, r *http.Request) (config.Provider, bool) {
	p, ok := s.lookup(r)
	if !ok {
		s.page(w, http.StatusNotFound, "Not offered", notOffered(r))
	}
	return p, ok
}

func (s *Server) providerJSON(w http.ResponseWriter, r *http.Request) (config.Provider, bool) {
	p, ok := s.lookup(r)
	if !ok {
		writeError(w, http.StatusNotFound, "invalid_request", notOffered(r))
	}
	return p, ok
}

func notOffered(r *http.Request) string {
	name := providerName(r)
	if known, ok := provider.Lookup(name); ok {
		name = known.Title
	} else if len(name) > 64 {
		name = name[:64] + "…"
	}
	return "This sign-in server doesn't offer " + strings.ToValidUTF8(name, "") + "."
}
