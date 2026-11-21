package relay

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/jakeobsen/fudge-oauth/internal/config"
	"github.com/jakeobsen/fudge-oauth/internal/provider"
)

const (
	maxRequestBody  = 64 << 10
	maxProviderBody = 1 << 20
)

// exchange sends a token request to the provider with the relay's own client
// credentials, and answers with the provider's token response as JSON.
func (s *Server) exchange(w http.ResponseWriter, r *http.Request, p config.Provider, params map[string]string) {
	if p.ClientAuth == provider.ClientAuthBody {
		params["client_id"] = p.ClientID
		params["client_secret"] = p.ClientSecret
	}
	var body []byte
	contentType := "application/x-www-form-urlencoded"
	if p.TokenBody == provider.BodyJSON {
		body, _ = json.Marshal(params)
		contentType = "application/json"
	} else {
		v := url.Values{}
		for k, x := range params {
			v.Set(k, x)
		}
		body = []byte(v.Encode())
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, p.TokenURL, bytes.NewReader(body))
	if err != nil {
		s.log.Error("building the token request failed", "provider", p.Name)
		writeError(w, http.StatusInternalServerError, "server_error", "The sign-in server's address for "+p.Title+" isn't valid.")
		return
	}
	req.Header.Set("Content-Type", contentType)
	// GitHub answers in form encoding unless asked for JSON.
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "fudge-oauth")
	if p.ClientAuth == provider.ClientAuthBasic {
		req.SetBasicAuth(p.ClientID, p.ClientSecret)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		s.log.Warn("provider unreachable", "provider", p.Name)
		writeError(w, http.StatusBadGateway, "temporarily_unavailable", p.Title+" couldn't be reached. Try again.")
		return
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderBody+1))
	if err != nil || len(raw) > maxProviderBody {
		s.log.Warn("provider's answer unreadable", "provider", p.Name, "upstream_status", resp.StatusCode)
		writeError(w, http.StatusBadGateway, "temporarily_unavailable", p.Title+"'s answer couldn't be read. Try again.")
		return
	}

	tokens, parsed := parseTokenResponse(resp.Header.Get("Content-Type"), raw)
	if resp.StatusCode < 300 && parsed && !isProviderError(tokens) {
		writeJSON(w, http.StatusOK, tokens)
		return
	}
	s.log.Warn("provider refused the token request", "provider", p.Name, "upstream_status", resp.StatusCode)
	// A refusal (4xx, or a 200 carrying an error) is the client's; anything else is the provider failing.
	if refused := (resp.StatusCode >= 400 && resp.StatusCode < 500) || (resp.StatusCode < 300 && parsed); refused {
		code, desc := describeProviderError(p, tokens)
		writeError(w, http.StatusBadRequest, code, desc)
		return
	}
	writeError(w, http.StatusBadGateway, "temporarily_unavailable", p.Title+" couldn't complete the sign-in. Try again.")
}

// parseTokenResponse reads a token response: JSON, or form encoding as some
// providers answer by default. Form values become JSON strings, except expiry
// times, which OAuthService reads as numbers.
func parseTokenResponse(contentType string, raw []byte) (map[string]any, bool) {
	mt, _, _ := mime.ParseMediaType(contentType)
	if mt == "application/json" || strings.HasSuffix(mt, "+json") || bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var obj map[string]any
		if err := dec.Decode(&obj); err != nil || obj == nil {
			return nil, false
		}
		return obj, true
	}
	if mt == "application/x-www-form-urlencoded" || mt == "text/plain" {
		values, err := url.ParseQuery(string(raw))
		if err != nil || len(values) == 0 {
			return nil, false
		}
		obj := make(map[string]any, len(values))
		for k, v := range values {
			obj[k] = v[0]
			if strings.HasSuffix(k, "expires_in") && isDigits(v[0]) {
				obj[k] = json.Number(v[0])
			}
		}
		return obj, true
	}
	return nil, false
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// isProviderError spots errors that come back with a 200: GitHub's
// {"error": …} and Slack's {"ok": false, …}.
func isProviderError(tokens map[string]any) bool {
	if ok, present := tokens["ok"].(bool); present && !ok {
		return true
	}
	e, _ := tokens["error"].(string)
	return e != "" && tokens["access_token"] == nil && tokens["authed_user"] == nil
}

var errorCode = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,64}$`)

func describeProviderError(p config.Provider, tokens map[string]any) (string, string) {
	code, _ := tokens["error"].(string)
	if !errorCode.MatchString(code) {
		code = "invalid_grant"
	}
	desc, _ := tokens["error_description"].(string)
	if desc == "" {
		desc = p.Title + " refused the request (" + code + ")."
	}
	return code, clip(desc)
}

// readForm reads a token request's body, JSON or form encoded, as OAuthService sends it.
func readForm(w http.ResponseWriter, r *http.Request) (map[string]string, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	form := map[string]string{}
	switch mt {
	case "application/json":
		var raw map[string]any
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil || raw == nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "The body isn't a JSON object.")
			return nil, false
		}
		for k, v := range raw {
			switch v := v.(type) {
			case string:
				form[k] = v
			case nil:
			default:
				writeError(w, http.StatusBadRequest, "invalid_request", k+" must be a string.")
				return nil, false
			}
		}
	case "application/x-www-form-urlencoded":
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "The body isn't valid form data.")
			return nil, false
		}
		for k, v := range r.PostForm {
			form[k] = v[0]
		}
	default:
		writeError(w, http.StatusUnsupportedMediaType, "invalid_request", "Send the body as JSON or form data.")
		return nil, false
	}
	return form, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}
