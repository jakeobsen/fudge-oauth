package relay

import (
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/jakeobsen/fudge-oauth/internal/provider"
)

const pageStyle = `body{font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;color:#1d1d1f;background:#fff}
h1{font-size:1.4rem}code{font-size:.9em}table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:.4rem .6rem .4rem 0;border-bottom:1px solid #ddd;vertical-align:top}
@media (prefers-color-scheme:dark){body{color:#f5f5f7;background:#1d1d1f}td,th{border-color:#444}}`

var messageTemplate = template.Must(template.New("message").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title><style>` + pageStyle + `</style></head>
<body><h1>{{.Title}}</h1><p>{{.Message}}</p></body></html>
`))

var indexTemplate = template.Must(template.New("index").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>fudge-oauth</title><style>` + pageStyle + `</style></head>
<body>
<h1>fudge-oauth</h1>
<p>A sign-in server for Fudge. Extensions sign in to these services through it. To use it, choose <b>Your own server…</b> in Fudge's Settings → Sign-in and enter <code>{{.PublicURL}}</code>.</p>
<table>
<tr><th>Service</th><th>Callback URL to register</th><th>Where</th></tr>
{{range .Providers}}<tr><td>{{.Title}}</td><td><code>{{.Callback}}</code></td><td>{{.Setup}}</td></tr>
{{end}}</table>
</body></html>
`))

func (s *Server) page(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = messageTemplate.Execute(w, struct{ Title, Message string }{title, message})
}

func (s *Server) index(w http.ResponseWriter, _ *http.Request) {
	type row struct{ Title, Callback, Setup string }
	var rows []row
	for _, name := range s.cfg.Names() {
		p := s.cfg.Providers[name]
		rows = append(rows, row{Title: p.Title, Callback: s.cfg.CallbackURL(name), Setup: p.Setup})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = indexTemplate.Execute(w, struct {
		PublicURL string
		Providers []row
	}{s.cfg.PublicURL, rows})
}

// --- request logging ---

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// logged logs each request with its path, provider, status and duration, and
// nothing else: never a query string, a header or a body, where codes, tokens
// and secrets travel.
func (s *Server) logged(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		if r.URL.Path == "/healthz" && sw.status == http.StatusOK {
			return
		}
		path := r.URL.Path
		if len(path) > 200 {
			path = path[:200] + "…"
		}
		attrs := []any{"path", strings.ToValidUTF8(path, "?"), "status", sw.status, "duration_ms", time.Since(start).Milliseconds()}
		if name, _, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/"); name != "" {
			if _, ok := provider.Lookup(name); ok {
				attrs = append(attrs, "provider", name)
			}
		}
		s.log.Info("request", attrs...)
	})
}
