package config

import (
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/jakeobsen/fudge-oauth/internal/provider"
)

const testKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" // bytes 0…31

type fakeEnv struct {
	vars  map[string]string
	files map[string]string
}

func (f fakeEnv) getenv(k string) string { return f.vars[k] }

func (f fakeEnv) readFile(p string) ([]byte, error) {
	if s, ok := f.files[p]; ok {
		return []byte(s), nil
	}
	return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
}

func load(t *testing.T, vars, files map[string]string) (*Config, error) {
	t.Helper()
	e := fakeEnv{vars: vars, files: files}
	return Load(e.getenv, e.readFile)
}

func TestFromFile(t *testing.T) {
	cfg, err := load(t,
		map[string]string{"FUDGE_OAUTH_CONFIG": "/c.yaml"},
		map[string]string{
			"/c.yaml": `
public_url: https://oauth.example.com/
key_file: /run/secrets/key
providers:
  github:
    client_id: gh-id
    client_secret_file: /run/secrets/github
  atlassian:
    client_id: atlassian-id
    client_secret: atlassian-secret
    authorize_url: https://auth.example.com/authorize?audience=api.example.com
    pkce: true
`,
			"/run/secrets/key":    testKey + "\n",
			"/run/secrets/github": "gh-secret\n",
		})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":8080" {
		t.Errorf("Listen = %q", cfg.Listen)
	}
	if cfg.PublicURL != "https://oauth.example.com" {
		t.Errorf("PublicURL = %q", cfg.PublicURL)
	}
	if len(cfg.Key) != 32 || cfg.Key[31] != 31 {
		t.Errorf("Key = %v", cfg.Key)
	}
	if got := strings.Join(cfg.Names(), ","); got != "github,atlassian" {
		t.Errorf("Names = %s", got)
	}
	gh := cfg.Providers["github"]
	if gh.ClientID != "gh-id" || gh.ClientSecret != "gh-secret" || gh.TokenURL != "https://github.com/login/oauth/access_token" || !gh.PKCE {
		t.Errorf("github = %+v", gh)
	}
	atlassian := cfg.Providers["atlassian"]
	if atlassian.AuthorizeURL != "https://auth.example.com/authorize?audience=api.example.com" || !atlassian.PKCE ||
		atlassian.ClientSecret != "atlassian-secret" {
		t.Errorf("atlassian = %+v", atlassian)
	}
	if len(cfg.Notes) != 0 {
		t.Errorf("Notes = %q", cfg.Notes)
	}
	if got := cfg.CallbackURL("github"); got != "https://oauth.example.com/github/callback" {
		t.Errorf("CallbackURL = %s", got)
	}
}

func TestEnvironmentOnly(t *testing.T) {
	cfg, err := load(t, map[string]string{
		"FUDGE_OAUTH_LISTEN":                    "127.0.0.1:9000",
		"FUDGE_OAUTH_PUBLIC_URL":                "http://localhost:9000",
		"FUDGE_OAUTH_KEY":                       strings.TrimRight(testKey, "="),
		"FUDGE_OAUTH_LINEAR_CLIENT_ID":          "lin-id",
		"FUDGE_OAUTH_LINEAR_CLIENT_SECRET_FILE": "/s",
		"FUDGE_OAUTH_LINEAR_PKCE":               "false",
	}, map[string]string{"/s": "lin-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:9000" || cfg.PublicURL != "http://localhost:9000" {
		t.Errorf("cfg = %+v", cfg)
	}
	lin := cfg.Providers["linear"]
	if lin.ClientID != "lin-id" || lin.ClientSecret != "lin-secret" || lin.PKCE {
		t.Errorf("linear = %+v", lin)
	}
}

func TestEnvironmentOverridesFile(t *testing.T) {
	cfg, err := load(t, map[string]string{
		"FUDGE_OAUTH_CONFIG":               "/c.yaml",
		"FUDGE_OAUTH_PUBLIC_URL":           "https://other.example.com",
		"FUDGE_OAUTH_GITHUB_CLIENT_ID":     "env-id",
		"FUDGE_OAUTH_SLACK_CLIENT_ID":      "slack-id",
		"FUDGE_OAUTH_SLACK_CLIENT_SECRET":  "slack-secret",
		"FUDGE_OAUTH_SLACK_TOKEN_URL":      "https://slack.example.com/token",
		"FUDGE_OAUTH_GITHUB_AUTHORIZE_URL": "https://ghe.example.com/login/oauth/authorize",
	}, map[string]string{"/c.yaml": `
public_url: https://oauth.example.com
key: ` + testKey + `
providers:
  github: {client_id: file-id, client_secret: file-secret}
`})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicURL != "https://other.example.com" {
		t.Errorf("PublicURL = %q", cfg.PublicURL)
	}
	gh := cfg.Providers["github"]
	if gh.ClientID != "env-id" || gh.ClientSecret != "file-secret" || gh.AuthorizeURL != "https://ghe.example.com/login/oauth/authorize" {
		t.Errorf("github = %+v", gh)
	}
	if s := cfg.Providers["slack"]; s.TokenURL != "https://slack.example.com/token" || s.ClientSecret != "slack-secret" {
		t.Errorf("slack = %+v", s)
	}
}

func TestRefused(t *testing.T) {
	good := map[string]string{
		"FUDGE_OAUTH_PUBLIC_URL":           "https://oauth.example.com",
		"FUDGE_OAUTH_KEY":                  testKey,
		"FUDGE_OAUTH_GITHUB_CLIENT_ID":     "id",
		"FUDGE_OAUTH_GITHUB_CLIENT_SECRET": "secret",
	}
	with := func(changes map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range good {
			m[k] = v
		}
		for k, v := range changes {
			if v == "" {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		return m
	}
	if _, err := load(t, good, nil); err != nil {
		t.Fatalf("the good config: %v", err)
	}

	cases := []struct {
		name  string
		vars  map[string]string
		files map[string]string
		want  string
	}{
		{"no public URL", with(map[string]string{"FUDGE_OAUTH_PUBLIC_URL": ""}), nil, "public_url: missing"},
		{"plain http", with(map[string]string{"FUDGE_OAUTH_PUBLIC_URL": "http://oauth.example.com"}), nil, "must use https"},
		{"a relative URL", with(map[string]string{"FUDGE_OAUTH_PUBLIC_URL": "/oauth"}), nil, "absolute URL"},
		{"a query", with(map[string]string{"FUDGE_OAUTH_PUBLIC_URL": "https://oauth.example.com/?a=b"}), nil, "no user, query"},
		{"another scheme", with(map[string]string{"FUDGE_OAUTH_PUBLIC_URL": "ftp://oauth.example.com"}), nil, "must use https"},
		{"no key", with(map[string]string{"FUDGE_OAUTH_KEY": ""}), nil, "key: missing"},
		{"a short key", with(map[string]string{"FUDGE_OAUTH_KEY": "c2hvcnQ="}), nil, "32 random bytes"},
		{"a key that isn't base64", with(map[string]string{"FUDGE_OAUTH_KEY": "not base64!"}), nil, "32 random bytes"},
		{"key and key_file", with(map[string]string{"FUDGE_OAUTH_KEY_FILE": "/k"}), map[string]string{"/k": testKey}, "both set"},
		{"a missing secret file", with(map[string]string{"FUDGE_OAUTH_GITHUB_CLIENT_SECRET": "", "FUDGE_OAUTH_GITHUB_CLIENT_SECRET_FILE": "/nope"}), nil, "client_secret_file"},
		{"no secret", with(map[string]string{"FUDGE_OAUTH_GITHUB_CLIENT_SECRET": ""}), nil, "providers.github: client_secret"},
		{"no client ID", with(map[string]string{"FUDGE_OAUTH_GITHUB_CLIENT_ID": ""}), nil, "providers.github: client_id is missing"},
		{"no providers", with(map[string]string{"FUDGE_OAUTH_GITHUB_CLIENT_ID": "", "FUDGE_OAUTH_GITHUB_CLIENT_SECRET": ""}), nil, "none configured"},
		{"an http token URL", with(map[string]string{"FUDGE_OAUTH_GITHUB_TOKEN_URL": "http://github.example.com/token"}), nil, "token_url"},
		{"a bad PKCE value", with(map[string]string{"FUDGE_OAUTH_GITHUB_PKCE": "maybe"}), nil, "PKCE"},
		{"a missing config file", with(map[string]string{"FUDGE_OAUTH_CONFIG": "/nope.yaml"}), nil, "reading the config file"},
		{"an unknown field", with(map[string]string{"FUDGE_OAUTH_CONFIG": "/c.yaml"}), map[string]string{"/c.yaml": "public_ur: x\n"}, "public_ur"},
		{"an unknown provider", with(map[string]string{"FUDGE_OAUTH_CONFIG": "/c.yaml"}), map[string]string{"/c.yaml": "providers:\n  gitlab: {client_id: a}\n"}, `unknown provider "gitlab"`},
		{"an empty provider entry", with(map[string]string{"FUDGE_OAUTH_CONFIG": "/c.yaml"}), map[string]string{"/c.yaml": "providers:\n  zoom:\n"}, "providers.zoom: client_id is missing"},
		{"a TLS certificate without its key", with(map[string]string{"FUDGE_OAUTH_TLS_CERT_FILE": "/tls/cert.pem"}), nil, "tls: cert_file and key_file go together"},
		{"a TLS key without its certificate", with(map[string]string{"FUDGE_OAUTH_TLS_KEY_FILE": "/tls/key.pem"}), nil, "tls: cert_file and key_file go together"},
		{"an info_page that isn't true or false", with(map[string]string{"FUDGE_OAUTH_INFO_PAGE": "off"}), nil, `FUDGE_OAUTH_INFO_PAGE: "off" isn't true or false`},
		{"an info_page in the file that isn't a boolean", with(map[string]string{"FUDGE_OAUTH_CONFIG": "/c.yaml"}), map[string]string{"/c.yaml": "info_page: hidden\n"}, "cannot unmarshal !!str `hidden` into bool"},
		{"an unknown TLS field", with(map[string]string{"FUDGE_OAUTH_CONFIG": "/c.yaml"}), map[string]string{"/c.yaml": "tls:\n  certfile: /c.pem\n"}, "certfile"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := load(t, c.vars, c.files)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q doesn't say %q", err, c.want)
			}
		})
	}
}

func TestTLS(t *testing.T) {
	base := map[string]string{
		"FUDGE_OAUTH_PUBLIC_URL":           "https://oauth.example.com",
		"FUDGE_OAUTH_KEY":                  testKey,
		"FUDGE_OAUTH_GITHUB_CLIENT_ID":     "id",
		"FUDGE_OAUTH_GITHUB_CLIENT_SECRET": "secret",
	}
	plain, err := load(t, base, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plain.TLS() || plain.Listen != ":8080" {
		t.Errorf("without TLS: TLS() = %v, Listen = %q; want plain HTTP on :8080", plain.TLS(), plain.Listen)
	}

	fromFile, err := load(t, map[string]string{"FUDGE_OAUTH_CONFIG": "/c.yaml"}, map[string]string{"/c.yaml": `
public_url: https://oauth.example.com
key: ` + testKey + `
tls:
  cert_file: /tls/fullchain.pem
  key_file: /tls/privkey.pem
providers:
  github: {client_id: id, client_secret: secret}
`})
	if err != nil {
		t.Fatal(err)
	}
	if !fromFile.TLS() || fromFile.TLSCertFile != "/tls/fullchain.pem" || fromFile.TLSKeyFile != "/tls/privkey.pem" {
		t.Errorf("from the file: %+v", fromFile)
	}
	if fromFile.Listen != ":8443" {
		t.Errorf("with TLS, Listen = %q; want :8443", fromFile.Listen)
	}

	vars := map[string]string{
		"FUDGE_OAUTH_TLS_CERT_FILE": "/run/secrets/cert.pem",
		"FUDGE_OAUTH_TLS_KEY_FILE":  "/run/secrets/key.pem",
		"FUDGE_OAUTH_LISTEN":        "127.0.0.1:9443",
	}
	for k, v := range base {
		vars[k] = v
	}
	fromEnv, err := load(t, vars, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !fromEnv.TLS() || fromEnv.TLSCertFile != "/run/secrets/cert.pem" || fromEnv.TLSKeyFile != "/run/secrets/key.pem" {
		t.Errorf("from the environment: %+v", fromEnv)
	}
	if fromEnv.Listen != "127.0.0.1:9443" {
		t.Errorf("a set listen address is kept: %q", fromEnv.Listen)
	}
}

func TestInfoPage(t *testing.T) {
	base := func(extra map[string]string) map[string]string {
		m := map[string]string{
			"FUDGE_OAUTH_PUBLIC_URL":           "https://oauth.example.com",
			"FUDGE_OAUTH_KEY":                  testKey,
			"FUDGE_OAUTH_GITHUB_CLIENT_ID":     "id",
			"FUDGE_OAUTH_GITHUB_CLIENT_SECRET": "secret",
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	cases := []struct {
		name  string
		vars  map[string]string
		files map[string]string
		hide  bool
	}{
		{"on by default", base(nil), nil, false},
		{"off from the environment", base(map[string]string{"FUDGE_OAUTH_INFO_PAGE": "false"}), nil, true},
		{"on from the environment", base(map[string]string{"FUDGE_OAUTH_INFO_PAGE": "true"}), nil, false},
		{"off from the file", base(map[string]string{"FUDGE_OAUTH_CONFIG": "/c.yaml"}), map[string]string{"/c.yaml": "info_page: false\n"}, true},
		{"the environment overrides the file", base(map[string]string{"FUDGE_OAUTH_CONFIG": "/c.yaml", "FUDGE_OAUTH_INFO_PAGE": "true"}), map[string]string{"/c.yaml": "info_page: false\n"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := load(t, c.vars, c.files)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.HideInfoPage != c.hide {
				t.Errorf("HideInfoPage = %v, want %v", cfg.HideInfoPage, c.hide)
			}
		})
	}
}

func TestEmptyFile(t *testing.T) {
	_, err := load(t, map[string]string{
		"FUDGE_OAUTH_CONFIG":             "/c.yaml",
		"FUDGE_OAUTH_PUBLIC_URL":         "https://oauth.example.com",
		"FUDGE_OAUTH_KEY":                testKey,
		"FUDGE_OAUTH_ZOOM_CLIENT_ID":     "id",
		"FUDGE_OAUTH_ZOOM_CLIENT_SECRET": "secret",
	}, map[string]string{"/c.yaml": ""})
	if err != nil {
		t.Fatal(err)
	}
}

func TestErrorsNeverShowSecrets(t *testing.T) {
	_, err := load(t, map[string]string{
		"FUDGE_OAUTH_PUBLIC_URL":           "https://oauth.example.com",
		"FUDGE_OAUTH_KEY":                  "TOP-SECRET-KEY",
		"FUDGE_OAUTH_GITHUB_CLIENT_ID":     "id",
		"FUDGE_OAUTH_GITHUB_CLIENT_SECRET": "TOP-SECRET-CLIENT",
	}, nil)
	if err == nil || strings.Contains(err.Error(), "TOP-SECRET") {
		t.Fatalf("err = %v", err)
	}
	if errors.Unwrap(err) != nil && strings.Contains(errors.Unwrap(err).Error(), "TOP-SECRET") {
		t.Fatal("the wrapped error shows the key")
	}
}

// The Atlassian provider was "jira" until v0.3.0. Its old names still configure it, for one release, with a note
// for the log at start.
func TestJiraConfiguresAtlassian(t *testing.T) {
	base := map[string]string{"FUDGE_OAUTH_PUBLIC_URL": "https://oauth.example.com", "FUDGE_OAUTH_KEY": testKey}
	with := func(extra map[string]string) map[string]string {
		vars := map[string]string{}
		for k, v := range base {
			vars[k] = v
		}
		for k, v := range extra {
			vars[k] = v
		}
		return vars
	}
	check := func(t *testing.T, cfg *Config, err error, wantID string, wantNotes ...string) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(cfg.Names(), ","); got != "atlassian" {
			t.Errorf("Names = %s", got)
		}
		if p := cfg.Providers["atlassian"]; p.ClientID != wantID || p.Name != "atlassian" {
			t.Errorf("atlassian = %+v, want client_id %s", p, wantID)
		}
		if !slices.Equal(cfg.Notes, wantNotes) {
			t.Errorf("Notes = %q, want %q", cfg.Notes, wantNotes)
		}
		for _, note := range cfg.Notes {
			if strings.Contains(note, "secret-") || strings.Contains(note, "-id") {
				t.Errorf("a note shows a value: %q", note)
			}
		}
	}

	t.Run("providers.jira", func(t *testing.T) {
		cfg, err := load(t, with(map[string]string{"FUDGE_OAUTH_CONFIG": "/c.yaml"}), map[string]string{
			"/c.yaml": "providers:\n  jira:\n    client_id: old-id\n    client_secret: secret-1\n",
		})
		check(t, cfg, err, "old-id", "providers.jira is deprecated: rename it providers.atlassian")
	})
	t.Run("providers.jira beside providers.atlassian", func(t *testing.T) {
		cfg, err := load(t, with(map[string]string{"FUDGE_OAUTH_CONFIG": "/c.yaml"}), map[string]string{
			"/c.yaml": "providers:\n  jira:\n    client_id: old-id\n    client_secret: secret-1\n" +
				"  atlassian:\n    client_id: new-id\n    client_secret: secret-2\n",
		})
		check(t, cfg, err, "new-id", "providers.jira is ignored: providers.atlassian is set, and jira is its old name")
	})
	t.Run("FUDGE_OAUTH_JIRA_*", func(t *testing.T) {
		cfg, err := load(t, with(map[string]string{
			"FUDGE_OAUTH_JIRA_CLIENT_ID": "old-id", "FUDGE_OAUTH_JIRA_CLIENT_SECRET": "secret-1",
		}), nil)
		// One note for the old prefix, however many of its variables are set.
		check(t, cfg, err, "old-id", "FUDGE_OAUTH_JIRA_* is deprecated: use FUDGE_OAUTH_ATLASSIAN_*")
	})
	t.Run("FUDGE_OAUTH_ATLASSIAN_* wins", func(t *testing.T) {
		cfg, err := load(t, with(map[string]string{
			"FUDGE_OAUTH_JIRA_CLIENT_ID": "old-id", "FUDGE_OAUTH_JIRA_CLIENT_SECRET": "secret-1",
			"FUDGE_OAUTH_ATLASSIAN_CLIENT_ID": "new-id", "FUDGE_OAUTH_ATLASSIAN_CLIENT_SECRET": "secret-2",
		}), nil)
		check(t, cfg, err, "new-id",
			"FUDGE_OAUTH_JIRA_CLIENT_ID is ignored: FUDGE_OAUTH_ATLASSIAN_CLIENT_ID is set",
			"FUDGE_OAUTH_JIRA_CLIENT_SECRET is ignored: FUDGE_OAUTH_ATLASSIAN_CLIENT_SECRET is set")
		if got := cfg.Providers["atlassian"].ClientSecret; got != "secret-2" {
			t.Errorf("client_secret from the old name")
		}
	})
	t.Run("FUDGE_OAUTH_ATLASSIAN_*", func(t *testing.T) {
		cfg, err := load(t, with(map[string]string{
			"FUDGE_OAUTH_ATLASSIAN_CLIENT_ID": "new-id", "FUDGE_OAUTH_ATLASSIAN_CLIENT_SECRET": "secret-2",
		}), nil)
		check(t, cfg, err, "new-id")
	})
}

// Loading a service sets the relay's client id and secret, and only the endpoints and PKCE the file names: every
// other field stays the built-in's (its authorize defaults, token parameters, client auth and body encoding).
func TestLoadKeepsBuiltinFields(t *testing.T) {
	vars := map[string]string{
		"FUDGE_OAUTH_CONFIG": "/c.yaml", "FUDGE_OAUTH_PUBLIC_URL": "https://oauth.example.com", "FUDGE_OAUTH_KEY": testKey,
	}
	loadOne := func(t *testing.T, name, extra string) Provider {
		t.Helper()
		cfg, err := load(t, vars, map[string]string{
			"/c.yaml": "providers:\n  " + name + ":\n    client_id: id-1\n    client_secret: secret-1\n" + extra,
		})
		if err != nil {
			t.Fatal(err)
		}
		canonical := provider.Canonical(name)
		if got := cfg.Names(); !slices.Equal(got, []string{canonical}) {
			t.Fatalf("Names = %q, want [%s]", got, canonical)
		}
		p := cfg.Providers[canonical]
		if p.ClientID != "id-1" || p.ClientSecret != "secret-1" {
			t.Errorf("client_id %q, client_secret set %t", p.ClientID, p.ClientSecret == "secret-1")
		}
		return p
	}

	// Every built-in service, and a deprecated name, which loads as the service it names.
	names := provider.Names()
	if aliases := sortedAliases(); len(aliases) > 0 {
		names = append(names, aliases[0])
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			want, ok := provider.Lookup(provider.Canonical(name))
			if !ok {
				t.Fatalf("no built-in %s", provider.Canonical(name))
			}
			if got := loadOne(t, name, "").Provider; !reflect.DeepEqual(got, want) {
				t.Errorf("loaded as\n%+v\nwant the built-in\n%+v", got, want)
			}
		})
	}

	t.Run("authorize_url, token_url and pkce from the file", func(t *testing.T) {
		want, _ := provider.Lookup("atlassian")
		want.AuthorizeURL = "https://auth.example.com/authorize?audience=api.example.com"
		want.TokenURL = "https://auth.example.com/oauth/token"
		want.PKCE = !want.PKCE
		got := loadOne(t, "atlassian", fmt.Sprintf("    authorize_url: %s\n    token_url: %s\n    pkce: %t\n",
			want.AuthorizeURL, want.TokenURL, want.PKCE)).Provider
		if !reflect.DeepEqual(got, want) {
			t.Errorf("loaded as\n%+v\nwant\n%+v", got, want)
		}
	})
}
