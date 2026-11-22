// Package config reads the relay's configuration: a YAML file named by
// FUDGE_OAUTH_CONFIG, environment variables that override it value by value,
// and secrets read from files.
package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/jakeobsen/fudge-oauth/internal/provider"
	"github.com/jakeobsen/fudge-oauth/internal/seal"
)

// EnvPrefix starts every environment variable the relay reads.
const EnvPrefix = "FUDGE_OAUTH_"

// DefaultListen is the address the relay listens on unless configured: plain HTTP behind a proxy.
const DefaultListen = ":8080"

// DefaultListenTLS is the address the relay listens on unless configured, when it serves HTTPS itself.
const DefaultListenTLS = ":8443"

// Config is the relay's validated configuration.
type Config struct {
	// Listen is the address to listen on, e.g. ":8080".
	Listen string
	// TLSCertFile and TLSKeyFile are a PEM certificate chain and its key. With both, the relay serves HTTPS only;
	// with neither, plain HTTP behind a proxy.
	TLSCertFile string
	TLSKeyFile  string
	// PublicURL is the relay's address as browsers and Fudge reach it, without a trailing slash.
	PublicURL string
	// Key seals the relay's state and codes.
	Key []byte
	// HideInfoPage turns off the front page that lists the services and their callback URLs (info_page: false).
	// GET / then answers as any unknown path does.
	HideInfoPage bool
	// HideServiceList turns off GET /api/services, which lists the services' paths and titles for Fudge
	// (service_list: false). The address then answers as any unknown path does. It doesn't depend on HideInfoPage.
	HideServiceList bool
	// Providers holds the configured providers by name.
	Providers map[string]Provider
	// Notes say which deprecated names the configuration used, for the log at start. They name settings, never
	// their values.
	Notes []string
}

// Provider is a built-in provider with the relay's OAuth app for it.
type Provider struct {
	provider.Provider
	ClientID     string
	ClientSecret string
}

// TLS says whether the relay serves HTTPS itself.
func (c *Config) TLS() bool { return c.TLSCertFile != "" }

// CallbackURL is where the provider sends the browser back to the relay.
// It's the URL to register with the provider.
func (c *Config) CallbackURL(name string) string {
	return c.PublicURL + "/" + name + "/callback"
}

// Names lists the configured providers in the built-in order.
func (c *Config) Names() []string {
	var names []string
	for _, name := range provider.Names() {
		if _, ok := c.Providers[name]; ok {
			names = append(names, name)
		}
	}
	return names
}

type fileConfig struct {
	Listen      string                   `yaml:"listen"`
	TLS         fileTLS                  `yaml:"tls"`
	PublicURL   string                   `yaml:"public_url"`
	Key         string                   `yaml:"key"`
	KeyFile     string                   `yaml:"key_file"`
	InfoPage    *bool                    `yaml:"info_page"`
	ServiceList *bool                    `yaml:"service_list"`
	Providers   map[string]*fileProvider `yaml:"providers"`
}

type fileTLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type fileProvider struct {
	ClientID         string `yaml:"client_id"`
	ClientSecret     string `yaml:"client_secret"`
	ClientSecretFile string `yaml:"client_secret_file"`
	AuthorizeURL     string `yaml:"authorize_url"`
	TokenURL         string `yaml:"token_url"`
	PKCE             *bool  `yaml:"pkce"`
}

// Load reads the configuration. getenv and readFile are os.Getenv and os.ReadFile outside tests.
func Load(getenv func(string) string, readFile func(string) ([]byte, error)) (*Config, error) {
	var fc fileConfig
	if path := getenv(EnvPrefix + "CONFIG"); path != "" {
		data, err := readFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading the config file: %w", err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&fc); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("reading the config file %s: %w", path, err)
		}
	}
	var notes []string
	// A provider under a deprecated name (providers.jira) counts as its new one, unless that's set too.
	for _, alias := range sortedAliases() {
		fp, ok := fc.Providers[alias]
		if !ok {
			continue
		}
		delete(fc.Providers, alias)
		name := provider.Aliases[alias]
		if _, both := fc.Providers[name]; both {
			notes = append(notes, fmt.Sprintf("providers.%s is ignored: providers.%s is set, and %s is its old name", alias, name, alias))
			continue
		}
		fc.Providers[name] = fp
		notes = append(notes, fmt.Sprintf("providers.%s is deprecated: rename it providers.%s", alias, name))
	}
	for name := range fc.Providers {
		if _, ok := provider.Lookup(name); !ok {
			return nil, fmt.Errorf("providers: unknown provider %q; the relay knows %s", name, strings.Join(provider.Names(), ", "))
		}
	}

	env := func(key string, into *string) {
		if v := getenv(EnvPrefix + key); v != "" {
			*into = v
		}
	}
	env("LISTEN", &fc.Listen)
	env("TLS_CERT_FILE", &fc.TLS.CertFile)
	env("TLS_KEY_FILE", &fc.TLS.KeyFile)
	if v := getenv(EnvPrefix + "INFO_PAGE"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("%sINFO_PAGE: %q isn't true or false", EnvPrefix, v)
		}
		fc.InfoPage = &b
	}
	if v := getenv(EnvPrefix + "SERVICE_LIST"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("%sSERVICE_LIST: %q isn't true or false", EnvPrefix, v)
		}
		fc.ServiceList = &b
	}
	env("PUBLIC_URL", &fc.PublicURL)
	env("KEY", &fc.Key)
	env("KEY_FILE", &fc.KeyFile)
	if fc.Providers == nil {
		fc.Providers = map[string]*fileProvider{}
	}
	for _, name := range provider.Names() {
		fp, listed := fc.Providers[name]
		if fp == nil {
			fp = &fileProvider{}
		}
		prefix := strings.ToUpper(name) + "_"
		// A deprecated name's variables (FUDGE_OAUTH_JIRA_*) count where the new name's aren't set.
		providerEnv := func(key string) (string, string) {
			value, from := getenv(EnvPrefix+prefix+key), EnvPrefix+prefix+key
			for _, alias := range provider.AliasesOf(name) {
				old := strings.ToUpper(alias) + "_"
				v := getenv(EnvPrefix + old + key)
				switch {
				case v == "":
				case value == "":
					value, from = v, EnvPrefix+old+key
					notes = appendOnce(notes, fmt.Sprintf("%s%s* is deprecated: use %s%s*", EnvPrefix, old, EnvPrefix, prefix))
				default:
					notes = appendOnce(notes, fmt.Sprintf("%s%s%s is ignored: %s%s%s is set", EnvPrefix, old, key, EnvPrefix, prefix, key))
				}
			}
			return value, from
		}
		penv := func(key string, into *string) {
			if v, _ := providerEnv(key); v != "" {
				*into = v
			}
		}
		penv("CLIENT_ID", &fp.ClientID)
		penv("CLIENT_SECRET", &fp.ClientSecret)
		penv("CLIENT_SECRET_FILE", &fp.ClientSecretFile)
		penv("AUTHORIZE_URL", &fp.AuthorizeURL)
		penv("TOKEN_URL", &fp.TokenURL)
		if v, from := providerEnv("PKCE"); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				return nil, fmt.Errorf("%s: %q isn't true or false", from, v)
			}
			fp.PKCE = &b
		}
		if listed || *fp != (fileProvider{}) {
			fc.Providers[name] = fp
		}
	}

	cfg := &Config{
		Listen:      fc.Listen,
		TLSCertFile: strings.TrimSpace(fc.TLS.CertFile),
		TLSKeyFile:  strings.TrimSpace(fc.TLS.KeyFile),
		Providers:   map[string]Provider{},
		Notes:       notes,
	}
	if fc.InfoPage != nil {
		cfg.HideInfoPage = !*fc.InfoPage
	}
	if fc.ServiceList != nil {
		cfg.HideServiceList = !*fc.ServiceList
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return nil, errors.New("tls: cert_file and key_file go together; set both to serve HTTPS, or neither to serve plain HTTP behind a proxy")
	}
	if cfg.Listen == "" {
		cfg.Listen = DefaultListen
		if cfg.TLS() {
			cfg.Listen = DefaultListenTLS
		}
	}

	publicURL, err := checkURL(fc.PublicURL, true)
	if err != nil {
		return nil, fmt.Errorf("public_url: %w", err)
	}
	cfg.PublicURL = strings.TrimRight(publicURL.String(), "/")

	key, err := secret(fc.Key, fc.KeyFile, "key", readFile)
	if err != nil {
		return nil, err
	}
	if key == "" {
		return nil, errors.New("key: missing; set it to 32 random bytes in base64, e.g. from `openssl rand -base64 32`")
	}
	cfg.Key, err = base64.StdEncoding.DecodeString(key)
	if err != nil {
		cfg.Key, err = base64.RawStdEncoding.DecodeString(key)
	}
	if err != nil || len(cfg.Key) != seal.KeySize {
		return nil, errors.New("key: must be 32 random bytes in base64, e.g. from `openssl rand -base64 32`")
	}

	names := make([]string, 0, len(fc.Providers))
	for name := range fc.Providers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fp := fc.Providers[name]
		p, err := buildProvider(name, fp, readFile)
		if err != nil {
			return nil, fmt.Errorf("providers.%s: %w", name, err)
		}
		cfg.Providers[name] = p
	}
	if len(cfg.Providers) == 0 {
		return nil, fmt.Errorf("providers: none configured; give at least one of %s a client_id and client_secret", strings.Join(provider.Names(), ", "))
	}
	return cfg, nil
}

func buildProvider(name string, fp *fileProvider, readFile func(string) ([]byte, error)) (Provider, error) {
	base, _ := provider.Lookup(name)
	p := Provider{Provider: base, ClientID: strings.TrimSpace(fp.ClientID)}
	var err error
	p.ClientSecret, err = secret(fp.ClientSecret, fp.ClientSecretFile, "client_secret", readFile)
	if err != nil {
		return Provider{}, err
	}
	if p.ClientID == "" {
		return Provider{}, errors.New("client_id is missing")
	}
	if p.ClientSecret == "" {
		return Provider{}, errors.New("client_secret (or client_secret_file) is missing")
	}
	if fp.AuthorizeURL != "" {
		u, err := checkURL(fp.AuthorizeURL, false)
		if err != nil {
			return Provider{}, fmt.Errorf("authorize_url: %w", err)
		}
		p.AuthorizeURL = u.String()
	}
	if fp.TokenURL != "" {
		u, err := checkURL(fp.TokenURL, false)
		if err != nil {
			return Provider{}, fmt.Errorf("token_url: %w", err)
		}
		p.TokenURL = u.String()
	}
	if fp.PKCE != nil {
		p.PKCE = *fp.PKCE
	}
	return p, nil
}

// sortedAliases lists the deprecated provider names in order, so notes come out the same each time.
func sortedAliases() []string {
	aliases := make([]string, 0, len(provider.Aliases))
	for alias := range provider.Aliases {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	return aliases
}

func appendOnce(notes []string, note string) []string {
	if slices.Contains(notes, note) {
		return notes
	}
	return append(notes, note)
}

// secret returns value, or the trimmed contents of file. Setting both is an error.
func secret(value, file, field string, readFile func(string) ([]byte, error)) (string, error) {
	if value != "" && file != "" {
		return "", fmt.Errorf("%s and %s_file are both set; use one", field, field)
	}
	if file == "" {
		return strings.TrimSpace(value), nil
	}
	data, err := readFile(file)
	if err != nil {
		return "", fmt.Errorf("%s_file: %w", field, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// checkURL accepts an absolute https URL, or http on a loopback host (for testing).
// A public URL may not carry a query or fragment; an endpoint override may carry a query.
func checkURL(raw string, public bool) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("missing")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%q isn't a URL", raw)
	}
	if u.Host == "" || u.User != nil || u.Fragment != "" || (public && (u.RawQuery != "" || u.ForceQuery)) {
		return nil, fmt.Errorf("%q must be an absolute URL with a host, and no user, query or fragment", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return nil, fmt.Errorf("%q must use https (http only on localhost, for testing)", raw)
		}
	default:
		return nil, fmt.Errorf("%q must use https", raw)
	}
	return u, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
