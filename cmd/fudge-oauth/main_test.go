package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jakeobsen/fudge-oauth/internal/config"
	"github.com/jakeobsen/fudge-oauth/internal/testcert"
)

const testKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" // bytes 0…31

// env is a relay's environment, as getenv and readFile.
type env map[string]string

func (e env) getenv(k string) string { return e[k] }

func readFile(p string) ([]byte, error) { return os.ReadFile(p) }

// relayEnv configures a relay on listen, serving HTTPS with certFile and keyFile when they're set.
func relayEnv(listen, certFile, keyFile string) env {
	e := env{
		"FUDGE_OAUTH_LISTEN":               listen,
		"FUDGE_OAUTH_PUBLIC_URL":           "https://oauth.example.com",
		"FUDGE_OAUTH_KEY":                  testKey,
		"FUDGE_OAUTH_GITHUB_CLIENT_ID":     "id",
		"FUDGE_OAUTH_GITHUB_CLIENT_SECRET": "secret",
	}
	if certFile != "" {
		e["FUDGE_OAUTH_TLS_CERT_FILE"] = certFile
		e["FUDGE_OAUTH_TLS_KEY_FILE"] = keyFile
	}
	return e
}

// start runs a relay configured by e on a free loopback port, and returns its address and environment with that
// port as its listen address.
func start(t *testing.T, e env) (addr string, withAddr env) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = listener.Addr().String()
	e["FUDGE_OAUTH_LISTEN"] = addr
	cfg, err := config.Load(e.getenv, readFile)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newServer(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- run(server, listener, cfg.TLS()) }()
	t.Cleanup(func() {
		_ = server.Close()
		if err := <-done; err != http.ErrServerClosed {
			t.Errorf("serving ended with %v", err)
		}
	})
	return addr, e
}

// trusting is a client that trusts the certificate in certFile, for the name in it, and asks for HTTP/2. A
// maxVersion other than 0 caps the TLS version it offers.
func trusting(t *testing.T, certFile string, maxVersion uint16) *http.Client {
	t.Helper()
	pemData, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pemData)
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: roots, ServerName: "oauth.example.com", MaxVersion: maxVersion},
			ForceAttemptHTTP2: true,
		},
	}
}

func TestServesHTTPSWithItsOwnCertificate(t *testing.T) {
	certFile, keyFile := testcert.Write(t, t.TempDir(), "oauth.example.com")
	addr, _ := start(t, relayEnv("", certFile, keyFile))

	resp, err := trusting(t, certFile, 0).Get("https://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok\n" {
		t.Errorf("/healthz: %d %q", resp.StatusCode, body)
	}
	if resp.ProtoMajor != 2 {
		t.Errorf("served over %s; want HTTP/2", resp.Proto)
	}
	if resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		t.Errorf("TLS state %+v", resp.TLS)
	}

	if _, err := trusting(t, certFile, tls.VersionTLS11).Get("https://" + addr + "/healthz"); err == nil {
		t.Error("TLS 1.1 was accepted; the minimum is TLS 1.2")
	}

	plain, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = plain.Body.Close()
	if plain.StatusCode == http.StatusOK {
		t.Error("plain HTTP was served too; with a certificate, the relay serves HTTPS only")
	}
}

func TestRefusesToStartWithAPairThatDoesntLoad(t *testing.T) {
	dir := t.TempDir()
	certFile, _ := testcert.Write(t, dir, "oauth.example.com")
	_, otherKey := testcert.Make(t, "other.example.com")
	mismatched := filepath.Join(dir, "other-key.pem")
	if err := os.WriteFile(mismatched, otherKey, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, keyFile := range map[string]string{"mismatched": mismatched, "missing": filepath.Join(dir, "nope.pem")} {
		t.Run(name, func(t *testing.T) {
			e := relayEnv("127.0.0.1:0", certFile, keyFile)
			cfg, err := config.Load(e.getenv, readFile)
			if err != nil {
				t.Fatal(err)
			}
			_, err = newServer(cfg, slog.New(slog.DiscardHandler))
			if err == nil || !strings.HasPrefix(err.Error(), "tls.") {
				t.Errorf("newServer: %v", err)
			}
		})
	}
}

func TestHealthcheck(t *testing.T) {
	check := func(args []string, e env) (int, string) {
		var stderr bytes.Buffer
		code := healthcheck(args, e.getenv, readFile, &stderr)
		return code, stderr.String()
	}

	t.Run("plain HTTP", func(t *testing.T) {
		addr, e := start(t, relayEnv("", "", ""))
		if code, out := check(nil, e); code != 0 {
			t.Errorf("its own /healthz: %d %q", code, out)
		}
		if code, out := check([]string{"http://" + addr + "/healthz"}, env{}); code != 0 {
			t.Errorf("a given URL: %d %q", code, out)
		}
		if code, _ := check([]string{"http://" + addr + "/nope"}, env{}); code != 1 {
			t.Errorf("a 404 is healthy")
		}
	})

	t.Run("HTTPS", func(t *testing.T) {
		certFile, keyFile := testcert.Write(t, t.TempDir(), "oauth.example.com")
		addr, e := start(t, relayEnv("", certFile, keyFile))
		if code, out := check(nil, e); code != 0 {
			t.Errorf("its own /healthz over HTTPS, though the certificate names oauth.example.com: %d %q", code, out)
		}
		if code, out := check([]string{"https://" + addr + "/healthz"}, env{}); code != 1 || !strings.Contains(out, "certificate") {
			t.Errorf("a given URL skipped verification: %d %q", code, out)
		}
	})

	t.Run("nothing listening", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := listener.Addr().String()
		_ = listener.Close()
		if code, out := check(nil, relayEnv(addr, "", "")); code != 1 || !strings.HasPrefix(out, "unhealthy:") {
			t.Errorf("%d %q", code, out)
		}
	})

	t.Run("a configuration that doesn't load", func(t *testing.T) {
		if code, out := check(nil, env{}); code != 1 || !strings.Contains(out, "public_url: missing") {
			t.Errorf("%d %q", code, out)
		}
	})
}

func TestHealthURL(t *testing.T) {
	cases := []struct {
		listen string
		tls    bool
		want   string
	}{
		{":8080", false, "http://127.0.0.1:8080/healthz"},
		{":8443", true, "https://127.0.0.1:8443/healthz"},
		{"0.0.0.0:9000", false, "http://127.0.0.1:9000/healthz"},
		{"[::]:9443", true, "https://127.0.0.1:9443/healthz"},
		{"127.0.0.1:9000", true, "https://127.0.0.1:9000/healthz"},
		{"[::1]:9000", false, "http://[::1]:9000/healthz"},
		{"localhost:9000", false, "http://localhost:9000/healthz"},
	}
	for _, c := range cases {
		if got, err := healthURL(c.listen, c.tls); err != nil || got != c.want {
			t.Errorf("healthURL(%q, %v) = %q, %v; want %q", c.listen, c.tls, got, err, c.want)
		}
	}
	if _, err := healthURL("8080", false); err == nil {
		t.Error("a listen address without a port was accepted")
	}
}

func TestTheCACertificatesAreChecked(t *testing.T) {
	if hasRoots(x509.NewCertPool()) {
		t.Error("an empty pool has roots")
	}
	certPEM, _ := testcert.Make(t, "ca.example.com")
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	if !hasRoots(pool) {
		t.Error("a pool with a certificate has none")
	}
	// The test machine has its CA certificates; CI's image job checks the image without them.
	if err := checkRoots(); err != nil {
		t.Error(err)
	}
}
