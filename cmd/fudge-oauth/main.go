// Command fudge-oauth is Fudge's sign-in relay. It holds the OAuth apps'
// client secrets, so Fudge doesn't have to.
//
// Usage:
//
//	fudge-oauth                     serve, configured by FUDGE_OAUTH_CONFIG and FUDGE_OAUTH_* variables
//	fudge-oauth healthcheck [URL]   exit 0 if the CA certificates load and the relay answers at URL (default: its
//	                                own /healthz, over HTTPS when it serves HTTPS itself)
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jakeobsen/fudge-oauth/internal/config"
	"github.com/jakeobsen/fudge-oauth/internal/relay"
	"github.com/jakeobsen/fudge-oauth/internal/tlscert"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" && len(os.Args) <= 3 {
		os.Exit(healthcheck(os.Args[2:], os.Getenv, os.ReadFile, os.Stderr))
	}
	if len(os.Args) > 1 {
		fmt.Fprintln(os.Stderr, "usage: fudge-oauth [healthcheck [URL]]")
		os.Exit(2)
	}
	if err := serve(); err != nil {
		fmt.Fprintln(os.Stderr, "fudge-oauth:", err)
		os.Exit(1)
	}
}

func serve() error {
	cfg, err := config.Load(os.Getenv, os.ReadFile)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	server, err := newServer(cfg, log)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	failed := make(chan error, 1)
	go func() { failed <- run(server, listener, cfg.TLS()) }()
	logStart(log, cfg)

	select {
	case err := <-failed:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// logStart logs where the relay listens, then one line per service it offers with the callback URL to register,
// whether or not the front page lists them. These are built only from the public URL and provider names.
func logStart(log *slog.Logger, cfg *config.Config) {
	log.Info("listening", "addr", cfg.Listen, "tls", cfg.TLS(), "public_url", cfg.PublicURL,
		"providers", strings.Join(cfg.Names(), ","), "info_page", !cfg.HideInfoPage, "service_list", !cfg.HideServiceList)
	for _, name := range cfg.Names() {
		log.Info("service", "provider", name, "callback", cfg.CallbackURL(name))
	}
	for _, note := range cfg.Notes {
		log.Warn(note)
	}
}

// newServer returns the relay's server for cfg. When the relay serves HTTPS itself, it serves the configured pair,
// picking up a renewal without a restart, and refuses to start if the pair doesn't load.
func newServer(cfg *config.Config, log *slog.Logger) (*http.Server, error) {
	r, err := relay.New(cfg, log)
	if err != nil {
		return nil, err
	}
	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           r.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	if cfg.TLS() {
		certs, err := tlscert.New(cfg.TLSCertFile, cfg.TLSKeyFile, log)
		if err != nil {
			return nil, err
		}
		// Go's defaults otherwise, HTTP/2 included.
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: certs.GetCertificate}
	}
	return server, nil
}

// run serves on listener until the server shuts down: HTTPS only when useTLS is set, else plain HTTP.
func run(server *http.Server, listener net.Listener, useTLS bool) error {
	if useTLS {
		return server.ServeTLS(listener, "", "")
	}
	return server.Serve(listener)
}

// healthcheck answers 0 when the system's CA certificates load and the relay answers 200. args may name the URL to
// ask; otherwise it's the relay's own /healthz, found from its configuration (getenv and readFile, as for serving).
func healthcheck(args []string, getenv func(string) string, readFile func(string) ([]byte, error), stderr io.Writer) int {
	unhealthy := func(v ...any) int {
		fmt.Fprintln(stderr, append([]any{"unhealthy:"}, v...)...)
		return 1
	}
	if err := checkRoots(); err != nil {
		return unhealthy(err)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	var target string
	if len(args) > 0 {
		target = args[0]
	} else {
		cfg, err := config.Load(getenv, readFile)
		if err != nil {
			return unhealthy(err)
		}
		if target, err = healthURL(cfg.Listen, cfg.TLS()); err != nil {
			return unhealthy(err)
		}
		if cfg.TLS() {
			// The relay asks its own listen address, which its certificate doesn't name (it names the public host),
			// so this call alone skips verification. A URL given as an argument is verified.
			client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		}
	}
	resp, err := client.Get(target)
	if err != nil {
		return unhealthy(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return unhealthy("status", resp.StatusCode)
	}
	return 0
}

// healthURL is the relay's own /healthz for listen: on 127.0.0.1 when it listens on every address, over HTTPS when
// it serves HTTPS.
func healthURL(listen string, useTLS bool) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("listen: %w", err)
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(host, port) + "/healthz", nil
}

// checkRoots fails when the system has no CA certificates. The image holds them as one copied file, and without them
// every call to a service's token endpoint fails.
func checkRoots() error {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return fmt.Errorf("the CA certificates don't load: %w", err)
	}
	if !hasRoots(roots) {
		return errors.New("there are no CA certificates, so the services' token endpoints can't be reached; " +
			"the image needs /etc/ssl/certs/ca-certificates.crt")
	}
	return nil
}

// hasRoots says whether pool holds any certificate. On Linux, the system pool is the certificates read from the
// usual files; on macOS it's the platform's verifier, which always has them.
func hasRoots(pool *x509.CertPool) bool { return !pool.Equal(x509.NewCertPool()) }
