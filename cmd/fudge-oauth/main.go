// Command fudge-oauth is Fudge's sign-in relay. It holds the OAuth apps'
// client secrets, so Fudge doesn't have to.
//
// Usage:
//
//	fudge-oauth                     serve, configured by FUDGE_OAUTH_CONFIG and FUDGE_OAUTH_* variables
//	fudge-oauth healthcheck [URL]   exit 0 if the relay answers at URL (default http://127.0.0.1:8080/healthz)
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jakeobsen/fudge-oauth/internal/config"
	"github.com/jakeobsen/fudge-oauth/internal/relay"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		target := "http://127.0.0.1:8080/healthz"
		if len(os.Args) > 2 {
			target = os.Args[2]
		}
		os.Exit(healthcheck(target))
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
	r, err := relay.New(cfg, log)
	if err != nil {
		return err
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	failed := make(chan error, 1)
	go func() { failed <- server.ListenAndServe() }()
	log.Info("listening", "addr", cfg.Listen, "public_url", cfg.PublicURL, "providers", strings.Join(cfg.Names(), ","))

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

func healthcheck(target string) int {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "unhealthy:", err)
		return 1
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "unhealthy: status", resp.StatusCode)
		return 1
	}
	return 0
}
