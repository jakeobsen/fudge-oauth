// Package tlscert serves the relay's own certificate when it terminates TLS itself, and picks up renewed files
// without a restart.
package tlscert

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"sync"
	"time"
)

// CheckInterval is how often, at most, the files' modification times are checked for a renewal.
const CheckInterval = time.Minute

// Reloader holds the certificate and key from two PEM files. Its GetCertificate goes in a tls.Config.
type Reloader struct {
	certFile, keyFile string
	log               *slog.Logger
	now               func() time.Time
	stat              func(string) (fs.FileInfo, error)
	readFile          func(string) ([]byte, error)

	mu      sync.Mutex
	cert    *tls.Certificate
	loaded  modTimes // the files' modification times when cert was read
	checked time.Time
}

type modTimes struct{ cert, key time.Time }

// Option changes a Reloader, for tests.
type Option func(*Reloader)

// WithClock replaces time.Now.
func WithClock(now func() time.Time) Option { return func(r *Reloader) { r.now = now } }

// New reads the certificate chain and key, and fails if they can't be read or don't match. Errors and log lines
// name the setting, never the file's path.
func New(certFile, keyFile string, log *slog.Logger, opts ...Option) (*Reloader, error) {
	r := &Reloader{certFile: certFile, keyFile: keyFile, log: log, now: time.Now, stat: os.Stat, readFile: os.ReadFile}
	for _, o := range opts {
		o(r)
	}
	times, err := r.modTimes()
	if err != nil {
		return nil, err
	}
	cert, err := r.load()
	if err != nil {
		return nil, err
	}
	r.cert, r.loaded, r.checked = cert, times, r.now()
	return r, nil
}

// GetCertificate returns the current pair, first reading the files again if they've changed since they were read
// and a minute has passed since the last check. A new pair that fails to load is logged, and the old one stays.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now := r.now(); now.Sub(r.checked) >= CheckInterval {
		r.checked = now
		r.reloadIfChanged()
	}
	return r.cert, nil
}

func (r *Reloader) reloadIfChanged() {
	times, err := r.modTimes()
	if err != nil {
		r.log.Error("tls: keeping the current certificate", "error", err.Error())
		return
	}
	if times == r.loaded {
		return
	}
	cert, err := r.load()
	if err != nil {
		r.log.Error("tls: keeping the current certificate; the changed files don't load", "error", err.Error())
		return
	}
	r.cert, r.loaded = cert, times
	r.log.Info("tls: loaded the renewed certificate", "not_after", cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
}

func (r *Reloader) modTimes() (modTimes, error) {
	cert, err := r.stat(r.certFile)
	if err != nil {
		return modTimes{}, fmt.Errorf("tls.cert_file: %w", pathless(err))
	}
	key, err := r.stat(r.keyFile)
	if err != nil {
		return modTimes{}, fmt.Errorf("tls.key_file: %w", pathless(err))
	}
	return modTimes{cert.ModTime(), key.ModTime()}, nil
}

// load reads both files. tls.X509KeyPair's errors never quote the key.
func (r *Reloader) load() (*tls.Certificate, error) {
	certPEM, err := r.readFile(r.certFile)
	if err != nil {
		return nil, fmt.Errorf("tls.cert_file: %w", pathless(err))
	}
	keyPEM, err := r.readFile(r.keyFile)
	if err != nil {
		return nil, fmt.Errorf("tls.key_file: %w", pathless(err))
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("tls.cert_file and tls.key_file: %w", err)
	}
	return &cert, nil
}

// pathless drops the path from a file error: config values other than the listen address, public URL and provider
// names are never logged.
func pathless(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}
	return err
}
