package tlscert

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jakeobsen/fudge-oauth/internal/testcert"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

func (c *clock) advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// host is the common name of the certificate GetCertificate serves now.
func host(t *testing.T, r *Reloader) string {
	t.Helper()
	cert, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	return cert.Leaf.Subject.CommonName
}

// replace writes a new pair over the files, dated mtime.
func replace(t *testing.T, certFile, keyFile string, certPEM, keyPEM []byte, mtime time.Time) {
	t.Helper()
	for file, data := range map[string][]byte{certFile: certPEM, keyFile: keyPEM} {
		if err := os.WriteFile(file, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(file, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoadsThePair(t *testing.T) {
	certFile, keyFile := testcert.Write(t, t.TempDir(), "one.example.com")
	r, err := New(certFile, keyFile, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if got := host(t, r); got != "one.example.com" {
		t.Errorf("serves %q", got)
	}
}

func TestRefusesWhatDoesntLoad(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := testcert.Write(t, dir, "one.example.com")
	_, otherKey := testcert.Make(t, "other.example.com")
	mismatched := filepath.Join(dir, "other-key.pem")
	if err := os.WriteFile(mismatched, otherKey, 0o600); err != nil {
		t.Fatal(err)
	}
	notPEM := filepath.Join(dir, "not.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.pem")

	cases := []struct {
		name, cert, key, want string
	}{
		{"a key that isn't the certificate's", certFile, mismatched, "tls.cert_file and tls.key_file: tls: private key does not match public key"},
		{"a certificate that isn't PEM", notPEM, keyFile, "tls.cert_file and tls.key_file"},
		{"a missing certificate", missing, keyFile, "tls.cert_file: no such file or directory"},
		{"a missing key", certFile, missing, "tls.key_file: no such file or directory"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(c.cert, c.key, slog.New(slog.DiscardHandler))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q doesn't say %q", err, c.want)
			}
			if strings.Contains(err.Error(), dir) {
				t.Errorf("error %q names the file's path", err)
			}
		})
	}
}

func TestPicksUpARenewal(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := testcert.Write(t, dir, "one.example.com")
	start := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	replace(t, certFile, keyFile, mustRead(t, certFile), mustRead(t, keyFile), start)
	c := &clock{t: start}
	var logs bytes.Buffer
	r, err := New(certFile, keyFile, slog.New(slog.NewJSONHandler(&logs, nil)), WithClock(c.now))
	if err != nil {
		t.Fatal(err)
	}

	c.advance(CheckInterval)
	if got := host(t, r); got != "one.example.com" || logs.Len() != 0 {
		t.Fatalf("unchanged files: serves %q, logs %q", got, logs.String())
	}

	two, twoKey := testcert.Make(t, "two.example.com")
	replace(t, certFile, keyFile, two, twoKey, start.Add(time.Hour))
	c.advance(CheckInterval - time.Second)
	if got := host(t, r); got != "one.example.com" {
		t.Fatalf("checked again within a minute: serves %q", got)
	}
	c.advance(time.Second)
	if got := host(t, r); got != "two.example.com" {
		t.Fatalf("after a minute: serves %q", got)
	}
	if !strings.Contains(logs.String(), "tls: loaded the renewed certificate") {
		t.Errorf("logs %q", logs.String())
	}
}

func TestKeepsTheOldPairWhenANewOneBreaks(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := testcert.Write(t, dir, "one.example.com")
	start := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	c := &clock{t: start}
	var logs bytes.Buffer
	r, err := New(certFile, keyFile, slog.New(slog.NewJSONHandler(&logs, nil)), WithClock(c.now))
	if err != nil {
		t.Fatal(err)
	}

	// The certificate is renewed, but the key isn't written yet: the old pair stays, and the error is logged.
	two, twoKey := testcert.Make(t, "two.example.com")
	oldKey := mustRead(t, keyFile)
	replace(t, certFile, keyFile, two, oldKey, start.Add(time.Hour))
	c.advance(CheckInterval)
	if got := host(t, r); got != "one.example.com" {
		t.Fatalf("a broken pair: serves %q", got)
	}
	if !strings.Contains(logs.String(), "keeping the current certificate") || !strings.Contains(logs.String(), "does not match") {
		t.Errorf("logs %q", logs.String())
	}
	if strings.Contains(logs.String(), dir) {
		t.Errorf("logs name the files' paths: %q", logs.String())
	}

	// A file that's gone keeps the old pair too.
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	c.advance(CheckInterval)
	if got := host(t, r); got != "one.example.com" {
		t.Fatalf("a missing key: serves %q", got)
	}

	// Once the key arrives, the next check loads the new pair.
	replace(t, certFile, keyFile, two, twoKey, start.Add(2*time.Hour))
	c.advance(CheckInterval)
	if got := host(t, r); got != "two.example.com" {
		t.Fatalf("the fixed pair: serves %q", got)
	}
}

func mustRead(t *testing.T, file string) []byte {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
