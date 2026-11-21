package seal

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

type payload struct {
	A string `json:"a"`
	B int    `json:"b"`
}

func newSealer(t *testing.T, fill byte) *Sealer {
	t.Helper()
	s, err := New(bytes.Repeat([]byte{fill}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRoundTrip(t *testing.T) {
	s := newSealer(t, 1)
	now := time.Unix(1_800_000_000, 0)
	sealed, err := s.Seal("state", payload{A: "secret-value", B: 7}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "secret-value") {
		t.Fatal("the sealed value shows its contents")
	}
	if strings.ContainsAny(sealed, "+/=") {
		t.Fatalf("not URL-safe: %q", sealed)
	}
	var got payload
	if err := s.Open("state", sealed, now, &got); err != nil {
		t.Fatal(err)
	}
	if got != (payload{A: "secret-value", B: 7}) {
		t.Fatalf("got %+v", got)
	}
}

func TestSealingTwiceDiffers(t *testing.T) {
	s := newSealer(t, 1)
	exp := time.Now().Add(time.Minute)
	a, _ := s.Seal("state", payload{A: "x"}, exp)
	b, _ := s.Seal("state", payload{A: "x"}, exp)
	if a == b {
		t.Fatal("two seals of one value are equal; the nonce isn't random")
	}
}

func TestExpired(t *testing.T) {
	s := newSealer(t, 1)
	now := time.Unix(1_800_000_000, 0)
	sealed, _ := s.Seal("code", payload{A: "x"}, now.Add(5*time.Minute))
	var got payload
	if err := s.Open("code", sealed, now.Add(5*time.Minute-time.Second), &got); err != nil {
		t.Fatalf("a second before expiry: %v", err)
	}
	if err := s.Open("code", sealed, now.Add(5*time.Minute), &got); !errors.Is(err, ErrExpired) {
		t.Fatalf("at expiry: %v, want ErrExpired", err)
	}
}

func TestRefused(t *testing.T) {
	s := newSealer(t, 1)
	now := time.Unix(1_800_000_000, 0)
	sealed, _ := s.Seal("state", payload{A: "x"}, now.Add(time.Minute))
	raw, _ := base64.RawURLEncoding.DecodeString(sealed)

	flipped := func(i int) string {
		b := bytes.Clone(raw)
		b[i] ^= 0x01
		return base64.RawURLEncoding.EncodeToString(b)
	}

	cases := map[string]struct {
		sealer  *Sealer
		purpose string
		value   string
	}{
		"another purpose":     {s, "code", sealed},
		"another key":         {newSealer(t, 2), "state", sealed},
		"a changed nonce":     {s, "state", flipped(0)},
		"a changed body":      {s, "state", flipped(len(raw) / 2)},
		"a changed tag":       {s, "state", flipped(len(raw) - 1)},
		"cut short":           {s, "state", sealed[:len(sealed)-4]},
		"empty":               {s, "state", ""},
		"not base64":          {s, "state", "%%%"},
		"too short to be one": {s, "state", "AAAA"},
		"too long":            {s, "state", strings.Repeat("A", MaxLen+1)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var got payload
			if err := c.sealer.Open(c.purpose, c.value, now, &got); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
}

func TestKeySize(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := New(make([]byte, n)); err == nil {
			t.Errorf("a %d-byte key was accepted", n)
		}
	}
}
