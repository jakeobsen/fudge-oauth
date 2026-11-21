// Package seal turns small values into opaque strings that only this relay can
// read: AES-256-GCM with the relay's key, an expiry inside the ciphertext, and
// a purpose bound in as additional data, so one kind of sealed value can never
// pass for another.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// KeySize is the key's length in bytes.
const KeySize = 32

// MaxLen is the longest sealed string Open reads.
const MaxLen = 8192

var (
	// ErrInvalid means the value wasn't sealed by this key for this purpose, or was changed.
	ErrInvalid = errors.New("sealed value isn't valid")
	// ErrExpired means the value was valid but its time is up.
	ErrExpired = errors.New("sealed value has expired")
)

// Sealer seals and opens values with one key.
type Sealer struct {
	aead cipher.AEAD
}

// New returns a Sealer for a KeySize-byte key.
func New(key []byte) (*Sealer, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("the key must be %d bytes, not %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

type envelope struct {
	Expires int64           `json:"exp"`
	Value   json.RawMessage `json:"v"`
}

func additionalData(purpose string) []byte {
	return []byte("fudge-oauth/" + purpose)
}

// Seal encodes v as JSON and seals it for purpose until expires.
func (s *Sealer) Seal(purpose string, v any, expires time.Time) (string, error) {
	value, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	plain, err := json.Marshal(envelope{Expires: expires.Unix(), Value: value})
	if err != nil {
		return "", err
	}
	nonce := make([]byte, s.aead.NonceSize(), s.aead.NonceSize()+len(plain)+s.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := s.aead.Seal(nonce, nonce, plain, additionalData(purpose))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Open reads a value Seal made for purpose into v. It returns ErrInvalid or ErrExpired.
func (s *Sealer) Open(purpose, sealed string, now time.Time, v any) error {
	if sealed == "" || len(sealed) > MaxLen {
		return ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil || len(raw) < s.aead.NonceSize()+s.aead.Overhead() {
		return ErrInvalid
	}
	nonce, box := raw[:s.aead.NonceSize()], raw[s.aead.NonceSize():]
	plain, err := s.aead.Open(nil, nonce, box, additionalData(purpose))
	if err != nil {
		return ErrInvalid
	}
	var env envelope
	if err := json.Unmarshal(plain, &env); err != nil {
		return ErrInvalid
	}
	if !now.Before(time.Unix(env.Expires, 0)) {
		return ErrExpired
	}
	if err := json.Unmarshal(env.Value, v); err != nil {
		return ErrInvalid
	}
	return nil
}
