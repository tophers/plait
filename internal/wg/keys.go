// Package wg holds WireGuard key types shared by the controller, agent, and CLI.
package wg

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

// KeyLen is the length of WireGuard private, public, and preshared keys.
const KeyLen = 32

// Key is a 32-byte WireGuard key. Its String form is standard base64, the
// same encoding used by wg(8) and configuration files.
type Key [KeyLen]byte

var ErrInvalidKey = errors.New("invalid WireGuard key")

// ParseKey decodes a base64 WireGuard key.
func ParseKey(s string) (Key, error) {
	var k Key
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != KeyLen {
		return k, ErrInvalidKey
	}
	copy(k[:], b)
	return k, nil
}

func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

func (k Key) IsZero() bool {
	var zero Key
	return subtle.ConstantTimeCompare(k[:], zero[:]) == 1
}

// Equal compares keys in constant time.
func (k Key) Equal(o Key) bool { return subtle.ConstantTimeCompare(k[:], o[:]) == 1 }

func (k Key) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

func (k *Key) UnmarshalText(b []byte) error {
	parsed, err := ParseKey(string(b))
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}

// GeneratePrivateKey returns a clamped Curve25519 private key, matching
// `wg genkey`.
func GeneratePrivateKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return k, fmt.Errorf("generate private key: %w", err)
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return k, nil
}

// GeneratePresharedKey returns 32 random bytes, matching `wg genpsk`.
func GeneratePresharedKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return k, fmt.Errorf("generate preshared key: %w", err)
	}
	return k, nil
}

// PublicKey derives the public key for a private key, matching `wg pubkey`.
func (k Key) PublicKey() (Key, error) {
	var pub Key
	priv, err := ecdh.X25519().NewPrivateKey(k[:])
	if err != nil {
		return pub, ErrInvalidKey
	}
	copy(pub[:], priv.PublicKey().Bytes())
	return pub, nil
}
