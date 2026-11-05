// Package secrets encrypts preshared keys and administrator TOTP secrets at
// rest with a key held outside SQLite. Encryption at rest does not protect against a compromised running
// controller.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"plait/internal/wg"
)

const keyLen = 32

var ErrUnknownKey = errors.New("ciphertext was encrypted with an unknown key")

// Sealer encrypts secrets with AES-256-GCM. Ciphertext layout is
// nonce||sealed. Associated data binds each ciphertext to its kind and row ID
// (link or administrator) so ciphertexts cannot be swapped between rows or
// kinds.
type Sealer struct {
	id   string
	aead cipher.AEAD
}

// NewSealer builds a Sealer from a 32-byte key. The key ID is derived from
// the key so a mismatched key file is detected rather than producing garbage.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != keyLen {
		return nil, fmt.Errorf("encryption key must be %d bytes", keyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append([]byte("plait-key-id-v1:"), key...))
	return &Sealer{id: hex.EncodeToString(sum[:8]), aead: aead}, nil
}

// LoadSealer reads a base64 key file, refusing files readable by group or
// other users.
func LoadSealer(path string) (*Sealer, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("encryption key file %s must not be accessible by group or others (mode %o)", path, fi.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("encryption key file %s: invalid base64", path)
	}
	return NewSealer(key)
}

// GenerateKeyFile writes a new random key, failing if the file exists.
func GenerateKeyFile(path string) error {
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(key) + "\n"); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (s *Sealer) KeyID() string { return s.id }

func pskAAD(linkID string) []byte { return []byte("plait-psk-v1:" + linkID) }

func totpAAD(adminID string) []byte { return []byte("plait-totp-v1:" + adminID) }

func (s *Sealer) seal(plain, aad []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize(), s.aead.NonceSize()+len(plain)+s.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plain, aad), nil
}

func (s *Sealer) open(what, keyID string, ciphertext, aad []byte) ([]byte, error) {
	if keyID != s.id {
		return nil, ErrUnknownKey
	}
	n := s.aead.NonceSize()
	if len(ciphertext) < n {
		return nil, fmt.Errorf("%s ciphertext too short", what)
	}
	plain, err := s.aead.Open(nil, ciphertext[:n], ciphertext[n:], aad)
	if err != nil {
		return nil, fmt.Errorf("%s ciphertext failed authentication", what)
	}
	return plain, nil
}

func (s *Sealer) SealPSK(linkID string, psk wg.Key) ([]byte, error) {
	return s.seal(psk[:], pskAAD(linkID))
}

func (s *Sealer) OpenPSK(linkID, keyID string, ciphertext []byte) (wg.Key, error) {
	var psk wg.Key
	plain, err := s.open("preshared key", keyID, ciphertext, pskAAD(linkID))
	if err != nil {
		return psk, err
	}
	if len(plain) != wg.KeyLen {
		return psk, errors.New("preshared key ciphertext failed authentication")
	}
	copy(psk[:], plain)
	return psk, nil
}

// SealTOTP encrypts an administrator's TOTP secret.
func (s *Sealer) SealTOTP(adminID string, secret []byte) ([]byte, error) {
	return s.seal(secret, totpAAD(adminID))
}

func (s *Sealer) OpenTOTP(adminID, keyID string, ciphertext []byte) ([]byte, error) {
	return s.open("TOTP secret", keyID, ciphertext, totpAAD(adminID))
}
