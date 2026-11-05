package secrets

import (
	"os"
	"path/filepath"
	"testing"

	"plait/internal/wg"
)

func TestSealRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := GenerateKeyFile(path); err != nil {
		t.Fatal(err)
	}
	s, err := LoadSealer(path)
	if err != nil {
		t.Fatal(err)
	}
	psk, _ := wg.GeneratePresharedKey()
	ct, err := s.SealPSK("link-a", psk)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.OpenPSK("link-a", s.KeyID(), ct)
	if err != nil || !got.Equal(psk) {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := s.OpenPSK("link-b", s.KeyID(), ct); err == nil {
		t.Fatal("ciphertext accepted for a different link")
	}
	ct[len(ct)-1] ^= 1
	if _, err := s.OpenPSK("link-a", s.KeyID(), ct); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	other, _ := NewSealer(make([]byte, 32))
	if _, err := other.OpenPSK("link-a", s.KeyID(), ct); err != ErrUnknownKey {
		t.Fatalf("err = %v, want ErrUnknownKey", err)
	}
}

func TestLoadSealerRejectsLoosePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := GenerateKeyFile(path); err != nil {
		t.Fatal(err)
	}
	os.Chmod(path, 0o644)
	if _, err := LoadSealer(path); err == nil {
		t.Fatal("world-readable key accepted")
	}
	if err := GenerateKeyFile(path); err == nil {
		t.Fatal("existing key file overwritten")
	}
}

func TestSealTOTPBindsAdminAndKind(t *testing.T) {
	s, _ := NewSealer(make([]byte, 32))
	secret := []byte("12345678901234567890")
	ct, err := s.SealTOTP("admin-a", secret)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.OpenTOTP("admin-a", s.KeyID(), ct)
	if err != nil || string(got) != string(secret) {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := s.OpenTOTP("admin-b", s.KeyID(), ct); err == nil {
		t.Fatal("ciphertext accepted for a different administrator")
	}
	// A PSK ciphertext for a link with the same ID is not a TOTP secret.
	psk, _ := wg.GeneratePresharedKey()
	pct, _ := s.SealPSK("admin-a", psk)
	if _, err := s.OpenTOTP("admin-a", s.KeyID(), pct); err == nil {
		t.Fatal("PSK ciphertext opened as a TOTP secret")
	}
}
