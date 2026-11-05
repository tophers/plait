package wg

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// RFC 7748 section 6.1 X25519 vector. `wg pubkey` performs the same scalar
// base-point multiplication, so it must produce this public key.
func TestPublicKeyRFC7748(t *testing.T) {
	privHex := "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	pubHex := "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	raw, _ := hex.DecodeString(privHex)
	priv, err := ParseKey(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(pub[:]); got != pubHex {
		t.Fatalf("public key = %s, want %s", got, pubHex)
	}
}

func TestGenerateClamped(t *testing.T) {
	k, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if k[0]&7 != 0 || k[31]&128 != 0 || k[31]&64 == 0 {
		t.Fatalf("key not clamped: %x", k)
	}
	if _, err := k.PublicKey(); err != nil {
		t.Fatal(err)
	}
}

func TestParseKeyRejects(t *testing.T) {
	for _, s := range []string{"", "short", base64.StdEncoding.EncodeToString(make([]byte, 31)), "not base64!!"} {
		if _, err := ParseKey(s); err == nil {
			t.Errorf("ParseKey(%q) succeeded", s)
		}
	}
	k, _ := GeneratePresharedKey()
	if back, err := ParseKey(k.String()); err != nil || !back.Equal(k) {
		t.Fatal("round trip failed")
	}
}
