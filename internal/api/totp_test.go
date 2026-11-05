package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func totpCode(t *testing.T, b32 string, at time.Time) string {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(b32)
	if err != nil {
		t.Fatal(err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1000000)
}

func TestLoginRequiresTOTPCodeOnceEnabled(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	setup, err := e.svc.BeginTOTP(ctx, "admin", adminPassword)
	if err != nil {
		t.Fatal(err)
	}
	_, sess, err := e.svc.Login(ctx, "admin", adminPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ConfirmTOTP(ctx, sess, totpCode(t, setup.Secret, e.now())); err != nil {
		t.Fatal(err)
	}
	login := func(code string) int {
		resp := e.raw("POST", "/api/v1/admin/login", map[string]string{"username": "admin", "password": adminPassword, "code": code}, nil)
		resp.Body.Close()
		return resp.StatusCode
	}
	if s := login(""); s != http.StatusUnauthorized {
		t.Fatalf("without code: %d", s)
	}
	e.advance(30 * time.Second)
	if s := login(totpCode(t, setup.Secret, e.now())); s != http.StatusOK {
		t.Fatalf("with code: %d", s)
	}
	if s := login(totpCode(t, setup.Secret, e.now())); s != http.StatusUnauthorized {
		t.Fatalf("code reused: %d", s)
	}
}
