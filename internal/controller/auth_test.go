package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fillArgonSlots occupies every hashing slot until the test ends.
func fillArgonSlots(t *testing.T) {
	t.Helper()
	for range cap(argonSlots) {
		argonSlots <- struct{}{}
	}
	t.Cleanup(func() {
		for range cap(argonSlots) {
			<-argonSlots
		}
	})
}

func TestArgonSlotsBoundConcurrentHashing(t *testing.T) {
	svc, _ := newService(t, "10.0.0.0/24")
	ctx := context.Background()
	if err := svc.CreateAdmin(ctx, "admin", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	fillArgonSlots(t)
	old := argonWait
	argonWait = 20 * time.Millisecond
	t.Cleanup(func() { argonWait = old })

	for _, user := range []string{"admin", "nobody"} {
		if _, _, err := svc.Login(ctx, user, "correct horse battery", ""); !errors.Is(err, ErrBusy) {
			t.Fatalf("login as %s with slots full: %v, want ErrBusy", user, err)
		}
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := svc.Login(cctx, "admin", "correct horse battery", ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled login: %v", err)
	}
	// Oversized passwords fail without waiting for a slot.
	if _, _, err := svc.Login(ctx, "admin", strings.Repeat("x", maxPasswordLen+1), ""); !errors.Is(err, ErrBadLogin) {
		t.Fatalf("oversized password: %v, want ErrBadLogin", err)
	}
}

func TestPasswordLengthBounds(t *testing.T) {
	if validatePassword(strings.Repeat("x", maxPasswordLen)) != nil {
		t.Fatal("maximum-length password rejected")
	}
	if validatePassword(strings.Repeat("x", maxPasswordLen+1)) == nil {
		t.Fatal("oversized password accepted")
	}
}
