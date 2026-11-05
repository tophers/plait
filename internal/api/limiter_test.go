package api

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLoginLimiterHoldsOnlyRecentFailures(t *testing.T) {
	l := NewLoginLimiter()
	ip := "ip:192.0.2.1"
	for range loginMaxFailures {
		l.Attempt("user:admin", ip)
	}
	// A blocked client spraying distinct names adds nothing.
	for i := range 100 {
		if _, ok := l.Attempt(fmt.Sprintf("user:%s%d", strings.Repeat("A", 1000), i), ip); ok {
			t.Fatal("blocked address allowed")
		}
	}
	if len(l.failures) != 2 {
		t.Fatalf("limiter holds %d keys, want 2", len(l.failures))
	}
	// Expired failures release the block and their keys.
	for k, ts := range l.failures {
		for i := range ts {
			ts[i] = ts[i].Add(-loginWindow - time.Second)
		}
		l.failures[k] = ts
	}
	if _, ok := l.Attempt("user:other", "ip:198.51.100.1"); !ok {
		t.Fatal("fresh keys blocked")
	}
	if _, ok := l.Attempt("user:admin", ip); !ok {
		t.Fatalf("expired failures still block: %v", l.failures)
	}
	if len(l.failures) != 4 {
		t.Fatalf("limiter holds %d keys, want 4", len(l.failures))
	}
}

// Attempts count before they finish, so a burst cannot all pass the check
// while earlier attempts are still waiting to hash.
func TestLoginLimiterCountsInFlightAttempts(t *testing.T) {
	l := NewLoginLimiter()
	keys := []string{"user:admin", "ip:192.0.2.1"}
	var started []time.Time
	for range loginMaxFailures {
		at, ok := l.Attempt(keys...)
		if !ok {
			t.Fatal("blocked before the limit")
		}
		started = append(started, at)
	}
	if _, ok := l.Attempt(keys...); ok {
		t.Fatal("in-flight attempts did not count")
	}
	l.Withdraw(started[0], keys...)
	if _, ok := l.Attempt(keys...); !ok {
		t.Fatal("withdrawn attempt still counted")
	}
	for _, at := range started[1:] {
		l.Withdraw(at, keys...)
	}
	if n := len(l.failures["ip:192.0.2.1"]); n != 1 {
		t.Fatalf("%d entries after withdrawing, want 1", n)
	}
}

func TestLoginLimiterSweepsExpiredKeys(t *testing.T) {
	l := NewLoginLimiter()
	old := time.Now().Add(-loginWindow - time.Second)
	for i := range minLoginSweep - 1 {
		l.failures[fmt.Sprintf("ip:%d", i)] = []time.Time{old}
	}
	l.Attempt("ip:new")
	if len(l.failures) != 1 {
		t.Fatalf("sweep left %d keys, want 1", len(l.failures))
	}
}

func TestLoginKeys(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "192.0.2.1:4242"
	if u, ip := LoginKeys("admin", r); u != "user:admin" || ip != "ip:192.0.2.1" {
		t.Fatalf("keys = %q %q", u, ip)
	}
	for addr, want := range map[string]string{
		"[2001:db8:1:2:aaaa::1]:4242": "ip:2001:db8:1:2::/64",
		"[2001:db8:1:2:bbbb::9]:4242": "ip:2001:db8:1:2::/64",
		"[fe80::1%eth0]:4242":         "ip:fe80::/64",
		"[::ffff:192.0.2.7]:4242":     "ip:192.0.2.7",
		"203.0.113.5:1":               "ip:203.0.113.5",
	} {
		r.RemoteAddr = addr
		if _, ip := LoginKeys("admin", r); ip != want {
			t.Errorf("%s keyed as %q, want %q", addr, ip, want)
		}
	}
	for _, bad := range []string{strings.Repeat("A", 65), "a\nb", ""} {
		if u, _ := LoginKeys(bad, r); u != "user:" {
			t.Errorf("%q keyed as %q", bad, u)
		}
	}
}
