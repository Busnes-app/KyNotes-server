package auth

import (
	"testing"
	"time"
)

func TestLockout(t *testing.T) {
	l := NewLockout(3, time.Minute, 10)
	now := time.Unix(0, 0)
	for i := 0; i < 3; i++ {
		if !l.Try("x", now) {
			t.Fatal("unexpected lock")
		}
		l.Fail("x", now)
	}
	if l.Try("x", now) {
		t.Fatal("lockout not enforced")
	}
	if l.Try("x", now.Add(30*time.Second)) {
		t.Fatal("cooldown not enforced")
	}
	if !l.Try("x", now.Add(2*time.Minute)) {
		t.Fatal("expired cooldown not reopened")
	}
	l.Success("x")
	if !l.Try("x", now) {
		t.Fatal("success did not clear")
	}
}

// One failure per invented username fills the table without locking anything; a fresh key still gets in.
func TestLockoutFloodOfCountsAdmitsFreshKey(t *testing.T) {
	l := NewLockout(3, time.Hour, 3)
	now := time.Unix(0, 0)
	for _, k := range []string{"a", "b", "c"} {
		l.Fail(k, now)
	}
	if !l.Try("fresh", now) {
		t.Fatal("full table of counts refused a fresh key")
	}
	for i := 0; i < 3; i++ {
		l.Fail("fresh", now)
	}
	if len(l.items) != 1 || l.Try("fresh", now) {
		t.Fatalf("fresh key not locked within the bound: %d entries", len(l.items))
	}
}

func TestLockoutDropsExpiredLocksWhenFull(t *testing.T) {
	l := NewLockout(1, time.Minute, 3)
	now := time.Unix(0, 0)
	later := now.Add(2 * time.Minute)
	l.Fail("expired1", now)
	l.Fail("expired2", now)
	l.Fail("live", later)
	l.Fail("new", later)
	if _, ok := l.items["expired1"]; ok {
		t.Fatal("expired lock kept")
	}
	if _, ok := l.items["expired2"]; ok {
		t.Fatal("expired lock kept")
	}
	if l.Try("live", later) || l.Try("new", later) {
		t.Fatal("live locks evicted")
	}
}
