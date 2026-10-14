package auth

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestDeviceLockoutRequiresResolvableDeviceID(t *testing.T) {
	key := "device-test-lockout"
	l := NewLockout(10, 15*time.Minute, 100)
	now := time.Now().UTC()
	for i := 0; i < 10; i++ {
		if !l.Try(key, now) {
			t.Fatalf("attempt %d unexpectedly blocked", i)
		}
		l.Fail(key, now)
	}
	if l.Try(key, now) {
		t.Fatal("locked device was accepted")
	}
}

func TestDeviceLockoutIPv6Uses64BitKey(t *testing.T) {
	r1 := httptest.NewRequest("GET", "/", nil)
	r1.RemoteAddr = "[2001:db8:1:2:1111:2222:3333:4444]:1234"
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "[2001:db8:1:2:aaaa:bbbb:cccc:dddd]:4321"
	if ClientIP(r1) != ClientIP(r2) {
		t.Fatalf("IPv6 addresses were not folded to /64: %q != %q", ClientIP(r1), ClientIP(r2))
	}
}
