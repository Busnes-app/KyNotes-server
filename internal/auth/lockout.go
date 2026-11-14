package auth

import (
	"sync"
	"time"
)

type lockEntry struct {
	Failures    int
	LockedUntil time.Time
}
type Lockout struct {
	mu         sync.Mutex
	items      map[string]lockEntry
	max, limit int
	cooldown   time.Duration
}

func NewLockout(limit int, cooldown time.Duration, max int) *Lockout {
	return &Lockout{items: make(map[string]lockEntry), limit: limit, cooldown: cooldown, max: max}
}
func (l *Lockout) Try(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.items[key]
	if now.Before(e.LockedUntil) {
		return false
	}
	if e.LockedUntil.IsZero() && e.Failures >= l.limit {
		e.LockedUntil = now.Add(l.cooldown)
		l.items[key] = e
		return false
	}
	if e.Failures >= l.limit {
		delete(l.items, key)
		return true
	}
	return l.room(key, now)
}
func (l *Lockout) Fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.room(key, now) {
		return
	}
	e := l.items[key]
	e.Failures++
	if e.Failures >= l.limit {
		e.LockedUntil = now.Add(l.cooldown)
	}
	l.items[key] = e
}

// Reserve is Try and Fail in one step: it counts this attempt as a failure before the caller
// verifies anything, so concurrent guesses cannot all pass a check none of them has recorded
// yet. The caller hands the reservation back with Success (verified) or Release (the attempt
// never reached a verdict, such as an internal error).
func (l *Lockout) Reserve(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.items[key]
	if now.Before(e.LockedUntil) {
		return false
	}
	if e.LockedUntil.IsZero() && e.Failures >= l.limit {
		e.LockedUntil = now.Add(l.cooldown)
		l.items[key] = e
		return false
	}
	if e.Failures >= l.limit {
		delete(l.items, key)
		e = lockEntry{}
	}
	if !l.room(key, now) {
		return false
	}
	e.Failures++
	if e.Failures >= l.limit {
		e.LockedUntil = now.Add(l.cooldown)
	}
	l.items[key] = e
	return true
}

// Release hands back one Reserve that reached no verdict, lifting the lock it may have set.
func (l *Lockout) Release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.items[key]
	if !ok {
		return
	}
	if e.Failures--; e.Failures <= 0 {
		delete(l.items, key)
		return
	}
	if e.Failures < l.limit {
		e.LockedUntil = time.Time{}
	}
	l.items[key] = e
}

func (l *Lockout) Success(key string) { l.mu.Lock(); delete(l.items, key); l.mu.Unlock() }

// room reports whether key fits. A full table first drops every entry that is not a live lock;
// live locks are never evicted (that would be a bypass), so only a table of live locks sheds the key.
func (l *Lockout) room(key string, now time.Time) bool {
	if _, ok := l.items[key]; ok || len(l.items) < l.max {
		return true
	}
	for k, e := range l.items {
		if !now.Before(e.LockedUntil) {
			delete(l.items, k)
		}
	}
	return len(l.items) < l.max
}
