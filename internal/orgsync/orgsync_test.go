package orgsync

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/suitedir"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

type fakeDirectory struct {
	orgs  []suitedir.Org
	calls []int64
	err   error
}

func (f *fakeDirectory) list(_ context.Context, since int64) ([]suitedir.Org, int64, error) {
	f.calls = append(f.calls, since)
	if f.err != nil {
		return nil, 0, f.err
	}
	var out []suitedir.Org
	next := since
	for _, o := range f.orgs {
		if o.Revision > since {
			out = append(out, o)
			next = max(next, o.Revision)
		}
	}
	return out, next, nil
}

func open(t *testing.T) *storage.Store {
	t.Helper()
	s, err := storage.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func orgState(t *testing.T, s *storage.Store, id string) string {
	t.Helper()
	var status, region string
	var revision, enabled int64
	if err := s.DB().QueryRow(`SELECT status,revision,enabled,home_region FROM orgs WHERE id=?`, id).Scan(&status, &revision, &enabled, &region); err != nil {
		return "absent"
	}
	return status + "/" + region + "/" + map[int64]string{0: "off", 1: "on"}[enabled] + "/" + string(rune('0'+revision))
}

// The mirror follows KyIdentity's listing by revision, never backwards, from the stored cursor,
// and a failed poll changes nothing.
func TestPollMirrorsOrgsByRevision(t *testing.T) {
	s := open(t)
	dir := &fakeDirectory{orgs: []suitedir.Org{{ID: "org_a", Status: "active", Revision: 1, HomeRegion: "eu", Enabled: true}, {ID: "org_b", Status: "suspended", Revision: 2, HomeRegion: "eu"}}}
	p := New(s.DB(), dir.list)
	if err := p.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a, b := orgState(t, s, "org_a"), orgState(t, s, "org_b"); a != "active/eu/on/1" || b != "suspended/eu/off/2" {
		t.Fatalf("after the first poll: %s %s", a, b)
	}
	dir.orgs = append(dir.orgs, suitedir.Org{ID: "org_a", Status: "deletion_scheduled", Revision: 3, HomeRegion: "eu", Enabled: true})
	if err := p.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := orgState(t, s, "org_a"); got != "deletion_scheduled/eu/on/3" {
		t.Fatalf("after the change: %s", got)
	}
	if dir.calls[1] != 2 {
		t.Fatalf("the second poll asked since %d, want the stored cursor 2", dir.calls[1])
	}
	// A stale listing (an older revision) never moves an org back.
	dir.orgs = []suitedir.Org{{ID: "org_a", Status: "active", Revision: 4, HomeRegion: "eu", Enabled: true}}
	if _, err := s.DB().Exec(`UPDATE orgs SET revision=9 WHERE id='org_a'`); err != nil {
		t.Fatal(err)
	}
	if err := p.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := orgState(t, s, "org_a"); got != "deletion_scheduled/eu/on/9" {
		t.Fatalf("an older revision moved the mirror: %s", got)
	}
	dir.err = errors.New("unreachable")
	if err := p.Poll(context.Background()); err == nil {
		t.Fatal("a failed poll reported success")
	}
	if got := orgState(t, s, "org_b"); got != "suspended/eu/off/2" {
		t.Fatalf("a failed poll changed the mirror: %s", got)
	}
}

// Sign-in's wait: an unmirrored org triggers one poll, and an ID KyIdentity does not list
// triggers at most one poll every ten seconds.
func TestAwaitPollsOnceForAnUnknownOrg(t *testing.T) {
	s := open(t)
	dir := &fakeDirectory{orgs: []suitedir.Org{{ID: "org_new", Status: "active", Revision: 1, HomeRegion: "eu", Enabled: true}}}
	p := New(s.DB(), dir.list)
	clock := time.Unix(1_800_000_000, 0)
	p.now = func() time.Time { return clock }
	if ok, err := p.Await(context.Background(), "org_new"); err != nil || !ok {
		t.Fatalf("listed org: %v %v", ok, err)
	}
	if ok, _ := p.Await(context.Background(), "org_new"); !ok || len(dir.calls) != 1 {
		t.Fatalf("a mirrored org polled again: %d polls", len(dir.calls))
	}
	for range 3 {
		if ok, err := p.Await(context.Background(), "org_forged"); ok || err != nil {
			t.Fatalf("unlisted org: %v %v", ok, err)
		}
	}
	if len(dir.calls) != 2 {
		t.Fatalf("an unknown org polled %d times in ten seconds, want once", len(dir.calls)-1)
	}
	clock = clock.Add(11 * time.Second)
	_, _ = p.Await(context.Background(), "org_forged")
	if len(dir.calls) != 3 {
		t.Fatalf("after ten seconds: %d polls, want 3", len(dir.calls))
	}
}

// A sign-in's wait ends at its own deadline even while another poll holds the slot.
func TestAwaitGivesUpAtItsDeadlineBehindASlowPoll(t *testing.T) {
	s := open(t)
	release := make(chan struct{})
	started := make(chan struct{})
	p := New(s.DB(), func(ctx context.Context, since int64) ([]suitedir.Org, int64, error) {
		close(started)
		<-release
		return nil, since, nil
	})
	done := make(chan error, 1)
	go func() { done <- p.Poll(context.Background()) }()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	begun := time.Now()
	ok, err := p.Await(ctx, "org_new")
	if ok || err != nil || time.Since(begun) > time.Second {
		t.Fatalf("Await behind a held poll: %v %v after %s", ok, err, time.Since(begun))
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
