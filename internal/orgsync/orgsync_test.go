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

// A poll that stops an org deletes its sessions with the change and audits it once; a later
// listing of the same state changes nothing more.
func TestPollEndsTheSessionsOfAnOrgThatStops(t *testing.T) {
	s := open(t)
	for _, q := range []string{
		`UPDATE server_settings SET value='multi' WHERE key='tenancy_mode'`,
		`INSERT INTO server_settings(key,value,updated_at) VALUES('region','eu','t'),('cell:eu','','t'),('staff_org_id','org_staff','t')`,
		`INSERT INTO orgs(id,status,revision,home_region) VALUES('org_a','active',1,'eu')`,
		`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at,org_id) VALUES('usr_a','a','x','x',1,'t','t','org_a')`,
		`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,created_at,expires_at,hard_expires_at) VALUES('ses_a','usr_a','h','c','t','2099-01-01T00:00:00Z','2099-01-01T00:00:00Z')`,
	} {
		if _, err := s.DB().Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	dir := &fakeDirectory{orgs: []suitedir.Org{{ID: "org_a", Status: "suspended", Revision: 2, HomeRegion: "eu", Enabled: true}}}
	p := New(s.DB(), dir.list)
	count := func(q string) int {
		var n int
		if err := s.DB().QueryRow(q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for range 2 {
		if _, err := s.DB().Exec(`DELETE FROM server_settings WHERE key='org_poll_revision'`); err != nil {
			t.Fatal(err)
		}
		if err := p.Poll(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n := count(`SELECT count(*) FROM sessions WHERE user_id='usr_a'`); n != 0 {
		t.Fatalf("%d sessions survived the suspension", n)
	}
	if n := count(`SELECT count(*) FROM audit_events WHERE event='org.sessions_ended' AND object_id='org_a' AND reason_code='status=suspended,sessions=1' AND org_id IS NULL`); n != 1 {
		t.Fatalf("%d audit rows for the suspension, want exactly 1 platform row", n)
	}
}

// deletion_scheduled keeps the org's export_only sessions and ends the rest.
func TestPollKeepsExportOnlySessionsForDeletion(t *testing.T) {
	s := open(t)
	for _, q := range []string{
		`UPDATE server_settings SET value='multi' WHERE key='tenancy_mode'`,
		`INSERT INTO server_settings(key,value,updated_at) VALUES('region','eu','t'),('cell:eu','','t'),('staff_org_id','org_staff','t')`,
		`INSERT INTO orgs(id,status,revision,home_region) VALUES('org_a','active',1,'eu')`,
		`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at,org_id) VALUES('usr_a','a','x','x',1,'t','t','org_a')`,
		`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,created_at,expires_at,hard_expires_at,export_only) VALUES('ses_plain','usr_a','h1','c','t','2099-01-01T00:00:00Z','2099-01-01T00:00:00Z',0),('ses_export','usr_a','h2','c','t','2099-01-01T00:00:00Z','2099-01-01T00:00:00Z',1)`,
	} {
		if _, err := s.DB().Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	dir := &fakeDirectory{orgs: []suitedir.Org{{ID: "org_a", Status: "deletion_scheduled", Revision: 2, HomeRegion: "eu", Enabled: true}}}
	if err := New(s.DB(), dir.list).Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	var left string
	if err := s.DB().QueryRow(`SELECT COALESCE(MAX(id),'') FROM sessions WHERE user_id='usr_a'`).Scan(&left); err != nil || left != "ses_export" {
		t.Fatalf("sessions left: %q %v, want only ses_export", left, err)
	}
}

// C4, no moves: a listing that puts a serving org in a cell this deployment does not serve
// stops it here, and its sessions end as for a suspension.
func TestPollEndsTheSessionsOfAnOrgMovedToAnotherCell(t *testing.T) {
	s := open(t)
	for _, q := range []string{
		`UPDATE server_settings SET value='multi' WHERE key='tenancy_mode'`,
		`INSERT INTO server_settings(key,value,updated_at) VALUES('region','eu','t'),('cell:eu','','t'),('staff_org_id','org_staff','t')`,
		`INSERT INTO orgs(id,status,revision,home_region) VALUES('org_a','active',1,'eu')`,
		`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at,org_id) VALUES('usr_a','a','x','x',1,'t','t','org_a')`,
		`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,created_at,expires_at,hard_expires_at) VALUES('ses_a','usr_a','h','c','t','2099-01-01T00:00:00Z','2099-01-01T00:00:00Z')`,
	} {
		if _, err := s.DB().Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	dir := &fakeDirectory{orgs: []suitedir.Org{{ID: "org_a", Status: "active", Revision: 2, HomeRegion: "us-east-2", Enabled: true}}}
	if err := New(s.DB(), dir.list).Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.DB().QueryRow(`SELECT count(*) FROM sessions WHERE user_id='usr_a'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d sessions survived the move to another cell (%v)", n, err)
	}
}

// C4, no moves: a listing that moves an org between two served cells keeps its home_region (its
// objects' cell), stops it with an audited refusal, and serves it again once the move is undone.
func TestPollRefusesToMoveAnOrgBetweenServedCells(t *testing.T) {
	s := open(t)
	for _, q := range []string{
		`UPDATE server_settings SET value='multi' WHERE key='tenancy_mode'`,
		`INSERT INTO server_settings(key,value,updated_at) VALUES('region','eu','t'),('cell:eu','','t'),('cell:us-east-2','','t'),('staff_org_id','org_staff','t')`,
		`INSERT INTO orgs(id,status,revision,enabled,home_region) VALUES('org_a','active',1,1,'eu')`,
		`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at,org_id) VALUES('usr_a','a','x','x',1,'t','t','org_a')`,
		`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,created_at,expires_at,hard_expires_at) VALUES('ses_a','usr_a','h','c','t','2099-01-01T00:00:00Z','2099-01-01T00:00:00Z')`,
	} {
		if _, err := s.DB().Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	dir := &fakeDirectory{orgs: []suitedir.Org{{ID: "org_a", Status: "active", Revision: 2, HomeRegion: "us-east-2", Enabled: true}}}
	p := New(s.DB(), dir.list)
	if err := p.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	count := func(q string) int {
		var n int
		if err := s.DB().QueryRow(q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if got := orgState(t, s, "org_a"); got != "active/eu/off/2" {
		t.Fatalf("after the move: %s, want the org kept in eu and stopped", got)
	}
	if n := count(`SELECT count(*) FROM sessions WHERE user_id='usr_a'`); n != 0 {
		t.Fatalf("%d sessions survived the move", n)
	}
	if n := count(`SELECT count(*) FROM audit_events WHERE event='org.cell_move_refused' AND object_id='org_a' AND outcome='denied' AND reason_code='from=eu,to=us-east-2'`); n != 1 {
		t.Fatalf("%d refusal audit rows, want 1", n)
	}
	dir.orgs = []suitedir.Org{{ID: "org_a", Status: "active", Revision: 3, HomeRegion: "eu", Enabled: true}}
	if err := p.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := orgState(t, s, "org_a"); got != "active/eu/on/3" {
		t.Fatalf("after the move was undone: %s", got)
	}
}
