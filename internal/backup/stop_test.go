package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/ky-primitives/recoverykey"
)

// stalledRecovery is an upload that never completes on its own: like the real client's HTTP
// request, it returns only when its context ends.
type stalledRecovery struct {
	recoveryFixture
	once    sync.Once
	entered chan struct{}
}

func (f *stalledRecovery) Deposit(ctx context.Context, _, _ string, _ []byte) (recoveryclient.Receipt, error) {
	f.once.Do(func() { close(f.entered) })
	<-ctx.Done()
	return recoveryclient.Receipt{}, fmt.Errorf("%w: %w", recoveryclient.ErrRemote, ctx.Err())
}

// pairedFixture is fixture paired with KyRecovery on a daily schedule.
func pairedFixture(t *testing.T) (*Service, recoverykey.PrivateKey) {
	t.Helper()
	svc, key := fixture(t)
	svc.client = &recoveryFixture{t: t, key: key}
	if err := svc.Pair(context.Background(), "system", "test", "https://recovery.example", "123456"); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetSchedule("system", "test", 86400); err != nil {
		t.Fatal(err)
	}
	return svc, key
}

// stopDuring starts a run, calls Stop once started reports the moment has come, and returns
// the run's error. It fails the test if the run takes more than two seconds to stop.
func stopDuring(t *testing.T, svc *Service, started <-chan struct{}) error {
	t.Helper()
	result := make(chan error, 1)
	go func() {
		_, err := svc.Run(context.Background(), "system", "scheduler")
		result <- err
	}()
	select {
	case <-started:
	case err := <-result:
		t.Fatalf("the run ended before it could be interrupted: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the run never reached the step to interrupt")
	}
	svc.Stop()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("the run was still going two seconds after Stop")
		return nil
	}
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func lastRunAudit(t *testing.T, svc *Service) string {
	t.Helper()
	var outcome, reason string
	if err := svc.store.DB().QueryRow(`SELECT outcome,reason_code FROM audit_events WHERE event='admin.backup_run' ORDER BY at DESC,rowid DESC LIMIT 1`).Scan(&outcome, &reason); err != nil {
		t.Fatal(err)
	}
	return outcome + " " + reason
}

// Shutdown mid-upload: the run stops at once, is audited as stopping, records no receipt and
// is due again, so the next start delivers. The local copy was complete before the upload
// began; what the backup directory holds afterwards is a whole capsule, never a partial one.
func TestInterruptedRunIsDueAgain(t *testing.T) {
	svc, key := pairedFixture(t)
	stalled := &stalledRecovery{recoveryFixture: recoveryFixture{t: t, key: key}, entered: make(chan struct{})}
	svc.client = stalled

	err := stopDuring(t, svc, stalled.entered)
	if !errors.Is(err, ErrClosed) || ErrorCode(err) != "backup_stopping" {
		t.Fatalf("interrupted run returned %v (%s), want backup_stopping", err, ErrorCode(err))
	}
	if audit := lastRunAudit(t, svc); !strings.HasPrefix(audit, "failure ") || !strings.Contains(audit, "backup_stopping") {
		t.Errorf("interrupted run audited as %q", audit)
	}
	if _, ok, _ := recoveryclient.LastDeposit(settings{svc.store}); ok {
		t.Error("an interrupted upload recorded a receipt")
	}
	names := dirNames(t, svc.cfg.Backup.Dir)
	if len(names) != 1 {
		t.Fatalf("backup directory holds %v, want exactly the one local copy", names)
	}
	raw, _ := os.ReadFile(filepath.Join(svc.cfg.Backup.Dir, names[0]))
	if _, _, err := capsule.Open(raw, key, filepath.Join(t.TempDir(), "opened")); err != nil {
		t.Fatalf("the local copy left by an interrupted run does not open: %v", err)
	}
	if m, _ := filepath.Glob(filepath.Join(svc.cfg.DataDir, "snapshot-*")); len(m) > 0 {
		t.Errorf("the interrupted run left %v in the data directory", m)
	}
	// A stopping service starts nothing more, and Close does not wait.
	if _, err := svc.Run(context.Background(), "system", "scheduler"); !errors.Is(err, ErrClosed) {
		t.Errorf("a run after Stop returned %v, want ErrClosed", err)
	}
	closed := make(chan struct{})
	go func() { svc.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close was still blocked two seconds after Stop")
	}

	// The next start: the run is due and delivers.
	restarted := New(svc.cfg, svc.store, "test")
	restarted.client = &recoveryFixture{t: t, key: key}
	if due, err := restarted.Due(time.Now()); err != nil || !due {
		t.Fatalf("after the interruption due=%v err=%v: the next run would wait a whole interval", due, err)
	}
	if _, err := restarted.Run(context.Background(), "system", "scheduler"); err != nil {
		t.Fatalf("the run after the interruption failed: %v", err)
	}
	if _, ok, _ := recoveryclient.LastDeposit(settings{svc.store}); !ok {
		t.Fatal("the run after the interruption recorded no receipt")
	}
	if due, _ := restarted.Due(time.Now()); due {
		t.Fatal("a completed run did not stamp its attempt")
	}

	// Interrupted again, with an attempt on record: the earlier stamp comes back unchanged.
	if err := svc.store.SetSetting(lastAttemptKey, "2026-01-02T03:04:05Z"); err != nil {
		t.Fatal(err)
	}
	stalled = &stalledRecovery{recoveryFixture: recoveryFixture{t: t, key: key}, entered: make(chan struct{})}
	restarted.client = stalled
	if err := stopDuring(t, restarted, stalled.entered); !errors.Is(err, ErrClosed) {
		t.Fatalf("second interrupted run returned %v", err)
	}
	if after, _ := svc.store.GetSetting(lastAttemptKey); after != "2026-01-02T03:04:05Z" {
		t.Errorf("attempt stamp after an interrupted run is %q, want the one from before it", after)
	}
}

// Shutdown mid-snapshot: VACUUM INTO is interrupted, the scratch directory is removed, and
// nothing reaches the backup directory or KyRecovery.
func TestInterruptedSnapshotLeavesNothingBehind(t *testing.T) {
	svc, key := pairedFixture(t)
	remote := &recoveryFixture{t: t, key: key}
	svc.client = remote
	if _, err := svc.store.DB().Exec(`CREATE TABLE ballast (b BLOB)`); err != nil {
		t.Fatal(err)
	}
	for range 48 { // 48 MiB: large enough to interrupt mid-copy
		if _, err := svc.store.DB().Exec(`INSERT INTO ballast VALUES (randomblob(1048576))`); err != nil {
			t.Fatal(err)
		}
	}
	snapshotStarted := make(chan struct{})
	quit := make(chan struct{})
	defer close(quit)
	go func() {
		for {
			if m, _ := filepath.Glob(filepath.Join(svc.cfg.DataDir, "snapshot-*", "kynotes.sqlite")); len(m) > 0 {
				close(snapshotStarted)
				return
			}
			select {
			case <-quit:
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()
	if err := stopDuring(t, svc, snapshotStarted); !errors.Is(err, ErrClosed) {
		t.Fatalf("interrupted run returned %v, want ErrClosed", err)
	}
	if m, _ := filepath.Glob(filepath.Join(svc.cfg.DataDir, "snapshot-*")); len(m) > 0 {
		t.Errorf("the interrupted snapshot left %v in the data directory", m)
	}
	if names := dirNames(t, svc.cfg.Backup.Dir); len(names) > 0 {
		t.Errorf("the interrupted snapshot left %v in the backup directory", names)
	}
	if remote.raw != nil {
		t.Error("a capsule was uploaded from an interrupted snapshot")
	}
	if due, err := New(svc.cfg, svc.store, "test").Due(time.Now()); err != nil || !due {
		t.Errorf("after the interruption due=%v err=%v", due, err)
	}
}
