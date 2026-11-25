package app

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/Busnes-app/ky-primitives/suitedir"
	"github.com/Busnes-app/kynotes-server/internal/health"
	"github.com/Busnes-app/kynotes-server/internal/httpapi"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/orgsync"
	"github.com/Busnes-app/kynotes-server/internal/storage"
	"github.com/Busnes-app/kynotes-server/internal/webpush"
	"github.com/Busnes-app/kynotes-server/internal/worker"
)

// replicaSchedules is the application adapter, not another scheduler. The eventual multi
// startup binds gc to storage.RunObjectGC, purge to the org's blobstore.Objects.Purge and
// backup to backup.BackupPostgres with its object-storage destination.
// Until then config.Load refuses multi; the single-mode loops stay unchanged.
type replicaSchedules struct {
	db           *sql.DB
	orgs         *orgsync.Poller
	directory    suitedir.Client
	reports      *orgsync.Reporter
	push         *webpush.Sender
	gcInterval   time.Duration
	gc           func(context.Context, time.Time) error
	purge        storage.PurgeObjects
	backup       func(context.Context, time.Time) error
	log          *logging.Logger
	minute, gcAt time.Time
}

func runReplicaSchedules(ctx context.Context, s replicaSchedules) {
	worker.Run(ctx, s.db, time.Second, s.tick)
}

func (s *replicaSchedules) tick(owned context.Context, now time.Time) {
	run := func(label string, job func() error) {
		if owned.Err() != nil {
			return
		}
		if err := job(); err != nil && owned.Err() == nil {
			s.log.Error("replica_schedule_failed", "reason_code", label)
		}
	}
	if !now.Before(s.minute) {
		s.minute = now.Add(time.Minute) // count attempts, including failures
		run("org_poll", func() error { return s.orgs.Poll(owned) })
		run("erased_poll", func() error { return httpapi.PollErased(owned, s.db, s.directory) })
		run("restore_replay", func() error { return httpapi.FinishRestoreReplay(owned, s.db, s.directory) })
		run("org_purge", func() error { return storage.PurgeDeletedOrgs(owned, s.db, s.purge) })
		run("member_erase", func() error { return storage.EraseMembers(owned, s.db) })
		run("shared_state", func() error { return storage.SweepSharedState(owned, s.db) })
		run("reminders", func() error { return s.push.Fire(owned, s.db, now) })
		run("backup", func() error { return s.backup(owned, now) })
	}
	if !now.Before(s.gcAt) {
		s.gcAt = now.Add(s.gcInterval)
		run("gc", func() error { return s.gc(owned, now) })
	}
	// Byte growth/lower usage can need an immediate report, even between minute jobs.
	run("pool_report", func() error { return s.reports.Report(owned) })
}

const replicaProxyDrain = 5 * time.Second
const replicaRequestDrain = 5 * time.Second
const replicaWorkerDrain = 10 * time.Second

// drainReplica implements the replica pattern. stop cancels scheduled work and interrupts
// backups before the proxy convergence delay. Single mode does not use this entry point.
func drainReplica(ready *health.Checker, stop func(), done <-chan struct{}, server *http.Server) error {
	ready.SetReady(false)
	stop()
	timer := time.NewTimer(replicaProxyDrain)
	defer timer.Stop()
	<-timer.C
	ctx, cancel := context.WithTimeout(context.Background(), replicaRequestDrain)
	defer cancel()
	err := server.Shutdown(ctx)
	drain := time.NewTimer(replicaWorkerDrain)
	defer drain.Stop()
	select {
	case <-done:
		return err
	case <-drain.C:
		return errors.Join(err, errors.New("replicas: scheduled work did not drain"))
	}
}
