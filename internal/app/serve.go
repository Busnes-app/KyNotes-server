package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/backup"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/health"
	"github.com/Busnes-app/kynotes-server/internal/httpapi"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/sso"
	"github.com/Busnes-app/kynotes-server/internal/storage"
	"github.com/Busnes-app/kynotes-server/internal/webpush"
)

func Serve(ctx context.Context, c config.Config, log *logging.Logger, version string) error {
	if err := config.Validate(c); err != nil {
		return err
	}
	auth.SetCSRFKey(c.Secrets.PairingSecret)
	unlock, err := storage.LockDirectory(c.DataDir)
	if err != nil {
		return err
	}
	defer unlock()

	store, err := storage.Open(filepath.Join(c.DataDir, "kynotes.sqlite"))
	if err != nil {
		return err
	}
	defer store.Close()
	if err := EnsureBootstrapAdmin(store.DB(), c); err != nil {
		return fmt.Errorf("bootstrap admin failed: %w", err)
	}
	WarnWithoutAdmin(store.DB(), log)
	blobs, err := blobstore.New(c.DataDir)
	if err != nil {
		return err
	}
	backups := backup.New(c, store, version)
	defer backups.Close()
	workerCtx, stopWorker := context.WithCancel(ctx)
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); runBackupLoop(workerCtx, backups, log) }()
	defer func() { stopWorker(); <-workerDone }()
	ssoStore := sso.NewStore(store.DB())
	adminLn, err := listenAdminSocket(c.DataDir)
	if err != nil {
		return err
	}
	setup := httpapi.SetupHandler(httpapi.SetupDeps{DB: store.DB(), Config: c, SSO: ssoStore, Backups: backups, Version: version, Log: log})
	admin := &http.Server{Handler: setup, ReadHeaderTimeout: parse(c.Server.ReadHeaderTimeout)}
	go func() {
		if err := admin.Serve(adminLn); !errors.Is(err, http.ErrServerClosed) {
			log.Error("admin_socket_failed", "reason_code", "serve_error")
		}
	}()
	// Runs before the backup and store defers: SQLite must outlive a running apply.
	defer func() {
		sh, cancel := context.WithTimeout(context.Background(), parse(c.Server.ShutdownGrace))
		defer cancel()
		_ = admin.Shutdown(sh)
		drain, cancelDrain := context.WithTimeout(context.Background(), backup.OperationTimeout+time.Minute)
		defer cancelDrain()
		if !setup.Drain(drain) {
			log.Error("apply_setup_drain_cut_off", "reason_code", "timeout")
		}
		_ = os.Remove(AdminSocketPath(c.DataDir))
	}()
	if c.Backup.AllowPrivateRecovery {
		log.Info("backup_private_recovery_enabled", "outcome", "enabled")
	}
	gcCtx, stopGC := context.WithCancel(ctx)
	gcDone := make(chan struct{})
	go func() { defer close(gcDone); runGC(gcCtx, store.DB(), blobs, c) }()
	// A GC pass cannot be cancelled; give it the shutdown grace before SQLite closes.
	defer func() {
		stopGC()
		select {
		case <-gcDone:
		case <-time.After(parse(c.Server.ShutdownGrace)):
			log.Error("gc_drain_cut_off", "reason_code", "timeout")
		}
	}()
	vapid, err := webpush.LoadKey(c.DataDir)
	if err != nil {
		return fmt.Errorf("secrets/vapid.key: %w", err)
	}
	push, err := webpush.New(vapid)
	if err != nil {
		return err
	}
	pushCtx, stopPush := context.WithCancel(ctx)
	pushDone := make(chan struct{})
	go func() { defer close(pushDone); runReminderPush(pushCtx, store.DB(), push, log) }()
	// Cancelling aborts in-flight pushes (unsent reminders stay for the next start); SQLite outlives the pass.
	defer func() {
		stopPush()
		select {
		case <-pushDone:
		case <-time.After(parse(c.Server.ShutdownGrace)):
			log.Error("reminder_push_drain_cut_off", "reason_code", "timeout")
		}
	}()
	h := &health.Checker{}
	h.SetReady(true)
	srv := &http.Server{Addr: c.Server.Bind, Handler: httpapi.NewRouter(log, c.Server.MaxRequestBytes, h.IsReady, store.DB(), blobs, c, backups, ssoStore, push), ReadHeaderTimeout: parse(c.Server.ReadHeaderTimeout), ReadTimeout: parse(c.Server.ReadTimeout), WriteTimeout: parse(c.Server.WriteTimeout), IdleTimeout: parse(c.Server.IdleTimeout)}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		h.SetReady(false)
		sh, cancel := context.WithTimeout(context.Background(), parse(c.Server.ShutdownGrace))
		defer cancel()
		return srv.Shutdown(sh)
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

var gcPass = storage.RunGC

func runGC(ctx context.Context, db *sql.DB, blobs *blobstore.Store, c config.Config) {
	ticker := time.NewTicker(parse(c.GC.Interval))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			_, _ = gcPass(db, blobs, now, time.Duration(parse(c.GC.Retention)), c.GC.Enabled)
		}
	}
}

// runReminderPush fires due reminders once a minute.
func runReminderPush(ctx context.Context, db *sql.DB, push *webpush.Sender, log *logging.Logger) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			if err := push.Fire(ctx, db, now); err != nil && ctx.Err() == nil {
				log.Error("reminder_push_failed", "reason_code", "fire_error")
			}
		}
	}
}

func parse(s string) time.Duration { d, _ := time.ParseDuration(s); return d }

func runBackupLoop(ctx context.Context, service *backup.Service, log *logging.Logger) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		due, err := service.Due(time.Now())
		if err != nil {
			log.Error("backup_schedule_failed", "reason_code", backup.ErrorCode(err))
		}
		if due {
			operation, cancel := context.WithTimeout(context.WithoutCancel(ctx), backup.OperationTimeout)
			_, err := service.Run(operation, "system", "scheduler")
			cancel()
			if err != nil {
				log.Error("backup_run_failed", "reason_code", backup.ErrorCode(err))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
