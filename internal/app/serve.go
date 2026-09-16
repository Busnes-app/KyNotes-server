package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/backup"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/health"
	"github.com/Busnes-app/kynotes-server/internal/httpapi"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

func Serve(ctx context.Context, c config.Config, log *logging.Logger) error {
	if err := config.Validate(c); err != nil {
		return err
	}
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
	blobs, err := blobstore.New(c.DataDir)
	if err != nil {
		return err
	}
	backups := backup.New(c, store, "dev")
	defer backups.Close()
	workerCtx, stopWorker := context.WithCancel(ctx)
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); runBackupLoop(workerCtx, backups, log) }()
	defer func() { stopWorker(); <-workerDone }()
	if c.Backup.AllowPrivateRecovery {
		log.Info("backup_private_recovery_enabled", "outcome", "enabled")
	}
	go runGC(ctx, store.DB(), blobs, c)
	h := &health.Checker{Ready: true}
	srv := &http.Server{Addr: c.Server.Bind, Handler: httpapi.NewRouter(log, c.Server.MaxRequestBytes, h.IsReady, store.DB(), blobs, c, backups), ReadHeaderTimeout: parse(c.Server.ReadHeaderTimeout), ReadTimeout: parse(c.Server.ReadTimeout), WriteTimeout: parse(c.Server.WriteTimeout), IdleTimeout: parse(c.Server.IdleTimeout)}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
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

func runGC(ctx context.Context, db *sql.DB, blobs *blobstore.Store, c config.Config) {
	ticker := time.NewTicker(parse(c.GC.Interval))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			_, _ = storage.RunGC(db, blobs, now, time.Duration(parse(c.GC.Retention)), c.GC.Enabled)
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
