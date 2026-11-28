package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"time"

	shareds3 "github.com/Busnes-app/ky-primitives/s3"
	"github.com/Busnes-app/ky-primitives/suitedir"
	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/backup"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/health"
	"github.com/Busnes-app/kynotes-server/internal/httpapi"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/orgsync"
	"github.com/Busnes-app/kynotes-server/internal/sso"
	"github.com/Busnes-app/kynotes-server/internal/storage"
	"github.com/Busnes-app/kynotes-server/internal/webpush"
)

func serveReplica(ctx context.Context, c config.Config, log *logging.Logger) error {
	c, in, err := readReplicaInputs(c)
	if err != nil {
		return err
	}
	if c.Backup.BlobTarget.URL != "" || c.Backup.Dir != "" {
		return errors.New("replicas: single-mode offsite mirror and local capsule directory are not supported")
	}
	client, err := newReplicaObjectClient(in)
	if err != nil {
		return err
	}
	// Validate the native archive schedule before changing any database binding.
	backupRun, _, err := replicaBackup(c, in, client)
	if err != nil {
		return err
	}
	store, err := storage.OpenPostgresReplica(ctx, in.DSN, in.Tenancy, in.Cells)
	if err != nil {
		return errors.New("replicas: PostgreSQL open or immutable tenancy binding failed")
	}
	defer store.Close()
	if in.Tenancy, err = storage.TenancyOfContext(ctx, store.DB()); err != nil {
		return err
	}
	fields := replicaFields(c, in)
	if err := storage.VerifyReplicaConfig(ctx, store.DB(), c.Secrets.ServerSaltKey, fields); err != nil {
		return err
	}
	// Only a start whose KY_CELLS every replica shares (the fingerprint) replaces the served cells.
	if err := storage.SetServedCells(ctx, store.DB(), in.Cells); err != nil {
		return err
	}
	// Identity I/O is deliberately after the fingerprint transaction has committed.
	if err := blobstore.VerifySharedIdentity(ctx, store.DB(), func(ctx context.Context, name string) ([]byte, error) {
		body, meta, err := client.Get(ctx, "control/"+name, "")
		if err != nil {
			return nil, err
		}
		defer body.Close()
		if meta.Size != 43 {
			return nil, blobstore.ErrStoreIdentity
		}
		return io.ReadAll(io.LimitReader(body, 44))
	}, func(ctx context.Context, name string, raw []byte) error {
		_, err := client.PutIfAbsent(ctx, "control/"+name, bytes.NewReader(raw), int64(len(raw)))
		return err
	}); err != nil {
		return err
	}
	if err := ensureStaffBootstrap(store.DB(), c, in.Tenancy); err != nil {
		return fmt.Errorf("staff bootstrap: %w", err)
	}
	auth.SetCSRFKey(c.Secrets.PairingSecret)
	fixed := sso.NewFixedStore(in.SSO)
	push, err := webpush.New(in.VAPID)
	if err != nil {
		return err
	}
	maxBytes := max(c.Limits.ObjectMaxBytes, c.Limits.AttachmentMaxBytes)
	stores := storage.CellObjectStores(store.DB(), func(cell, org string) (*blobstore.Objects, error) {
		return blobstore.NewObjects(client, cell, org, c.DataDir, maxBytes)
	})
	directory := suitedir.Client{Issuer: in.SSO.IssuerURL, ClientID: in.SSO.ClientID, ClientSecret: in.SSO.ClientSecret}
	orgs := orgsync.New(store.DB(), directory.Orgs)
	ready := &health.Checker{}
	srv := &http.Server{Addr: c.Server.Bind, Handler: httpapi.NewRouter(log, c.Server.MaxRequestBytes, ready.IsReady, store.DB(), c, fixed, push, orgs, stores), ReadHeaderTimeout: parse(c.Server.ReadHeaderTimeout), ReadTimeout: parse(c.Server.ReadTimeout), WriteTimeout: parse(c.Server.WriteTimeout), IdleTimeout: parse(c.Server.IdleTimeout)}
	// Bind before starting any worker; a bind failure owns no background work.
	listener, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	workerCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	schedules := replicaSchedules{db: store.DB(), orgs: orgs, directory: directory, reports: &orgsync.Reporter{DB: store.DB(), Dir: directory}, push: push, gcInterval: parse(c.GC.Interval), log: log,
		gc: func(ctx context.Context, now time.Time) error {
			if err := storage.RunObjectMaintenance(ctx, store.DB(), stores, now); err != nil {
				return err
			}
			if !c.GC.Enabled {
				return nil
			}
			_, err := storage.RunObjectGC(ctx, store.DB(), stores, now, parse(c.GC.Retention))
			return err
		}, purge: func(ctx context.Context, org string) error {
			objects, err := stores(ctx, org)
			if err != nil {
				return err
			}
			return objects.Purge(ctx)
		},
		backup: func(ctx context.Context, now time.Time) error { return backupRun(ctx, store, now) },
	}
	go func() { defer close(done); runReplicaSchedules(workerCtx, schedules) }()
	ready.SetReady(true)
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(listener) }()
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errc:
	}
	drainErr := drainReplica(ready, stop, done, srv)
	// Shutdown's timeout does not close active connections. Abort them before closing the DB.
	if drainErr != nil {
		_ = srv.Close()
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil
	}
	return errors.Join(serveErr, drainErr)
}

// replicaBackup writes native, sealed PG archives to the primary bucket. It never invokes
// the single-mode capsule/SQLite service. Attempts, including failures, count toward cadence.
func replicaBackup(c config.Config, in replicaInputs, client *shareds3.Client) (func(context.Context, *storage.Store, time.Time) error, string, error) {
	interval := parse(c.Backup.DepositInterval)
	if interval == 0 {
		return func(context.Context, *storage.Store, time.Time) error { return nil }, "off", nil
	}
	key, err := replicaBackupKey()
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(key)
	prefix := os.Getenv("KYNOTES_PG_BACKUP_PREFIX")
	if !regexp.MustCompile(`^backups/(?:[A-Za-z0-9][A-Za-z0-9_.-]{0,63}/)+$`).MatchString(prefix) || len(prefix) > 256 {
		return nil, "", errors.New("replicas: enabled native backup requires KYNOTES_PG_BACKUP_PREFIX under backups/, ending with /")
	}
	if parse(c.GC.Retention) < time.Hour {
		return nil, "", errors.New("replicas: native backup requires at least one hour of blob retention")
	}
	return func(ctx context.Context, store *storage.Store, now time.Time) (runErr error) {
		// The shared attempt timestamp survives elected-owner changes.
		var last string
		if err := store.DB().QueryRowContext(ctx, `SELECT COALESCE(MAX(value),'') FROM server_settings WHERE key='pg_backup_last_attempt'`).Scan(&last); err != nil {
			return err
		}
		if at, err := time.Parse(time.RFC3339Nano, last); err == nil && now.Before(at.Add(interval)) {
			return nil
		}
		if _, err := store.DB().ExecContext(ctx, `INSERT INTO server_settings(key,value,updated_at) VALUES('pg_backup_last_attempt',?,'') ON CONFLICT(key) DO UPDATE SET value=excluded.value`, now.UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
		defer func() {
			outcome, reason := "success", "native_archive_stored"
			if runErr != nil {
				outcome, reason = "failure", "native_archive_failed"
			}
			runErr = errors.Join(runErr, storage.RecordAuditOutcome(store.DB(), "", "platform.pg_backup", "", "", outcome, reason, "replica-scheduler"))
		}()
		file, err := os.CreateTemp(c.DataDir, ".kynotes-pg-backup-")
		if err != nil {
			return err
		}
		defer os.Remove(file.Name())
		defer file.Close()
		if _, err = backup.BackupPostgres(ctx, store.DB(), key, file); err != nil {
			return err
		}
		size, err := file.Seek(0, io.SeekCurrent)
		if err != nil {
			return err
		}
		if _, err = file.Seek(0, io.SeekStart); err != nil {
			return err
		}
		name := prefix + now.UTC().Format("20060102T150405.000000000") + ".kypg"
		if _, err = client.PutIfAbsent(ctx, name, file, size); err != nil {
			return err
		}
		// Archives older than blob retention cannot promise coverage and are not retained.
		token := ""
		seen := map[string]bool{}
		for {
			page, err := client.ListObjects(ctx, prefix, token)
			if err != nil {
				return err
			}
			for _, object := range page.Objects {
				if !object.LastModified.IsZero() && object.LastModified.Before(now.Add(-parse(c.GC.Retention))) {
					if err := client.DeleteAllVersions(ctx, object.Key); err != nil {
						return err
					}
				}
			}
			if page.Next == "" {
				break
			}
			if seen[page.Next] {
				return errors.New("replicas: archive listing repeated a continuation token")
			}
			seen[page.Next] = true
			token = page.Next
		}
		return nil
	}, hex.EncodeToString(digest[:]), nil
}

func replicaBackupKey() ([]byte, error) {
	bad := errors.New("replicas: native backup requires KYNOTES_PG_BACKUP_KEY_FILE with 64 hex characters, or an off schedule")
	path := os.Getenv("KYNOTES_PG_BACKUP_KEY_FILE")
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, bad
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, bad
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 67))
	if err != nil {
		return nil, bad
	}
	key, err := hex.DecodeString(string(bytes.TrimSuffix(bytes.TrimSuffix(raw, []byte("\n")), []byte("\r"))))
	if err != nil || len(key) != backup.BackupKeyBytes {
		return nil, bad
	}
	return key, nil
}
