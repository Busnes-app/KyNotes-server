package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/backup"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// The DSN stays out of argv and errors. This command acts only on a separately restored,
// stopped target; it never starts a server or performs the underlying native PG recovery.
func preparePostgresRestoreCommand(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("prepare-postgres-restore", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	confirm := flags.Bool("confirm-restored", false, "target was separately restored and all replicas are stopped")
	if err := flags.Parse(args); err != nil {
		return errors.New("usage: prepare-postgres-restore --confirm-restored (KYNOTES_DB_DSN in environment)")
	}
	if flags.NArg() != 0 || !*confirm {
		return errors.New("prepare-postgres-restore requires --confirm-restored and no positional arguments; stop every replica first")
	}
	dsn := os.Getenv("KYNOTES_DB_DSN")
	if dsn == "" {
		return errors.New("prepare-postgres-restore requires KYNOTES_DB_DSN in the environment")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	store, err := storage.OpenPostgresCurrent(ctx, dsn)
	if err != nil {
		return errors.New("prepare-postgres-restore cannot open the current PostgreSQL schema; check the target and use its matching release")
	}
	defer store.Close()
	if err := backup.PreparePostgresRestore(ctx, store); err != nil {
		return errors.New("prepare-postgres-restore safety reset failed; keep every replica stopped")
	}
	_, err = fmt.Fprintln(stdout, "Prepared restored PostgreSQL target: credentials revoked, deposits off, customer orgs stale, directory cursors reset. Preserve the original keys and store identity; reconcile both suite feeds and verify blob coverage before serving. This command does not enable multi startup.")
	return err
}
