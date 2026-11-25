package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Busnes-app/kynotes-server/internal/backup"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// pg-backup and pg-restore are the multi-mode PostgreSQL backup transport. The DSN and the
// backup key stay out of argv: KYNOTES_DB_DSN and KYNOTES_PG_BACKUP_KEY_FILE.
//
//	pg-backup --out FILE                   sealed archive of the live database, created new
//	pg-restore --in FILE --confirm-stopped load into a new, empty database, fenced and gated
func postgresArchiveCommand(name string, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	out := flags.String("out", "", "new archive file")
	in := flags.String("in", "", "archive file")
	confirm := flags.Bool("confirm-stopped", false, "every replica is stopped")
	usage := errors.New("usage: pg-backup --out FILE | pg-restore --in FILE --confirm-stopped (KYNOTES_DB_DSN and KYNOTES_PG_BACKUP_KEY_FILE in the environment)")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return usage
	}
	if name == "pg-backup" && (*out == "" || *in != "" || *confirm) || name == "pg-restore" && (*in == "" || *out != "" || !*confirm) {
		return usage
	}
	dsn := os.Getenv("KYNOTES_DB_DSN")
	if dsn == "" {
		return errors.New(name + " requires KYNOTES_DB_DSN in the environment")
	}
	key, err := readBackupKey()
	if err != nil {
		return err
	}
	ctx := context.Background()
	if name == "pg-backup" {
		return postgresBackup(ctx, dsn, key, *out, stdout)
	}
	return postgresRestore(ctx, dsn, key, *in, stdout)
}

func postgresBackup(ctx context.Context, dsn string, key []byte, path string, stdout io.Writer) error {
	store, err := storage.OpenPostgresCurrent(ctx, dsn)
	if err != nil {
		return errors.New("pg-backup cannot open the current PostgreSQL schema; run the release that owns it")
	}
	defer store.Close()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("pg-backup cannot create the archive file; it must not exist yet")
	}
	sum, err := backup.BackupPostgres(ctx, store.DB(), key, f)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return fmt.Errorf("pg-backup failed and removed the partial archive: %w", err)
	}
	_, err = fmt.Fprintf(stdout, "PostgreSQL backup written: schema %d, snapshot %s, %d tables. Keep the backup key apart from the archive.\n", sum.Schema, sum.TakenAt, len(sum.Rows))
	return err
}

func postgresRestore(ctx context.Context, dsn string, key []byte, path string, stdout io.Writer) error {
	store, err := storage.OpenPostgresCurrent(ctx, dsn)
	if err != nil && !errors.Is(err, storage.ErrSchemaOlder) && !errors.Is(err, storage.ErrSchemaNewer) {
		store, err = storage.OpenPostgres(dsn) // a new database: create this release's schema
	}
	if err != nil {
		return errors.New("pg-restore needs a new, empty database for this release")
	}
	defer store.Close()
	f, err := os.Open(path)
	if err != nil {
		return errors.New("pg-restore cannot open the archive file")
	}
	defer f.Close()
	sum, err := backup.RestorePostgres(ctx, store.DB(), key, f)
	if err != nil {
		return fmt.Errorf("pg-restore loaded nothing: %w", err)
	}
	_, err = fmt.Fprintf(stdout, "Restored PostgreSQL snapshot %s (schema %d): credentials revoked, deposits off, customer orgs stale and unserved until the elected worker replays the org and erased feeds from zero. Verify blob coverage before serving. This command does not enable multi startup.\n", sum.TakenAt, sum.Schema)
	return err
}

// The key file holds 64 hex characters (32 bytes), optionally followed by one newline.
func readBackupKey() ([]byte, error) {
	bad := errors.New("KYNOTES_PG_BACKUP_KEY_FILE must name a regular file holding 64 hex characters")
	path := os.Getenv("KYNOTES_PG_BACKUP_KEY_FILE")
	if path == "" {
		return nil, bad
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, bad
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, bad
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 2*backup.BackupKeyBytes+3))
	if err != nil {
		return nil, bad
	}
	key, err := hex.DecodeString(strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r"))
	if err != nil || len(key) != backup.BackupKeyBytes {
		return nil, bad
	}
	return key, nil
}
