package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Busnes-app/kynotes-server/internal/backup"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/mirror"
	"github.com/Busnes-app/kynotes-server/internal/storage"
	"github.com/Busness-app/ky-primitives/offsite"
)

func mirrorCommand(command string, args []string) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	path := flags.String("config", "/data/kynotes.yaml", "configuration path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected mirror argument")
	}
	load := config.Load
	if command == "test-blob-target" {
		load = config.LoadBlobTargetProbe
	}
	cfg, err := load(*path)
	if err != nil {
		return err
	}
	if cfg.Backup.BlobTarget.URL == "" {
		return backup.ErrNoBlobTarget
	}
	target, err := offsite.Parse(cfg.Backup.BlobTarget.Offsite())
	if err != nil {
		return errors.New("invalid blob target")
	}
	ctx, cancel := context.WithTimeout(context.Background(), backup.OperationTimeout)
	defer cancel()
	if command == "test-blob-target" {
		if err = target.Test(ctx); err != nil {
			var pin *offsite.UnknownHostKeyError
			if errors.As(err, &pin) {
				return fmt.Errorf("untrusted SFTP host key %s; compare out of band before setting KYNOTES_BLOB_TARGET_HOST_KEY", pin.Fingerprint)
			}
			return errors.New("blob target test failed; check destination and credentials")
		}
		fmt.Println("Blob target test passed.")
		return nil
	}
	unlock, err := storage.LockDirectory(cfg.DataDir)
	if err != nil {
		return err
	}
	defer unlock()
	if _, err = os.Stat(filepath.Join(cfg.DataDir, "kynotes.sqlite")); err != nil {
		return errors.New("existing or restored database required")
	}
	st, err := storage.Open(filepath.Join(cfg.DataDir, "kynotes.sqlite"))
	if err != nil {
		return err
	}
	defer st.Close()
	if command == "mirror-blobs" {
		service := backup.New(cfg, st, "dev")
		defer service.Close()
		stats, err := service.MirrorNow(ctx, "system", "cli")
		if e := json.NewEncoder(os.Stdout).Encode(stats); e != nil {
			return e
		}
		if err != nil {
			return errors.New(backup.ErrorCode(err))
		}
		return nil
	}
	blobs, err := blobstore.New(cfg.DataDir)
	if err != nil {
		return err
	}
	stats, err := mirror.Fetch(ctx, st.DB(), blobs, target)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	raw, _ := json.Marshal(stats)
	if e := storage.RecordAuditOutcome(st.DB(), "system", "admin.blob_fetch", "", "", outcome, string(raw), "cli"); e != nil {
		return backup.ErrAudit
	}
	if e := json.NewEncoder(os.Stdout).Encode(stats); e != nil {
		return e
	}
	if err != nil {
		return mirror.ErrIncomplete
	}
	fmt.Println("Ciphertext blobs recovered; run consistency-check before starting KyNotes.")
	return nil
}
