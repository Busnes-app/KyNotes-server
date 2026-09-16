package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/ky-primitives/shamir"
	"github.com/Busnes-app/kynotes-server/internal/backup"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/storage"
	"gopkg.in/yaml.v3"
)

func capsuleCommand(command string, args []string) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	configPath := flags.String("config", "/data/kynotes.yaml", "configuration path")
	out := flags.String("out", "", "new sealed capsule file")
	in := flags.String("in", "", "sealed capsule file")
	to := flags.String("to", "", "empty destination data directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected argument; custodian shares belong on stdin")
	}
	if command == "restore" {
		if *in == "" || *to == "" {
			return errors.New("usage: restore --in capsule.kycap --to empty-directory (shares on stdin)")
		}
		return restoreCapsule(*in, *to, os.Stdin, os.Stdout)
	}
	if command == "export-capsule" && *out == "" {
		return errors.New("export-capsule requires --out")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	unlock, err := storage.LockDirectory(cfg.DataDir)
	if err != nil {
		return err
	}
	defer unlock()
	store, err := storage.Open(filepath.Join(cfg.DataDir, "kynotes.sqlite"))
	if err != nil {
		return err
	}
	defer store.Close()
	service := backup.New(cfg, store, "dev")
	defer service.Close()
	ctx, cancel := context.WithTimeout(context.Background(), backup.OperationTimeout)
	defer cancel()
	switch command {
	case "deposit":
		result, err := service.Run(ctx, "system", "cli")
		if result.Manifest.CapsuleID != "" {
			if e := json.NewEncoder(os.Stdout).Encode(result); e != nil {
				return e
			}
		}
		if err != nil {
			return errors.New(backup.ErrorCode(err))
		}
		return nil
	case "backup-drill":
		result, err := service.Drill(ctx, "system", "cli")
		if result != nil {
			if e := json.NewEncoder(os.Stdout).Encode(result); e != nil {
				return e
			}
		}
		if err != nil {
			return errors.New(backup.ErrorCode(err))
		}
		return nil
	case "export-capsule":
		raw, _, err := service.Export(ctx, "system", "cli")
		if err != nil {
			return errors.New(backup.ErrorCode(err))
		}
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, err = f.Write(raw)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			_ = os.Remove(*out)
			return err
		}
		return closeErr
	}
	return errors.New("unknown capsule command")
}

// restoreCapsule is the only production entry point allowed to combine custodian
// shares or open a suite capsule. The server never executes this function.
func restoreCapsule(path, target string, stdin io.Reader, stdout io.Writer) error {
	target, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	if entries, e := os.ReadDir(target); e == nil && len(entries) > 0 {
		return errors.New("restore target must be empty")
	} else if e != nil && !os.IsNotExist(e) {
		return e
	}
	source, err := os.Open(path)
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(source, int64(capsule.MaxContainerBytes)+1))
	source.Close()
	if err != nil {
		return err
	}
	if len(raw) > capsule.MaxContainerBytes {
		return errors.New("capsule exceeds container limit")
	}
	peek, err := capsule.ReadUnverifiedManifest(raw)
	if err != nil {
		return err
	}
	if peek.ServiceName != config.AppName {
		return errors.New("capsule is not for KyNotes")
	}
	lines, err := recoveryclient.ReadShares(stdin)
	if err != nil {
		return err
	}
	shares := make([]shamir.Share, 0, len(lines))
	for _, line := range lines {
		share, e := shamir.ParseShare(line)
		if e != nil {
			return errors.New("invalid custodian share")
		}
		shares = append(shares, share)
	}
	private, err := recoverykey.Combine(shares)
	if err != nil {
		return errors.New("custodian shares could not reconstruct the recovery key")
	}
	manifest, _, err := capsule.Open(raw, private, target)
	if err != nil {
		return err
	}
	for _, check := range backup.Checks(target, manifest) {
		if !check.Passed {
			return fmt.Errorf("restore verification failed: %s; preserve this target for inspection", check.Message)
		}
	}
	// Relocate only the data path. Keep effective deployment keys, issuer and pairing.
	configPath := filepath.Join(target, "kynotes.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var cfg config.Config
	if err = yaml.Unmarshal(data, &cfg); err != nil {
		return err
	}
	cfg.DataDir = target
	data, err = yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	if err = os.WriteFile(configPath, data, 0600); err != nil {
		return err
	}
	store, err := storage.Open(filepath.Join(target, "kynotes.sqlite"))
	if err != nil {
		return err
	}
	defer store.Close()
	// A restored database must not resurrect previously captured session cookies.
	if _, err = store.DB().Exec(`UPDATE sessions SET revoked_at=? WHERE revoked_at=''`, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Restored capsule %s; recovery key %s. Verify its receipt and recover ciphertext blobs before starting KyNotes.\n", recoveryclient.AuditSafe(manifest.CapsuleID), recoveryclient.AuditSafe(manifest.RecoveryKeyID))
	return err
}
