package blobstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/storage/pgdialect"
)

var ErrStoreIdentity = errors.New("KYNOTES_BLOB_BACKEND: blob store identity differs or storage is not shared")

// VerifySharedIdentity implements N15's control-file protocol. The primary backend binds read
// and create-exclusive to its control objects; these callbacks are not an S3 client contract.
// No backend is selected here, and the volume store never becomes a hosted fallback.
func VerifySharedIdentity(ctx context.Context, db *sql.DB, read func(context.Context, string) ([]byte, error), create func(context.Context, string, []byte) error) error {
	var mode string
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(value),'single') FROM server_settings WHERE key='tenancy_mode'`).Scan(&mode); err != nil {
		return err
	}
	if mode != "multi" {
		return nil
	}
	if _, ok := db.Driver().(pgdialect.Driver); !ok {
		return ErrStoreIdentity
	}
	nonce := func() (string, error) {
		var b [32]byte
		_, err := rand.Read(b[:])
		return base64.RawURLEncoding.EncodeToString(b[:]), err
	}
	valid := func(value string) bool {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
		return err == nil && len(raw) == 32
	}
	candidate, err := nonce()
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO server_settings(key,value,updated_at) VALUES('blob_store_id',?,'') ON CONFLICT(key) DO NOTHING`, candidate); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO server_settings(key,value,updated_at) VALUES('blob_probe','','') ON CONFLICT(key) DO NOTHING`); err != nil {
		return err
	}
	var id string
	if err := tx.QueryRowContext(ctx, `SELECT value FROM server_settings WHERE key='blob_store_id'`).Scan(&id); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if !valid(id) {
		return ErrStoreIdentity
	}
	if err := create(ctx, "store-id", []byte(id)); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return ErrStoreIdentity
		}
		actual, err := read(ctx, "store-id")
		if err != nil || !bytes.Equal(actual, []byte(id)) {
			return ErrStoreIdentity
		}
	}
	current := func() (string, error) {
		var name string
		err := db.QueryRowContext(ctx, `SELECT value FROM server_settings WHERE key='blob_probe'`).Scan(&name)
		return name, err
	}
	// A failed read may race a successful start. Re-read the pointer, at most three times;
	// never excuse a missing probe when the database still names it.
	check := func(name string) (string, error) {
		for range 3 {
			if name == "" {
				return name, nil
			}
			if !valid(name) {
				return "", ErrStoreIdentity
			}
			value, err := read(ctx, "probes/"+name)
			if err == nil && bytes.Equal(value, []byte(id)) {
				return name, nil
			}
			newer, err := current()
			if err != nil {
				return "", err
			}
			if newer == name || newer == "" {
				return "", ErrStoreIdentity
			}
			name = newer
		}
		return "", ErrStoreIdentity
	}
	old, err := current()
	if err != nil {
		return err
	}
	old, err = check(old)
	if err != nil {
		return err
	}
	probe, err := nonce()
	if err != nil {
		return err
	}
	if err := create(ctx, "probes/"+probe, []byte(id)); err != nil {
		return ErrStoreIdentity
	}
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var retiredAt time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&retiredAt); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `UPDATE server_settings SET value=?,updated_at=? WHERE key='blob_probe' AND value=?`, probe, retiredAt.UTC().Format(time.RFC3339Nano), old)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 1 && old != "" {
		retired, _ := json.Marshal(struct {
			Name string    `json:"name"`
			At   time.Time `json:"at"`
		}{old, retiredAt.UTC()})
		if _, err := tx.ExecContext(ctx, `INSERT INTO server_settings(key,value,updated_at) VALUES('blob_probe_prev',?,'') ON CONFLICT(key) DO UPDATE SET value=excluded.value`, string(retired)); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if n == 1 {
		return nil
	}
	latest, err := current()
	if err != nil {
		return err
	}
	_, err = check(latest) // the other fresh starter must be visible before this replica serves
	return err
}
