package storage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// VerifyReplicaConfig records keyed per-field fingerprints once. A database reader sees no
// shared setting values, and a mismatch names fields only. The key is the retained server salt.
// Restore clears the record; deliberate rotation requires every replica stopped (phase 6 CLI).
func VerifyReplicaConfig(ctx context.Context, db *sql.DB, key string, fields map[string]string) error {
	shared, err := SharedMode(db)
	if err != nil || !shared {
		return err
	}
	digest := func(name, value string) string {
		h := hmac.New(sha256.New, []byte(key))
		h.Write([]byte("kynotes/replica-config/v1\x00" + name + "\x00" + value))
		return hex.EncodeToString(h.Sum(nil))
	}
	want := make(map[string]string, len(fields)+1)
	for name, value := range fields {
		want[name] = digest(name, value)
	}
	want["$key"] = digest("$key", key)
	encoded, err := json.Marshal(want)
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO server_settings(key,value,updated_at) VALUES('replica_config_fingerprint',?,'') ON CONFLICT(key) DO NOTHING`, string(encoded)); err != nil {
		return err
	}
	var raw string
	if err := tx.QueryRowContext(ctx, `SELECT value FROM server_settings WHERE key='replica_config_fingerprint'`).Scan(&raw); err != nil {
		return err
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		return errors.New("replicas: stored configuration fingerprint is invalid")
	}
	if got["$key"] != want["$key"] {
		return errors.New("replicas: KYNOTES_SECRETS_SERVER_SALT_KEY differs")
	}
	changed := map[string]bool{}
	for name, value := range want {
		if got[name] != value {
			changed[name] = true
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			changed[name] = true
		}
	}
	if len(changed) > 0 {
		names := make([]string, 0, len(changed))
		for name := range changed {
			names = append(names, name)
		}
		sort.Strings(names)
		return fmt.Errorf("replicas: shared configuration differs: %s", strings.Join(names, ", "))
	}
	return tx.Commit()
}
