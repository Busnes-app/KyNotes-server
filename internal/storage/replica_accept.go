package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

// AcceptReplicaConfig is preparation for explicit offline configuration acceptance, never an
// automatic mismatch fallback. The host caller must stop every replica first. Immutable
// install bindings and the retained salt/encryption key cannot be changed through this path.
func AcceptReplicaConfig(ctx context.Context, db *sql.DB, key string, fields map[string]string) error {
	tenancy, err := TenancyOfContext(ctx, db)
	if err != nil {
		return err
	}
	if !IsPostgres(db) || !tenancy.Multi() {
		return errors.New("replicas: configuration acceptance requires multi PostgreSQL")
	}
	want := replicaFingerprint(key, fields)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw string
	if err := tx.QueryRowContext(ctx, `SELECT value FROM server_settings WHERE key='replica_config_fingerprint'`).Scan(&raw); err != nil {
		return errors.New("replicas: no usable stored configuration to accept")
	}
	var got map[string]string
	if json.Unmarshal([]byte(raw), &got) != nil || got["$key"] != want["$key"] {
		return errors.New("replicas: retained server salt key is required")
	}
	for _, name := range []string{"tenancy_mode", "staff_org_id", "region"} {
		if got[name] != want[name] {
			return errors.New("replicas: immutable install binding differs: " + name)
		}
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
	if len(changed) == 0 {
		return nil
	}
	names := make([]string, 0, len(changed))
	for name := range changed {
		names = append(names, name)
	}
	sort.Strings(names)
	encoded, err := json.Marshal(want)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE server_settings SET value=?,updated_at=? WHERE key='replica_config_fingerprint'`, string(encoded), time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	if err := RecordAuditOutcomeTx(tx, "", "admin.replica_config_accepted", "", "", "success", "fields="+strings.Join(names, ","), "replica-config"); err != nil {
		return err
	}
	return tx.Commit()
}
