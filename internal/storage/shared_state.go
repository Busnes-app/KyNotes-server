package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"math"
	"time"
)

// SharedMode selects the recorded multi-mode contract, never a request or a process-global flag.
// SQLite and single mode retain their existing memory-only security state.
func SharedMode(db *sql.DB) (bool, error) {
	if db == nil || !IsPostgres(db) {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var mode string
	err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(value),'single') FROM server_settings WHERE key='tenancy_mode'`).Scan(&mode)
	return mode == "multi", err
}

func StateHash(key string) string { h := sha256.Sum256([]byte(key)); return hex.EncodeToString(h[:]) }

// AllowRate is KyIdentity's GCRA spend, with PostgreSQL time rather than a replica's clock.
// A refused conflict changes no row. Hashing keys also keeps NUL-separated identities out of TEXT.
func AllowRate(ctx context.Context, db *sql.DB, namespace, key string, burst int, rate float64) (bool, error) {
	if burst <= 0 || rate <= 0 {
		return true, nil
	}
	interval := int64(math.Max(1, math.Min(1e15, 1e6/rate)))
	tolerance := int64(math.Min(1e18, float64(burst-1)*float64(interval)))
	res, err := db.ExecContext(ctx, `WITH tick AS (SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint AS n)
 INSERT INTO replica_rates(key_hash,tat_us) SELECT ?,n+? FROM tick
 ON CONFLICT(key_hash) DO UPDATE SET tat_us=GREATEST(replica_rates.tat_us,(SELECT n FROM tick))+?
 WHERE replica_rates.tat_us-(SELECT n FROM tick)<=?`, StateHash(namespace+"\x00"+key), interval, interval, tolerance)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// ReserveLockout atomically reserves a password/device attempt before verification. N3 keeps
// pruning, cap admission and the increment in one transaction. Live locks are never evicted.
func ReserveLockout(ctx context.Context, db *sql.DB, namespace, key string, limit, cap int, cooldown time.Duration) (string, bool, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback()
	var now int64
	if err := tx.QueryRowContext(ctx, `SELECT floor(extract(epoch FROM clock_timestamp()))::bigint`).Scan(&now); err != nil {
		return "", false, err
	}
	key = StateHash(key)
	var failures, until int64
	var generation string
	err = tx.QueryRowContext(ctx, `SELECT failures,locked_until,generation FROM replica_lockouts WHERE namespace=? AND key_hash=?`, namespace, key).Scan(&failures, &until, &generation)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", false, err
	}
	exists := err == nil
	if until > now {
		return "", false, nil
	}
	if !exists || until != 0 {
		failures = 0
		generation = rand.Text()
	}
	if !exists {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM replica_lockouts WHERE namespace=?`, namespace).Scan(&count); err != nil {
			return "", false, err
		}
		if count >= cap {
			if _, err := tx.ExecContext(ctx, `DELETE FROM replica_lockouts WHERE namespace=? AND locked_until<=?`, namespace, now); err != nil {
				return "", false, err
			}
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM replica_lockouts WHERE namespace=?`, namespace).Scan(&count); err != nil {
				return "", false, err
			}
			if count >= cap {
				return "", false, nil
			}
		}
	}
	failures++
	until = 0
	if failures >= int64(limit) {
		until = now + int64(cooldown/time.Second)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO replica_lockouts(namespace,key_hash,failures,locked_until,generation) VALUES(?,?,?,?,?) ON CONFLICT(namespace,key_hash) DO UPDATE SET failures=excluded.failures,locked_until=excluded.locked_until,generation=excluded.generation`, namespace, key, failures, until, generation); err != nil {
		return "", false, err
	}
	return generation, true, tx.Commit()
}

func ReleaseLockout(ctx context.Context, db *sql.DB, namespace, key, generation string, limit int, success bool) error {
	key = StateHash(key)
	if success {
		_, err := db.ExecContext(ctx, `DELETE FROM replica_lockouts WHERE namespace=? AND key_hash=? AND generation=?`, namespace, key, generation)
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE replica_lockouts SET failures=failures-1,locked_until=CASE WHEN failures-1<? THEN 0 ELSE locked_until END WHERE namespace=? AND key_hash=? AND generation=?`, limit, namespace, key, generation); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM replica_lockouts WHERE namespace=? AND key_hash=? AND generation=? AND failures<=0`, namespace, key, generation); err != nil {
		return err
	}
	return tx.Commit()
}

func SweepSharedState(ctx context.Context, db *sql.DB) error {
	for _, q := range []string{
		`DELETE FROM replica_logins WHERE expires_at<=extract(epoch FROM clock_timestamp())`,
		`DELETE FROM replica_rates WHERE tat_us<=extract(epoch FROM clock_timestamp())*1000000`,
		`DELETE FROM replica_presence WHERE expires_at<=extract(epoch FROM clock_timestamp())`,
		`DELETE FROM replica_lockouts WHERE locked_until>0 AND locked_until<=extract(epoch FROM clock_timestamp())`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

func PutLogin(ctx context.Context, db *sql.DB, state string, payload []byte, ttl time.Duration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM replica_logins WHERE expires_at<=extract(epoch FROM clock_timestamp())`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM replica_logins WHERE state_hash IN (SELECT state_hash FROM replica_logins ORDER BY expires_at,state_hash LIMIT (SELECT GREATEST(count(*)-1023,0) FROM replica_logins))`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO replica_logins(state_hash,payload,expires_at) VALUES(?,?,floor(extract(epoch FROM clock_timestamp()))::bigint+?)`, StateHash(state), payload, int64(ttl/time.Second)); err != nil {
		return err
	}
	return tx.Commit()
}

func TakeLogin(ctx context.Context, db *sql.DB, state string) ([]byte, bool, error) {
	var payload []byte
	err := db.QueryRowContext(ctx, `DELETE FROM replica_logins WHERE state_hash=? AND expires_at>extract(epoch FROM clock_timestamp()) RETURNING payload`, StateHash(state)).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	return payload, err == nil, err
}
