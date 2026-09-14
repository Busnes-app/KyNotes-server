package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Busness-app/kynotes-server/internal/auth"
	"github.com/Busness-app/kynotes-server/internal/config"
	"github.com/Busness-app/kynotes-server/internal/ids"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func DeviceRoutes(mux *http.ServeMux, db *sql.DB, cfg config.Config) {
	mux.Handle("GET /api/v1/devices/{id}/containers", auth.RequireEither(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, _ := auth.CredentialUserID(r)
		id := r.PathValue("id")
		if ids.Validate("dev", id) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		if d, ok := auth.DeviceFromContext(r); ok && d.ID != id {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		var owner string
		if db.QueryRow(`SELECT user_id FROM devices WHERE id=?`, id).Scan(&owner) != nil || owner != uid {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		rows, e := db.Query(`SELECT container_id FROM device_containers WHERE device_id=?`, id)
		if e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		defer rows.Close()
		out := []string{}
		for rows.Next() {
			var cid string
			_ = rows.Scan(&cid)
			out = append(out, cid)
		}
		writeJSON(w, out)
	})))
	mux.Handle("PUT /api/v1/devices/{id}/containers", auth.RequireEither(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		uid, _ := auth.CredentialUserID(r)
		id := r.PathValue("id")
		if ids.Validate("dev", id) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		if d, ok := auth.DeviceFromContext(r); ok && d.ID != id {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		var owner string
		if db.QueryRow(`SELECT user_id FROM devices WHERE id=?`, id).Scan(&owner) != nil || owner != uid {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		var idsIn []string
		if json.NewDecoder(r.Body).Decode(&idsIn) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		e := dbTx(db, func(tx *sql.Tx) error {
			if _, e := tx.Exec(`DELETE FROM device_containers WHERE device_id=?`, id); e != nil {
				return e
			}
			for _, cid := range idsIn {
				if ids.Validate("cnt", cid) != nil {
					return errors.New("invalid container")
				}
				var member int
				if e := tx.QueryRow(`SELECT COUNT(*) FROM memberships m JOIN devices d ON d.user_id=m.user_id WHERE m.container_id=? AND m.user_id=? AND m.revoked_at='' AND d.id=? AND d.revoked_at=''`, cid, uid, id).Scan(&member); e != nil || member == 0 {
					return errors.New("not a member")
				}
				if _, e := tx.Exec(`INSERT INTO device_containers(device_id,container_id,selected_at) VALUES(?,?,?)`, id, cid, time.Now().UTC().Format(time.RFC3339)); e != nil {
					return e
				}
			}
			return nil
		})
		if e != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	mux.Handle("GET /api/v1/containers/{id}/envelopes", auth.RequireEither(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, _ := auth.CredentialUserID(r)
		device, isDevice := auth.DeviceFromContext(r)
		cid := r.PathValue("id")
		if ids.Validate("cnt", cid) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var member int
		if db.QueryRow(`SELECT COUNT(*) FROM memberships WHERE container_id=? AND user_id=? AND revoked_at=''`, cid, uid).Scan(&member) != nil || member == 0 {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		query := `SELECT id,device_id,key_generation,alg,envelope,created_at FROM key_envelopes WHERE container_id=?`
		args := []any{cid}
		if isDevice {
			query += ` AND device_id=?`
			args = append(args, device.ID)
		}
		rows, e := db.Query(query, args...)
		if e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var id, did, alg, created string
			var gen int
			var env []byte
			_ = rows.Scan(&id, &did, &gen, &alg, &env, &created)
			out = append(out, map[string]any{"id": id, "deviceId": did, "keyGeneration": gen, "alg": alg, "envelope": base64.StdEncoding.EncodeToString(env), "createdAt": created})
		}
		writeJSON(w, out)
	})))
	mux.Handle("PUT /api/v1/containers/{id}/envelopes", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		if s, _ := auth.SessionFromContext(r); time.Since(s.CreatedAt) >= 5*time.Minute {
			WriteError(w, r, 403, "forbidden", "re-authentication required")
			return
		}
		s, _ := auth.SessionFromContext(r)
		cid := r.PathValue("id")
		if ids.Validate("cnt", cid) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var role string
		if db.QueryRow(`SELECT role FROM memberships WHERE container_id=? AND user_id=? AND revoked_at=''`, cid, s.UserID).Scan(&role) != nil || (role != "owner" && role != "admin") {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		var generation int
		if db.QueryRow(`SELECT key_generation FROM containers WHERE id=?`, cid).Scan(&generation) != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		var in struct {
			Envelopes []struct {
				DeviceID      string `json:"deviceId"`
				KeyGeneration int    `json:"keyGeneration"`
				Alg           string `json:"alg"`
				Envelope      string `json:"envelope"`
			} `json:"envelopes"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		e := dbTx(db, func(tx *sql.Tx) error {
			for _, v := range in.Envelopes {
				if v.Alg != "x25519-hkdf-sha256-chacha20poly1305" {
					return errors.New("algorithm")
				}
				env, e := base64.StdEncoding.DecodeString(v.Envelope)
				if e != nil || len(env) > 4096 || ids.Validate("dev", v.DeviceID) != nil {
					return errors.New("envelope")
				}
				var deviceUser string
				if e = tx.QueryRow(`SELECT user_id FROM devices WHERE id=? AND revoked_at=''`, v.DeviceID).Scan(&deviceUser); e != nil || deviceUser == "" {
					return errors.New("device")
				}
				var member int
				if e = tx.QueryRow(`SELECT COUNT(*) FROM memberships WHERE container_id=? AND user_id=? AND revoked_at=''`, cid, deviceUser).Scan(&member); e != nil || member == 0 {
					return errors.New("membership")
				}
				if v.KeyGeneration != generation {
					return errors.New("generation")
				}
				id, _ := ids.Mint("env")
				if _, e = tx.Exec(`INSERT OR REPLACE INTO key_envelopes(id,container_id,device_id,key_generation,alg,envelope,created_at) VALUES(?,?,?,?,?,?,?)`, id, cid, v.DeviceID, v.KeyGeneration, v.Alg, env, now); e != nil {
					return e
				}
			}
			return nil
		})
		if e != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	mux.Handle("GET /api/v1/devices", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := auth.SessionFromContext(r)
		rows, e := db.Query(`SELECT id,fingerprint,platform,created_at,last_seen_at,revoked_at FROM devices WHERE user_id=?`, s.UserID)
		if e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var id, fp, p, created, last, rev string
			_ = rows.Scan(&id, &fp, &p, &created, &last, &rev)
			out = append(out, map[string]any{"id": id, "fingerprint": fp, "platform": p, "createdAt": created, "lastSeenAt": last, "revoked": rev != ""})
		}
		writeJSON(w, out)
	})))
	mux.Handle("DELETE /api/v1/devices/{id}", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		if s, _ := auth.SessionFromContext(r); time.Since(s.CreatedAt) >= 5*time.Minute {
			WriteError(w, r, 403, "forbidden", "re-authentication required")
			return
		}
		s, _ := auth.SessionFromContext(r)
		id := r.PathValue("id")
		if ids.Validate("dev", id) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		auditID, _ := ids.Mint("aud")
		e := dbTx(db, func(tx *sql.Tx) error {
			var n int
			if e := tx.QueryRow(`SELECT COUNT(*) FROM devices WHERE id=? AND user_id=?`, id, s.UserID).Scan(&n); e != nil || n == 0 {
				return sql.ErrNoRows
			}
			if _, e := tx.Exec(`UPDATE devices SET revoked_at=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339), id); e != nil {
				return e
			}
			if _, e := tx.Exec(`DELETE FROM key_envelopes WHERE device_id=?`, id); e != nil {
				return e
			}
			if _, e := tx.Exec(`DELETE FROM device_containers WHERE device_id=?`, id); e != nil {
				return e
			}
			_, e := tx.Exec(`INSERT INTO audit_events(id,user_id,event,container_id,object_id,created_at,at,outcome,actor_user_id,actor_device_id,request_id,reason_code) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, auditID, s.UserID, "device.revoke", "", "", time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339), "success", s.UserID, id, r.Header.Get("X-Request-Id"), "")
			return e
		})
		if e == sql.ErrNoRows {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		if e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	mux.Handle("POST /api/v1/devices/pairing-token", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		if s, _ := auth.SessionFromContext(r); time.Since(s.CreatedAt) >= 5*time.Minute {
			WriteError(w, r, 403, "forbidden", "re-authentication required")
			return
		}
		s, _ := auth.SessionFromContext(r)
		tok, c, e := auth.MintSessionPairingToken(cfg.Secrets.PairingSecret, s.UserID, s.ID, time.Now().UTC())
		if e != nil {
			WriteError(w, r, 503, "unavailable", "pairing is unavailable")
			return
		}
		scheme := "https"
		if cfg.Server.DevInsecureCookies && !cfg.Server.BehindProxy {
			scheme = "http"
		}
		deepLink := "kynotes://pair?host=" + url.QueryEscape(scheme+"://"+r.Host) + "&token=" + url.QueryEscape(tok)
		writeJSON(w, map[string]any{"token": tok, "expiresAt": time.Unix(c.Exp, 0).UTC().Format(time.RFC3339), "deepLink": deepLink})
	})))
	mux.Handle("POST /api/v1/devices/register", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(cfg.Secrets.PairingSecret) < 32 {
			WriteError(w, r, 503, "unavailable", "pairing is unavailable")
			return
		}
		var in struct {
			PairingToken, PublicKey, Platform string
			LabelCiphertext                   string `json:"labelCiphertext"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var raw []byte
		var e error
		if raw, e = base64.StdEncoding.DecodeString(in.PublicKey); e != nil || len(raw) != 32 {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var userID string
		parts := strings.Split(in.PairingToken, ".")
		if len(parts) != 2 {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		p, _ := base64.RawURLEncoding.DecodeString(parts[0])
		var claim auth.PairingClaims
		if json.Unmarshal(p, &claim) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		if _, e = auth.ParsePairingToken(cfg.Secrets.PairingSecret, in.PairingToken, claim.Sub, time.Now().UTC()); e != nil {
			WriteError(w, r, 401, "unauthenticated", "invalid pairing token")
			return
		}
		userID = claim.Sub
		fp := sha256.Sum256(raw)
		deviceID, _ := ids.Mint("dev")
		secretBytes := make([]byte, 24)
		if _, e = rand.Read(secretBytes); e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		secret := hex.EncodeToString(secretBytes)
		sh := sha256.Sum256([]byte(secret))
		nonceHash := sha256.Sum256([]byte(claim.Nonce))
		label, _ := base64.StdEncoding.DecodeString(in.LabelCiphertext)
		if len(label) > 4096 {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		e = dbTx(db, func(tx *sql.Tx) error {
			// Recheck expiry after acquiring the writer lock.
			currentTime := time.Now().UTC()
			if !currentTime.Before(time.Unix(claim.Exp, 0)) {
				return errors.New("expired pairing token")
			}
			now = currentTime.Format(time.RFC3339)
			var subject string
			if err := tx.QueryRow(`SELECT sso_subject FROM users WHERE id=? AND status='active'`, userID).Scan(&subject); err != nil {
				return err
			}
			originSession := ""
			if claim.SessionID != "" {
				var issuer string
				if err := tx.QueryRow(`SELECT sso_issuer FROM sessions WHERE id=? AND user_id=? AND revoked_at='' AND expires_at>? AND hard_expires_at>?`, claim.SessionID, userID, now, now).Scan(&issuer); err != nil {
					return err
				}
				if issuer != "" {
					originSession = claim.SessionID
				}
			} else if subject != "" {
				// Pre-upgrade tokens cannot prove whether their authorizing SSO login ended.
				return errors.New("unbound SSO pairing token")
			}
			if _, e := tx.Exec(`INSERT INTO pairing_nonces(nonce,purpose,user_id,used_at,expires_at) VALUES(?,?,?,?,?)`, hex.EncodeToString(nonceHash[:]), claim.Purpose, userID, now, time.Unix(claim.Exp, 0).UTC().Format(time.RFC3339)); e != nil {
				return e
			}
			var existing string
			if scanErr := tx.QueryRow(`SELECT id FROM devices WHERE user_id=? AND fingerprint=?`, userID, hex.EncodeToString(fp[:])).Scan(&existing); scanErr == nil {
				deviceID = existing
				_, e = tx.Exec(`UPDATE devices SET public_key=?,secret_hash=?,label_ciphertext=?,platform=?,revoked_at='',sso_session_id=? WHERE id=?`, in.PublicKey, "sha256:"+hex.EncodeToString(sh[:]), label, in.Platform, originSession, existing)
				return e
			}
			_, e = tx.Exec(`INSERT INTO devices(id,user_id,public_key,fingerprint,secret_hash,label_ciphertext,platform,created_at,sso_session_id) VALUES(?,?,?,?,?,?,?,?,?)`, deviceID, userID, in.PublicKey, hex.EncodeToString(fp[:]), "sha256:"+hex.EncodeToString(sh[:]), label, in.Platform, now, originSession)
			return e
		})
		if e != nil {
			WriteError(w, r, 409, "pairing_token_used", "pairing token already used")
			return
		}
		writeJSON(w, map[string]string{"deviceId": deviceID, "deviceSecret": secret, "fingerprint": hex.EncodeToString(fp[:])})
	}))
}
