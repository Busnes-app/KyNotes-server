package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Busness-app/ky-primitives/syncauth"
	"github.com/Busness-app/kynotes-server/internal/auth"
	"github.com/Busness-app/kynotes-server/internal/config"
	"github.com/Busness-app/kynotes-server/internal/ids"
	"github.com/Busness-app/kynotes-server/internal/sso"
	"github.com/Busness-app/kynotes-server/internal/storage"
)

type syncSettingsKey struct{}

type directoryUser struct {
	Schemas    []string `json:"schemas"`
	ID         string   `json:"id"`
	ExternalID string   `json:"externalId"`
	UserName   string   `json:"userName"`
	Active     *bool    `json:"active"`
	Meta       struct {
		Version string `json:"version"`
	} `json:"meta"`
}

func directoryIdentifier(s string) bool {
	return s != "" && len(s) <= 256 && strings.TrimSpace(s) == s && !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) })
}

func (u directoryUser) revision(kind string) (int64, error) {
	n, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(u.Meta.Version, `W/"`), `"`), 10, 64)
	if err != nil || n <= 0 || u.Meta.Version != fmt.Sprintf(`W/"%d"`, n) || !directoryIdentifier(u.ID) || u.ExternalID != u.ID || u.Active == nil || (u.UserName != "" && !directoryIdentifier(u.UserName)) || (u.Active != nil && *u.Active && u.UserName == "") || len(u.Schemas) != 1 || u.Schemas[0] != "urn:ietf:params:scim:schemas:core:2.0:User" {
		return 0, errors.New("invalid versioned user")
	}
	switch kind {
	case "user.created", "user.updated":
	case "user.deleted":
		if *u.Active {
			return 0, errors.New("active deletion")
		}
	default:
		return 0, errors.New("unsupported event")
	}
	return n, nil
}

func registerDirectorySync(mux *http.ServeMux, db *sql.DB, cfg config.Config, settings *sso.Store) {
	verify := syncauth.Middleware(func(r *http.Request) ([]byte, error) {
		return []byte(r.Context().Value(syncSettingsKey{}).(sso.SSOSettings).HMACSecret), nil
	}, syncauth.Options{}, cfg.Server.MaxRequestBytes, nil)
	wrap := func(handler http.HandlerFunc) http.Handler {
		verified := verify(handler)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			r = r.WithContext(context.WithValue(r.Context(), syncSettingsKey{}, settings.Load()))
			verified.ServeHTTP(&syncAuthWriter{ResponseWriter: w, request: r}, r)
		})
	}
	apply := wrap(func(w http.ResponseWriter, r *http.Request) { directoryRequest(w, r, db, cfg, false) })
	for _, path := range []string{"/api/v1/sync/events", "/api/sync/events", "/sync/events"} {
		mux.Handle("POST "+path, apply)
	}
	mux.Handle("POST /api/v1/sync/readback", wrap(func(w http.ResponseWriter, r *http.Request) { directoryRequest(w, r, db, cfg, true) }))
}

func directoryRequest(w http.ResponseWriter, r *http.Request, db *sql.DB, cfg config.Config, readback bool) {
	settings := r.Context().Value(syncSettingsKey{}).(sso.SSOSettings)
	event, ok := syncauth.EventFromContext(r)
	if !ok {
		WriteError(w, r, 401, "invalid_signature", "unverified event")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		WriteError(w, r, 400, "invalid_request", "failed to read event")
		return
	}
	var u directoryUser
	var revision int64
	if readback {
		// The signature does not bind method/path: both purpose and subject must be signed.
		var query struct {
			Subject string `json:"subject"`
		}
		if json.Unmarshal(body, &query) != nil || event.Type != "user.readback" || !directoryIdentifier(query.Subject) {
			WriteError(w, r, 400, "invalid_event", "invalid readback request")
			return
		}
		u.ID = query.Subject
	} else {
		if json.Unmarshal(body, &u) != nil {
			WriteError(w, r, 400, "invalid_json", "invalid user resource")
			return
		}
		revision, err = u.revision(event.Type)
		if err != nil {
			WriteError(w, r, 400, "invalid_event", "expected a versioned SCIM User")
			return
		}
	}
	if settings.IssuerURL == "" || !directoryIdentifier(event.ID) {
		WriteError(w, r, 400, "invalid_event", "directory issuer and event ID required")
		return
	}
	tx, err := db.BeginTx(r.Context(), nil)
	if err != nil {
		WriteError(w, r, 500, "sync_failed", "transaction failed")
		return
	}
	defer tx.Rollback()
	var current int
	if err = tx.QueryRow(`SELECT count(*) FROM server_settings WHERE key='sso_hmac_secret' AND value=? AND EXISTS(SELECT 1 FROM server_settings WHERE key='sso_issuer_url' AND value=?)`, settings.HMACSecret, settings.IssuerURL).Scan(&current); err != nil || current != 1 {
		WriteError(w, r, 422, "sync_configuration_changed", "directory configuration changed")
		return
	}
	var prior int64
	var digest string
	err = tx.QueryRow(`SELECT revision,digest FROM sso_directory_state WHERE issuer=? AND subject=?`, settings.IssuerURL, u.ID).Scan(&prior, &digest)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		WriteError(w, r, 500, "sync_failed", "state lookup failed")
		return
	}
	if readback {
		var status string
		err = tx.QueryRow(`SELECT status FROM users WHERE sso_issuer=? AND sso_subject=?`, settings.IssuerURL, u.ID).Scan(&status)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			WriteError(w, r, 500, "sync_failed", "account lookup failed")
			return
		}
		observed := map[string]any{"subject": u.ID, "present": err == nil, "active": status == "active", "version": ""}
		if prior > 0 {
			observed["version"] = fmt.Sprintf(`W/"%d"`, prior)
		}
		if err = storage.RecordAuditOutcomeTx(tx, "", "directory.readback", "", "", "success", "", RequestID(r)); err == nil {
			err = tx.Commit()
		}
		if err != nil {
			WriteError(w, r, 500, "sync_failed", "readback audit failed")
			return
		}
		writeJSON(w, observed)
		return
	}
	sum := sha256.Sum256(append([]byte(event.Type+"\n"), body...))
	incoming := hex.EncodeToString(sum[:])
	// 409 on user.created is treated as success by the sender; use 422 for conflicts.
	if revision < prior || (revision == prior && incoming != digest) {
		WriteError(w, r, 422, "directory_version_conflict", "stale or conflicting resource version")
		return
	}
	if _, err = tx.Exec(`DELETE FROM sso_sync_events WHERE expires_at < ?`, time.Now().Unix()); err != nil {
		WriteError(w, r, 500, "sync_failed", "replay pruning failed")
		return
	}
	var oldIssuer, oldDigest string
	err = tx.QueryRow(`SELECT issuer,digest FROM sso_sync_events WHERE event_id=?`, event.ID).Scan(&oldIssuer, &oldDigest)
	if err == nil && (oldIssuer != settings.IssuerURL || oldDigest != incoming) {
		WriteError(w, r, 422, "event_conflict", "event ID already used")
		return
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		WriteError(w, r, 500, "sync_failed", "replay lookup failed")
		return
	}
	if _, err = tx.Exec(`INSERT INTO sso_sync_events(event_id,expires_at,issuer,digest) VALUES(?,?,?,?) ON CONFLICT(event_id) DO NOTHING`, event.ID, event.At.Add(syncauth.DefaultWindow).Unix(), settings.IssuerURL, incoming); err != nil {
		WriteError(w, r, 500, "sync_failed", "replay admission failed")
		return
	}
	status := "already_applied"
	if revision > prior {
		status = "applied"
		_, err = tx.Exec(`INSERT INTO sso_directory_state(issuer,subject,revision,digest,active,event_id) VALUES(?,?,?,?,?,?) ON CONFLICT(issuer,subject) DO UPDATE SET revision=excluded.revision,digest=excluded.digest,active=excluded.active,event_id=excluded.event_id`, settings.IssuerURL, u.ID, revision, incoming, *u.Active, event.ID)
		if err == nil {
			err = syncSingleUser(tx, cfg, settings.IssuerURL, &u)
		}
		if err == nil && !*u.Active {
			now := time.Now().UTC().Format(time.RFC3339)
			for _, table := range []string{"sessions", "devices"} {
				if _, err = tx.Exec(`UPDATE `+table+` SET revoked_at=? WHERE revoked_at='' AND user_id IN (SELECT id FROM users WHERE sso_issuer=? AND sso_subject=?)`, now, settings.IssuerURL, u.ID); err != nil {
					break
				}
			}
		}
		if err == nil {
			err = storage.RecordAuditOutcomeTx(tx, "", "directory.apply", "", event.ID, "success", fmt.Sprintf("revision=%d,active=%t", revision, *u.Active), RequestID(r))
		}
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		WriteError(w, r, 500, "sync_failed", "directory event was not applied")
		return
	}
	writeJSON(w, map[string]any{"status": status, "eventId": event.ID, "version": u.Meta.Version})
}

func syncSingleUser(db *sql.Tx, cfg config.Config, issuer string, u *directoryUser) error {
	if u.ID == "" {
		return errors.New("missing directory subject")
	}
	var existingID, existingUsername, existingRole, existingStatus, existingSubject, existingIssuer string
	err := db.QueryRow(`SELECT id, username, role, status, coalesce(sso_subject,''),sso_issuer FROM users WHERE sso_subject=? AND sso_issuer=?`, u.ID, issuer).Scan(&existingID, &existingUsername, &existingRole, &existingStatus, &existingSubject, &existingIssuer)
	if errors.Is(err, sql.ErrNoRows) && u.UserName != "" {
		err = db.QueryRow(`SELECT id, username, role, status, coalesce(sso_subject,''),sso_issuer FROM users WHERE username=?`, strings.ToLower(u.UserName)).Scan(&existingID, &existingUsername, &existingRole, &existingStatus, &existingSubject, &existingIssuer)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && existingSubject != "" && (existingSubject != u.ID || existingIssuer != issuer) {
		return errors.New("directory subject conflict")
	}
	now := time.Now().UTC().Format(time.RFC3339)

	username := strings.ToLower(u.UserName)
	if username == "" {
		username = existingUsername
	}
	role := existingRole
	if role == "" {
		role = "user"
	}
	status := "disabled"
	if *u.Active {
		status = "active"
	}

	if errors.Is(err, sql.ErrNoRows) && !*u.Active {
		// An absent inactive account needs only its durable fence, never a placeholder.
		return nil
	}
	if err != nil {
		// Insert new user
		if username == "" {
			username = u.ID
		}
		newID, mintErr := ids.Mint("usr")
		if mintErr != nil {
			return mintErr
		}
		dummyBytes := make([]byte, 32)
		_, _ = rand.Read(dummyBytes)
		dummySecret := hex.EncodeToString(dummyBytes)
		dummyHash, hashErr := auth.HashAuthSecret(dummySecret)
		if hashErr != nil {
			return hashErr
		}
		loginSalt := auth.SyntheticLoginSalt(cfg.Secrets.ServerSaltKey, username)

		_, err = db.Exec(`INSERT INTO users(id, username, auth_secret_hash, login_salt, login_iterations, role, status, sso_subject, sso_issuer, created_at, updated_at) VALUES(?, ?, ?, ?, 600000, ?, ?, ?, ?, ?, ?)`,
			newID, username, dummyHash, loginSalt, role, status, u.ID, issuer, now, now)
		return err
	}

	// Update existing user
	_, err = db.Exec(`UPDATE users SET username=?, role=?, status=?, sso_subject=?, sso_issuer=?, updated_at=? WHERE id=?`,
		username, role, status, u.ID, issuer, now, existingID)
	return err
}
