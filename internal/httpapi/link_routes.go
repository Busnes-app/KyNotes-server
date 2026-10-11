package httpapi

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// Device linking relay (team keys P3c, spec §8). A row holds a commitment, two one-time public keys
// and one sealed bundle: nothing the server can open. It belongs to one user and two of that user's
// live sessions, the newcomer that created it and the trusted session that claimed it.
const (
	linkTTL         = 10 * time.Minute
	linkMaxPending  = 3
	linkBundleBytes = 61 // 0x01 | nonce(12) | ChaCha20-Poly1305(identity private key)(48)
	linkCommitLabel = "kynotes/link-commit/v1"
)

var (
	errLinkGone = errors.New("link request gone")
	errLinkBusy = errors.New("too many pending link requests")
)

// Session liveness of the row's other side, at ?1 (now).
const (
	liveNewcomer = ` AND EXISTS(SELECT 1 FROM sessions x WHERE x.id=link_requests.newcomer_session_id AND x.revoked_at='' AND x.expires_at>?1 AND x.hard_expires_at>?1)`
	liveApprover = ` AND EXISTS(SELECT 1 FROM sessions x WHERE x.id=link_requests.approver_session_id AND x.revoked_at='' AND x.expires_at>?1 AND x.hard_expires_at>?1)`
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// readField decodes {"<name>": "<base64>"} of exactly size bytes.
func readField(w http.ResponseWriter, r *http.Request, name string, size int) ([]byte, bool) {
	var in map[string]string
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&in) != nil {
		return nil, false
	}
	b, err := base64.StdEncoding.DecodeString(in[name])
	return b, err == nil && len(b) == size
}

func sessionLive(tx *sql.Tx, s auth.Session, now time.Time) error {
	_, err := auth.RecheckSessionTx(tx, s, now)
	return err
}

// partyLive is sessionLive for either side of a link. A local session whose password an
// administrator set proves nothing about the user: it can neither receive the identity nor take the
// approver slot.
func partyLive(tx *sql.Tx, s auth.Session, now time.Time) error {
	if err := sessionLive(tx, s, now); err != nil || s.SSOIssuer != "" {
		return err
	}
	var adminKnown int
	if err := tx.QueryRow(`SELECT password_admin_known FROM users WHERE id=?`, s.UserID).Scan(&adminKnown); err != nil {
		return err
	}
	if adminKnown != 0 {
		return auth.ErrPasswordAdminKnown
	}
	return nil
}

// linkHandler: no-store, CSRF on mutations, a well-formed path ID or a uniform 404.
func linkHandler(h func(w http.ResponseWriter, r *http.Request, s auth.Session, id string)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		id := r.PathValue("id")
		if id != "" && ids.Validate("lnk", id) != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		s, _ := auth.SessionFromContext(r)
		h(w, r, s, id)
	})
}

// linkWriter keeps the start of an error body, and whether the step audited its own refusal.
type linkWriter struct {
	responseWriter
	body    []byte
	audited bool
}

func (w *linkWriter) Write(p []byte) (int, error) {
	if len(w.body) < 512 {
		w.body = append(w.body, p...)
	}
	return w.responseWriter.Write(p)
}

// markAudited tells linkAudited that the step recorded its refusal itself.
func markAudited(w http.ResponseWriter) {
	if lw, ok := w.(*linkWriter); ok {
		lw.audited = true
	}
}

// linkAudited gates a relay step on a session and audits every refusal under the step's event, with
// the status the caller saw. The object is the request ID only when well formed. A KySignOn
// confirmation in progress is not a refusal (it has its own auth.sso_step_up.start audit). The
// link-step and link rate buckets bound how many refusal rows one account can write.
func linkAudited(db *sql.DB, event string, next http.Handler) http.Handler {
	return auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &linkWriter{responseWriter: responseWriter{ResponseWriter: w}}
		next.ServeHTTP(rw, r)
		if rw.status < 400 || rw.audited {
			return
		}
		var reply struct{ Error struct{ Code string } }
		if json.Unmarshal(rw.body, &reply) == nil && (reply.Error.Code == "sso_step_up_required" || reply.Error.Code == "step_up_pending") {
			return
		}
		s, _ := auth.SessionFromContext(r)
		id := r.PathValue("id")
		if ids.Validate("lnk", id) != nil {
			id = ""
		}
		outcome := "denied"
		if rw.status >= 500 {
			outcome = "failure"
		}
		recordAuditOutcome(db, s.UserID, event, "", id, outcome, strconv.Itoa(rw.status), RequestID(r))
	}))
}

// linkTx runs one relay step after rechecking the caller. Every miss is the same 404, so a caller
// learns nothing about requests that are not its own.
func linkTx(w http.ResponseWriter, r *http.Request, db *sql.DB, s auth.Session, recheck func(*sql.Tx, auth.Session, time.Time) error, step func(tx *sql.Tx, now time.Time) error) bool {
	err := dbTx(db, func(tx *sql.Tx) error {
		now := time.Now().UTC()
		if err := recheck(tx, s, now); err != nil {
			return err
		}
		return step(tx, now)
	})
	switch {
	case err == nil:
		return true
	case errors.Is(err, auth.ErrSessionInvalid):
		auth.WriteAuthError(w, "unauthenticated", "authentication required")
	case errors.Is(err, auth.ErrStepUpInvalid):
		auth.WriteAuthError(w, "step_up_required", "re-enter your password to continue")
	case errors.Is(err, auth.ErrPasswordAdminKnown):
		WriteError(w, r, 409, "password_change_required", "change the password an administrator set first")
	case errors.Is(err, errLinkGone):
		WriteError(w, r, 404, "not_found", "not found")
	case errors.Is(err, errLinkBusy):
		WriteError(w, r, 409, "already_exists", "too many pending link requests; cancel one or wait ten minutes")
	default:
		WriteError(w, r, 500, "internal", "internal server error")
	}
	return false
}

func audit(tx *sql.Tx, r *http.Request, s auth.Session, event, id, outcome, reason string) error {
	return storage.RecordAuditOutcomeTx(tx, s.UserID, event, "", id, outcome, reason, RequestID(r))
}

func LinkRoutes(mux RouteMux, db *sql.DB) {
	step := func(event string, h http.Handler) http.Handler { return linkAudited(db, event, h) }
	mux.Handle("POST /api/v1/me/link-requests", step("identity.link.request", createLink(db)))
	mux.Handle("GET /api/v1/me/link-requests", auth.RequireSession(db, listLinks(db)))
	mux.Handle("POST /api/v1/me/link-requests/{id}/claim", step("identity.link.claim", claimLink(db)))
	mux.Handle("POST /api/v1/me/link-requests/{id}/reveal", step("identity.link.reveal", revealLink(db)))
	mux.Handle("POST /api/v1/me/link-requests/{id}/approve", step("identity.link.approve", auth.RequireUserActionStepUp(db, approveLink(db))))
	mux.Handle("DELETE /api/v1/me/link-requests/{id}", step("identity.link.cancel", cancelLink(db)))
	// Polled every four seconds (link-poll bucket); its misses change nothing and are not audited.
	mux.Handle("POST /api/v1/me/link-requests/{id}/collect", auth.RequireSession(db, collectLink(db)))
}

func createLink(db *sql.DB) http.Handler {
	return linkHandler(func(w http.ResponseWriter, r *http.Request, s auth.Session, _ string) {
		commitment, ok := readField(w, r, "commitment", 32)
		if !ok {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		id, err := ids.Mint("lnk")
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		var expires string
		if !linkTx(w, r, db, s, partyLive, func(tx *sql.Tx, now time.Time) error {
			at := now.Format(time.RFC3339)
			expires = now.Add(linkTTL).Format(time.RFC3339)
			var identities int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM user_identities WHERE user_id=?`, s.UserID).Scan(&identities); err != nil {
				return err
			}
			if identities == 0 {
				return errLinkGone // nothing to link
			}
			// The same browser starting again replaces its earlier request.
			if _, err := tx.Exec(`DELETE FROM link_requests WHERE newcomer_session_id=?`, s.ID); err != nil {
				return err
			}
			var pending int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM link_requests WHERE user_id=? AND expires_at>?`, s.UserID, at).Scan(&pending); err != nil {
				return err
			}
			if pending >= linkMaxPending {
				return errLinkBusy
			}
			if _, err := tx.Exec(`INSERT INTO link_requests(id,user_id,newcomer_session_id,commitment,created_at,expires_at) VALUES(?,?,?,?,?,?)`, id, s.UserID, s.ID, commitment, at, expires); err != nil {
				return err
			}
			return audit(tx, r, s, "identity.link.request", id, "success", "")
		}) {
			return
		}
		writeJSON(w, map[string]string{"id": id, "expiresAt": expires})
	})
}

// listLinks shows the trusted side the account's live requests from other live sessions that are
// unclaimed or claimed by the caller, with the newcomer key once revealed.
func listLinks(db *sql.DB) http.Handler {
	return linkHandler(func(w http.ResponseWriter, r *http.Request, s auth.Session, _ string) {
		rows, err := db.Query(`SELECT id,commitment,created_at,expires_at,approver_session_id IS NOT NULL,COALESCE(newcomer_key,X'') FROM link_requests
 WHERE user_id=?2 AND expires_at>?1 AND newcomer_session_id<>?3 AND bundle IS NULL AND (approver_session_id IS NULL OR approver_session_id=?3)`+liveNewcomer+` ORDER BY created_at,id`, time.Now().UTC().Format(time.RFC3339), s.UserID, s.ID)
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var id, created, expires string
			var commitment, newcomer []byte
			var claimed bool
			if err := rows.Scan(&id, &commitment, &created, &expires, &claimed, &newcomer); err != nil {
				WriteError(w, r, 500, "internal", "internal server error")
				return
			}
			row := map[string]any{"id": id, "commitment": b64(commitment), "createdAt": created, "expiresAt": expires, "claimed": claimed, "newcomerKey": ""}
			if len(newcomer) > 0 {
				row["newcomerKey"] = b64(newcomer)
			}
			out = append(out, row)
		}
		if rows.Err() != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		writeJSON(w, out)
	})
}

func claimLink(db *sql.DB) http.Handler {
	return linkHandler(func(w http.ResponseWriter, r *http.Request, s auth.Session, id string) {
		key, ok := readField(w, r, "approverKey", 32)
		if !ok {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		if !linkTx(w, r, db, s, partyLive, func(tx *sql.Tx, now time.Time) error {
			res, err := tx.Exec(`UPDATE link_requests SET approver_session_id=?4,approver_key=?5 WHERE id=?2 AND user_id=?3 AND expires_at>?1 AND newcomer_session_id<>?4 AND approver_session_id IS NULL`+liveNewcomer, now.Format(time.RFC3339), id, s.UserID, s.ID, key)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return errLinkGone
			}
			return audit(tx, r, s, "identity.link.claim", id, "success", "")
		}) {
			return
		}
		w.WriteHeader(204)
	})
}

// revealLink takes the newcomer's key after a claim, only if it is the key the request committed to.
func revealLink(db *sql.DB) http.Handler {
	return linkHandler(func(w http.ResponseWriter, r *http.Request, s auth.Session, id string) {
		key, ok := readField(w, r, "newcomerKey", 32)
		if !ok {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		refused := false
		if !linkTx(w, r, db, s, partyLive, func(tx *sql.Tx, now time.Time) error {
			var commitment []byte
			err := tx.QueryRow(`SELECT commitment FROM link_requests WHERE id=?2 AND user_id=?3 AND newcomer_session_id=?4 AND expires_at>?1 AND approver_key IS NOT NULL AND newcomer_key IS NULL`+liveApprover, now.Format(time.RFC3339), id, s.UserID, s.ID).Scan(&commitment)
			if errors.Is(err, sql.ErrNoRows) {
				return errLinkGone
			}
			if err != nil {
				return err
			}
			want := sha256.Sum256(append([]byte(linkCommitLabel), key...))
			if !bytes.Equal(want[:], commitment) {
				// Not the committed key: this attempt is over.
				refused = true
				markAudited(w)
				if _, err := tx.Exec(`DELETE FROM link_requests WHERE id=?`, id); err != nil {
					return err
				}
				return audit(tx, r, s, "identity.link.refuse", id, "denied", "commitment")
			}
			res, err := tx.Exec(`UPDATE link_requests SET newcomer_key=? WHERE id=? AND newcomer_key IS NULL`, key, id)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return errLinkGone
			}
			return audit(tx, r, s, "identity.link.reveal", id, "success", "")
		}) {
			return
		}
		if refused {
			WriteError(w, r, 400, "invalid_request", "the key does not match this request")
			return
		}
		w.WriteHeader(204)
	})
}

// cancelLink: any session of the account may end a request ("Not me" on the trusted side).
func cancelLink(db *sql.DB) http.Handler {
	return linkHandler(func(w http.ResponseWriter, r *http.Request, s auth.Session, id string) {
		if !linkTx(w, r, db, s, sessionLive, func(tx *sql.Tx, now time.Time) error {
			res, err := tx.Exec(`DELETE FROM link_requests WHERE id=? AND user_id=?`, id, s.UserID)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return errLinkGone
			}
			return audit(tx, r, s, "identity.link.cancel", id, "success", "")
		}) {
			return
		}
		w.WriteHeader(204)
	})
}

// approveLink stores the bundle once, from the session that claimed the request, after a fresh
// step-up (an administrator-known password is refused in the recheck), while the newcomer session is
// still live and only after the newcomer revealed its committed key.
func approveLink(db *sql.DB) http.Handler {
	return linkHandler(func(w http.ResponseWriter, r *http.Request, s auth.Session, id string) {
		bundle, ok := readField(w, r, "bundle", linkBundleBytes)
		if !ok {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		if !linkTx(w, r, db, s, auth.RecheckUserActionTx, func(tx *sql.Tx, now time.Time) error {
			res, err := tx.Exec(`UPDATE link_requests SET bundle=?5 WHERE id=?2 AND user_id=?3 AND approver_session_id=?4 AND expires_at>?1 AND newcomer_key IS NOT NULL AND bundle IS NULL`+liveNewcomer, now.Format(time.RFC3339), id, s.UserID, s.ID, bundle)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return errLinkGone
			}
			return audit(tx, r, s, "identity.link.approve", id, "success", "")
		}) {
			return
		}
		w.WriteHeader(204)
	})
}

// collectLink: the newcomer's view of its request, polled. A plain read answers until a bundle is
// ready; only then does a write transaction deliver it once and delete the row. A POST with CSRF,
// because it deletes.
func collectLink(db *sql.DB) http.Handler {
	return linkHandler(func(w http.ResponseWriter, r *http.Request, s auth.Session, id string) {
		var approver, newcomer []byte
		var expires string
		var ready, adminKnown bool
		err := db.QueryRow(`SELECT COALESCE(l.approver_key,X''),COALESCE(l.newcomer_key,X''),l.bundle IS NOT NULL,l.expires_at,u.password_admin_known<>0 FROM link_requests l JOIN users u ON u.id=l.user_id
 WHERE l.id=?2 AND l.user_id=?3 AND l.newcomer_session_id=?4 AND l.expires_at>?1`, time.Now().UTC().Format(time.RFC3339), id, s.UserID, s.ID).Scan(&approver, &newcomer, &ready, &expires, &adminKnown)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			WriteError(w, r, 404, "not_found", "not found")
			return
		case err != nil:
			WriteError(w, r, 500, "internal", "internal server error")
			return
		case adminKnown && s.SSOIssuer == "":
			WriteError(w, r, 409, "password_change_required", "change the password an administrator set first")
			return
		}
		out := map[string]string{"state": "pending", "expiresAt": expires}
		if len(approver) > 0 {
			out["state"], out["approverKey"] = "claimed", b64(approver)
		}
		if len(newcomer) > 0 {
			out["state"] = "revealed"
		}
		if !ready {
			writeJSON(w, out)
			return
		}
		if !linkTx(w, r, db, s, partyLive, func(tx *sql.Tx, now time.Time) error {
			var bundle []byte
			err := tx.QueryRow(`DELETE FROM link_requests WHERE id=?2 AND user_id=?3 AND newcomer_session_id=?4 AND expires_at>?1 AND bundle IS NOT NULL RETURNING bundle`, now.Format(time.RFC3339), id, s.UserID, s.ID).Scan(&bundle)
			if errors.Is(err, sql.ErrNoRows) {
				return errLinkGone
			}
			if err != nil {
				return err
			}
			out["state"], out["bundle"] = "approved", b64(bundle)
			return audit(tx, r, s, "identity.link.collect", id, "success", "")
		}) {
			return
		}
		writeJSON(w, out)
	})
}
