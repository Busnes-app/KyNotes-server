package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/storage"
	"io"
	"net/http"
	"time"
)

// MaxCommentBytes caps one comment's ciphertext (owner decision Q7).
const MaxCommentBytes = 64 << 10

var errCommentPageGone = errors.New("comment page deleted")

func CollabRoutes(mux RouteMux, db *sql.DB, limits config.Limits) {
	mux.Handle("GET /api/v1/containers/{id}/members", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := auth.SessionFromContext(r)
		cid := r.PathValue("id")
		var role string
		if db.QueryRow(`SELECT role FROM memberships WHERE container_id=? AND user_id=? AND revoked_at=''`, cid, s.UserID).Scan(&role) != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		// keyResetAt (stewards only): the member's last self-service key reset, which retires this
		// notebook's key until a steward mints the next one; the cause of a waiting notebook.
		rows, err := db.Query(`SELECT m.user_id,u.username,m.role,COALESCE((SELECT MAX(a.created_at) FROM audit_events a WHERE a.user_id=m.user_id AND a.event='identity.create' AND a.outcome='success' AND a.reason_code LIKE '%,reset%'),''),m.approved,m.pending_role FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.container_id=? AND m.revoked_at='' ORDER BY u.username`, cid)
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var id, username, memberRole, resetAt string
			var approved bool
			var pending string
			if rows.Scan(&id, &username, &memberRole, &resetAt, &approved, &pending) != nil {
				WriteError(w, r, 500, "internal", "internal server error")
				return
			}
			member := map[string]any{"userId": id, "username": username, "role": memberRole, "approved": approved}
			if pending != "" {
				member["pendingRole"] = pending // the role approval grants; role reads viewer until then
			}
			if isSteward(role) && resetAt != "" {
				member["keyResetAt"] = resetAt
			}
			out = append(out, member)
		}
		writeJSON(w, out)
	})))
	mux.Handle("DELETE /api/v1/containers/{id}/members/{userID}", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
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
			WriteError(w, r, 403, "forbidden", "insufficient role")
			return
		}
		target := r.PathValue("userID")
		if ids.Validate("usr", target) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		if target == s.UserID {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		err := dbTx(db, func(tx *sql.Tx) error {
			var role, targetRole, invitedBy string
			if tx.QueryRow(`SELECT role FROM memberships WHERE container_id=? AND user_id=? AND revoked_at=''`, cid, s.UserID).Scan(&role) != nil || !isSteward(role) {
				return errInsufficientRole
			}
			// An admin removes another admin only when its own invitation admitted that membership.
			if tx.QueryRow(`SELECT role,invited_by FROM memberships WHERE container_id=? AND user_id=? AND revoked_at=''`, cid, target).Scan(&targetRole, &invitedBy) != nil || targetRole == "owner" || (role == "admin" && targetRole == "admin" && invitedBy != s.UserID) {
				return errInsufficientRole
			}
			if err := removeMemberTx(tx, cid, target); err != nil {
				return err
			}
			return storage.RecordAuditOutcomeTx(tx, s.UserID, "container.member_remove", cid, target, "success", "", RequestID(r))
		})
		if writeTeamKeyError(w, r, err) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	// A steward approves a member the server administrator added, on the team and its child workspaces.
	mux.Handle("POST /api/v1/containers/{id}/members/{userID}/approve", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		cid, target := r.PathValue("id"), r.PathValue("userID")
		if ids.Validate("cnt", cid) != nil || ids.Validate("usr", target) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		err := dbTx(db, func(tx *sql.Tx) error {
			var role string
			if err := tx.QueryRow(`SELECT m.role FROM memberships m JOIN containers c ON c.id=m.container_id AND c.deleted_at='' AND c.team_id='' WHERE m.container_id=? AND m.user_id=? AND m.revoked_at='' AND m.approved=1`, cid, s.UserID).Scan(&role); err != nil {
				return err
			}
			if !isSteward(role) {
				return errInsufficientRole
			}
			res, err := tx.Exec(`UPDATE memberships SET role=CASE WHEN approved=0 THEN pending_role ELSE role END,pending_role='',approved=1 WHERE user_id=? AND revoked_at='' AND container_id IN (SELECT id FROM containers WHERE (id=? OR team_id=?) AND deleted_at='')`, target, cid, cid)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return errNotMember
			}
			return storage.RecordAuditOutcomeTx(tx, s.UserID, "container.member_approve", cid, target, "success", "", RequestID(r))
		})
		if writeTeamKeyError(w, r, err) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	mux.Handle("POST /api/v1/containers/{id}/invitations", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
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
			WriteError(w, r, 403, "forbidden", "insufficient role")
			return
		}
		var in struct {
			InviteeID, Role string
			Envelopes       []invitationEnvelopeIn `json:"envelopes"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.InviteeID == "" {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		if ids.Validate("usr", in.InviteeID) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		if in.Role != "admin" && in.Role != "editor" && in.Role != "commenter" && in.Role != "viewer" {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		// Envelopes reach key_envelopes on acceptance: local password step-up only (ruling 13); SSO invitations carry no envelopes.
		if len(in.Envelopes) > 0 && !auth.HasUserStepUp(s) {
			auth.WriteAuthError(w, "step_up_required", "re-enter your password to continue")
			return
		}
		raw := make([]byte, 32)
		_, _ = rand.Read(raw)
		token := base64.RawURLEncoding.EncodeToString(raw)
		sum := sha256.Sum256([]byte(token))
		id, _ := ids.Mint("inv")
		now := time.Now().UTC()
		e := dbTx(db, func(tx *sql.Tx) error {
			if len(in.Envelopes) > 0 {
				if e := auth.RecheckUserStepUpTx(tx, s, time.Now().UTC()); e != nil {
					return e
				}
			}
			if _, e := tx.Exec(`INSERT INTO invitations(id,container_id,inviter_id,invitee_id,token_hash,role,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)`, id, cid, s.UserID, in.InviteeID, hex.EncodeToString(sum[:]), in.Role, now.Format(time.RFC3339), now.Add(24*time.Hour).Format(time.RFC3339)); e != nil {
				return e
			}
			for _, v := range in.Envelopes {
				if e := insertInvitationEnvelopeTx(tx, id, cid, s.UserID, in.InviteeID, v); e != nil {
					return e
				}
			}
			return nil
		})
		if writeTeamKeyError(w, r, e) {
			return
		}
		writeJSON(w, map[string]any{"id": id, "token": token, "expiresAt": now.Add(24 * time.Hour).UTC().Format(time.RFC3339)})
	})))
	mux.Handle("POST /api/v1/invitations/{id}/accept", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		var in struct {
			Token string `json:"token"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		if ids.Validate("inv", r.PathValue("id")) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		sum := sha256.Sum256([]byte(in.Token))
		id, tokenHash := r.PathValue("id"), hex.EncodeToString(sum[:])
		e := dbTx(db, func(tx *sql.Tx) error {
			now := time.Now().UTC().Format(time.RFC3339)
			// One read, in the transaction that consumes it: invitee, status and expiry cannot change before the update.
			var cid, inviter, role string
			if e := tx.QueryRow(`SELECT container_id,inviter_id,role FROM invitations WHERE id=? AND token_hash=? AND invitee_id=? AND status='pending' AND expires_at>?`, id, tokenHash, s.UserID, now).Scan(&cid, &inviter, &role); e != nil {
				return e
			}
			if _, e := tx.Exec(`UPDATE invitations SET status='accepted',responded_at=? WHERE id=?`, now, id); e != nil {
				return e
			}
			// The inviter must still be a live steward of a live container.
			var steward int
			if e := tx.QueryRow(`SELECT COUNT(*) FROM memberships m JOIN containers c ON c.id=m.container_id AND c.deleted_at='' JOIN users u ON u.id=m.user_id AND u.status='active' WHERE m.container_id=? AND m.user_id=? AND m.revoked_at='' AND m.role IN ('owner','admin')`, cid, inviter).Scan(&steward); e != nil {
				return e
			}
			if steward == 0 {
				return sql.ErrNoRows
			}
			readmit, e := admitMemberTx(tx, cid, s.UserID, role, inviter, true, now)
			if e != nil {
				return e
			}
			if e = storage.RecordAuditOutcomeTx(tx, s.UserID, "container.member_accept", cid, inviter, "success", fmt.Sprintf("role=%s,readmit=%t", role, readmit), RequestID(r)); e != nil {
				return e
			}
			return moveInvitationEnvelopesTx(tx, id, s.UserID, now)
		})
		if e != nil {
			auditRefusal(db, r, s.UserID, "container.member_accept", "", id, e)
		}
		if errors.Is(e, errMembershipExists) {
			WriteError(w, r, 409, "already_exists", "membership already exists")
			return
		}
		if writeTeamKeyError(w, r, e) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	mux.Handle("POST /api/v1/objects/{id}/comments", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		oid := r.PathValue("id")
		if ids.Validate("obj", oid) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var cid, role string
		// A deleted page (or a deleted notebook's page) takes no comments: they would never be charged.
		if db.QueryRow(`SELECT o.container_id,m.role FROM objects o JOIN memberships m ON m.container_id=o.container_id AND m.user_id=? WHERE o.id=? AND o.deleted_at='' AND m.revoked_at=''`, s.UserID, oid).Scan(&cid, &role) != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		if role == "viewer" {
			WriteError(w, r, 403, "forbidden", "insufficient role")
			return
		}
		var in struct {
			BodyCiphertext string   `json:"bodyCiphertext"`
			KeyGeneration  int      `json:"keyGeneration"`
			Mentions       []string `json:"mentions"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		if in.KeyGeneration < 1 || len(in.Mentions) > 100 {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		if writeTeamKeyError(w, r, checkWriteGate(db, cid, s.UserID, int64(in.KeyGeneration), r.Header.Get(keySchemeHeader))) {
			return
		}
		body, e := base64.StdEncoding.DecodeString(in.BodyCiphertext)
		if e != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		if len(body) > MaxCommentBytes {
			WriteError(w, r, 413, "payload_too_large", "This comment is too long. Shorten it, or put the text on the page.")
			return
		}
		id, _ := ids.Mint("cmt")
		now := time.Now().UTC().Format(time.RFC3339)
		e = dbTx(db, func(tx *sql.Tx) error {
			if e := checkWriteGate(tx, cid, s.UserID, int64(in.KeyGeneration), r.Header.Get(keySchemeHeader)); e != nil {
				return e
			}
			// Again inside the write: a page deleted meanwhile has dropped its comments and takes no new one.
			var live int
			if e := tx.QueryRow(`SELECT COUNT(*) FROM objects WHERE id=? AND deleted_at=''`, oid).Scan(&live); e != nil || live == 0 {
				if e == nil {
					e = errCommentPageGone
				}
				return e
			}
			// Comments are stored writes like any other: charged to the notebook owner's and team's quota.
			if over, e := quotaExceeded(tx, limits, cid, "", int64(len(body))); e != nil || over {
				if e == nil {
					e = errQuota
				}
				return e
			}
			var seq int64
			if e := tx.QueryRow(`UPDATE containers SET change_seq=change_seq+1,updated_at=? WHERE id=? RETURNING change_seq`, now, cid).Scan(&seq); e != nil {
				return e
			}
			if _, e := tx.Exec(`INSERT INTO comments(id,container_id,object_id,author_user_id,body_ciphertext,key_generation,change_seq,created_at) VALUES(?,?,?,?,?,?,?,?)`, id, cid, oid, s.UserID, body, in.KeyGeneration, seq, now); e != nil {
				return e
			}
			// Only a current member of the notebook can be mentioned; anyone else refuses the comment.
			for _, uid := range in.Mentions {
				res, e := tx.Exec(`INSERT INTO mentions(comment_id,mentioned_user_id) SELECT ?,user_id FROM memberships WHERE container_id=? AND user_id=? AND revoked_at=''`, id, cid, uid)
				if e != nil {
					return e
				}
				if n, _ := res.RowsAffected(); n != 1 {
					return errMentionNotMember
				}
			}
			return checkDatabaseBudget(tx)
		})
		if writeStorageFull(w, r, e) {
			return
		}
		if errors.Is(e, errQuota) {
			WriteError(w, r, 413, "quota_exceeded", "quota exceeded")
			return
		}
		if errors.Is(e, errCommentPageGone) {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		if writeTeamKeyError(w, r, e) {
			return
		}
		writeJSON(w, map[string]string{"id": id})
	})))
	mux.Handle("DELETE /api/v1/comments/{id}", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		id := r.PathValue("id")
		if ids.Validate("cmt", id) != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		s, _ := auth.SessionFromContext(r)
		err := dbTx(db, func(tx *sql.Tx) error {
			var cid, author, role, deleted string
			// A server administrator has no notebook authority. A current approved member
			// may delete its own comment; notebook owners/admins may delete any comment.
			err := tx.QueryRow(`SELECT c.container_id,c.author_user_id,m.role,c.deleted_at FROM comments c JOIN containers n ON n.id=c.container_id AND n.deleted_at='' JOIN objects o ON o.id=c.object_id AND o.deleted_at='' JOIN memberships m ON m.container_id=c.container_id AND m.user_id=? AND m.revoked_at='' AND m.approved=1 WHERE c.id=?`, s.UserID, id).Scan(&cid, &author, &role, &deleted)
			if err != nil {
				return err
			}
			if author != s.UserID && !isSteward(role) {
				return errInsufficientRole
			}
			if deleted != "" {
				return nil
			} // An authorized retry releases nothing twice and adds no audit.
			now := time.Now().UTC().Format(time.RFC3339)
			var seq int64
			if err := tx.QueryRow(`UPDATE containers SET change_seq=change_seq+1,updated_at=? WHERE id=? RETURNING change_seq`, now, cid).Scan(&seq); err != nil {
				return err
			}
			// Keep the tombstone for authorized retries, but drop ciphertext to free backup
			// capacity as well as quota. Mentions must stop producing notifications too.
			if _, err := tx.Exec(`UPDATE comments SET deleted_at=?,body_ciphertext=X'',change_seq=? WHERE id=?`, now, seq, id); err != nil {
				return err
			}
			if _, err := tx.Exec(`DELETE FROM mentions WHERE comment_id=?`, id); err != nil {
				return err
			}
			return storage.RecordAuditOutcomeTx(tx, s.UserID, "comment.delete", cid, id, "success", "", RequestID(r))
		})
		if writeTeamKeyError(w, r, err) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	mux.Handle("GET /api/v1/objects/{id}/comments", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := auth.SessionFromContext(r)
		oid := r.PathValue("id")
		rows, err := db.Query(`SELECT c.id,c.author_user_id,u.username,c.body_ciphertext,c.key_generation,c.created_at FROM comments c JOIN users u ON u.id=c.author_user_id JOIN memberships m ON m.container_id=c.container_id AND m.user_id=? AND m.revoked_at='' WHERE c.object_id=? AND c.deleted_at='' ORDER BY c.created_at`, s.UserID, oid)
		if err != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		defer rows.Close()
		// Streamed row by row: a page may hold many 64 KiB comments, and building the whole answer
		// first held it twice in memory per reader. A failure mid-way ends the answer short, which
		// the client cannot parse and reports.
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		enc := json.NewEncoder(w)
		sep := "["
		for rows.Next() {
			var id, author, username, created string
			var body []byte
			var generation int
			if rows.Scan(&id, &author, &username, &body, &generation, &created) != nil {
				return
			}
			if _, err := io.WriteString(w, sep); err != nil {
				return
			}
			sep = ","
			if enc.Encode(map[string]any{"id": id, "authorUserId": author, "username": username, "bodyCiphertext": base64.StdEncoding.EncodeToString(body), "keyGeneration": generation, "createdAt": created}) != nil {
				return
			}
		}
		if rows.Err() != nil {
			return
		}
		if sep == "[" {
			_, _ = io.WriteString(w, "[")
		}
		_, _ = io.WriteString(w, "]\n")
	})))
}
