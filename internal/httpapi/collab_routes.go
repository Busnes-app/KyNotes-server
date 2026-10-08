package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/storage"
	"net/http"
	"time"
)

func CollabRoutes(mux *http.ServeMux, db *sql.DB) {
	mux.Handle("GET /api/v1/containers/{id}/members", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := auth.SessionFromContext(r)
		cid := r.PathValue("id")
		var role string
		if db.QueryRow(`SELECT role FROM memberships WHERE container_id=? AND user_id=? AND revoked_at=''`, cid, s.UserID).Scan(&role) != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		rows, err := db.Query(`SELECT m.user_id,u.username,m.role FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.container_id=? AND m.revoked_at='' ORDER BY u.username`, cid)
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		defer rows.Close()
		out := []map[string]string{}
		for rows.Next() {
			var id, username, memberRole string
			if rows.Scan(&id, &username, &memberRole) != nil {
				WriteError(w, r, 500, "internal", "internal server error")
				return
			}
			out = append(out, map[string]string{"userId": id, "username": username, "role": memberRole})
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
			var role, targetRole string
			if tx.QueryRow(`SELECT role FROM memberships WHERE container_id=? AND user_id=? AND revoked_at=''`, cid, s.UserID).Scan(&role) != nil || !isSteward(role) {
				return errInsufficientRole
			}
			if tx.QueryRow(`SELECT role FROM memberships WHERE container_id=? AND user_id=? AND revoked_at=''`, cid, target).Scan(&targetRole) != nil || targetRole == "owner" || (role == "admin" && targetRole == "admin") {
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
		// Envelopes reach key_envelopes on acceptance: same proof as an envelope PUT.
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
			if e := admitMemberTx(tx, cid, s.UserID, role, now); e != nil {
				return e
			}
			return moveInvitationEnvelopesTx(tx, id, s.UserID, now)
		})
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
		if db.QueryRow(`SELECT o.container_id,m.role FROM objects o JOIN memberships m ON m.container_id=o.container_id AND m.user_id=? WHERE o.id=? AND m.revoked_at=''`, s.UserID, oid).Scan(&cid, &role) != nil {
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
		id, _ := ids.Mint("cmt")
		now := time.Now().UTC().Format(time.RFC3339)
		e = dbTx(db, func(tx *sql.Tx) error {
			if e := checkWriteGate(tx, cid, s.UserID, int64(in.KeyGeneration), r.Header.Get(keySchemeHeader)); e != nil {
				return e
			}
			var seq int64
			if e := tx.QueryRow(`UPDATE containers SET change_seq=change_seq+1,updated_at=? WHERE id=? RETURNING change_seq`, now, cid).Scan(&seq); e != nil {
				return e
			}
			if _, e := tx.Exec(`INSERT INTO comments(id,container_id,object_id,author_user_id,body_ciphertext,key_generation,change_seq,created_at) VALUES(?,?,?,?,?,?,?,?)`, id, cid, oid, s.UserID, body, in.KeyGeneration, seq, now); e != nil {
				return e
			}
			for _, uid := range in.Mentions {
				if _, e := tx.Exec(`INSERT INTO mentions(comment_id,mentioned_user_id) VALUES(?,?)`, id, uid); e != nil {
					return e
				}
			}
			return nil
		})
		if writeTeamKeyError(w, r, e) {
			return
		}
		writeJSON(w, map[string]string{"id": id})
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
		out := []map[string]any{}
		for rows.Next() {
			var id, author, username, created string
			var body []byte
			var generation int
			if rows.Scan(&id, &author, &username, &body, &generation, &created) != nil {
				WriteError(w, r, 500, "internal", "internal server error")
				return
			}
			out = append(out, map[string]any{"id": id, "authorUserId": author, "username": username, "bodyCiphertext": base64.StdEncoding.EncodeToString(body), "keyGeneration": generation, "createdAt": created})
		}
		writeJSON(w, out)
	})))
}
