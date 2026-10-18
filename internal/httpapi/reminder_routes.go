package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/webpush"
)

// Reminder push (opt-in, IMPLEMENTATION_PLAN.md "Reminder push extension"): the server learns that an
// account has a reminder at a UTC minute under an opaque id, and where to send an empty push.
// Reminders are not audited (volume); subscription changes are, naming only the push service host.
const (
	maxReminders     = 500
	maxSubscriptions = 10
	reminderHorizon  = 400 * 24 * time.Hour
	// reminderGrace admits a reminder that just passed (clock skew); it fires at the next tick.
	reminderGrace = time.Hour
)

var errTooMany = errors.New("too many")

// reminderHandler: an everyday session, CSRF on mutations, no-store.
func reminderHandler(db *sql.DB, h func(w http.ResponseWriter, r *http.Request, s auth.Session)) http.Handler {
	return auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		h(w, r, s)
	}))
}

// writeTx runs fn in one transaction and answers its error.
func writeTx(w http.ResponseWriter, r *http.Request, db *sql.DB, event string, fn func(tx *sql.Tx) error) bool {
	tx, err := db.BeginTx(r.Context(), nil)
	if err == nil {
		if err = fn(tx); err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
	}
	switch {
	case err == nil:
		return true
	case errors.Is(err, sql.ErrNoRows):
		WriteError(w, r, 404, "not_found", "not found")
	case errors.Is(err, errTooMany):
		WriteError(w, r, 409, "already_exists", "too many "+event+"s")
	default:
		writeInternal(w, r, event, err)
	}
	return false
}

func readEndpoint(w http.ResponseWriter, r *http.Request) (string, bool) {
	var in struct {
		Endpoint string `json:"endpoint"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in) != nil || in.Endpoint == "" || len(in.Endpoint) > webpush.MaxEndpoint {
		WriteError(w, r, 400, "invalid_request", "invalid request")
		return "", false
	}
	return in.Endpoint, true
}

func ReminderRoutes(mux RouteMux, db *sql.DB, sender *webpush.Sender) {
	mux.Handle("GET /api/v1/push/web/key", reminderHandler(db, func(w http.ResponseWriter, r *http.Request, _ auth.Session) {
		if sender == nil {
			WriteError(w, r, 503, "unavailable", "web push is unavailable")
			return
		}
		writeJSON(w, map[string]string{"publicKey": sender.PublicKey()})
	}))
	// We send no payload, so the subscription's p256dh/auth keys are neither needed nor kept.
	mux.Handle("PUT /api/v1/push/web/subscriptions", reminderHandler(db, func(w http.ResponseWriter, r *http.Request, s auth.Session) {
		endpoint, ok := readEndpoint(w, r)
		if !ok {
			return
		}
		u, err := webpush.ParseEndpoint(endpoint)
		if err != nil {
			WriteError(w, r, 400, "invalid_request", "endpoint is not a browser push service")
			return
		}
		id, err := ids.Mint("wps")
		if err != nil {
			writeInternal(w, r, "push.subscription.add", err)
			return
		}
		if !writeTx(w, r, db, "subscription", func(tx *sql.Tx) error {
			var owner string
			switch err := tx.QueryRow(`SELECT user_id FROM web_push_subscriptions WHERE endpoint=?`, endpoint).Scan(&owner); {
			case err == nil && owner == s.UserID:
				return nil // idempotent
			case err == nil:
				// The same browser, now signed in to this account: the subscription moves here.
				if _, err := tx.Exec(`DELETE FROM web_push_subscriptions WHERE endpoint=?`, endpoint); err != nil {
					return err
				}
			case !errors.Is(err, sql.ErrNoRows):
				return err
			}
			var n int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM web_push_subscriptions WHERE user_id=?`, s.UserID).Scan(&n); err != nil {
				return err
			}
			if n >= maxSubscriptions {
				return errTooMany
			}
			if _, err := tx.Exec(`INSERT INTO web_push_subscriptions(id,user_id,endpoint,created_at) VALUES(?,?,?,?)`, id, s.UserID, endpoint, time.Now().UTC().Format(time.RFC3339)); err != nil {
				return err
			}
			return audit(tx, r, s, "push.subscription.add", id, "success", "host="+u.Hostname())
		}) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.Handle("DELETE /api/v1/push/web/subscriptions", reminderHandler(db, func(w http.ResponseWriter, r *http.Request, s auth.Session) {
		endpoint, ok := readEndpoint(w, r)
		if !ok {
			return
		}
		if !writeTx(w, r, db, "subscription", func(tx *sql.Tx) error {
			var id string
			switch err := tx.QueryRow(`DELETE FROM web_push_subscriptions WHERE endpoint=? AND user_id=? RETURNING id`, endpoint, s.UserID).Scan(&id); {
			case errors.Is(err, sql.ErrNoRows):
				return nil // idempotent
			case err != nil:
				return err
			}
			host := ""
			if u, err := webpush.ParseEndpoint(endpoint); err == nil {
				host = u.Hostname()
			}
			return audit(tx, r, s, "push.subscription.remove", id, "success", "host="+host)
		}) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.Handle("GET /api/v1/reminders", reminderHandler(db, func(w http.ResponseWriter, r *http.Request, s auth.Session) {
		rows, err := db.QueryContext(r.Context(), `SELECT id,at FROM reminders WHERE user_id=? ORDER BY at,id`, s.UserID)
		if err != nil {
			writeInternal(w, r, "reminders.list", err)
			return
		}
		defer rows.Close()
		out := []map[string]string{}
		for rows.Next() {
			var id, at string
			if err := rows.Scan(&id, &at); err != nil {
				writeInternal(w, r, "reminders.list", err)
				return
			}
			out = append(out, map[string]string{"id": id, "at": at})
		}
		if err := rows.Err(); err != nil {
			writeInternal(w, r, "reminders.list", err)
			return
		}
		writeJSON(w, out)
	}))
	mux.Handle("PUT /api/v1/reminders/{id}", reminderHandler(db, func(w http.ResponseWriter, r *http.Request, s auth.Session) {
		id := r.PathValue("id")
		var in struct {
			At string `json:"at"`
		}
		now := time.Now().UTC()
		if !validReminderID(id) || json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&in) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		at, err := time.Parse(time.RFC3339, in.At)
		// Exactly a UTC minute, recent or ahead, within the horizon.
		if err != nil || at.UTC().Format("2006-01-02T15:04:00Z") != in.At || at.Before(now.Add(-reminderGrace)) || at.After(now.Add(reminderHorizon)) {
			WriteError(w, r, 400, "invalid_request", "at must be a UTC minute within 400 days")
			return
		}
		if !writeTx(w, r, db, "reminder", func(tx *sql.Tx) error {
			var owner string
			switch err := tx.QueryRow(`SELECT user_id FROM reminders WHERE id=?`, id).Scan(&owner); {
			case err == nil && owner != s.UserID:
				return sql.ErrNoRows // someone else's id: not this caller's to know
			case err == nil:
				_, err = tx.Exec(`UPDATE reminders SET at=? WHERE id=?`, in.At, id)
				return err
			case !errors.Is(err, sql.ErrNoRows):
				return err
			}
			var n int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM reminders WHERE user_id=?`, s.UserID).Scan(&n); err != nil {
				return err
			}
			if n >= maxReminders {
				return errTooMany
			}
			_, err := tx.Exec(`INSERT INTO reminders(id,user_id,at,created_at) VALUES(?,?,?,?)`, id, s.UserID, in.At, now.Format(time.RFC3339))
			return err
		}) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.Handle("DELETE /api/v1/reminders/{id}", reminderHandler(db, func(w http.ResponseWriter, r *http.Request, s auth.Session) {
		id := r.PathValue("id")
		if !validReminderID(id) {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		if _, err := db.ExecContext(r.Context(), `DELETE FROM reminders WHERE id=? AND user_id=?`, id, s.UserID); err != nil {
			writeInternal(w, r, "reminders.delete", err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
}

// validReminderID: 26 lowercase Crockford base32 characters, the ids alphabet without a prefix.
func validReminderID(id string) bool { return ids.Validate("rmd", "rmd_"+id) == nil }
