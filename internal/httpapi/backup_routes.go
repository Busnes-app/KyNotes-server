package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/backup"
)

func BackupRoutes(mux *http.ServeMux, db *sql.DB, service *backup.Service) {
	mux.Handle("GET /api/v1/admin/backup/status", auth.RequireAdmin(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status, err := service.Status()
		if err != nil {
			writeBackupError(w, r, err)
			return
		}
		writeJSON(w, status)
	})))
	mutation := func(path string, handler http.HandlerFunc) {
		mux.Handle(path, auth.RequireStepUp(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if auth.CheckCSRF(r) != nil {
				WriteError(w, r, 403, "csrf_failed", "CSRF validation failed")
				return
			}
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(backup.OperationTimeout))
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), backup.OperationTimeout)
			defer cancel()
			handler(w, r.WithContext(ctx))
		})))
	}
	mutation("POST /api/v1/admin/backup/pin-key", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			PublicKey string `json:"public_key"`
			Threshold int    `json:"threshold"`
			Total     int    `json:"total_shares"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid public key request")
			return
		}
		actor, _ := auth.SessionFromContext(r)
		if err := service.Pin(actor.UserID, RequestID(r), in.PublicKey, in.Threshold, in.Total); err != nil {
			writeBackupError(w, r, err)
			return
		}
		w.WriteHeader(204)
	})
	mutation("POST /api/v1/admin/backup/pair-remote", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			URL  string `json:"url"`
			Code string `json:"pairing_code"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid pairing request")
			return
		}
		actor, _ := auth.SessionFromContext(r)
		if err := service.Pair(r.Context(), actor.UserID, RequestID(r), in.URL, in.Code); err != nil {
			writeBackupError(w, r, err)
			return
		}
		w.WriteHeader(204)
	})
	mutation("POST /api/v1/admin/backup/unpair", func(w http.ResponseWriter, r *http.Request) {
		actor, _ := auth.SessionFromContext(r)
		if err := service.Unpair(actor.UserID, RequestID(r)); err != nil {
			writeBackupError(w, r, err)
			return
		}
		w.WriteHeader(204)
	})
	mutation("POST /api/v1/admin/backup/schedule", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Seconds *int64 `json:"interval_seconds"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.Seconds == nil {
			WriteError(w, r, 400, "invalid_request", "interval_seconds is required")
			return
		}
		actor, _ := auth.SessionFromContext(r)
		if err := service.SetSchedule(actor.UserID, RequestID(r), *in.Seconds); err != nil {
			writeBackupError(w, r, err)
			return
		}
		w.WriteHeader(204)
	})
	mutation("POST /api/v1/admin/backup/deposit", func(w http.ResponseWriter, r *http.Request) {
		actor, _ := auth.SessionFromContext(r)
		result, err := service.Run(r.Context(), actor.UserID, RequestID(r))
		// Preserve partial destination results even when the other destination failed.
		if err != nil && result.Manifest.CapsuleID == "" {
			writeBackupError(w, r, err)
			return
		}
		code := ""
		if err != nil {
			code = backup.ErrorCode(err)
		}
		writeJSON(w, map[string]any{"result": result, "error_code": code})
	})
	mutation("POST /api/v1/admin/backup/export-capsule", func(w http.ResponseWriter, r *http.Request) {
		actor, _ := auth.SessionFromContext(r)
		raw, m, err := service.Export(r.Context(), actor.UserID, RequestID(r))
		if err != nil {
			writeBackupError(w, r, err)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+m.CapsuleID+`.kycap"`)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(raw)
	})
	mutation("POST /api/v1/admin/backup/mirror", func(w http.ResponseWriter, r *http.Request) {
		actor, _ := auth.SessionFromContext(r)
		stats, err := service.MirrorNow(r.Context(), actor.UserID, RequestID(r))
		if err != nil && stats.Failed == 0 {
			writeBackupError(w, r, err)
			return
		}
		code := ""
		if err != nil {
			code = backup.ErrorCode(err)
		}
		writeJSON(w, map[string]any{"result": stats, "error_code": code})
	})

	mutation("POST /api/v1/admin/backup/drill", func(w http.ResponseWriter, r *http.Request) {
		actor, _ := auth.SessionFromContext(r)
		result, err := service.Drill(r.Context(), actor.UserID, RequestID(r))
		if err != nil && (result == nil || result.Passed) {
			writeBackupError(w, r, err)
			return
		}
		writeJSON(w, result)
	})
}
func writeBackupError(w http.ResponseWriter, r *http.Request, err error) {
	code := backup.ErrorCode(err)
	status := 500
	message := "Backup operation failed; check the key, destinations and audit result. Private KyRecovery hosts require KYNOTES_BACKUP_ALLOW_PRIVATE_RECOVERY=true; HTTPS is always required."
	switch code {
	case "recovery_key_required", "recovery_key_missing", "backup_destination_required", "blob_target_required":
		status = 412
	case "recovery_key_conflict", "backup_in_progress":
		status = 409
	case "invalid_backup_setting", "invalid_backup_request":
		status = 400
	case "backup_stopping":
		status = 503
	}
	WriteError(w, r, status, code, message)
}
