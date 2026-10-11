package httpapi

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/applysetup"
	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/backup"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/sso"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// applySSO stores the bundle's SSO settings only when none exist, after the same
// discovery check login uses. It writes through the router's store so login sees it now.
func applySSO(ctx context.Context, db *sql.DB, store *sso.Store, want applysetup.SSO) applysetup.Result {
	have, next := store.Load(), applysetup.WantSSO(want)
	res := applysetup.Result{Section: "sso", Status: applysetup.DecideSSO(have, next)}
	switch res.Status {
	case applysetup.Present:
		return res
	case applysetup.Conflict:
		res.Detail = applysetup.SSODiff(have, next)
		return res
	}
	if _, err := sso.DiscoverEndpoints(ctx, next.IssuerURL); err != nil {
		res.Status, res.Detail = applysetup.Invalid, "issuer metadata probe failed: "+err.Error()
		if errors.Is(err, sso.ErrIssuerUnavailable) {
			res.Status = applysetup.Failed
		}
		return res
	}
	if err := store.Save(next); err != nil {
		res.Status, res.Detail = applysetup.Failed, "storing SSO settings failed"
		return res
	}
	if err := storage.RecordAuditOutcome(db, applysetup.Actor, "admin.sso_update", "", "", "success", applysetup.RequestID, applysetup.RequestID); err != nil {
		res.Status, res.Detail = applysetup.Failed, "SSO settings stored but the audit row failed"
	}
	return res
}

// applyAdmin ensures an active admin bound to issuer+subject. issuer is the stored SSO
// issuer, so a bundle without an sso section is still checked against the server's
// settings. Accounts are never adopted by username; a grant revokes the account's
// credentials like a directory promotion.
func applyAdmin(db *sql.DB, cfg config.Config, issuer string, want applysetup.Admin) (applysetup.Result, string) {
	res := applysetup.Result{Section: "admin:" + strings.ToLower(want.Username)}
	failed := func() (applysetup.Result, string) {
		res.Status, res.Detail = applysetup.Failed, "account update failed"
		return res, ""
	}
	if issuer == "" || want.Issuer != issuer {
		res.Status, res.Detail = applysetup.Invalid, "admin issuer must equal the configured SSO issuer"
		if issuer == "" {
			res.Detail = "no SSO issuer is configured; admins need the sso section or existing SSO settings"
		}
		return res, ""
	}
	tx, err := db.Begin()
	if err != nil {
		return failed()
	}
	defer tx.Rollback()
	bound, err := lookupAccount(tx, `SELECT id,username,role,status,account_kind FROM users WHERE sso_issuer=? AND sso_subject=?`, want.Issuer, want.Subject)
	if err != nil {
		return failed()
	}
	var named *applysetup.Account
	if bound == nil {
		if named, err = lookupAccount(tx, `SELECT id,username,role,status,account_kind FROM users WHERE username=?`, strings.ToLower(want.Username)); err != nil {
			return failed()
		}
	}
	status, action, detail := applysetup.DecideAdmin(bound, named)
	res.Status, res.Detail = status, detail
	now := time.Now().UTC().Format(time.RFC3339)
	switch action {
	case applysetup.CreateAdmin:
		err = createSSOAdmin(tx, cfg, want, now)
	case applysetup.GrantAdmin:
		err = grantAdmin(tx, bound.ID, want, now)
	}
	if err == nil && action != applysetup.NoAction {
		err = tx.Commit()
	}
	switch {
	case err != nil:
		return failed()
	case status == applysetup.Conflict:
		return res, ""
	case bound != nil:
		return res, bound.Username
	}
	return res, strings.ToLower(want.Username)
}

func lookupAccount(tx *sql.Tx, query string, args ...any) (*applysetup.Account, error) {
	var a applysetup.Account
	err := tx.QueryRow(query, args...).Scan(&a.ID, &a.Username, &a.Role, &a.Status, &a.Kind)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func createSSOAdmin(tx *sql.Tx, cfg config.Config, want applysetup.Admin, now string) error {
	id, err := ids.Mint("usr")
	if err != nil {
		return err
	}
	// No usable password: the verifier is for a random secret nobody keeps.
	unusable := make([]byte, 32)
	if _, err := rand.Read(unusable); err != nil {
		return err
	}
	hash, err := auth.HashAuthSecret(hex.EncodeToString(unusable))
	if err != nil {
		return err
	}
	username := strings.ToLower(want.Username)
	if _, err = tx.Exec(`INSERT INTO users(id, username, auth_secret_hash, login_salt, login_iterations, role, account_kind, status, sso_subject, sso_issuer, created_at, updated_at) VALUES(?, ?, ?, ?, 600000, 'admin', 'admin', 'active', ?, ?, ?, ?)`,
		id, username, hash, auth.SyntheticLoginSalt(cfg.Secrets.ServerSaltKey, username), want.Subject, want.Issuer, now, now); err != nil {
		return err
	}
	return storage.RecordAuditOutcomeTx(tx, applysetup.Actor, "admin.user.create", "", id, "success", "role=admin", applysetup.RequestID)
}

func grantAdmin(tx *sql.Tx, userID string, want applysetup.Admin, now string) error {
	if err := revokeForRoleChange(tx, want.Issuer, want.Subject, userID, now); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE users SET role='admin', updated_at=? WHERE id=?`, now, userID); err != nil {
		return err
	}
	return storage.RecordAuditOutcomeTx(tx, applysetup.Actor, "admin.user.update", "", userID, "success", "role=admin", applysetup.RequestID)
}

type SetupDeps struct {
	DB      *sql.DB
	Config  config.Config
	SSO     *sso.Store
	Backups *backup.Service
	Version string
	Log     *logging.Logger
}

// Setup serves apply-setup. It is mounted only on the admin Unix socket, never on the
// network router.
type Setup struct {
	mux     *http.ServeMux
	running sync.Mutex
	closing atomic.Bool
}

func (s *Setup) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// Drain refuses new applies and waits for the running one, so SQLite outlives it. It
// reports false if ctx ends first.
func (s *Setup) Drain(ctx context.Context) bool {
	s.closing.Store(true)
	done := make(chan struct{})
	go func() { s.running.Lock(); s.running.Unlock(); close(done) }()
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}

// SocketRequestID attributes deposit and drill audit rows to the admin socket.
const SocketRequestID = "admin-socket"

// SocketResult answers deposit and drill: the service's result (null when nothing was
// produced) and its error code, empty on success.
type SocketResult struct {
	Result    json.RawMessage `json:"result"`
	ErrorCode string          `json:"error_code"`
}

func SetupHandler(d SetupDeps) *Setup {
	s := &Setup{mux: http.NewServeMux()}
	s.mux.HandleFunc("POST /v1/apply-setup", s.exclusive(func(w http.ResponseWriter, r *http.Request, ctx context.Context) {
		req, err := applysetup.DecodeRequest(http.MaxBytesReader(w, r.Body, 1<<20), d.Config.Backup.AllowPrivateRecovery)
		if err != nil {
			WriteError(w, r, http.StatusBadRequest, "invalid_bundle", err.Error())
			return
		}
		report := applySetup(ctx, d, req)
		d.Log.Info("apply_setup", "outcome", report.ExitCode(), "count", len(report.Results))
		writeJSON(w, report)
	}))
	operation := func(name string, run func(ctx context.Context) (any, error)) {
		s.mux.HandleFunc("POST /v1/"+name, s.exclusive(func(w http.ResponseWriter, r *http.Request, ctx context.Context) {
			var out SocketResult
			if d.Backups == nil {
				out.ErrorCode = "backup_unavailable"
			} else {
				result, err := run(ctx)
				if result != nil {
					out.Result, _ = json.Marshal(result)
				}
				if err != nil {
					out.ErrorCode = backup.ErrorCode(err)
				}
			}
			d.Log.Info("admin_socket_"+strings.ReplaceAll(name, "-", "_"), "outcome", out.ErrorCode == "")
			writeJSON(w, out)
		}))
	}
	operation("deposit", func(ctx context.Context) (any, error) {
		result, err := d.Backups.Run(ctx, applysetup.Actor, SocketRequestID)
		if result.Manifest.CapsuleID == "" {
			return nil, err
		}
		return result, err
	})
	operation("backup-drill", func(ctx context.Context) (any, error) {
		result, err := d.Backups.Drill(ctx, applysetup.Actor, SocketRequestID)
		if result == nil {
			return nil, err
		}
		return result, err
	})
	return s
}

// exclusive runs one socket operation at a time, refuses new ones once Drain starts and
// gives each a context that a client hang-up cannot cancel halfway.
func (s *Setup) exclusive(next func(http.ResponseWriter, *http.Request, context.Context)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.closing.Load() {
			WriteError(w, r, http.StatusServiceUnavailable, "shutting_down", "kynotes-server is shutting down")
			return
		}
		if !s.running.TryLock() {
			WriteError(w, r, http.StatusConflict, "operation_in_progress", "another admin socket operation is already running")
			return
		}
		defer s.running.Unlock()
		if s.closing.Load() {
			WriteError(w, r, http.StatusServiceUnavailable, "shutting_down", "kynotes-server is shutting down")
			return
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), backup.OperationTimeout)
		defer cancel()
		next(w, r, ctx)
	}
}

func applySetup(ctx context.Context, d SetupDeps, req applysetup.Request) applysetup.Report {
	var results []applysetup.Result
	if req.SSO != nil {
		results = append(results, applySSO(ctx, d.DB, d.SSO, *req.SSO))
	}
	var admins []string
	for _, a := range req.Admins {
		res, username := applyAdmin(d.DB, d.Config, d.SSO.Load().IssuerURL, a)
		results = append(results, res)
		if username != "" {
			admins = append(admins, username)
		}
	}
	h := applysetup.Handover{URL: applysetup.Origin(d.SSO.Load().RedirectURI), AdminUsernames: admins, BackupDir: d.Config.Backup.Dir, Version: d.Version}
	switch {
	case d.Backups != nil:
		if req.Backup != nil {
			results = append(results, d.Backups.ApplySetup(ctx, *req.Backup)...)
		}
		h.RecoveryKeyFingerprint, _ = d.Backups.KeyID()
	case req.Backup != nil:
		results = append(results, applysetup.Result{Section: "backup", Status: applysetup.Failed, Detail: "backup service unavailable"})
	}
	return applysetup.NewReport(results, h)
}
