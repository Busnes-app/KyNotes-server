// Package backup adapts KyNotes storage and audit to the shared recovery client.
package backup

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"sync"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/mirror"
	"github.com/Busnes-app/kynotes-server/internal/storage"
	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoveryclient"
)

const TokenLabel = "kynotes:setting:kyrecovery_token"
const OperationTimeout = 16 * time.Minute

var ErrInvalid = errors.New("invalid backup request")
var ErrClosed = errors.New("backup service is stopping")
var ErrAudit = errors.New("backup audit could not be recorded")

type settings struct{ store *storage.Store }

func (s settings) Get(k string) (string, error) {
	v, e := s.store.GetSetting(k)
	if errors.Is(e, storage.ErrNotFound) {
		e = recoveryclient.ErrNotFound
	}
	return v, e
}
func (s settings) Set(k, v string) error { return s.store.SetSetting(k, v) }
func (s settings) Delete(k string) error { return s.store.DeleteSetting(k) }

// recoveryTransport is the shared client's network boundary; tests hold the only
// private recovery key and inspect the actual sealed bytes received here.
type recoveryTransport interface {
	ClaimPairing(context.Context, string, string, string, string) (recoveryclient.PairingResult, error)
	Deposit(context.Context, string, string, []byte) (recoveryclient.Receipt, error)
}

type Service struct {
	cfg     config.Config
	store   *storage.Store
	version string
	mu      sync.Mutex
	closed  bool
	client  recoveryTransport
}

func New(cfg config.Config, store *storage.Store, version string) *Service {
	return &Service{cfg: cfg, store: store, version: version, client: recoveryclient.NewClient(recoveryclient.Options{AllowPrivate: cfg.Backup.AllowPrivateRecovery})}
}
func (s *Service) begin() error {
	if !s.mu.TryLock() {
		return recoveryclient.ErrInProgress
	}
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	return nil
}

// Close waits for the bounded active operation before the application closes SQLite.
func (s *Service) Close() { s.mu.Lock(); defer s.mu.Unlock(); s.closed = true }
func (s *Service) sealer() (recoveryclient.Sealer, error) {
	return recoveryclient.NewAESGCMSealer([]byte(s.cfg.Secrets.ServerSaltKey), TokenLabel)
}
func (s *Service) audit(actor, event, requestID string, err error, details map[string]any) error {
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	if details == nil {
		details = map[string]any{}
	}
	if err != nil {
		details["code"] = ErrorCode(err)
	}
	reason, _ := json.Marshal(details)
	if e := storage.RecordAuditOutcome(s.store.DB(), actor, event, "", "", outcome, string(reason), requestID); e != nil {
		return errors.Join(err, ErrAudit)
	}
	return err
}
func ErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrNoBlobTarget):
		return "blob_target_required"
	case errors.Is(err, mirror.ErrIncomplete):
		return "blob_mirror_incomplete"
	case errors.Is(err, ErrInvalid):
		return "invalid_backup_request"
	case errors.Is(err, ErrAudit):
		return "audit_failed"
	case errors.Is(err, recoveryclient.ErrKeyPinMissing):
		return "recovery_key_missing"
	case errors.Is(err, recoveryclient.ErrNotPaired):
		return "recovery_key_required"
	case errors.Is(err, recoveryclient.ErrNoDestination):
		return "backup_destination_required"
	case errors.Is(err, fs.ErrExist), errors.Is(err, recoveryclient.ErrKeyMismatch):
		return "recovery_key_conflict"
	case errors.Is(err, recoveryclient.ErrInProgress):
		return "backup_in_progress"
	case errors.Is(err, recoveryclient.ErrBadInterval), errors.Is(err, recoveryclient.ErrBadKeep):
		return "invalid_backup_setting"
	case errors.Is(err, recoveryclient.ErrReceiptUnrecorded):
		return "receipt_unrecorded"
	case errors.Is(err, ErrClosed):
		return "backup_stopping"
	default:
		return "backup_failed"
	}
}
func (s *Service) Pin(actor, requestID, publicKey string, threshold, total int) error {
	if e := s.begin(); e != nil {
		return e
	}
	defer s.mu.Unlock()
	key, err := recoveryclient.ParsePinRequest(publicKey, threshold, total)
	if err != nil {
		err = errors.Join(ErrInvalid, err)
	}
	if err == nil {
		err = recoveryclient.StoreRecoveryKey(s.cfg.DataDir, settings{s.store}, key)
	}
	return s.audit(actor, "admin.backup_pin", requestID, err, map[string]any{"key_id": key.Public.ID()})
}
func (s *Service) Pair(ctx context.Context, actor, requestID, url, code string) error {
	if e := s.begin(); e != nil {
		return e
	}
	defer s.mu.Unlock()
	// Refuse before sending the code; preserve the same domain-separated sealer forever.
	err := recoveryclient.ValidateURL(url, s.cfg.Backup.AllowPrivateRecovery)
	if err != nil {
		err = errors.Join(ErrInvalid, err)
	}
	var pair recoveryclient.PairingResult
	var seal recoveryclient.Sealer
	if err == nil {
		seal, err = s.sealer()
	}
	if err == nil {
		pair, err = s.client.ClaimPairing(ctx, url, code, config.AppName, config.AppName)
	}
	if err == nil {
		err = recoveryclient.StoreRecoveryKey(s.cfg.DataDir, settings{s.store}, pair.Key)
	}
	if err == nil {
		err = recoveryclient.StorePairing(settings{s.store}, seal, url, pair.APIToken)
	}
	return s.audit(actor, "admin.backup_pair", requestID, err, map[string]any{"key_id": pair.Key.Public.ID(), "allow_private_recovery": s.cfg.Backup.AllowPrivateRecovery})
}
func (s *Service) Unpair(actor, requestID string) error {
	if e := s.begin(); e != nil {
		return e
	}
	defer s.mu.Unlock()
	return s.audit(actor, "admin.backup_unpair", requestID, recoveryclient.ClearPairing(settings{s.store}), nil)
}
func (s *Service) SetSchedule(actor, requestID string, seconds int64) error {
	if e := s.begin(); e != nil {
		return e
	}
	defer s.mu.Unlock()
	err := recoveryclient.SetInterval(settings{s.store}, seconds)
	var stored time.Duration
	if err == nil {
		stored, err = recoveryclient.Interval(0, settings{s.store})
	}
	return s.audit(actor, "admin.backup_schedule", requestID, err, map[string]any{"interval_seconds": int64(stored / time.Second)})
}

type Result struct {
	recoveryclient.Result
	Mirror      *mirror.Stats `json:"mirror,omitempty"`
	MirrorError string        `json:"mirror_error,omitempty"`
}

func (s *Service) Run(ctx context.Context, actor, requestID string) (Result, error) {
	if e := s.begin(); e != nil {
		return Result{}, e
	}
	defer s.mu.Unlock()
	seal, err := s.sealer()
	var result Result
	var inventory []mirror.Object
	if err == nil {
		result.Result, err = recoveryclient.Run(ctx, recoveryclient.RunConfig{DataDir: s.cfg.DataDir, AppName: config.AppName, AppVersion: s.version, BackupDir: s.cfg.Backup.Dir, Keep: s.cfg.Backup.Keep, Sealer: seal}, settings{s.store}, func() (recoveryclient.Payload, error) {
			payload, err := s.Collect(ctx)
			if err != nil {
				return payload, err
			}
			for _, file := range payload.Files {
				if file.Path == "blob-inventory.json" {
					if err = json.Unmarshal(file.Data, &inventory); err != nil {
						return payload, err
					}
				}
			}
			return payload, nil
		}, s.client)
	}
	// Outcome understands a successful remote deposit whose receipt write failed. Do not
	// put raw transport errors, which can contain URL credentials, into logs or responses.
	safeErr := err
	if err != nil && !errors.Is(err, recoveryclient.ErrReceiptUnrecorded) {
		safeErr = errors.New(ErrorCode(err))
	}
	event, outcome, details := recoveryclient.Outcome(result.Result, safeErr)
	details["local_error"] = ""
	if result.LocalError != "" {
		details["local_error"] = "local_copy_failed"
		result.LocalError = "local_copy_failed"
	}
	reason, _ := json.Marshal(details)
	if e := storage.RecordAuditOutcome(s.store.DB(), actor, event, "", "", outcome, string(reason), requestID); e != nil {
		err = errors.Join(err, ErrAudit)
	}
	if inventory != nil && s.cfg.Backup.BlobTarget.URL != "" {
		stats, mirrorErr := s.mirrorRun(ctx, actor, requestID, inventory)
		result.Mirror = &stats
		if mirrorErr != nil {
			result.MirrorError = "blob_mirror_incomplete"
			err = errors.Join(err, mirrorErr)
		}
	}
	return result, err
}
func (s *Service) Export(ctx context.Context, actor, requestID string) ([]byte, capsule.Manifest, error) {
	if e := s.begin(); e != nil {
		return nil, capsule.Manifest{}, e
	}
	defer s.mu.Unlock()
	key, err := recoveryclient.LoadRecoveryKey(s.cfg.DataDir, settings{s.store})
	var p recoveryclient.Payload
	var raw []byte
	var m capsule.Manifest
	if err == nil {
		p, err = s.Collect(ctx)
	}
	if err == nil {
		raw, m, err = recoveryclient.Seal(p, key)
	}
	err = s.audit(actor, "admin.backup_export", requestID, err, map[string]any{"capsule_id": m.CapsuleID})
	if err != nil {
		return nil, m, err
	}
	return raw, m, nil
}
func (s *Service) Drill(ctx context.Context, actor, requestID string) (*recoveryclient.DrillResult, error) {
	if e := s.begin(); e != nil {
		return nil, e
	}
	defer s.mu.Unlock()
	p, err := s.Collect(ctx)
	var result *recoveryclient.DrillResult
	if err == nil {
		result, err = recoveryclient.Drill(ctx, s.cfg.DataDir, p, Checks)
	}
	if err == nil && !result.Passed {
		err = errors.New("restore verification failed")
	}
	return result, s.audit(actor, "admin.backup_drill", requestID, err, nil)
}

type Status struct {
	Mirror               MirrorStatus               `json:"mirror"`
	KeyID                string                     `json:"key_id"`
	KeyError             string                     `json:"key_error,omitempty"`
	Paired               bool                       `json:"paired"`
	RemoteURL            string                     `json:"remote_url"`
	LocalDirectory       string                     `json:"local_directory"`
	LocalCopies          []recoveryclient.LocalCopy `json:"local_copies"`
	LocalError           string                     `json:"local_error,omitempty"`
	IntervalSeconds      int64                      `json:"interval_seconds"`
	NextRun              *time.Time                 `json:"next_run"`
	LastAttempt          string                     `json:"last_attempt"`
	LastResult           string                     `json:"last_result"`
	Receipt              *recoveryclient.Receipt    `json:"receipt"`
	BlobCount            int64                      `json:"blob_count"`
	BlobBytes            int64                      `json:"blob_bytes"`
	AllowPrivateRecovery bool                       `json:"allow_private_recovery"`
}

func (s *Service) Status() (Status, error) {
	st := Status{LocalDirectory: s.cfg.Backup.Dir, AllowPrivateRecovery: s.cfg.Backup.AllowPrivateRecovery, LocalCopies: []recoveryclient.LocalCopy{}}
	get := func(k string) (string, error) {
		v, e := s.store.GetSetting(k)
		if errors.Is(e, storage.ErrNotFound) {
			e = nil
		}
		return v, e
	}
	var err error
	if st.KeyID, err = get("kyrecovery_key_id"); err != nil {
		return st, err
	}
	if st.KeyID != "" {
		if _, e := recoveryclient.LoadRecoveryKey(s.cfg.DataDir, settings{s.store}); e != nil {
			st.KeyError = "recovery_key_missing_or_invalid"
		}
	}
	if st.RemoteURL, err = get("kyrecovery_url"); err != nil {
		return st, err
	}
	st.Paired = recoveryclient.HasPairing(settings{s.store})
	if st.LastAttempt, err = get("backup_last_attempt"); err != nil {
		return st, err
	}
	interval, err := recoveryclient.Interval(s.defaultInterval(), settings{s.store})
	if err != nil {
		return st, err
	}
	st.IntervalSeconds = int64(interval / time.Second)
	next, ok, err := recoveryclient.NextRun(s.defaultInterval(), settings{s.store})
	if err != nil {
		return st, err
	}
	if ok {
		st.NextRun = &next
	}
	receipt, ok, err := recoveryclient.LastDeposit(settings{s.store})
	if err != nil {
		return st, err
	}
	if ok {
		st.Receipt = &receipt
	}
	if st.LocalDirectory != "" {
		st.LocalCopies, err = recoveryclient.ListLocalCopies(st.LocalDirectory, config.AppName)
		if err != nil {
			st.LocalError = "local_directory_unavailable"
		}
		if st.LocalCopies == nil {
			st.LocalCopies = []recoveryclient.LocalCopy{}
		}
	}
	err = s.store.DB().QueryRow(`SELECT count(*),coalesce(sum(size_bytes),0) FROM blobs`).Scan(&st.BlobCount, &st.BlobBytes)
	if err != nil {
		return st, err
	}
	_ = s.store.DB().QueryRow(`SELECT outcome FROM audit_events WHERE event='admin.backup_run' ORDER BY at DESC,rowid DESC LIMIT 1`).Scan(&st.LastResult)
	st.Mirror, err = s.mirrorStatus()
	return st, err
}
func (s *Service) defaultInterval() time.Duration {
	d, _ := time.ParseDuration(s.cfg.Backup.DepositInterval)
	return d
}
func (s *Service) Due(now time.Time) (bool, error) {
	// Skip only an instance that has never pinned or paired. Corrupt/partial pairing is work.
	_, err := s.store.GetSetting("kyrecovery_key_id")
	if errors.Is(err, storage.ErrNotFound) && !recoveryclient.HasPairing(settings{s.store}) {
		return false, nil
	}
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return false, err
	}
	next, ok, err := recoveryclient.NextRun(s.defaultInterval(), settings{s.store})
	if err != nil || !ok {
		return false, err
	}
	// NextRun returns its own time.Now when no attempt exists. The scheduler's
	// timestamp was captured earlier, so comparing them would postpone the first run forever.
	last, err := s.store.GetSetting("backup_last_attempt")
	if errors.Is(err, storage.ErrNotFound) || (err == nil && last == "") {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return !now.Before(next), nil
}
