package backup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"time"

	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/kynotes-server/internal/applysetup"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// ApplySetup reconciles the installer's backup section. Directory and keep come from the
// process environment, so they are checked, not set.
func (s *Service) ApplySetup(ctx context.Context, want applysetup.Backup) []applysetup.Result {
	var out []applysetup.Result
	if want.Dir != "" {
		st, d := applysetup.DecideFixed(s.cfg.Backup.Dir, want.Dir, "KYNOTES_BACKUP_DIR")
		out = append(out, applysetup.Result{Section: "backup.dir", Status: st, Detail: d})
	}
	if want.Keep != 0 {
		st, d := applysetup.DecideFixed(strconv.Itoa(s.cfg.Backup.Keep), strconv.Itoa(want.Keep), "KYNOTES_BACKUP_KEEP")
		out = append(out, applysetup.Result{Section: "backup.keep", Status: st, Detail: d})
	}
	if want.DepositInterval != "" {
		out = append(out, s.applyInterval(want.DepositInterval))
	}
	if want.Recovery != nil {
		out = append(out, s.applyRecovery(ctx, *want.Recovery))
	}
	return out
}

func (s *Service) applyInterval(raw string) applysetup.Result {
	res := applysetup.Result{Section: "backup.interval"}
	sec, err := applysetup.IntervalSeconds(raw)
	if err != nil {
		res.Status, res.Detail = applysetup.Invalid, err.Error()
		return res
	}
	// Interval returns its default argument only when no admin setting exists.
	stored, err := recoveryclient.Interval(-time.Second, settings{s.store})
	if err != nil {
		res.Status, res.Detail = applysetup.Failed, ErrorCode(err)
		return res
	}
	res.Status = applysetup.DecideInterval(int64(stored/time.Second), sec)
	switch res.Status {
	case applysetup.Conflict:
		res.Detail = fmt.Sprintf("interval is already %s; left unchanged", stored)
	case applysetup.Created:
		if err := s.SetSchedule(applysetup.Actor, applysetup.RequestID, sec); err != nil {
			res.Status, res.Detail = applysetup.Failed, ErrorCode(err)
		}
	}
	return res
}

func (s *Service) applyRecovery(ctx context.Context, want applysetup.Recovery) applysetup.Result {
	res := applysetup.Result{Section: "backup.recovery"}
	keyID, err := s.KeyID()
	var pairedURL string
	if err == nil && recoveryclient.HasPairing(settings{s.store}) {
		pairedURL, err = s.setting("kyrecovery_url")
	}
	if err != nil {
		res.Status, res.Detail = applysetup.Failed, ErrorCode(err)
		return res
	}
	status, claim := applysetup.DecideRecovery(keyID, pairedURL, want.URL)
	res.Status = status
	if !claim {
		if status == applysetup.Conflict {
			res.Detail = "already paired to another KyRecovery, or the pairing has no pinned key; left unchanged"
		}
		return res
	}
	err = s.Pair(ctx, applysetup.Actor, applysetup.RequestID, want.URL, want.PairingCode)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrExist):
		res.Status, res.Detail = applysetup.Conflict, "KyRecovery returned a key other than the pinned one; the pin is unchanged and the code is spent"
	case errors.Is(err, ErrInvalid):
		res.Status, res.Detail = applysetup.Invalid, ErrorCode(err)
	default:
		res.Status, res.Detail = applysetup.Failed, ErrorCode(err)
	}
	return res
}

// KeyID is the pinned recovery key's ID, empty when none is pinned.
func (s *Service) KeyID() (string, error) { return s.setting("kyrecovery_key_id") }

func (s *Service) setting(k string) (string, error) {
	v, err := s.store.GetSetting(k)
	if errors.Is(err, storage.ErrNotFound) {
		return "", nil
	}
	return v, err
}
