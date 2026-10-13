package backup

import (
	"strconv"
	"time"

	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/kynotes-server/internal/applysetup"
)

// CheckSetup uses only settings reads and token/key verification. It never claims
// a pairing code or initializes an absent schedule or key.
func (s *Service) CheckSetup(want applysetup.Backup) []applysetup.Result {
	if err := s.begin(); err != nil {
		return []applysetup.Result{{Section: "backup", Status: applysetup.Failed}}
	}
	defer s.mu.Unlock()
	var out []applysetup.Result
	if want.Dir != "" {
		status, detail := applysetup.DecideFixed(s.cfg.Backup.Dir, want.Dir, "KYNOTES_BACKUP_DIR")
		out = append(out, applysetup.Result{Section: "backup.dir", Status: status, Detail: detail})
	}
	if want.Keep != 0 {
		status, detail := applysetup.DecideFixed(strconv.Itoa(s.cfg.Backup.Keep), strconv.Itoa(want.Keep), "KYNOTES_BACKUP_KEEP")
		out = append(out, applysetup.Result{Section: "backup.keep", Status: status, Detail: detail})
	}
	if want.DepositInterval != "" {
		r := applysetup.Result{Section: "backup.interval", Status: applysetup.Conflict}
		sec, err := applysetup.IntervalSeconds(want.DepositInterval)
		if err != nil {
			r.Status = applysetup.Invalid
		} else {
			d, err := recoveryclient.Interval(-time.Second, settings{s.store})
			if err != nil {
				r.Status = applysetup.Failed
			} else if int64(d/time.Second) == sec {
				r.Status = applysetup.Present
			}
		}
		out = append(out, r)
	}
	if want.Recovery != nil {
		r := applysetup.Result{Section: "backup.recovery", Status: applysetup.Conflict}
		sealer, err := s.sealer()
		if err != nil {
			r.Status = applysetup.Failed
		} else {
			pair, err := recoveryclient.LoadPairing(s.cfg.DataDir, settings{s.store}, sealer)
			if err == nil && pair.URL == want.Recovery.URL {
				r.Status = applysetup.Present
			}
		}
		out = append(out, r)
	}
	return out
}
