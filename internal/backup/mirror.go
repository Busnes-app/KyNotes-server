package backup

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"

	"github.com/Busnes-app/ky-primitives/offsite"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/mirror"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

var ErrNoBlobTarget = errors.New("no ciphertext blob mirror target configured")

type MirrorStatus struct {
	Configured bool          `json:"configured"`
	Target     string        `json:"target"`
	Pending    int           `json:"pending"`
	Last       *mirror.Stats `json:"last"`
}

func (s *Service) mirrorStatus() (MirrorStatus, error) {
	cfg := s.cfg.Backup.BlobTarget.Offsite()
	status := MirrorStatus{Configured: cfg.URL != ""}
	if !status.Configured {
		return status, nil
	}
	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return status, err
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	status.Target = parsed.String()
	status.Pending, err = mirror.Pending(s.store.DB(), mirror.TargetKey(cfg))
	if err != nil {
		return status, err
	}
	previous, err := s.store.GetSetting("blob_mirror_last")
	if errors.Is(err, storage.ErrNotFound) {
		return status, nil
	}
	if err != nil {
		return status, err
	}
	var stats mirror.Stats
	if err = json.Unmarshal([]byte(previous), &stats); err != nil {
		return status, err
	}
	status.Last = &stats
	return status, nil
}
func (s *Service) MirrorNow(ctx context.Context, actor, requestID string) (mirror.Stats, error) {
	if err := s.begin(); err != nil {
		return mirror.Stats{}, err
	}
	defer s.mu.Unlock()
	inventory, err := mirror.List(ctx, s.store.DB())
	if err != nil {
		return mirror.Stats{}, err
	}
	return s.mirrorRun(ctx, actor, requestID, inventory)
}
func (s *Service) mirrorRun(ctx context.Context, actor, requestID string, inventory []mirror.Object) (mirror.Stats, error) {
	if s.cfg.Backup.BlobTarget.URL == "" {
		return mirror.Stats{}, ErrNoBlobTarget
	}
	cfg := s.cfg.Backup.BlobTarget.Offsite()
	target, err := offsite.Parse(cfg)
	var stats mirror.Stats
	if err == nil {
		var blobs *blobstore.Store
		blobs, err = blobstore.New(s.cfg.DataDir)
		if err == nil {
			stats, err = mirror.Sync(ctx, s.store.DB(), blobs, target, mirror.TargetKey(cfg), inventory)
		}
	}
	if err != nil && stats.FirstError == "" {
		stats.FirstError = "mirror_failed"
		stats.Failed++
	}
	raw, _ := json.Marshal(stats)
	if e := s.store.SetSetting("blob_mirror_last", string(raw)); e != nil {
		err = errors.Join(err, ErrAudit)
	}
	return stats, s.audit(actor, "admin.blob_mirror_run", requestID, err, map[string]any{"uploaded": stats.Uploaded, "skipped": stats.Skipped, "failed": stats.Failed, "missing": stats.Missing, "target_id": mirror.TargetKey(cfg)})
}
