package backup

import (
	"bytes"
	"io"
	"path/filepath"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/storage"
)

func sealed(t *testing.T, key, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := newSealWriter(&buf, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func opened(key, archive []byte) ([]byte, error) {
	r, err := newOpenReader(bytes.NewReader(archive), key)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// A sealed archive opens only whole, in order, under its key.
func TestSealedArchiveRefusesEveryChange(t *testing.T) {
	key := bytes.Repeat([]byte{7}, BackupKeyBytes)
	plain := bytes.Repeat([]byte("row\n"), frameBytes/2+10) // three frames: two full and the final one
	archive := sealed(t, key, plain)
	if got, err := opened(key, archive); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("round trip: %v", err)
	}
	if got, err := opened(key, sealed(t, key, nil)); err != nil || len(got) != 0 {
		t.Fatalf("empty archive: %v", err)
	}
	head := len(archiveMagic) + saltBytes
	frame := 5 + frameBytes + 28
	flip := append([]byte{}, archive...)
	flip[head+frame+100] ^= 1
	swapped := append(append(append([]byte{}, archive[:head]...), archive[head+frame:head+2*frame]...), archive[head:head+frame]...)
	swapped = append(swapped, archive[head+2*frame:]...)
	early := append([]byte{}, archive[:head+frame]...) // the first frame relabelled final
	early[head] = 1
	cases := map[string]struct {
		key, archive []byte
	}{
		"wrong key":       {bytes.Repeat([]byte{8}, BackupKeyBytes), archive},
		"flipped bit":     {key, flip},
		"frames swapped":  {key, swapped},
		"frame dropped":   {key, append(append([]byte{}, archive[:head]...), archive[head+frame:]...)},
		"final dropped":   {key, archive[:head+2*frame]},
		"cut in a frame":  {key, archive[:len(archive)-3]},
		"data after":      {key, append(append([]byte{}, archive...), 0)},
		"other magic":     {key, append([]byte("KYNOTES-PGB2\n"), archive[len(archiveMagic):]...)},
		"early final":     {key, early},
		"final flag lost": {key, append(append([]byte{}, archive[:head+2*frame]...), append([]byte{0}, archive[head+2*frame+1:]...)...)},
	}
	for name, c := range cases {
		if got, err := opened(c.key, c.archive); err == nil {
			t.Errorf("%s: opened %d bytes", name, len(got))
		}
	}
	if _, err := newSealWriter(io.Discard, key[:16]); err == nil {
		t.Fatal("a short key sealed")
	}
}

// The sealed PostgreSQL backup restores into a new database with the restore fence and
// the replay gate committed in the same transaction as the rows.
func TestPostgresBackupRestoresFencedAndGated(t *testing.T) {
	src := postgresRestoreFixture(t)
	key := bytes.Repeat([]byte{3}, BackupKeyBytes)
	var buf bytes.Buffer
	if _, err := BackupPostgres(t.Context(), src.DB(), key, &buf); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte("sealed-token-to-retain")) || bytes.Contains(buf.Bytes(), []byte("usr_restore")) {
		t.Fatal("the archive holds plaintext")
	}
	dst, err := storage.Open(filepath.Join(t.TempDir(), "target.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	if _, err := RestorePostgres(t.Context(), dst.DB(), bytes.Repeat([]byte{4}, BackupKeyBytes), bytes.NewReader(buf.Bytes())); err == nil {
		t.Fatal("restored under the wrong key")
	}
	if _, err := RestorePostgres(t.Context(), dst.DB(), key, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`SELECT count(*) FROM users WHERE id='usr_restore'`,
		`SELECT count(*) FROM objects WHERE id='obj_restore'`,
		`SELECT count(*) FROM sessions WHERE revoked_at<>''`,
		`SELECT count(*) FROM devices WHERE id='dev_restore' AND revoked_at<>''`,
		`SELECT count(*) FROM orgs WHERE id='00000000-0000-0000-0000-000000000001' AND status='stale' AND revision=0`,
		`SELECT count(*) FROM erased_subjects WHERE subject='already-erased'`,
		`SELECT count(*) FROM server_settings WHERE key='kyrecovery_token' AND value='sealed-token-to-retain'`,
		`SELECT count(*) FROM server_settings WHERE key='` + storage.RestoreReplayKey + `'`,
		`SELECT count(*) FROM audit_events WHERE event='platform.restore_prepared'`,
	} {
		if restoreCount(t, dst, q) != 1 {
			t.Fatalf("restored target: %s", q)
		}
	}
}
