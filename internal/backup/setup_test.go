package backup

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/kynotes-server/internal/applysetup"
)

type setupClaims struct {
	key    recoverykey.PrivateKey
	claims int
}

func (c *setupClaims) ClaimPairing(context.Context, string, string, string, string) (recoveryclient.PairingResult, error) {
	c.claims++
	return recoveryclient.PairingResult{APIToken: "setup-private-token", Key: recoveryclient.RecoveryKey{Public: c.key.Public(), Threshold: 2, TotalShares: 3}}, nil
}
func (c *setupClaims) Deposit(context.Context, string, string, []byte) (recoveryclient.Receipt, error) {
	return recoveryclient.Receipt{}, errors.New("apply-setup never deposits")
}

func setupStatuses(rs []applysetup.Result) map[string]applysetup.Result {
	out := map[string]applysetup.Result{}
	for _, r := range rs {
		out[r.Section] = r
	}
	return out
}

func setupAudits(t *testing.T, svc *Service, event string) int {
	t.Helper()
	var n int
	if err := svc.store.DB().QueryRow(`SELECT count(*) FROM audit_events WHERE event=? AND outcome='success' AND request_id=?`, event, applysetup.RequestID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestApplySetupLocalSettings(t *testing.T) {
	svc, _ := fixture(t)
	ctx := context.Background()
	want := applysetup.Backup{Dir: svc.cfg.Backup.Dir, Keep: svc.cfg.Backup.Keep, DepositInterval: "24h"}
	got := setupStatuses(svc.ApplySetup(ctx, want))
	if got["backup.dir"].Status != applysetup.Present || got["backup.keep"].Status != applysetup.Present || got["backup.interval"].Status != applysetup.Created {
		t.Fatalf("%+v", got)
	}
	if got = setupStatuses(svc.ApplySetup(ctx, want)); got["backup.interval"].Status != applysetup.Present {
		t.Fatalf("%+v", got)
	}
	got = setupStatuses(svc.ApplySetup(ctx, applysetup.Backup{Dir: "/elsewhere", Keep: 3, DepositInterval: "12h"}))
	for _, section := range []string{"backup.dir", "backup.keep", "backup.interval"} {
		if got[section].Status != applysetup.Conflict {
			t.Errorf("%s: %+v", section, got[section])
		}
	}
	if !strings.Contains(got["backup.dir"].Detail, "KYNOTES_BACKUP_DIR") {
		t.Fatal(got["backup.dir"].Detail)
	}
	if d, err := recoveryclient.Interval(0, settings{svc.store}); err != nil || d != 24*time.Hour {
		t.Fatalf("interval changed to %s (%v)", d, err)
	}
	if n := setupAudits(t, svc, "admin.backup_schedule"); n != 1 {
		t.Fatalf("audit rows: %d", n)
	}
}

func TestApplySetupRecoveryPairsOnceAndNeverRepins(t *testing.T) {
	svc, key := fixture(t) // fixture pins key by hand
	claims := &setupClaims{key: key}
	svc.client = claims
	ctx := context.Background()
	want := applysetup.Backup{Recovery: &applysetup.Recovery{URL: "https://kyrecovery.example", PairingCode: "123456"}}
	if got := setupStatuses(svc.ApplySetup(ctx, want)); got["backup.recovery"].Status != applysetup.Created {
		t.Fatalf("%+v", got)
	}
	if got := setupStatuses(svc.ApplySetup(ctx, want)); got["backup.recovery"].Status != applysetup.Present || claims.claims != 1 {
		t.Fatalf("%+v claims=%d", got, claims.claims)
	}
	elsewhere := applysetup.Backup{Recovery: &applysetup.Recovery{URL: "https://kyrecovery-2.example", PairingCode: "654321"}}
	if got := setupStatuses(svc.ApplySetup(ctx, elsewhere)); got["backup.recovery"].Status != applysetup.Conflict || claims.claims != 1 {
		t.Fatalf("%+v claims=%d", got, claims.claims)
	}
	if n := setupAudits(t, svc, "admin.backup_pair"); n != 1 {
		t.Fatalf("audit rows: %d", n)
	}
}

func TestApplySetupRecoveryKeyMismatchIsConflict(t *testing.T) {
	svc, _ := fixture(t)
	other, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	svc.client = &setupClaims{key: other}
	pinned, _ := svc.KeyID()
	got := svc.ApplySetup(context.Background(), applysetup.Backup{Recovery: &applysetup.Recovery{URL: "https://kyrecovery.example", PairingCode: "123456"}})
	if len(got) != 1 || got[0].Status != applysetup.Conflict {
		t.Fatalf("%+v", got)
	}
	if after, _ := svc.KeyID(); after != pinned || pinned == "" {
		t.Fatalf("pin moved from %q to %q", pinned, after)
	}
	if recoveryclient.HasPairing(settings{svc.store}) {
		t.Fatal("token stored for a refused key")
	}
}

// blockingClaims holds the KyRecovery claim open until release closes.
type blockingClaims struct {
	setupClaims
	started, release chan struct{}
}

func (c *blockingClaims) ClaimPairing(ctx context.Context, a, b, d, e string) (recoveryclient.PairingResult, error) {
	close(c.started)
	<-c.release
	return c.setupClaims.ClaimPairing(ctx, a, b, d, e)
}

func TestCloseWaitsForInFlightPairing(t *testing.T) {
	svc, key := fixture(t)
	claims := &blockingClaims{setupClaims: setupClaims{key: key}, started: make(chan struct{}), release: make(chan struct{})}
	svc.client = claims
	applied := make(chan []applysetup.Result, 1)
	go func() {
		applied <- svc.ApplySetup(context.Background(), applysetup.Backup{Recovery: &applysetup.Recovery{URL: "https://kyrecovery.example", PairingCode: "123456"}})
	}()
	<-claims.started
	closed := make(chan struct{})
	go func() { svc.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close returned while a claim was in flight")
	case <-time.After(100 * time.Millisecond):
	}
	close(claims.release)
	<-closed
	if got := setupStatuses(<-applied); got["backup.recovery"].Status != applysetup.Created {
		t.Fatalf("%+v", got)
	}
	if !recoveryclient.HasPairing(settings{svc.store}) {
		t.Fatal("claimed token not persisted before Close returned")
	}
}
