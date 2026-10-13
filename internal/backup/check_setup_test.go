package backup

import (
	"context"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/applysetup"
)

func TestSetupInspectionNeverClaimsOrCreatesSchedule(t *testing.T) {
	svc, key := fixture(t)
	claims := &setupClaims{key: key}
	svc.client = claims
	want := applysetup.Backup{DepositInterval: "24h", Recovery: &applysetup.Recovery{URL: "https://kyrecovery.example", PairingCode: "123456"}}
	for _, r := range svc.CheckSetup(want) {
		if r.Status != applysetup.Conflict {
			t.Fatal(r)
		}
	}
	if claims.claims != 0 || setupAudits(t, svc, "admin.backup_schedule") != 0 || setupAudits(t, svc, "backup.paired") != 0 {
		t.Fatal("inspection mutated")
	}
	for _, r := range svc.ApplySetup(context.Background(), want) {
		if r.Status != applysetup.Created {
			t.Fatal(r)
		}
	}
	beforeSchedule := setupAudits(t, svc, "admin.backup_schedule")
	for _, r := range svc.CheckSetup(want) {
		if r.Status != applysetup.Present {
			t.Fatal(r)
		}
	}
	if claims.claims != 1 || setupAudits(t, svc, "admin.backup_schedule") != beforeSchedule {
		t.Fatal("inspection mutated configured state")
	}
}
