package sso

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestFixedSettingsKeepDeploymentSnapshotAcrossReloadAndSave(t *testing.T) {
	settings := SSOSettings{Enabled: true, IssuerURL: "https://identity.example", ClientID: "kynotes", ClientSecret: "environment-client-secret", HMACSecret: strings.Repeat("h", 32), AutoProvision: true}
	store := NewFixedStore(settings)
	settings.ClientSecret = "caller-change"
	var work sync.WaitGroup
	for range 8 {
		work.Go(func() {
			if err := store.Reload(); err != nil {
				t.Error(err)
			}
			if err := store.Save(SSOSettings{}); !errors.Is(err, ErrFixedSettings) {
				t.Error("fixed settings were writable", err)
			}
			if got := store.Load(); !got.Enabled || !got.AutoProvision || got.ClientSecret != "environment-client-secret" {
				t.Error("snapshot changed")
			}
		})
	}
	work.Wait()
	if store.db != nil {
		t.Fatal("fixed deployment snapshot holds a database")
	}
	if strings.Contains(ErrFixedSettings.Error(), "environment-client-secret") {
		t.Fatal("refusal disclosed a secret")
	}
	// The existing in-memory single-mode store remains writable.
	ordinary := NewStore(nil)
	if err := ordinary.Save(settings); err != nil {
		t.Fatal("single-mode memory store changed", err)
	}
}
