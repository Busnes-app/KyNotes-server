package storage

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"testing"
)

func TestReplicaConfigurationRejectsMismatchWithoutDisclosingValues(t *testing.T) {
	a, b := sharedReplicas(t)
	ctx := context.Background()
	key := strings.Repeat("k", 32)
	fields := map[string]string{"sso": "https://identity.private.example/client-secret", "region": "eu", "blob_bucket": "private-bucket"}
	if err := VerifyReplicaConfig(ctx, a, key, fields); err != nil {
		t.Fatal(err)
	}
	if err := VerifyReplicaConfig(ctx, b, key, fields); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := a.QueryRow(`SELECT value FROM server_settings WHERE key='replica_config_fingerprint'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{key, fields["sso"], fields["region"], fields["blob_bucket"]} {
		if strings.Contains(stored, value) {
			t.Fatalf("fingerprint disclosed setting %q", value)
		}
	}
	wrong := map[string]string{"sso": "https://other.private.example/new-secret", "region": "us", "blob_bucket": "other-bucket"}
	err := VerifyReplicaConfig(ctx, b, key, wrong)
	if err == nil || !strings.Contains(err.Error(), "region") || !strings.Contains(err.Error(), "sso") {
		t.Fatalf("mismatch not named: %v", err)
	}
	for _, value := range wrong {
		if strings.Contains(err.Error(), value) {
			t.Fatalf("mismatch disclosed a value: %v", err)
		}
	}
	if err := VerifyReplicaConfig(ctx, b, strings.Repeat("q", 32), wrong); err == nil || err.Error() != "replicas: KYNOTES_SECRETS_SERVER_SALT_KEY differs" {
		t.Fatalf("key mismatch: %v", err)
	}
	if err := VerifyReplicaConfig(ctx, a, key, fields); err != nil {
		t.Fatalf("mismatch changed stored fingerprint: %v", err)
	}
}

func TestReplicaConfigurationConcurrentFirstStartAdmitsOneConfiguration(t *testing.T) {
	a, b := sharedReplicas(t)
	ctx := context.Background()
	key := strings.Repeat("k", 32)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i, db := range []*sql.DB{a, b} {
		wg.Add(1)
		go func(i int, db *sql.DB) {
			defer wg.Done()
			results <- VerifyReplicaConfig(ctx, db, key, map[string]string{"region": []string{"eu", "us"}[i]})
		}(i, db)
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("different initial configurations admitted: %d", success)
	}
}
