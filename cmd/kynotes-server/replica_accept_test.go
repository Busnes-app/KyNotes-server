package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestReplicaMaintenanceCommandRequiresStoppedAcknowledgment(t *testing.T) {
	t.Setenv("KYNOTES_DB_DSN", "postgres://operator:private-dsn-secret@%zz/invalid")
	var out bytes.Buffer
	for _, args := range [][]string{nil, {"--config", "missing.yaml"}, {"--confirm-stopped", "extra"}, {"--confirm-stopped", "--password", "private-flag-secret"}} {
		err := acceptReplicaConfigCommand(args, &out)
		if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "private-") {
			t.Fatalf("command boundary: %v", err)
		}
	}
}
