package app

import (
	"context"
	"errors"

	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// AcceptReplicaConfiguration is host-only maintenance after every replica has stopped.
// It loads the same full field map used by startup preparation, never an operator-made map.
func AcceptReplicaConfiguration(ctx context.Context, path string) error {
	c, err := config.LoadReplicaMaintenance(path)
	if err != nil {
		return errors.New("replicas: configuration unavailable; check the deployment file and environment")
	}
	c, in, err := readReplicaInputs(c)
	if err != nil {
		return err
	}
	store, err := storage.OpenPostgresCurrent(ctx, in.DSN)
	if err != nil {
		return errors.New("replicas: cannot open the exact existing PostgreSQL schema")
	}
	defer store.Close()
	current, err := storage.TenancyOfContext(ctx, store.DB())
	if err != nil || current != in.Tenancy {
		return errors.New("replicas: recorded install binding differs")
	}
	return storage.AcceptReplicaConfig(ctx, store.DB(), c.Secrets.ServerSaltKey, replicaFields(c, in))
}
