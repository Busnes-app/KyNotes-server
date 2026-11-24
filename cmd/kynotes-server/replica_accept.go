package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/app"
)

func acceptReplicaConfigCommand(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("accept-replica-config", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	confirm := flags.Bool("confirm-stopped", false, "every replica has been stopped")
	path := flags.String("config", "/data/kynotes.yaml", "deployment configuration")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !*confirm {
		return errors.New("usage: accept-replica-config --confirm-stopped [--config <path>]; stop every replica first")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := app.AcceptReplicaConfiguration(ctx, *path); err != nil {
		return err
	}
	_, err := fmt.Fprintln(stdout, "Accepted shared configuration; changed field names audited. Start only replicas with the accepted settings when every hosted prerequisite is satisfied. This command does not enable multi startup.")
	return err
}
