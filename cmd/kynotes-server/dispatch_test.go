package main

import (
	"strings"
	"testing"
)

func TestUnknownSubcommandIsRejected(t *testing.T) {
	for _, args := range [][]string{{"backup", "--out", "DIR"}, {"unknown", "--config", "ignored.yaml"}} {
		err := rejectUnknownCommand(args)
		if err == nil {
			t.Fatal("unknown command reached server mode", args)
		}
		if args[0] == "backup" && !strings.Contains(err.Error(), "copy-data-dir") {
			t.Fatal("missing migration guidance")
		}
	}
	for _, args := range [][]string{nil, {"--config", "config.yaml"}, {"-h"}} {
		if err := rejectUnknownCommand(args); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVersionLineUsesVariable(t *testing.T) {
	old := version
	defer func() { version = old }()
	version = "abc123"
	if got := versionLine(); got != "kynotes-server abc123" {
		t.Fatal(got)
	}
}
