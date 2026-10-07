package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/app"
	"github.com/Busnes-app/kynotes-server/internal/applysetup"
	"github.com/Busnes-app/kynotes-server/internal/config"
)

// setupTimeout outlasts backup.OperationTimeout, the server's own bound.
const setupTimeout = 20 * time.Minute

// applySetupCommand validates the bundle locally, sends it to the running server over the
// admin socket and prints the server's report. It returns the process exit code.
func applySetupCommand(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("apply-setup", flag.ContinueOnError)
	flags.SetOutput(stderr)
	file := flags.String("file", "", "setup bundle (JSON)")
	cfgPath := flags.String("config", "/data/kynotes.yaml", "config path")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *file == "" {
		fmt.Fprintln(stderr, "usage: apply-setup --file BUNDLE [--config PATH]")
		return applysetup.ExitInvalid
	}
	c, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "apply-setup:", err)
		return applysetup.ExitInvalid
	}
	req, err := applysetup.Load(*file, c.Backup.AllowPrivateRecovery)
	if err != nil {
		fmt.Fprintln(stderr, "apply-setup:", err)
		return applysetup.ExitInvalid
	}
	body, code, err := postSetup(app.AdminSocketPath(c.DataDir), req)
	if err != nil {
		fmt.Fprintln(stderr, "apply-setup:", err)
		return code
	}
	_, _ = stdout.Write(body)
	return code
}

func postSetup(socket string, req applysetup.Request) ([]byte, int, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, applysetup.ExitError, err
	}
	status, body, err := socketPost(socket, "/v1/apply-setup", payload)
	if err != nil {
		return nil, applysetup.ExitError, err
	}
	switch status {
	case http.StatusOK:
		var report applysetup.Report
		if err := json.Unmarshal(body, &report); err != nil {
			return nil, applysetup.ExitError, fmt.Errorf("unreadable report: %w", err)
		}
		return body, report.ExitCode(), nil
	case http.StatusBadRequest:
		return nil, applysetup.ExitInvalid, fmt.Errorf("server rejected the bundle: %s", errorMessage(body))
	}
	return nil, applysetup.ExitError, fmt.Errorf("server answered %d: %s", status, errorMessage(body))
}

var errNotRunning = errors.New("kynotes-server is not running")

// socketPost sends one request to the running server's admin socket. A missing or dead
// socket is errNotRunning.
func socketPost(socket, path string, payload []byte) (int, []byte, error) {
	client := &http.Client{Timeout: setupTimeout, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
	resp, err := client.Post("http://kynotes"+path, "application/json", bytes.NewReader(payload))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
			return 0, nil, fmt.Errorf("%w (no admin socket at %s); start it and wait for the health check", errNotRunning, socket)
		}
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, err
}

func errorMessage(body []byte) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error.Message != "" {
		return e.Error.Message
	}
	return strings.TrimSpace(string(body))
}
