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
	"os"
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
	return applySetupCommandInput(args, os.Stdin, stdout, stderr)
}

func applySetupCommandInput(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("apply-setup", flag.ContinueOnError)
	flags.SetOutput(stderr)
	file := flags.String("file", "", "setup bundle (JSON)")
	cfgPath := flags.String("config", "/data/kynotes.yaml", "config path")
	check := flags.Bool("check", false, "inspect without changes")
	caps := flags.Bool("capabilities", false, "advertise setup contract")
	stage := flags.Bool("stage", false, "prepare a secret-free installer bundle from stdin")
	importClient := flags.Bool("import-client", false, "import one scoped private client frame from stdin")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *stage && *importClient || *caps && (*file != "" || *check || *stage || *importClient) || !*caps && *file == "" {
		fmt.Fprintln(stderr, "usage: apply-setup --capabilities | --file BUNDLE [--check] [--stage | --import-client] [--config PATH]")
		return applysetup.ExitInvalid
	}
	if *caps {
		_ = json.NewEncoder(stdout).Encode(struct {
			Schema       string   `json:"schema"`
			Service      string   `json:"service"`
			BundleSchema string   `json:"bundleSchema"`
			Features     []string `json:"features"`
		}{"ky.setup-capabilities/1", "kynotes", "kynotes.setup/1", []string{"sso", "issuer-bound-admin", "dedicated-admin", "protected-setup-files", "bundle-preparation", "client-credential-import", "backup", "check"}})
		return applysetup.ExitOK
	}
	c, err := config.LoadExisting(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "apply-setup:", err)
		return applysetup.ExitInvalid
	}
	if *stage || *importClient {
		raw, err := io.ReadAll(io.LimitReader(stdin, applysetup.MaxBundleBytes+1))
		if err != nil {
			fmt.Fprintln(stderr, "apply-setup: cannot read bounded setup input")
			return applysetup.ExitInvalid
		}
		defer clear(raw)
		var status string
		schema := "kynotes.setup-preparation/1"
		if *importClient {
			status, err = applysetup.ImportClient(c.DataDir, *file, raw, c.Backup.AllowPrivateRecovery, *check)
			schema = "kynotes.client-import/1"
		} else {
			status, err = applysetup.Stage(c.DataDir, *file, raw, c.Backup.AllowPrivateRecovery, *check)
		}
		if err != nil {
			fmt.Fprintln(stderr, "apply-setup:", err)
			return applysetup.ExitInvalid
		}
		if json.NewEncoder(stdout).Encode(struct {
			Schema string `json:"schema"`
			Status string `json:"status"`
		}{schema, status}) != nil {
			return applysetup.ExitError
		}
		return applysetup.ExitOK
	}
	req, err := applysetup.Load(*file, c.Backup.AllowPrivateRecovery)
	if err != nil {
		fmt.Fprintln(stderr, "apply-setup:", err)
		return applysetup.ExitInvalid
	}
	body, code, err := postSetupMode(app.AdminSocketPath(c.DataDir), req, *check)
	if err != nil {
		fmt.Fprintln(stderr, "apply-setup:", err)
		return code
	}
	_, _ = stdout.Write(body)
	return code
}

func postSetup(socket string, req applysetup.Request) ([]byte, int, error) {
	return postSetupMode(socket, req, false)
}

func postSetupMode(socket string, req applysetup.Request, check bool) ([]byte, int, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, applysetup.ExitError, err
	}
	endpoint := "/v1/apply-setup"
	if check {
		endpoint = "/v1/check-setup"
	}
	status, body, err := socketPost(socket, endpoint, payload)
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
