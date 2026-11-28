package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// Multi mode's host-only break-glass path never opens a data directory or mints server keys.
// The existing single-mode command remains responsible for its original flags and behavior.
func staffUserCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	usage := errors.New("multi mode: user add --admin --username <name>; derived {authSecret,loginSalt,iterations} on stdin, target/shared identity in environment")
	if len(args) == 0 || args[0] != "add" {
		return usage
	}
	flags := flag.NewFlagSet("user add", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	admin := flags.Bool("admin", false, "create a staff administrator")
	name := flags.String("username", "", "dedicated administrator username")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || !*admin {
		return usage
	}
	username := strings.ToLower(strings.TrimSpace(*name))
	if username == "" || len(username) > 128 || strings.IndexFunc(username, unicode.IsControl) >= 0 {
		return usage
	}
	dsn, staffOrg := os.Getenv("KYNOTES_DB_DSN"), os.Getenv("KYNOTES_STAFF_ORG_ID")
	cells, err := config.Cells()
	if dsn == "" || staffOrg == "" || err != nil {
		return errors.New("staff creation requires KYNOTES_DB_DSN, KYNOTES_STAFF_ORG_ID and KY_CELLS in the environment")
	}
	if file, ok := stdin.(*os.File); ok {
		if state, err := file.Stat(); err == nil && state.Mode()&os.ModeCharDevice != 0 {
			fmt.Fprintln(os.Stderr, "Reading JSON {authSecret, loginSalt, iterations} from stdin; end it with Ctrl-D.")
		}
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, 4097))
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		return errors.New("stdin must contain bounded derived credentials JSON")
	}
	var in struct {
		AuthSecret string `json:"authSecret"`
		LoginSalt  string `json:"loginSalt"`
		Iterations int    `json:"iterations"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&in) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("stdin must contain only derived authSecret, loginSalt and iterations")
	}
	secret, err := hex.DecodeString(in.AuthSecret)
	if err != nil || len(secret) != 32 || in.AuthSecret != strings.ToLower(in.AuthSecret) {
		return errors.New("derived authSecret must be 32 bytes in lowercase hexadecimal")
	}
	salt, err := base64.StdEncoding.Strict().DecodeString(in.LoginSalt)
	if err != nil || len(salt) < 16 || len(salt) > 64 {
		return errors.New("loginSalt must be 16 to 64 bytes in standard base64")
	}
	if in.Iterations == 0 {
		in.Iterations = auth.LoginIterations
	}
	if in.Iterations < auth.LoginIterations || in.Iterations > 1000000 {
		return errors.New("iterations must be between 600000 and 1000000")
	}
	store, err := storage.OpenPostgresCurrent(ctx, dsn)
	if err != nil {
		return errors.New("cannot open the exact existing PostgreSQL schema; check target and matching release")
	}
	defer store.Close()
	// Verify the recorded target before spending password-hash work or creating credentials.
	tenancy, err := storage.TenancyOfContext(ctx, store.DB())
	if err != nil || !tenancy.Binds(storage.Tenancy{Mode: "multi", StaffOrg: staffOrg}, cells) {
		return errors.New("recorded multi-mode staff org or cells differ; no account created")
	}
	hash, err := auth.HashAuthSecret(in.AuthSecret)
	if err != nil {
		return errors.New("password verifier unavailable; no account created")
	}
	code, recoveryHash, err := auth.NewRecoveryCode()
	if err != nil {
		return err
	}
	id, err := ids.Mint("usr")
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	err = store.WithTx(ctx, func(tx *sql.Tx) error {
		current, err := storage.TenancyOfContext(ctx, tx)
		if err != nil {
			return err
		}
		if current != tenancy {
			return errors.New("target changed")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,recovery_hash,role,account_kind,status,password_admin_known,created_at,updated_at,org_id) VALUES(?,?,?,?,?,?,'admin','admin','active',1,?,?,?)`, id, username, hash, in.LoginSalt, in.Iterations, recoveryHash, now, now, staffOrg); err != nil {
			return err
		}
		return storage.RecordAuditOutcomeTx(tx, "", "admin.user.create", "", id, "success", "kind=admin,source=host", "staff-user-add")
	})
	if err != nil {
		return errors.New("staff account creation failed; check target, username and audit availability")
	}
	_, err = fmt.Fprintf(stdout, "Created staff administrator %s.\nrecovery code: %s\nStore it offline; it is shown once. This administrator cannot open notes.\n", username, code)
	if err != nil {
		return errors.New("staff account was created but recovery-code output failed; retain the input credentials")
	}
	return nil
}
