package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/Busnes-app/kynotes-server/internal/app"
	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/storage"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "gc" {
		if e := gcCommand(os.Args[2:]); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "mirror-blobs", "fetch-blobs", "test-blob-target":
			if e := mirrorCommand(os.Args[1], os.Args[2:]); e != nil {
				fmt.Fprintln(os.Stderr, e)
				os.Exit(1)
			}
			return
		case "deposit", "export-capsule", "backup-drill", "restore":
			if e := capsuleCommand(os.Args[1], os.Args[2:]); e != nil {
				fmt.Fprintln(os.Stderr, e)
				os.Exit(1)
			}
			return
		}
	}
	if len(os.Args) > 1 && os.Args[1] == "copy-data-dir" {
		if e := backupCommand(os.Args[2:]); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "restore-data-dir" {
		if e := restoreCommand(os.Args[2:]); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "quota" {
		if e := quotaCommand(os.Args[2:]); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && (os.Args[1] == "integrity-check" || os.Args[1] == "consistency-check") {
		if e := checkCommand(os.Args[1], os.Args[2:]); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "bootstrap-admin" {
		c, e := config.Load(commandConfig(os.Args[2:]))
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(2)
		}
		s, e := storage.Open(filepath.Join(c.DataDir, "kynotes.sqlite"))
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		defer s.Close()
		if e := app.EnsureBootstrapAdmin(s.DB(), c); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "user" {
		if e := userCommand(os.Args[2:]); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	path := flag.String("config", "/data/kynotes.yaml", "config path")
	check := flag.Bool("check-config", false, "validate configuration")
	version := flag.Bool("version", false, "print version")
	if err := rejectUnknownCommand(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments; server mode accepts flags only")
		os.Exit(2)
	}
	if *version {
		fmt.Println("kynotes-server dev")
		return
	}
	c, e := config.Load(*path)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
	if *check {
		return
	}
	log := logging.New(os.Stdout, c.Log.Level, c.Log.Format)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if e = app.Serve(ctx, c, log); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

func commandConfig(args []string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--config" {
			return args[i+1]
		}
	}
	return "/data/kynotes.yaml"
}

func loadStoreForCommand(configPath string) (config.Config, *storage.Store, *blobstore.Store, error) {
	c, e := config.Load(configPath)
	if e != nil {
		return c, nil, nil, e
	}
	s, e := storage.Open(filepath.Join(c.DataDir, "kynotes.sqlite"))
	if e != nil {
		return c, nil, nil, e
	}
	b, e := blobstore.New(c.DataDir)
	if e != nil {
		s.Close()
		return c, nil, nil, e
	}
	return c, s, b, nil
}
func gcCommand(args []string) error {
	if len(args) < 1 || args[0] != "--now" {
		return fmt.Errorf("usage: gc --now [--retention <duration>] [--config <path>]")
	}
	c, s, b, e := loadStoreForCommand(commandConfig(args))
	if e != nil {
		return e
	}
	defer s.Close()
	retention := mustDuration(c.GC.Retention)
	for i := 1; i+1 < len(args); i++ {
		if args[i] == "--retention" {
			retention = mustDuration(args[i+1])
		}
	}
	_, e = storage.RunGC(s.DB(), b, time.Now().UTC(), retention, c.GC.Enabled)
	return e
}
func mustDuration(v string) time.Duration { d, _ := time.ParseDuration(v); return d }
func backupCommand(args []string) error {
	if len(args) < 2 || args[0] != "--out" {
		return fmt.Errorf("usage: copy-data-dir --out <dir> [--config <path>]")
	}
	configPath := commandConfig(args)
	c, e := config.Load(configPath)
	if e != nil {
		return e
	}
	if _, e = os.Stat(filepath.Join(c.DataDir, ".kynotes.lock")); e == nil {
		return fmt.Errorf("server is using the data directory; stop it before backup")
	}
	_, s, _, e := loadStoreForCommand(configPath)
	if e != nil {
		return e
	}
	_ = s.Close()
	return copyTree(c.DataDir, args[1])
}
func restoreCommand(args []string) error {
	if len(args) < 2 || args[0] != "--in" {
		return fmt.Errorf("usage: restore-data-dir --in <dir> [--force]")
	}
	in := args[1]
	force := false
	for _, arg := range args[2:] {
		if arg == "--force" {
			force = true
		}
	}
	c, e := config.Load(commandConfig(args))
	if e != nil {
		return e
	}
	if _, e = os.Stat(filepath.Join(c.DataDir, ".kynotes.lock")); e == nil {
		return fmt.Errorf("server is using the data directory; stop it before restore")
	}
	entries, e := os.ReadDir(c.DataDir)
	if e != nil {
		return e
	}
	if len(entries) > 0 && !force {
		return fmt.Errorf("data directory is not empty; use --force")
	}
	if force {
		for _, x := range entries {
			if e = os.RemoveAll(filepath.Join(c.DataDir, x.Name())); e != nil {
				return e
			}
		}
	}
	if e = copyTree(in, c.DataDir); e != nil {
		return e
	}
	s, e := storage.Open(filepath.Join(c.DataDir, "kynotes.sqlite"))
	if e != nil {
		return e
	}
	defer s.Close()
	return s.IntegrityCheck(context.Background())
}
func quotaCommand(args []string) error {
	if len(args) != 5 || args[0] != "set" || args[1] != "--user" || args[3] != "--bytes" || args[4] == "" {
		return fmt.Errorf("usage: quota set --user <id> --bytes <n>")
	}
	c, s, _, e := loadStoreForCommand(commandConfig(args))
	_ = c
	if e != nil {
		return e
	}
	defer s.Close()
	n, e := strconv.ParseInt(args[4], 10, 64)
	if e != nil {
		return e
	}
	_, e = s.DB().Exec(`UPDATE users SET quota_bytes=? WHERE id=?`, n, args[2])
	return e
}
func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(src, path)
		if e != nil {
			return e
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		in, e := os.Open(path)
		if e != nil {
			return e
		}
		defer in.Close()
		if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
			return e
		}
		out, e := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode().Perm())
		if e != nil {
			return e
		}
		if _, e = io.Copy(out, in); e == nil {
			e = out.Sync()
		}
		_ = out.Close()
		return e
	})
}

func checkCommand(kind string, args []string) error {
	c, e := config.Load(commandConfig(args))
	if e != nil {
		return e
	}
	s, e := storage.Open(c.DataDir + "/kynotes.sqlite")
	if e != nil {
		return e
	}
	defer s.Close()
	if kind == "integrity-check" {
		return s.IntegrityCheck(context.Background())
	}
	b, e := blobstore.New(c.DataDir)
	if e != nil {
		return e
	}
	return storage.Consistency(s.DB(), b)
}
func userCommand(args []string) error {
	if len(args) < 1 || args[0] != "add" {
		return fmt.Errorf("usage: user add --username <name> [--password <pass>] [--admin]")
	}
	var username, password string
	admin := false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--username":
			if i+1 >= len(args) {
				return fmt.Errorf("--username requires a value")
			}
			username = args[i+1]
			i++
		case "--password":
			if i+1 >= len(args) {
				return fmt.Errorf("--password requires a value")
			}
			password = args[i+1]
			i++
		case "--admin":
			admin = true
		}
	}
	if strings.TrimSpace(username) == "" {
		return fmt.Errorf("username required")
	}
	c, e := config.Load(commandConfig(args))
	if e != nil {
		return e
	}
	s, e := storage.Open(filepath.Join(c.DataDir, "kynotes.sqlite"))
	if e != nil {
		return e
	}
	defer s.Close()

	var authSecret, loginSalt string
	iterations := 600000

	if password != "" {
		loginSalt = auth.SyntheticLoginSalt(c.Secrets.ServerSaltKey, username)
		authSecret, e = auth.DeriveAuthSecret(password, loginSalt, iterations)
		if e != nil {
			return e
		}
	} else {
		var in struct {
			AuthSecret string `json:"authSecret"`
			LoginSalt  string `json:"loginSalt"`
			Iterations int    `json:"iterations"`
		}
		b, e := io.ReadAll(os.Stdin)
		if e != nil || len(b) == 0 {
			return fmt.Errorf("either --password must be supplied or stdin must contain JSON {authSecret, loginSalt, iterations}")
		}
		if json.Unmarshal(b, &in) != nil || len(in.AuthSecret) != 64 || in.LoginSalt == "" {
			return fmt.Errorf("stdin must contain derived authSecret and loginSalt")
		}
		authSecret = in.AuthSecret
		loginSalt = in.LoginSalt
		if in.Iterations > 0 {
			iterations = in.Iterations
		}
	}

	hash, e := auth.HashAuthSecret(authSecret)
	if e != nil {
		return e
	}
	code, recoveryHash, e := auth.NewRecoveryCode()
	if e != nil {
		return e
	}
	id, e := ids.Mint("usr")
	if e != nil {
		return e
	}
	role := "user"
	if admin {
		role = "admin"
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, e = s.DB().Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,recovery_hash,role,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'active',?,?)`, id, strings.ToLower(username), hash, loginSalt, iterations, recoveryHash, role, now, now)
	if e != nil {
		return e
	}
	fmt.Fprintf(os.Stdout, "recovery code: %s\nStore it offline; it is shown once and unlocks the account without the password.\n", code)
	return nil
}

// Called only after all supported subcommands have dispatched and returned.
func rejectUnknownCommand(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return nil
	}
	if args[0] == "backup" {
		return fmt.Errorf("backup was removed; use copy-data-dir for a local directory copy or deposit for a sealed capsule")
	}
	return fmt.Errorf("unknown subcommand %q; server mode accepts flags only", args[0])
}
