package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/Busnes-app/kynotes-server/internal/app"
	"github.com/Busnes-app/kynotes-server/internal/appversion"
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
	if len(os.Args) > 1 && os.Args[1] == "apply-setup" {
		os.Exit(applySetupCommand(os.Args[2:], os.Stdout, os.Stderr))
	}
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		if e := healthcheckCommand(os.Args[2:]); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
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
		if e := bootstrapCommand(c); e != nil {
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
	showVersion := flag.Bool("version", false, "print version")
	if err := rejectUnknownCommand(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments; server mode accepts flags only")
		os.Exit(2)
	}
	if *showVersion {
		fmt.Println(versionLine())
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
	if e = app.Serve(ctx, c, log, appversion.String()); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

func versionLine() string { return "kynotes-server " + appversion.String() }

func commandConfig(args []string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--config" {
			return args[i+1]
		}
	}
	return "/data/kynotes.yaml"
}

// openLocked opens the store under the server's data-directory lock; done releases both.
func openLocked(c config.Config) (s *storage.Store, b *blobstore.Store, done func(), e error) {
	unlock, e := storage.LockDirectory(c.DataDir)
	if e != nil {
		return nil, nil, nil, e
	}
	if s, e = storage.Open(filepath.Join(c.DataDir, "kynotes.sqlite")); e != nil {
		unlock()
		return nil, nil, nil, e
	}
	if b, e = blobstore.New(c.DataDir); e != nil {
		s.Close()
		unlock()
		return nil, nil, nil, e
	}
	return s, b, func() { s.Close(); unlock() }, nil
}
func bootstrapCommand(c config.Config) error {
	s, _, done, e := openLocked(c)
	if e != nil {
		return e
	}
	defer done()
	return app.EnsureBootstrapAdmin(s.DB(), c)
}
func gcCommand(args []string) error {
	if len(args) < 1 || args[0] != "--now" {
		return fmt.Errorf("usage: gc --now [--retention <duration>] [--config <path>]")
	}
	c, e := config.Load(commandConfig(args))
	if e != nil {
		return e
	}
	retention, e := time.ParseDuration(c.GC.Retention)
	for i := 1; i+1 < len(args); i++ {
		if args[i] == "--retention" {
			retention, e = time.ParseDuration(args[i+1])
		}
	}
	if e != nil {
		return fmt.Errorf("gc --retention: %w", e)
	}
	if retention < 0 {
		return errors.New("gc --retention: must not be negative")
	}
	// ponytail: runs beside a live server without the lock, because the acceptance probe
	// (IMPLEMENTATION_PLAN.md step 12) does exactly that with --retention 0s. Upgrade
	// path: an admin.sock route like deposit, then the lock and the 1h floor here.
	s, e := storage.Open(filepath.Join(c.DataDir, "kynotes.sqlite"))
	if e != nil {
		return e
	}
	defer s.Close()
	b, e := blobstore.New(c.DataDir)
	if e != nil {
		return e
	}
	_, e = storage.RunGC(s.DB(), b, time.Now().UTC(), retention, c.GC.Enabled)
	return e
}
func backupCommand(args []string) error {
	if len(args) < 2 || args[0] != "--out" {
		return fmt.Errorf("usage: copy-data-dir --out <dir> [--config <path>]")
	}
	out := args[1]
	c, e := config.Load(commandConfig(args))
	if e != nil {
		return e
	}
	if entries, e := os.ReadDir(out); e == nil && len(entries) > 0 {
		return errors.New("copy-data-dir: --out must be absent or empty")
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e = os.MkdirAll(out, 0700); e != nil {
		return e
	}
	if inside, e := within(out, c.DataDir); e != nil {
		return e
	} else if inside {
		return errors.New("copy-data-dir: --out must be outside the data directory")
	}
	unlock, e := storage.LockDirectory(c.DataDir)
	if e != nil {
		return e
	}
	defer unlock()
	// Opening checkpoints the WAL and checks integrity; closing leaves one database file to copy.
	s, e := storage.Open(filepath.Join(c.DataDir, "kynotes.sqlite"))
	if e != nil {
		return e
	}
	if e = s.Close(); e != nil {
		return e
	}
	return copyTree(c.DataDir, out)
}

// within reports whether path is root or below it, following symlinks.
func within(path, root string) (bool, error) {
	rootInfo, e := os.Stat(root)
	if e != nil {
		return false, e
	}
	if path, e = filepath.EvalSymlinks(path); e != nil {
		return false, e
	}
	if path, e = filepath.Abs(path); e != nil {
		return false, e
	}
	for {
		if info, e := os.Stat(path); e == nil && os.SameFile(info, rootInfo) {
			return true, nil
		}
		parent := filepath.Dir(path)
		if parent == path {
			return false, nil
		}
		path = parent
	}
}

var restoreRequired = []string{"kynotes.sqlite", filepath.Join("secrets", "pairing.key"), filepath.Join("secrets", "serversalt.key")}

// restoreCommand copies --in into a staging directory beside the data, checks it, then
// swaps entries by rename. The data directory may be a mount point, so it is never
// renamed itself; its previous entries are kept in .restore-previous-* for the operator.
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
	unlock, e := storage.LockDirectory(c.DataDir)
	if e != nil {
		return e
	}
	defer unlock()
	for _, name := range restoreRequired {
		if info, e := os.Stat(filepath.Join(in, name)); e != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("restore-data-dir: --in has no %s; nothing was changed", name)
		}
	}
	if inside, e := within(c.DataDir, in); e != nil {
		return e
	} else if inside {
		return errors.New("restore-data-dir: the data directory is inside --in")
	}
	entries, e := os.ReadDir(c.DataDir)
	if e != nil {
		return e
	}
	var current []string
	for _, x := range entries {
		if x.Name() != storage.LockFileName {
			current = append(current, x.Name())
		}
	}
	if len(current) > 0 && !force {
		return fmt.Errorf("data directory is not empty; use --force")
	}
	staging, e := os.MkdirTemp(c.DataDir, ".restore-staging-")
	if e != nil {
		return e
	}
	if e = stageRestore(in, staging); e != nil {
		_ = os.RemoveAll(staging)
		return fmt.Errorf("restore-data-dir: %w; nothing was changed", e)
	}
	previous, e := os.MkdirTemp(c.DataDir, ".restore-previous-")
	if e != nil {
		_ = os.RemoveAll(staging)
		return e
	}
	if e = swapEntries(c.DataDir, staging, previous, current); e != nil {
		_ = os.Remove(previous)
		return fmt.Errorf("restore-data-dir: %w; entries moved back, staged copy kept in %s", e, staging)
	}
	_ = os.Remove(staging)
	if len(current) == 0 {
		return os.Remove(previous)
	}
	fmt.Printf("Previous data kept in %s; remove it once the restored server checks out.\n", previous)
	return nil
}
func stageRestore(in, staging string) error {
	if e := copyTree(in, staging); e != nil {
		return e
	}
	s, e := storage.Open(filepath.Join(staging, "kynotes.sqlite"))
	if e != nil {
		return e
	}
	defer s.Close()
	return s.IntegrityCheck(context.Background())
}

// swapEntries moves current entries of dir into previous and staged ones into dir,
// moving everything back if a rename fails.
func swapEntries(dir, staging, previous string, current []string) error {
	staged, e := os.ReadDir(staging)
	if e != nil {
		return e
	}
	var undo [][2]string
	move := func(from, to string) error {
		if e := os.Rename(from, to); e != nil {
			for i := len(undo) - 1; i >= 0; i-- {
				_ = os.Rename(undo[i][1], undo[i][0])
			}
			return e
		}
		undo = append(undo, [2]string{from, to})
		return nil
	}
	for _, name := range current {
		if e := move(filepath.Join(dir, name), filepath.Join(previous, name)); e != nil {
			return e
		}
	}
	for _, x := range staged {
		if e := move(filepath.Join(staging, x.Name()), filepath.Join(dir, x.Name())); e != nil {
			return e
		}
	}
	return nil
}
func quotaCommand(args []string) error {
	if len(args) != 5 || args[0] != "set" || args[1] != "--user" || args[3] != "--bytes" || args[4] == "" {
		return fmt.Errorf("usage: quota set --user <id> --bytes <n>")
	}
	c, e := config.Load(commandConfig(args))
	if e != nil {
		return e
	}
	s, _, done, e := openLocked(c)
	if e != nil {
		return e
	}
	defer done()
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
		// The lock belongs to its own directory; sockets and links are not data.
		if rel == storage.LockFileName || !info.Mode().IsRegular() {
			return nil
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
	// Opening migrates, so even the checks write.
	s, b, done, e := openLocked(c)
	if e != nil {
		return e
	}
	defer done()
	if kind == "integrity-check" {
		return s.IntegrityCheck(context.Background())
	}
	return storage.Consistency(s.DB(), b)
}

// An account is an administrator account or an everyday account, never both.
var errUserAddUsage = errors.New("usage: user add --username <name> [--password <pass>] [--admin | --everyday]  (default --everyday; --admin creates an administrator account, which cannot open notes)")

func userCommand(args []string) error {
	if len(args) < 1 || args[0] != "add" {
		return errUserAddUsage
	}
	var username, password string
	admin, everyday := false, false
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
		case "--everyday":
			everyday = true
		}
	}
	if admin && everyday {
		return errUserAddUsage
	}
	if strings.TrimSpace(username) == "" {
		return fmt.Errorf("username required")
	}
	c, e := config.Load(commandConfig(args))
	if e != nil {
		return e
	}
	s, _, done, e := openLocked(c)
	if e != nil {
		return e
	}
	defer done()

	var authSecret, loginSalt string
	iterations := auth.LoginIterations

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
		if in.Iterations != 0 {
			iterations = in.Iterations
		}
		if iterations < auth.LoginIterations || iterations > 1000000 {
			return fmt.Errorf("iterations must be between %d and 1000000", auth.LoginIterations)
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
	role, kind := "user", "user"
	if admin {
		role, kind = "admin", "admin"
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, e = s.DB().Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,recovery_hash,role,account_kind,status,password_admin_known,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,'active',1,?,?)`, id, strings.ToLower(username), hash, loginSalt, iterations, recoveryHash, role, kind, now, now)
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
