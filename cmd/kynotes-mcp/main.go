// Command kynotes-mcp is a local stdio MCP server that lets an AI agent read, and when allowed
// write, one KyNotes notebook as its own everyday account. It decrypts on this machine; the
// server only ever sees ciphertext. See docs/MCP.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var version = "dev"

var notebookID = regexp.MustCompile(`^cnt_[0-9a-hjkmnp-tv-z]{26}$`)

type config struct {
	server, username, password, notebook, stateDir string
	readOnly                                       bool
}

// parseConfig reads flags and the password; it touches no network and creates nothing.
func parseConfig(args []string, getenv func(string) string, stderr io.Writer) (config, error) {
	fs := flag.NewFlagSet("kynotes-mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c config
	var passwordFile string
	fs.StringVar(&c.server, "server", "", "KyNotes URL (https, or http on a loopback host)")
	fs.StringVar(&c.username, "username", "", "the agent's everyday account")
	fs.StringVar(&passwordFile, "password-file", "", "file holding the password, mode 0600 (else $KYNOTES_MCP_PASSWORD)")
	fs.StringVar(&c.notebook, "notebook", "", "the one notebook (cnt_…) the bridge may touch")
	fs.StringVar(&c.stateDir, "state-dir", "", "pins, key state and audit log (default: user config dir/kynotes-mcp/<host>/<user>)")
	fs.BoolVar(&c.readOnly, "read-only", false, "offer read tools only, even to an editor")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	u, err := url.Parse(c.server)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return c, errors.New("--server must be a URL such as https://notes.example.com")
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !loopback(u.Hostname())) {
		return c, errors.New("--server must use https (http only for localhost)")
	}
	c.server = strings.TrimRight(u.String(), "/")
	if c.username == "" {
		return c, errors.New("--username is required")
	}
	if !notebookID.MatchString(c.notebook) {
		return c, errors.New("--notebook must be a notebook ID (cnt_…)")
	}
	env := getenv("KYNOTES_MCP_PASSWORD")
	switch {
	case passwordFile != "" && env != "":
		return c, errors.New("set either --password-file or KYNOTES_MCP_PASSWORD, not both")
	case passwordFile != "":
		if c.password, err = readSecret(passwordFile); err != nil {
			return c, err
		}
	default:
		c.password = env
	}
	if c.password == "" {
		return c, errors.New("no password: set KYNOTES_MCP_PASSWORD or --password-file")
	}
	if c.stateDir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return c, err
		}
		c.stateDir = filepath.Join(base, "kynotes-mcp", pathPart(u.Host), pathPart(c.username))
	}
	return c, nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// pathPart makes a server-chosen name safe as one path element.
func pathPart(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '.' || r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			return r
		}
		return '_'
	}, s)
	if s == "" || s == "." || s == ".." {
		return "_" + s
	}
	return s
}

// readSecret reads a password file only the owner can read.
func readSecret(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s: mode %o; others can read it, run chmod 600", path, info.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	return strings.TrimRight(string(b), "\r\n"), err
}

func main() {
	c, err := parseConfig(os.Args[1:], os.Getenv, os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "kynotes-mcp:", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	b, err := newBridge(ctx, c, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "kynotes-mcp:", err)
		os.Exit(1)
	}
	defer b.close()
	b.fatal = func(err error) {
		fmt.Fprintln(os.Stderr, "kynotes-mcp:", err)
		os.Exit(1)
	}
	if err := b.server().Run(ctx, &mcp.StdioTransport{}); err != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, "kynotes-mcp:", err)
		os.Exit(1)
	}
}
