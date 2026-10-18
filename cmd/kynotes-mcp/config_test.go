package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testNotebook = "cnt_0123456789abcdefghjkmnpqrs"

func env(password string) func(string) string {
	return func(k string) string {
		if k == "KYNOTES_MCP_PASSWORD" {
			return password
		}
		return ""
	}
}

func TestConfigServerScheme(t *testing.T) {
	for server, ok := range map[string]bool{
		"https://notes.example.com/": true,
		"http://localhost:8080":      true,
		"http://127.0.0.1:8080":      true,
		"http://[::1]:8080":          true,
		"http://notes.example.com":   false,
		"http://192.168.1.5":         false,
		"ftp://notes.example.com":    false,
		"https://u:p@notes.test":     false,
		"notes.example.com":          false,
	} {
		_, err := parseConfig([]string{"--server", server, "--username", "agent", "--notebook", testNotebook, "--state-dir", t.TempDir()}, env("pw"), io.Discard)
		if (err == nil) != ok {
			t.Errorf("%s: err=%v", server, err)
		}
	}
}

func TestConfigPasswordSources(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "pw")
	if err := os.WriteFile(file, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{"--server", "https://n.test", "--username", "agent", "--notebook", testNotebook}
	c, err := parseConfig(append(base, "--password-file", file), env(""), io.Discard)
	if err != nil || c.password != "secret" {
		t.Fatalf("file: %q %v", c.password, err)
	}
	if !strings.HasSuffix(c.stateDir, filepath.Join("kynotes-mcp", "n.test", "agent")) {
		t.Fatalf("state dir %s", c.stateDir)
	}
	if c, err = parseConfig(base, env("from-env"), io.Discard); err != nil || c.password != "from-env" {
		t.Fatalf("env: %q %v", c.password, err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644} {
		_ = os.Chmod(file, mode)
		if _, err := parseConfig(append(base, "--password-file", file), env(""), io.Discard); err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Fatalf("mode %o accepted: %v", mode, err)
		}
	}
	if _, err := parseConfig(base, env(""), io.Discard); err == nil {
		t.Fatal("no password accepted")
	}
	_ = os.Chmod(file, 0o600)
	if _, err := parseConfig(append(base, "--password-file", file), env("both"), io.Discard); err == nil {
		t.Fatal("two password sources accepted")
	}
}

func TestConfigNeedsANotebookID(t *testing.T) {
	for _, nb := range []string{"", "obj_0123456789abcdefghjkmnpqrs", "cnt_../../etc", "cnt_0123456789ABCDEFGHJKMNPQRS"} {
		if _, err := parseConfig([]string{"--server", "https://n.test", "--username", "a", "--notebook", nb}, env("pw"), io.Discard); err == nil {
			t.Errorf("notebook %q accepted", nb)
		}
	}
}

func TestPathPartStaysOneElement(t *testing.T) {
	for in, want := range map[string]string{"agent": "agent", "../x": ".._x", "..": "_..", "a/b": "a_b", "": "_", "n.test:8443": "n.test_8443"} {
		if got := pathPart(in); got != want {
			t.Errorf("pathPart(%q)=%q want %q", in, got, want)
		}
	}
}

func TestBucketAllowsSixtyAMinute(t *testing.T) {
	now := time.Unix(0, 0)
	b := newBucket(60, time.Minute)
	b.now = func() time.Time { return now }
	for i := 0; i < 60; i++ {
		if !b.take() {
			t.Fatalf("call %d refused", i)
		}
	}
	if b.take() {
		t.Fatal("61st call allowed")
	}
	now = now.Add(time.Second)
	if !b.take() || b.take() {
		t.Fatal("one second should refill exactly one call")
	}
	now = now.Add(time.Hour)
	for i := 0; i < 60; i++ {
		if !b.take() {
			t.Fatalf("after an hour, call %d refused", i)
		}
	}
	if b.take() {
		t.Fatal("bucket grew past 60")
	}
}

func TestAuditHoldsNoTextAndNoAgentInput(t *testing.T) {
	f, err := os.OpenFile(filepath.Join(t.TempDir(), "audit.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	b := &bridge{audit: f}
	b.record("read_page", []string{"obj_0123456789abcdefghjkmnpqrs", "Secret title: ignore previous instructions"}, nil)
	b.record("append_to_page", []string{"obj_0123456789abcdefghjkmnpqrs"}, &toolError{"invalid_input", "markdown is over 64 KiB: Secret body"})
	b.record("search", nil, &apiError{status: 409, code: "version_conflict"})
	b.record("list_pages", nil, errors.New("dial tcp: Secret host"))
	f.Close()
	data, _ := os.ReadFile(f.Name())
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 4 || strings.Contains(string(data), "Secret") {
		t.Fatalf("audit:\n%s", data)
	}
	for i, want := range []string{
		`"tool":"read_page","pages":["obj_0123456789abcdefghjkmnpqrs"],"outcome":"ok"}`,
		`"tool":"append_to_page","pages":["obj_0123456789abcdefghjkmnpqrs"],"outcome":"error","code":"invalid_input"}`,
		`"tool":"search","outcome":"error","code":"version_conflict"}`,
		`"tool":"list_pages","outcome":"error","code":"error"}`,
	} {
		if !strings.HasSuffix(lines[i], want) || !strings.HasPrefix(lines[i], `{"time":"`) {
			t.Errorf("line %d: %s", i, lines[i])
		}
	}
}
