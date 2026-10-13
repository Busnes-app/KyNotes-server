package applysetup

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func importFixture(t *testing.T) (string, string, clientCredentials) {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "installer", "setup.json")
	frame := clientCredentials{Schema: "kyidentity.client-credentials/1", SetupID: "271333e2-c221-4601-b249-563b3d828530", IssuerURL: "https://identity.example.test", ClientID: "notes", RedirectURIs: []string{"https://notes.example.test/api/v1/auth/oidc/callback"}, DirectoryURL: "https://notes.example.test/api/v1/sync/events", ClientSecret: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{'c'}, 32)), DirectorySecret: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{'d'}, 32))}
	frame.Administrator.Subject, frame.Administrator.Username, frame.Administrator.Role = "owner-subject", "owner-admin", "kynotes.admin"
	metadata, err := json.Marshal(map[string]any{"version": 1, "sso": map[string]string{"issuerUrl": frame.IssuerURL, "clientId": frame.ClientID, "clientSecretFile": filepath.Join(dir, "installer", "client.secret"), "redirectUri": frame.RedirectURIs[0], "directoryHmacSecretFile": filepath.Join(dir, "installer", "directory.secret")}, "admins": []Admin{{Issuer: frame.IssuerURL, Subject: frame.Administrator.Subject, Username: frame.Administrator.Username}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Stage(dir, file, metadata, false, false); err != nil {
		t.Fatal(err)
	}
	return dir, file, frame
}

func importFrame(t *testing.T, dir, file string, frame clientCredentials, check bool) (string, error) {
	t.Helper()
	raw, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	return ImportClient(dir, file, raw, false, check)
}

func TestClientImportCopiesExactBytesAndResumes(t *testing.T) {
	dir, file, frame := importFixture(t)
	if _, err := importFrame(t, dir, file, frame, true); err == nil {
		t.Fatal("absent credentials inspected as present")
	}
	entries, _ := os.ReadDir(filepath.Dir(file))
	if len(entries) != 1 {
		t.Fatal("check created files")
	}
	if status, err := importFrame(t, dir, file, frame, false); err != nil || status != "created" {
		t.Fatal("import failed", err)
	}
	for _, check := range []bool{true, false} {
		if status, err := importFrame(t, dir, file, frame, check); err != nil || status != "present" {
			t.Fatal("retained import failed", err)
		}
	}
	req, err := Load(file, false)
	if err != nil || req.SSO.ClientSecret != frame.ClientSecret || req.SSO.HMACSecret != frame.DirectorySecret || req.Admins[0].Subject != frame.Administrator.Subject {
		t.Fatal("import did not feed native setup with exact scoped values", err)
	}
	for _, name := range []string{"client.secret", "directory.secret", "client-import.json"} {
		st, err := os.Stat(filepath.Join(filepath.Dir(file), name))
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatal("import file is not private")
		}
	}
	receipt, _ := os.ReadFile(filepath.Join(filepath.Dir(file), "client-import.json"))
	if bytes.Contains(receipt, []byte(frame.ClientSecret)) || bytes.Contains(receipt, []byte(frame.DirectorySecret)) {
		t.Fatal("receipt contains credentials")
	}
	// Only recopy the same source bytes after interruption; never generate a replacement.
	if err := os.Remove(filepath.Join(filepath.Dir(file), "directory.secret")); err != nil {
		t.Fatal(err)
	}
	if _, err := importFrame(t, dir, file, frame, true); err == nil {
		t.Fatal("check accepted missing credential")
	}
	if _, err := importFrame(t, dir, file, frame, false); err != nil {
		t.Fatal("same-source publication could not resume", err)
	}
	changed := frame
	changed.SetupID = "371333e2-c221-4601-b249-563b3d828530"
	if _, err := importFrame(t, dir, file, changed, false); err == nil {
		t.Fatal("import changed retained source ownership")
	}
	if err := os.Remove(filepath.Join(filepath.Dir(file), "client-import.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := importFrame(t, dir, file, frame, false); err == nil {
		t.Fatal("import adopted credentials with lost ownership receipt")
	}
}

func TestClientImportRefusesMismatchedScopeBeforeWrites(t *testing.T) {
	for _, kind := range []string{"schema", "id", "issuer", "client", "callback", "directory", "owner", "username", "role", "secret", "unknown", "large", "trailing"} {
		t.Run(kind, func(t *testing.T) {
			dir, file, frame := importFixture(t)
			switch kind {
			case "schema":
				frame.Schema = "other"
			case "id":
				frame.SetupID = "not-a-uuid"
			case "issuer":
				frame.IssuerURL = "https://other.example.test"
			case "client":
				frame.ClientID = "other"
			case "callback":
				frame.RedirectURIs = []string{"https://other.example.test/callback"}
			case "directory":
				frame.DirectoryURL = "https://other.example.test/api/v1/sync/events"
			case "owner":
				frame.Administrator.Subject = "other"
			case "username":
				frame.Administrator.Username = "other"
			case "role":
				frame.Administrator.Role = "admin"
			case "secret":
				frame.ClientSecret = "must-not-echo-secret"
			}
			raw, _ := json.Marshal(frame)
			if kind == "unknown" {
				raw = append(raw[:len(raw)-1], []byte(`,"password":"must-not-echo-secret"}`)...)
			}
			if kind == "large" {
				raw = bytes.Repeat([]byte{'x'}, MaxBundleBytes+1)
			}
			if kind == "trailing" {
				raw = append(raw, []byte(` {}`)...)
			}
			if _, err := ImportClient(dir, file, raw, false, false); err == nil || strings.Contains(err.Error(), "must-not-echo-secret") {
				t.Fatal("invalid private input accepted or disclosed")
			}
			entries, _ := os.ReadDir(filepath.Dir(file))
			if len(entries) != 1 {
				t.Fatal("rejected import wrote files")
			}
		})
	}
}

func TestClientImportPreservesForeignAndUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"foreign", "shared", "symlink", "changed", "receipt"} {
		t.Run(kind, func(t *testing.T) {
			dir, file, frame := importFixture(t)
			path := filepath.Join(filepath.Dir(file), "directory.secret")
			if kind == "changed" || kind == "receipt" {
				if _, err := importFrame(t, dir, file, frame, false); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "receipt" {
				path = filepath.Join(filepath.Dir(file), "client-import.json")
			}
			if kind == "symlink" {
				if err := os.Symlink(filepath.Join(dir, "foreign"), path); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(path, []byte("retain-foreign-bytes"), 0600); err != nil {
					t.Fatal(err)
				}
				if kind == "shared" {
					if err := os.Chmod(path, 0644); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := importFrame(t, dir, file, frame, false); err == nil {
				t.Fatal("unsafe/foreign retained file accepted")
			}
			if kind != "symlink" {
				retained, _ := os.ReadFile(path)
				if string(retained) != "retain-foreign-bytes" {
					t.Fatal("foreign bytes overwritten")
				}
			} else if _, err := os.Stat(filepath.Join(dir, "foreign")); !os.IsNotExist(err) {
				t.Fatal("linked target mutated")
			}
			if kind == "foreign" || kind == "shared" || kind == "symlink" {
				if _, err := os.Stat(filepath.Join(filepath.Dir(file), "client.secret")); !os.IsNotExist(err) {
					t.Fatal("conflict was discovered after credential writes")
				}
			}
		})
	}
}

func TestClientImportRequiresReservedDestinationAndOneOwner(t *testing.T) {
	for _, kind := range []string{"client-path", "directory-path", "no-owner", "extra-owner", "no-directory", "no-bundle"} {
		t.Run(kind, func(t *testing.T) {
			dir, file, frame := importFixture(t)
			before, err := readCapped(file, MaxBundleBytes)
			if err != nil {
				t.Fatal(err)
			}
			var b bundle
			if err := decodeStrict(bytes.NewReader(before), &b); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "client-path":
				b.SSO.ClientSecretFile = filepath.Join(dir, "foreign-client.secret")
			case "directory-path":
				b.SSO.DirectoryHMACSecretFile = filepath.Join(dir, "foreign-directory.secret")
			case "no-owner":
				b.Admins = nil
			case "extra-owner":
				b.Admins = append(b.Admins, Admin{Issuer: frame.IssuerURL, Subject: "other-owner", Username: "other-admin"})
			case "no-directory":
				b.SSO.DirectoryHMACSecretFile = ""
			}
			modified, _ := json.Marshal(b)
			if err := os.WriteFile(file, modified, 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "no-bundle" {
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := importFrame(t, dir, file, frame, false); err == nil {
				t.Fatal("import accepted an unselected owner, path or missing bundle")
			}
			for _, path := range []string{filepath.Join(dir, "foreign-client.secret"), filepath.Join(dir, "foreign-directory.secret"), filepath.Join(filepath.Dir(file), "client.secret"), filepath.Join(filepath.Dir(file), "client-import.json")} {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("rejected destination intent wrote files")
				}
			}
		})
	}
}
