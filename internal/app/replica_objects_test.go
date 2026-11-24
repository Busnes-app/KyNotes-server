package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/config"
)

func unsetObjectCredential(t *testing.T, name string) {
	t.Helper()
	for _, key := range []string{name, name + "_FILE"} {
		t.Setenv(key, "") // Register restoration of any inherited operator configuration.
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReplicaObjectCredentialInputsAreBoundedAndRedacted(t *testing.T) {
	const name = "KYNOTES_BLOB_S3_SECRET"
	const secret = "private-credential-DO-NOT-DISCLOSE"
	for _, tc := range []struct {
		name, contents string
		file, invalid  bool
	}{
		{"environment", secret, false, false},
		{"file", secret, true, false},
		{"file-newline", secret + "\n", true, false},
		{"file-crlf", secret + "\r\n", true, false},
		{"empty-environment", "", false, true},
		{"empty-file", "", true, true},
		{"multiline-environment", secret + "\nother", false, true},
		{"multiline-file", secret + "\nother", true, true},
		{"nul-file", secret + "\x00", true, true},
		{"oversized-environment", strings.Repeat("s", (64<<10)+1), false, true},
		{"oversized-file", strings.Repeat("s", (64<<10)+1), true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unsetObjectCredential(t, name)
			path := filepath.Join(t.TempDir(), "path-"+secret)
			if tc.file {
				if err := os.WriteFile(path, []byte(tc.contents), 0600); err != nil {
					t.Fatal(err)
				}
				t.Setenv(name+"_FILE", path)
			} else {
				t.Setenv(name, tc.contents)
			}
			got, err := replicaObjectCredential(name)
			if tc.invalid {
				if err == nil || got != "" || !strings.Contains(err.Error(), name) || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), path) {
					t.Fatal("credential boundary failed or disclosed input")
				}
			} else if err != nil || got != secret {
				t.Fatal("valid credential was not preserved")
			}
		})
	}
	for _, kind := range []string{"missing", "missing-file", "directory", "both", "both-empty"} {
		t.Run(kind, func(t *testing.T) {
			unsetObjectCredential(t, name)
			switch kind {
			case "missing-file":
				t.Setenv(name+"_FILE", filepath.Join(t.TempDir(), secret))
			case "directory":
				t.Setenv(name+"_FILE", t.TempDir())
			case "both", "both-empty":
				value := secret
				if kind == "both-empty" {
					value = ""
				}
				t.Setenv(name, value)
				t.Setenv(name+"_FILE", secret)
			}
			got, err := replicaObjectCredential(name)
			if err == nil || got != "" || strings.Contains(err.Error(), secret) {
				t.Fatal("invalid credential source accepted or disclosed")
			}
		})
	}
}

func TestReplicaObjectClientPreparationKeepsKeysOutOfSharedState(t *testing.T) {
	replicaEnvironment(t)
	const access, secret = "access-DO-NOT-DISCLOSE", "secret-DO-NOT-DISCLOSE"
	for _, name := range []string{"KYNOTES_BLOB_S3_ACCESS_KEY", "KYNOTES_BLOB_S3_SECRET"} {
		unsetObjectCredential(t, name)
	}
	t.Setenv("KYNOTES_BLOB_S3_ACCESS_KEY", access)
	path := filepath.Join(t.TempDir(), "object-secret")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KYNOTES_BLOB_S3_SECRET_FILE", path)
	c := config.Defaults()
	c.DataDir = filepath.Join(t.TempDir(), "not-created")
	c, in, err := readReplicaInputs(c)
	if err != nil {
		t.Fatal(err)
	}
	before := replicaFields(c, in)
	client, err := newReplicaObjectClient(in)
	if err != nil || client == nil {
		t.Fatalf("client preparation: %v", err)
	}
	encoded, err := json.Marshal(client)
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{string(encoded), fmt.Sprintf("%v %#v", client, client), fmt.Sprint(replicaFields(c, in))} {
		if strings.Contains(output, access) || strings.Contains(output, secret) || strings.Contains(output, path) {
			t.Fatal("object credential escaped its boundary")
		}
	}
	if !reflect.DeepEqual(before, replicaFields(c, in)) {
		t.Fatal("credentials changed shared fingerprint inputs")
	}
	if _, err := os.Stat(c.DataDir); !os.IsNotExist(err) {
		t.Fatal("client preparation wrote a local store")
	}
	for _, mode := range []string{"single", "multi"} {
		t.Setenv("KYNOTES_TENANCY", mode)
		if _, err := config.Load(filepath.Join(c.DataDir, "config.yaml")); err == nil {
			t.Fatal("preparation enabled unsupported configuration")
		}
	}
	for _, bad := range []replicaInputs{
		{BlobEndpoint: "http://" + secret, BlobBucket: "notes", BlobRegion: "eu"},
		{BlobEndpoint: "https://objects.example", BlobBucket: "bad/" + secret, BlobRegion: "eu"},
		{BlobEndpoint: "https://objects.example", BlobBucket: "notes", BlobRegion: "bad/" + secret},
	} {
		client, err := newReplicaObjectClient(bad)
		if err == nil || client != nil || strings.Contains(err.Error(), secret) {
			t.Fatal("invalid object configuration accepted or disclosed")
		}
	}
}
