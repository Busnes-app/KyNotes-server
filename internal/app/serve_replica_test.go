package app

import (
	"bytes"
	"context"
	shareds3 "github.com/Busnes-app/ky-primitives/s3"
	"github.com/Busnes-app/kynotes-server/internal/storage"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
)

func TestReplicaServeRejectsInputsBeforeCreatingLocalState(t *testing.T) {
	replicaEnvironment(t)
	c := config.Defaults()
	c.DataDir = t.TempDir()
	c.Server.Bind = "127.0.0.1:0"
	c.Server.DevInsecureCookies = true
	c.Backup.DepositInterval = "0"
	for name, value := range map[string]string{"KYNOTES_DB_DSN": "", "KYNOTES_SECRETS_PAIRING_SECRET": "", "KYNOTES_BLOB_BACKEND": "volume", "KYNOTES_BLOB_S3_ENDPOINT": "http://unsafe.example"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, value)
			err := serveReplica(context.Background(), c, logging.New(io.Discard, "info", "json"))
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("input accepted: %v", err)
			}
		})
	}
	entries, err := os.ReadDir(c.DataDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("local fallback artifacts: %v %v", entries, err)
	}
}

func TestReplicaBackupRequiresExplicitNativeKeyOrOffSchedule(t *testing.T) {
	t.Setenv("KYNOTES_PG_BACKUP_KEY_FILE", "")
	c := config.Defaults()
	if _, _, err := replicaBackup(c, replicaInputs{}, nil); err == nil {
		t.Fatal("enabled backup has no native key")
	}
	c.Backup.DepositInterval = "0"
	run, id, err := replicaBackup(c, replicaInputs{}, nil)
	if err != nil || id != "off" {
		t.Fatalf("off backup: %s %v", id, err)
	}
	if err := run(context.Background(), nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"", strings.Repeat("a", 63), strings.Repeat("x", 64), strings.Repeat("a", 67), strings.Repeat("a", 64) + "\nextra"} {
		path := filepath.Join(t.TempDir(), "key")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("KYNOTES_PG_BACKUP_KEY_FILE", path)
		if _, err := replicaBackupKey(); err == nil {
			t.Fatal("invalid backup key accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 64)+"\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KYNOTES_PG_BACKUP_KEY_FILE", path)
	if key, err := replicaBackupKey(); err != nil || len(key) != 32 {
		t.Fatalf("native key: %d %v", len(key), err)
	}
	c.Backup.DepositInterval = "15m"
	fields := replicaFieldsForBackupTest(t, c)
	if fields["pg_backup_key"] == "off" || strings.Contains(fields["pg_backup_key"], strings.Repeat("a", 32)) {
		t.Fatal("backup key identity omitted or exposed")
	}
}
func replicaFieldsForBackupTest(t *testing.T, c config.Config) map[string]string {
	t.Helper()
	replicaEnvironment(t)
	c, in, err := readReplicaInputs(c)
	if err != nil {
		t.Fatal(err)
	}
	return replicaFields(c, in)
}

func TestReplicaBackupUploadsSealedArchiveAndCountsAttempts(t *testing.T) {
	if !storage.OnPostgresTest() {
		t.Skip("set KYNOTES_TEST_DATABASE_URL")
	}
	st, err := storage.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.DB().Exec(`UPDATE server_settings SET value='multi' WHERE key='tenancy_mode'; INSERT INTO server_settings(key,value,updated_at) VALUES('staff_org_id','org_staff',''),('region','local',''),('cell:local','','')`); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 64)), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KYNOTES_PG_BACKUP_KEY_FILE", path)
	var puts atomic.Int32
	var archive atomic.Value
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			// Export has completed before PUT, so a simultaneous writer still progresses.
			tx, err := st.DB().BeginTx(r.Context(), nil)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			if err := tx.Commit(); err != nil {
				t.Error(err)
			}
			puts.Add(1)
			raw, _ := io.ReadAll(r.Body)
			archive.Store(raw)
			w.Header().Set("ETag", `"archive"`)
			return
		}
		io.WriteString(w, `<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>`)
	}))
	defer server.Close()
	client, err := shareds3.New(shareds3.Config{Endpoint: server.URL, Bucket: "bucket", AccessKey: "access", SecretKey: "secret", HTTP: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	c := config.Defaults()
	c.DataDir = t.TempDir()
	c.Backup.DepositInterval = "15m"
	t.Setenv("KYNOTES_PG_BACKUP_PREFIX", "backups/test-cell/")
	run, _, err := replicaBackup(c, replicaInputs{Tenancy: storage.Tenancy{Region: "local"}}, client)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := run(context.Background(), st, now); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), st, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if puts.Load() != 1 || !bytes.HasPrefix(archive.Load().([]byte), []byte("KYNOTES-PGB1\n")) {
		t.Fatalf("native archive missing or cadence ignored: puts=%d bytes=%d", puts.Load(), len(archive.Load().([]byte)))
	}
}
