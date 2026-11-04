package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/config"
)

func TestDeletedNotebookRefusesUploads(t *testing.T) {
	for _, kind := range []string{"attachment", "preview"} {
		t.Run(kind, func(t *testing.T) {
			u := newUploadClient(t)
			var up struct {
				ID string `json:"uploadId"`
			}
			body := []byte(`{"declaredBytes":0,"kind":"` + kind + `"}`)
			code, out := status(t, u.do(t, http.MethodPost, "/api/v1/containers/"+u.container+"/uploads", body, true))
			if code != http.StatusOK || json.Unmarshal([]byte(out), &up) != nil {
				t.Fatalf("create=%d %s", code, out)
			}
			if code, out := status(t, u.do(t, http.MethodDelete, "/api/v1/containers/"+u.container, nil, true)); code != http.StatusNoContent {
				t.Fatalf("delete=%d %s", code, out)
			}
			for _, path := range []string{"/api/v1/containers/" + u.container + "/uploads", "/api/v1/uploads/" + up.ID + "/finalize"} {
				if code, out := status(t, u.do(t, http.MethodPost, path, body, true)); code != http.StatusNotFound {
					t.Fatalf("%s=%d %s", path, code, out)
				}
			}
		})
	}
}

func TestUploadCommitRefusesNotebookDeletedDuringBody(t *testing.T) {
	for _, operation := range []string{"create", "attachment finalize"} {
		t.Run(operation, func(t *testing.T) {
			u := newUploadClient(t)
			path := "/api/v1/containers/" + u.container + "/uploads"
			body := `{"declaredBytes":0,"kind":"attachment"}`
			if operation != "create" {
				kind := strings.Fields(operation)[0]
				var up struct {
					ID string `json:"uploadId"`
				}
				code, out := status(t, u.do(t, http.MethodPost, path, []byte(`{"declaredBytes":0,"kind":"`+kind+`"}`), true))
				if code != http.StatusOK || json.Unmarshal([]byte(out), &up) != nil {
					t.Fatalf("create=%d %s", code, out)
				}
				path = "/api/v1/uploads/" + up.ID + "/finalize"
				body = `{"metadataCiphertext":"","keyGeneration":1}`
			}
			stall := &stallReader{started: make(chan struct{}), release: make(chan struct{}), body: strings.NewReader(body)}
			release := sync.OnceFunc(func() { close(stall.release) })
			defer release()
			req, err := http.NewRequest(http.MethodPost, u.url+path, stall)
			if err != nil {
				t.Fatal(err)
			}
			req.ContentLength = int64(len(body))
			req.Header.Set("Expect", "100-continue")
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(keySchemeHeader, keySchemeShared)
			for _, c := range u.hc.Jar.Cookies(req.URL) {
				req.AddCookie(c)
				if c.Name == "csrf_token" {
					req.Header.Set("X-CSRF-Token", c.Value)
				}
			}
			done := make(chan int, 1)
			go func() {
				client := &http.Client{Transport: &http.Transport{ExpectContinueTimeout: time.Minute}, Timeout: 10 * time.Second}
				defer client.CloseIdleConnections()
				res, err := client.Do(req)
				if err != nil {
					done <- 0
					return
				}
				res.Body.Close()
				done <- res.StatusCode
			}()
			select {
			case <-stall.started:
			case <-time.After(5 * time.Second):
				t.Fatal("handler never requested body")
			}
			if code, out := status(t, u.do(t, http.MethodDelete, "/api/v1/containers/"+u.container, nil, true)); code != http.StatusNoContent {
				t.Fatalf("delete=%d %s", code, out)
			}
			release()
			if code := <-done; code != http.StatusNotFound {
				t.Fatalf("late %s=%d", operation, code)
			}
			var live int
			if err := u.db.QueryRow(`SELECT (SELECT COUNT(*) FROM attachments WHERE deleted_at='')+(SELECT COUNT(*) FROM upload_sessions WHERE status IN ('pending','finalized'))`).Scan(&live); err != nil || live != 0 {
				t.Fatalf("late upload retained %d live rows: %v", live, err)
			}
		})
	}
}

func TestLegacyLateAttachmentRemainsCharged(t *testing.T) {
	u := newUploadClient(t)
	if _, err := u.db.Exec(`INSERT INTO blobs(digest,size_bytes,created_at) VALUES('dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',10,'now');`); err != nil {
		t.Fatal(err)
	}
	if _, err := u.db.Exec(`UPDATE containers SET deleted_at='then' WHERE id=?`, u.container); err != nil {
		t.Fatal(err)
	}
	if _, err := u.db.Exec(`INSERT INTO attachments(id,container_id,blob_digest,ciphertext_bytes,metadata_ciphertext,key_generation,change_seq,created_at) VALUES('att_late00000000000000000000000',?,'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',10,x'',1,1,'now')`, u.container); err != nil {
		t.Fatal(err)
	}
	if over, err := userQuotaExceeded(u.db, config.Limits{UserQuotaBytes: 10}, "usr_upload_test", 0, "", 1); err != nil || !over {
		t.Fatalf("historical late upload bypassed quota: %v %v", over, err)
	}
}
