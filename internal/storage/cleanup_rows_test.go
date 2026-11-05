package storage

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"strings"
	"testing"
)

func TestCleanupRecordSizeMatchesSQLite(t *testing.T) {
	for _, encoding := range []string{"UTF-8", "UTF-16le", "UTF-16be"} {
		t.Run(encoding, func(t *testing.T) {
			s, err := OpenUnmigrated(filepath.Join(t.TempDir(), "db.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if _, err = s.db.Exec(`PRAGMA encoding='` + encoding + `'; CREATE TABLE sizing(a,b,c,d)`); err != nil {
				t.Fatal(err)
			}
			code := uint32(1)
			if encoding == "UTF-16le" {
				code = 2
			}
			if encoding == "UTF-16be" {
				code = 3
			}
			for _, n := range []int{0, 1, 57, 58, 63, 64, 127, 128, 4096, 8191, 8192, 16383, 65536} {
				for _, counter := range []int64{-140737488355329, -2147483649, -8388609, -32769, -129, -128, -1, 0, 1, 127, 128, 32768, 8388608, 2147483648, 140737488355328} {
					values := []any{counter, strings.Repeat("λ𝄞", n/2), make([]byte, n), nil}
					if _, err = s.db.Exec(`DELETE FROM sizing; INSERT INTO sizing VALUES(?,?,?,?)`, values...); err != nil {
						t.Fatal(err)
					}
					var actual int
					if err = s.db.QueryRow(`SELECT max(mx_payload) FROM dbstat WHERE name='sizing' AND pagetype='leaf'`).Scan(&actual); err != nil {
						t.Fatal(err)
					}
					if got := sqliteRecordBytes(values, code); got != actual {
						t.Fatalf("n%d counter%d: calculated%d, SQLite%d", n, counter, got, actual)
					}
				}
			}
		})
	}
}

// Keep the physical database deliberately crowded. Exercise overflow cliffs,
// record-header and payload-varint boundaries, and large bodies, in three orders.
func TestCleanupRowsReleaseOverflowWithoutGrowingLeafCells(t *testing.T) {
	for _, scenario := range []struct {
		pageSize int
		encoding string
	}{{512, "UTF-8"}, {4096, "UTF-8"}, {65536, "UTF-8"}, {4096, "UTF-16le"}, {4096, "UTF-16be"}} {
		pageSize := scenario.pageSize
		for _, order := range []string{"forward", "reverse", "permuted"} {
			t.Run(fmt.Sprintf("page%d/%s/%s", pageSize, scenario.encoding, order), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "db.sqlite")
				prior, err := OpenUnmigrated(path)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = prior.db.Exec(fmt.Sprintf(`PRAGMA encoding='%s'; PRAGMA page_size=%d; VACUUM`, scenario.encoding, pageSize)); err != nil {
					t.Fatal(err)
				}
				prior.Close()
				s, err := Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				if _, err = s.db.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES('user','person','opaque','opaque',100000,'now','now')`); err != nil {
					t.Fatal(err)
				}
				sizes := []int{0, 1, 57, 58, 63, 64, 127, 128, pageSize - 200, pageSize - 35, pageSize, pageSize + 1, 8191, 8192, 16383, 16384, 65536}
				var ids []string
				if err = s.WithTx(context.Background(), func(tx *sql.Tx) error {
					for i, size := range sizes {
						for _, width := range []int{30, pageSize - 200} {
							id := fmt.Sprintf("cmt_%03d_%06d", i, width)
							container := fmt.Sprintf("cnt_%03d_%06d", i, width) + strings.Repeat("c", width)
							if _, err := tx.Exec(`INSERT INTO containers(id,kind,owner_user_id,change_seq,created_at,updated_at) VALUES(?,'workbook','user',127,'now','now')`, container); err != nil {
								return err
							}
							if _, err := tx.Exec(`INSERT INTO objects(id,container_id,kind,change_seq,created_at,updated_at) VALUES(?,?,'note',1,'now','now')`, id, container); err != nil {
								return err
							}
							if _, err := tx.Exec(`INSERT INTO comments(id,container_id,object_id,author_user_id,body_ciphertext,key_generation,change_seq,created_at) VALUES(?,?,?,'user',zeroblob(?),1,1,'now')`, id, container, id, size); err != nil {
								return err
							}
							if err := ReserveCleanupAuditTx(tx, "comment", id, container); err != nil {
								return err
							}
							ids = append(ids, id)
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if order == "reverse" {
					for i, j := 0, len(ids)-1; i < j; i, j = i+1, j-1 {
						ids[i], ids[j] = ids[j], ids[i]
					}
				}
				if order == "permuted" {
					rng := rand.New(rand.NewPCG(12, 34))
					rng.Shuffle(len(ids), func(i, j int) { ids[i], ids[j] = ids[j], ids[i] })
				}
				before, err := DatabaseBytes(s.db)
				if err != nil {
					t.Fatal(err)
				}
				compactBefore := compactCleanupBytes(t, s.db)
				for _, id := range ids {
					if err = s.WithTx(context.Background(), func(tx *sql.Tx) error {
						var container string
						if err := tx.QueryRow(`SELECT container_id FROM comments WHERE id=?`, id).Scan(&container); err != nil {
							return err
						}
						seq, err := AdvanceCleanupSeqTx(tx, container, "2026-11-05T00:00:00Z")
						if err != nil {
							return err
						}
						if err = TombstoneCommentTx(tx, id, "2026-11-05T00:00:00Z", seq); err != nil {
							return err
						}
						return FillCleanupAuditTx(tx, "comment", id, "user", strings.Repeat("<", 128), "2026-11-05T00:00:00Z")
					}); err != nil {
						t.Fatal(id, err)
					}
					after, err := DatabaseBytes(s.db)
					if err != nil {
						t.Fatal(err)
					}
					if after > before {
						t.Fatalf("%s allocated%d after%d", id, before, after)
					}
					before = after
					if compact := compactCleanupBytes(t, s.db); compact > compactBefore {
						t.Fatalf("%s compact grew%d->%d", id, compactBefore, compact)
					} else {
						compactBefore = compact
					}
					var body, pad int
					if err = s.db.QueryRow(`SELECT length(body_ciphertext),length(cleanup_padding) FROM comments WHERE id=?`, id).Scan(&body, &pad); err != nil {
						t.Fatal(err)
					}
					if body != 0 || pad > pageSize+18 {
						t.Fatalf("retained body%d/padding%d", body, pad)
					}
				}
				if err = s.IntegrityCheck(context.Background()); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
