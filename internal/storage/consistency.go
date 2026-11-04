package storage

import (
	"database/sql"
	"fmt"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
)

// Consistency fails when a blobs row has no file (content is missing). Files with no row are only
// returned: a restore that copied the original blobs/ beside an older database has them, and they
// harm nothing.
func Consistency(db *sql.DB, blobs *blobstore.Store) (untracked []string, err error) {
	rows, e := db.Query(`SELECT digest FROM blobs`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var d string
		if e = rows.Scan(&d); e != nil {
			return nil, e
		}
		seen[d] = true
		if _, ok, er := blobs.Stat(d); er != nil {
			return nil, er
		} else if !ok {
			return nil, fmt.Errorf("missing blob %s", d)
		}
	}
	files, e := blobs.ListDigests()
	if e != nil {
		return nil, e
	}
	for _, d := range files {
		if !seen[d] {
			untracked = append(untracked, d)
		}
	}
	return untracked, nil
}
