package storage

import (
	"database/sql"
	"fmt"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
)

func Consistency(db *sql.DB, blobs *blobstore.Store) error {
	rows, e := db.Query(`SELECT digest FROM blobs`)
	if e != nil {
		return e
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var d string
		if e = rows.Scan(&d); e != nil {
			return e
		}
		seen[d] = true
		if _, ok, er := blobs.Stat(d); er != nil {
			return er
		} else if !ok {
			return fmt.Errorf("missing blob %s", d)
		}
	}
	files, e := blobs.ListDigests()
	if e != nil {
		return e
	}
	for _, d := range files {
		if !seen[d] {
			return fmt.Errorf("untracked blob %s", d)
		}
	}
	return nil
}
