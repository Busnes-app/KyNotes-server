package httpapi

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/Busnes-app/ky-primitives/capsule"
)

var errStorageFull = errors.New("database backup budget exhausted")

// Owner decision Q12: leave ten percent for other database records and capsule members.
const databaseWriteBudget = capsule.MaxExpandedBytes * 9 / 10

// checkDatabaseBudget runs after the complete write, before commit, under SQLite's immediate
// writer transaction. Counting allocated pages includes ciphertext, indexes and audit overhead;
// subtracting free pages lets deletions make room without VACUUM. No competing writer can
// spend the same remaining capacity. The capsule's actual total limit is still checked at seal.
func checkDatabaseBudget(tx *sql.Tx) error {
	var used int64
	if err := tx.QueryRow(`SELECT (page_count-freelist_count)*page_size FROM pragma_page_count(),pragma_freelist_count(),pragma_page_size()`).Scan(&used); err != nil {
		return err
	}
	if used > databaseWriteBudget {
		return errStorageFull
	}
	return nil
}

func writeStorageFull(w http.ResponseWriter, r *http.Request, err error) bool {
	if !errors.Is(err, errStorageFull) {
		return false
	}
	WriteError(w, r, http.StatusInsufficientStorage, "storage_full", "The server's backup storage budget is full. Delete unneeded comments or revoke share links, then try again.")
	return true
}
