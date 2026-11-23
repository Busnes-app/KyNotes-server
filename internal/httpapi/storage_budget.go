package httpapi

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/Busnes-app/kynotes-server/internal/storage"
)

var errStorageFull = errors.New("database backup budget exhausted")

// Owner decision Q12: leave ten percent for other database records and capsule members.
const databaseWriteBudget = storage.CleanupDatabaseBudget

// Physical admission includes the already-allocated future audit slots and source padding.
// Creation funds its own slot in this transaction; migration/restore validate
// legacy bindings. Admission counts pages rather than rescanning every old slot.
func databaseBudgetBytes(tx *sql.Tx) (int64, error) {
	return storage.DatabaseBytes(tx)
}

// On PostgreSQL the org pool and a platform alarm replace this budget (tenancy spec, Replica
// work, item 6), so it admits every write.
func checkDatabaseBudget(db *sql.DB, tx *sql.Tx) error {
	if storage.IsPostgres(db) {
		return nil
	}
	used, err := databaseBudgetBytes(tx)
	if err != nil {
		return err
	}
	if used > databaseWriteBudget {
		return errStorageFull
	}
	return nil
}

func writeStorageFull(w http.ResponseWriter, r *http.Request, err error) bool {
	if !errors.Is(err, errStorageFull) && !errors.Is(err, storage.ErrCleanupCapacity) && !errors.Is(err, storage.ErrCleanupInvariant) {
		return false
	}
	WriteError(w, r, http.StatusInsufficientStorage, "storage_full", "The server's backup storage budget is full. Delete unneeded comments or revoke share links, then try again.")
	return true
}
