package health

import (
	"context"
	"database/sql"
	"sync"
	"time"
)

// DatabaseReady adds the replica pattern's one-second, cached ping to startup/drain readiness.
// The caller uses it only on PostgreSQL; single-tenant readiness remains byte-identical.
func DatabaseReady(db *sql.DB, ready func() bool) func() bool {
	var mu sync.Mutex
	var checked time.Time
	var healthy bool
	return func() bool {
		if !ready() {
			return false
		}
		mu.Lock()
		defer mu.Unlock()
		if time.Since(checked) >= time.Second {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			healthy = db.PingContext(ctx) == nil
			cancel()
			checked = time.Now()
		}
		return ready() && healthy
	}
}
