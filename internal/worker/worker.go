// Package worker elects one PostgreSQL scheduler. Jobs must honor cancellation and be resumable.
package worker

import (
	"context"
	"database/sql"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// Run waits for ownership, runs the schedule once per tick, and retries ownership after loss.
// Single mode keeps its existing app loops and never calls this entry point.
func Run(ctx context.Context, db *sql.DB, interval time.Duration, job func(context.Context, time.Time)) {
	for ctx.Err() == nil {
		lease, ok, _ := storage.SessionLock(ctx, db, "scheduled-worker", false)
		if ok {
			owned, cancel := context.WithCancel(lease.Context)
			probed := make(chan struct{})
			go func() {
				defer close(probed)
				tick := time.NewTicker(time.Second)
				defer tick.Stop()
				for {
					select {
					case <-owned.Done():
						return
					case <-tick.C:
						probe, stop := context.WithTimeout(owned, time.Second)
						err := lease.Ping(probe)
						stop()
						if err != nil {
							cancel()
							return
						}
					}
				}
			}()
			tick := time.NewTicker(interval)
			for owned.Err() == nil {
				select {
				case <-owned.Done():
				case now := <-tick.C:
					if owned.Err() == nil {
						job(owned, now)
					}
				}
			}
			tick.Stop()
			cancel()
			<-probed
			lease.Release()
		}
		retry := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			retry.Stop()
			return
		case <-retry.C:
		}
	}
}
