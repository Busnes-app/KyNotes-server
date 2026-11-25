package blobstore

import "time"

// SetPutDeadline shortens the put deadline for one test.
func SetPutDeadline(d time.Duration) (restore func()) {
	old := putDeadline
	putDeadline = d
	return func() { putDeadline = old }
}
