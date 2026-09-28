package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	"github.com/Busnes-app/ky-primitives/health"
	sharedlogging "github.com/Busnes-app/ky-primitives/logging"
)

func healthHandler(ready func() bool, db *sql.DB) http.Handler {
	lg, err := sharedlogging.New(sharedlogging.Config{App: "kynotes"})
	if err != nil {
		panic(err) // fixed app name, validated at construction
	}
	checks := []health.Check{{Name: "startup", Run: func(context.Context) error {
		if !ready() {
			return errors.New("not ready")
		}
		return nil
	}}}
	if db != nil {
		checks = append(checks, health.Check{Name: "database", Run: db.PingContext})
	}
	return health.Handler("kynotes", lg, checks...)
}
