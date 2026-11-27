# Runtime integration tests

## Purpose

Verify the environment-gated application startup and release refusal through exported APIs.

## Ownership

- `serve_runtime_test.go` drives `app.Serve` with the suite test build, native PostgreSQL and a verified TLS S3 wire fixture.
- `serve_release_test.go` proves direct `Serve` callers cannot bypass the release build gate.

## Local Contracts

- Use isolated schemas with cleanup. `TEST_POSTGRES_DSN` selects PostgreSQL; `KYNOTES_TEST_DATABASE_URL` is accepted for the existing CI backend profile. Skip when neither is set.
- Keep the test build tag inside this directory and the existing config gate allowlist.
- Throwaway instances explicitly disable both push relays. TLS fixtures prove product wiring, not hosted provider qualification.
- Stop and drain every instance before dropping its schema or restoring the test transport.

## Work Guidance

## Verification

- `go test -race ./e2e`
- `go test -tags kye2e -race ./e2e` with a PostgreSQL test URL.

## Child DOX Index

None.
