# Public key protocol

## Purpose

Own shared public identity encodings and v4 envelope framing.

## Ownership

- `protocol.go` owns sizes, public-key validation and untrusted sender-ID parsing.
- `internal/teamkeys` owns private keys, sealing and opening; the server must not import it.

## Local Contracts

- Keep Go and browser encodings aligned with `docs/PQC.md` and its protocol fixtures.
- An envelope sender ID is untrusted until the recipient verifies both HybridSig halves.
- Keep private-key generation, derivation, sealing and opening out of this package.

## Work Guidance

## Verification

- `go test ./internal/teamkeys ./internal/notecrypto`
- `TestNotLinkedIntoServer` preserves the private-crypto boundary.

## Child DOX Index

None.
