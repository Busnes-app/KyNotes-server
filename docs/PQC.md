# Post-quantum container keys and device linking

Wave 1 uses `ky-primitives v0.11.0` in Go and its `cmd/pqwasm` in browsers.
The server imports only `internal/keyprotocol` public framing and key validation;
private-key helpers remain outside the server dependency graph.
The encryption suite is HPKE base X-Wing (KEM **0x647A**, ML-KEM-768 + X25519),
HKDF-SHA256 and AES-256-GCM. Sender proofs use HybridSig **ML-DSA-65 + Ed25519**;
verification requires both halves. There is no classical write fallback.

## Upgrade an existing account

1. Open Settings → Account in a browser holding your current key.
2. Choose **Upgrade encryption**, confirm your password or KySignOn identity,
   and save and type back the new recovery code.
3. Sign other browsers in again, or link/restore them. Compare the new fingerprint
   with team members and accept changed colleague pins only after comparison.
4. Every approved member with an identity must upgrade before the owner's browser
   mints a new container-key generation. A key-sharing notice names pending members.

The upgrade retains the identity device ID, classical private key and old envelope
rows. Historical notebooks and local waiting drafts remain readable. It atomically
replaces password/recovery copies, retires current container keys, ends other sessions
and device credentials, deletes pending links and records `identity.pq_upgrade`.
An identical retry returns the committed result without another retirement. A stale
identity ID, a different classical public key or a second different PQ key is refused.
This is separate from **Reset encryption key**, which still discards the old identity.
Old recovery codes remain effective against old server backups. Existing classical
ciphertexts remain harvestable; upgrading cannot retroactively protect them.

New accounts and self-service resets create PQ identities. A legacy identity remains
readable and linkable, but cannot seal new container-key envelopes. CIRCL and hpke-js
remain for stored v3 readers and frozen interoperability tests; stored v2 readers stay.

## Wire formats

All sizes below are bytes. IDs are the existing fixed 30-byte UTF-8 IDs. All integers
are big-endian. Standard base64 encodes public keys and opaque blobs in JSON.

- Identity public (3249): `04 | classicalPublic(32) | XWingPublic(1216) | HybridSigPublic(2000)`.
- Identity private (3378): `04 | classicalPrivate(32) | XWingSeed(32) | MLDSASeed(32) | Ed25519Seed(32) | identityPublic(3249)`.
  Public components are checked against the seeds when opening a local/password/recovery copy.
  The browser uses the shared WASM to prove the X-Wing and signing pairs match, rather than
  implementing key derivation again. Classical components serve historical reads only.
- Password copy: existing AES-256-GCM wrapper, 3406 bytes for PQ, 60 for legacy.
- Recovery copy: existing fixed PBKDF2-SHA256-600000/AES-256-GCM wrapper, 3422 for PQ,
  76 for legacy. The account and complete public key remain AAD-bound.
- Envelope v4 (4589): `04 | senderDeviceID(30) | xwing.Seal(CK)(1169) | HybridSig(3389)`.
  Algorithm: `hpke-base-xwing-647a-hkdfsha256-aes256gcm-hybridsig`.
  Context: `kynotes/envelope/v4 | 00 | containerID | generation(u32) | recipientDeviceID | senderDeviceID | orgLength(u16) | orgUTF8`.
  The org comes from the authenticated account's identity response; empty means absent.
  Context is both HPKE info and AAD. HybridSig label `kynotes/envelope/v4/sender` signs
  `context | unsignedEnvelope`, including the outer version and inner X-Wing frame.
  The recipient resolves the sender through the existing steward/pin policy and verifies
  both signatures before decrypting. Alg, version and exact length must agree. Server
  writes accept only v4 framing; historical v2/v3 rows are returned unchanged.
- Linking v3 (7905 for PQ identities, 4559 for legacy): `03 | xwing.Seal(identityPrivate) | HybridSig(3389)`.
  Each one-time public key uses the identity public encoding, with its own X-Wing and
  HybridSig keys. Info and AAD: `kynotes/link/v3 | userID | requestID | identityDeviceID | approverPublic | newcomerPublic`.
  Label `kynotes/link/v3/sender` signs `context | unsignedBundle`, proving possession
  of the approver key covered by the SAS despite HPKE's base mode.
- Linking commitment: `SHA256(kynotes/link-commit/v2 | completeNewcomerPublic)`.
  SAS: first four bytes, big-endian, of
  `SHA256(kynotes/link-check/v2 | userID | requestID | completeApproverPublic | completeNewcomerPublic)`
  modulo one million, zero-padded and shown as `123 456`. Every byte of both X-Wing
  public keys and signing keys is covered. Six digits can collide; the full-key
  regression checks each one-bit byte flip in fixed fixtures, not collision freedom.

PQ identities accept classical envelopes only below the observed current container
generation, in both browser and MCP keyrings. A legacy row at the write generation
is refused, preventing a future break of the retained classical key from downgrading
new writes. Existing generation floors and key digests remain add-only.

The existing commitment/reveal ordering, typed approver confirmation, newcomer
confirmation, TTL, one-shot collect, audit and session authorization remain required.
Old linking attempts must restart after upgrading. Envelope rotations may bind up to
8 MiB in one KySignOn confirmation; other actions retain their 64 KiB limit.

## Build and verify

`npm test --prefix web`, `npm run build --prefix web`, and `make build/test` generate
WASM and the matching `wasm_exec.js` with the module's pinned Go toolchain.
`scripts/build-pqwasm.sh` writes `/assets/pq/` in browser public assets and the embed.
Docker builds it in a Go stage; CI installs Go before browser checks. Generated WASM
and runtime files are ignored and never committed. A direct `go build` requires
running the helper first. The checked-in frontend bundle remains synchronized after
frontend changes. CSP permits `'wasm-unsafe-eval'` for WebAssembly compilation, without
allowing JavaScript eval. Loading is same-origin and begins only when crypto is needed.

Checks: `make test` (full Go race suite including MCP), `go vet ./...`, browser tests
against the real WASM, browser build/embed diff, `npm run e2e --prefix web`, the existing
normal/FIPS CI profiles and image/probe checks. `testdata/protocol/pq_vectors.json` is a
Go-generated v4 fixture opened by browser tests. `internal/teamkeys/pq_test.go` checks
both signature halves, contextual replay refusal and upgraded legacy v2/v3 reads.
Frozen classical vectors remain historical interoperability checks.
