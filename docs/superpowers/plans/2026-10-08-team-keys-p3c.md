# Team Keys Phase 3c (Device Linking and Identities for SSO Users) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A browser that does not hold the account's identity (a new browser, or any browser of an account that signs in only through KyIdentity) gets it from a trusted browser of the same account. The server relays only public keys, a commitment and one sealed bundle. Both screens show one check code. SSO-only accounts create their first identity after a KyIdentity confirmation, so team owners can share keys with them. Every browser keeps the identity sealed under a non-extractable WebCrypto key.

**Architecture:** The server work is in four places:
- `internal/auth`: SSO step-up gets a `user` scope beside `admin`. `RequireUserActionStepUp` accepts a local password step-up or a KySignOn confirmation of the exact request, with no admin role needed. Identity creation, envelope writes, key rotations and link approval use it.
- `internal/httpapi/identity_routes.go`: an SSO session may create a **device-only** identity (`wrap_alg = 'none'`, no server copy). A password never unlocks or re-wraps one.
- `internal/httpapi/link_routes.go`: a seven-route relay over one `link_requests` table (migration `0024_device_linking.sql`). It is single-use, expires after 10 minutes, allows at most 3 live requests per account, is rate-limited and audited, and needs a live session of the same user on both sides.
- `internal/teamkeys` generates the link vectors. The server does not import it.

The web client gets pure modules, each tested on its own:
- `linking.ts`: the commitment, the check code, the bundle format and the `CheckCodeConfirmation` brand.
- `linkFlow.ts`: the newcomer and approver steps against an injected API.
- `storage.ts`: the identity sealed under a non-extractable device key.
- `identity.ts`: `settleSSOIdentity`, `identityStatus` and `currentCopy`.
- `outbound.ts`: `sendLinkBundle`, the one gate a bundle leaves through.
- `keyService.ts`: `deferred`, so SSO stewards share keys only on a click.

`components/DeviceLink.tsx` holds the two link screens, and `main.tsx` wires them in.

**Tech Stack:** Go 1.26 (`net/http`, SQLite via `modernc`), TypeScript/React (Vite, vitest, fake-indexeddb), `@noble/curves`/`@noble/ciphers` (already pinned), WebCrypto AES-GCM, `@playwright/test` 1.63.0 (already a devDependency).

**Spec:** `docs/superpowers/specs/2026-10-07-team-keys-design.md`: §8 (the owner-approved SSO identity design), §7 P3c, §6 (threat model; the SSO and at-rest bullets change here), §7 P3a/P3b as built and known limits. Conventions follow `docs/superpowers/plans/2026-10-07-team-keys-p3b.md`.

**Evidence status:** this plan was **not** prototyped. The code blocks were written against `feat/team-keys-p3c` at `f1b4f93` (P3b). None of them has been compiled or run, so each task's own test step is the first proof. If a block does not compile, fix the code and keep the test's assertions. Facts checked in the pre-flight (`.superpowers/sdd/2026-10-08-team-keys-p3c/preflight.md`):
- `fake-indexeddb` 6.2.5 is already a pinned devDependency used by five suites; it was only not installed (`npm ci`). Under Node v24.21.0 it stores a non-extractable AES-GCM `CryptoKey`, returns one that still decrypts, and `exportKey` on it rejects. No injectable store is needed.
- Over plain `http://` to a LAN address, Chromium and Firefox report `isSecureContext === false` and `crypto.subtle === undefined` (`getRandomValues` and IndexedDB remain); on `http://127.0.0.1` both are available. WebKit did not launch here: unproven for Safari.
- Chromium writes the raw bytes of a non-extractable `CryptoKey` stored in IndexedDB, in plain text, to the profile's LevelDB log. The device key therefore does not protect the copy against anyone who can read the profile (ruling 8). Firefox did not show the raw bytes; that proves nothing, as its store may compress them.

---

## Global Constraints

| Item | Exact value |
|---|---|
| Migration | `internal/storage/migrations/0024_device_linking.sql`. Task 1 writes `ALTER TABLE sso_stepup ADD COLUMN scope TEXT NOT NULL DEFAULT 'admin'`; Task 4 appends `CREATE TABLE link_requests`. The runner refuses gaps; nothing between |
| Link request ID | prefix `lnk` (`ids.Mint("lnk")`, `ids.Validate("lnk", id)`); a malformed path ID is a uniform `404 not_found` |
| Relay limits | TTL 10 minutes (`expires_at`, RFC 3339 UTC, compared as text). At most 3 unexpired requests per user (`409 already_exists`). A new request from the same session first deletes that session's earlier one |
| Relay routes | `POST /api/v1/me/link-requests` (newcomer: `{commitment}` → `{id, expiresAt}`), `GET /api/v1/me/link-requests` (trusted: requests of other sessions, unclaimed or claimed by the caller), `POST …/{id}/claim` (trusted: `{approverKey}`), `POST …/{id}/reveal` (newcomer: `{newcomerKey}`), `POST …/{id}/approve` (claiming session: `{bundle}`, `RequireUserActionStepUp`), `POST …/{id}/collect` (newcomer, polled, CSRF: state, approver key, bundle once; the row is deleted in the same transaction), `DELETE …/{id}` (any session of the user). Session only: device credentials get `401`. CSRF on every mutation. `Cache-Control: no-store` |
| Live sessions | Claim and approve need the newcomer session live; reveal needs the approver session live; every route rechecks the caller's session in its transaction (`auth.RecheckSessionTx`; approve: `auth.RecheckUserActionTx`) |
| Commitment | `SHA-256("kynotes/link-commit/v1" ‖ newcomerKey(32))`, posted at create, before the approver's key exists. The server checks it at reveal (mismatch: row deleted, `identity.link.refuse` audited, `400`); the approver checks it again against the commitment it saw **before** claiming |
| Check code | `SHA-256("kynotes/link-check/v1" ‖ userID(30) ‖ requestID(30) ‖ approverKey(32) ‖ newcomerKey(32))`; first 4 bytes big-endian `mod 1_000_000`, zero-padded to 6 digits, shown as `"123 456"` |
| Bundle | `0x01 ‖ nonce(12) ‖ ChaCha20-Poly1305(key, nonce, identityPrivateKey(32), aad)` = 61 bytes. `key = HKDF-SHA256(ikm = X25519(approverPriv, newcomerPub), salt = approverKey ‖ newcomerKey, info = "kynotes/link/v1", L = 32)`. `aad = "kynotes/link/v1" ‖ userID(30) ‖ requestID(30) ‖ identityDeviceID(30) ‖ approverKey(32) ‖ newcomerKey(32)`. IDs are validated fixed-length ASCII (`teamKeys.ts` `idBytes`). `testdata/protocol/link_vectors.json` pins every byte |
| Sender rule | A link bundle is self-to-self: it carries the account's own identity private key. The newcomer accepts it only after **its own** user confirmed the check code, only when it opens under the approver key that code was computed from, and only when `x25519(privateKey)` equals the `publicKey` of `GET /me/identity`, and stores it under that identity's `deviceId` |
| Release gate | The bundle leaves only through `outbound.ts` `sendLinkBundle(confirmation, requestID, bundle)`, which refuses anything but a `confirmCheckCode(requestID)` result for that request |
| Device-only identity | `PUT /me/identity` from an SSO session: `{"publicKey","wrapAlg":"none"}` (no `wrappedPrivateKey`), stored with `wrap_alg='none'` and an empty blob; `users.password_admin_known` does not block it. Local sessions keep `aes-256-gcm` only; each kind of session gets `400` for the other kind. `GET /me/identity` also returns `wrapAlg`. A password change carries a re-wrap exactly when the identity is `aes-256-gcm` |
| Step-up | `auth.RequireUserActionStepUp`: local session, `stepup_at` within `StepUpWindow`; SSO session, a `user`-scope KySignOn grant bound to method, URI, Content-Type and body (no `kynotes.admin`). `RequireStepUp` keeps `admin` scope. The three `/api/v1/auth/oidc/step-up` routes need a session, not an admin. Invitation envelopes keep the local password step-up (SSO invitations go out keyless) |
| Vault | Secure contexts (`isSecureContext` and `crypto.subtle`): the private key sealed with AES-256-GCM under a `generateKey(…, false, ["encrypt","decrypt"])` key stored in the **same** vault record, AAD `kynotes/device-identity/v1|<userID>|<deviceId>`. Plain-HTTP origins keep the raw key, as today (spec §7 P3c), and Settings says so. Raw P1–P3b copies are re-sealed on first read in a secure context. Every identity write that could race another tab is a compare-and-swap (`storeIdentityKey(…, expected)`). "Forget this device" deletes the record: sealed key and device key together. The device key only keeps the raw private key out of the record's plain values. It is **not** at-rest protection (Chromium writes the device key's bytes into the same profile) and not XSS protection (page script can call `decrypt`) |
| No storage | A browser without a usable vault (no IndexedDB, no record) creates no link request and no SSO identity, and holds no identity (fail closed) |
| Rate limit | `POST /api/v1/me/link-requests` uses `ratelimit.pairing_per_hour` (default 20/hour per account) in its own bucket (label `link`), not the pairing-token bucket. No new config key |
| Error codes | No new codes. `400 invalid_request`, `401 unauthenticated`, `403 csrf_failed`/`step_up_required`/`sso_step_up_required`, `404 not_found`, `409 already_exists`, `429 rate_limited` |
| Audit events | `identity.link.request`, `.claim`, `.reveal`, `.refuse` (outcome `denied`), `.approve`, `.collect`, `.cancel`; object ID = request ID. Never key material |
| Key decisions | No key decision reads `kind` or `teamId`. Every container read still goes through `observe.ts`, every ciphertext upload through `outbound.ts` |
| Unchanged (checked) | Envelope v2 bytes, `openKeyring`, `planSweep`, `sealFor`, pins, floors, `observe.ts`, `inviteWithKeys` (SSO: keyless), the save gate, `CanvasPage.tsx`, mobile/probe clients |
| Out of scope | Recovery code (P5), phone linking and QR codes (P5), a self-service identity reset, signed membership log |

## Resolved ambiguities (recorded in the spec in Task 11)

### 1. The check code needs a commitment, so the relay has seven routes, not five
The spec's five routes let the newcomer post its key, the approver post its own, and both hash the two. A server that sits in the middle sees the newcomer's key at create time. It hands the approver a key of its own, waits for the approver's key, and then grinds a one-time key for the newcomer until both screens show the same six digits: about 10^6 X25519 keygens, which takes seconds. A longer code (about 64 bits, or six words) would resist grinding, but people compare it badly. Instead, the newcomer posts `SHA-256(label ‖ key)` first (create), the approver posts its key (claim), and the newcomer reveals its key only after that (reveal). A middle server must then commit to both substitutions before it learns the value it would need to match. Its success chance is 10^-6 per attempt, and every failed attempt is a visible mismatch. This is the ZRTP / Bluetooth numeric-comparison pattern. Adding `claim` and `reveal` makes 7 routes. The server also checks the commitment, but only as defence in depth: the approver's browser checks it against the commitment it saw before claiming, never against a later list response.

### 2. Who starts, who confirms
The newcomer starts, because it is the browser that is stuck. Its screen shows a 6-character request code (`id.slice(-6)`, for identification only), and the trusted browser lists the account's requests. **Both** screens show the check code, and both users confirm it:
- The approver's confirmation gates the release: nothing leaves without `CheckCodeConfirmation`.
- The newcomer's confirmation gates acceptance: a bundle the newcomer collects stays unopened until its own user clicks "Codes match".

A one-sided check would let a server that swapped only the newcomer's view install an identity of its own choosing on the newcomer.

### 3. Check code shape
Six decimal digits, from SHA-256 over a domain label, the user ID, the request ID and both one-time public keys, in that fixed order. Both IDs are fixed-length, so the concatenation is unambiguous. Six digits is enough only because of the commitment (ruling 1). The modulo bias of `2^32 mod 10^6` is under 0.03 % and does not matter at this size.

### 4. The link bundle is its own format, not envelope v2
Envelope v2 needs a container, a generation and a sender identity row. A link moves the account's own identity between two of its own browsers, so its "sender" is that same identity. The newcomer cannot authenticate a static sender key without trusting the server's `GET /me/identity`. Authentication instead comes from the confirmed check code over both one-time keys. The format reuses the primitives (X25519, HKDF-SHA256, ChaCha20-Poly1305) with its own label and version byte `0x01`. The AAD binds the user ID, the request ID, the identity's device ID and both one-time keys. The newcomer also requires the opened private key to produce the identity public key the server lists. A swap there is therefore caught as a mismatch, and only a server that also swapped `GET /me/identity` could plant a key. That attack needs the check code to match, which ruling 1 prevents.

### 5. What step-up means for SSO-only sessions
The existing KySignOn action-bound step-up was admin-only (`RequireAdmin`, `kynotes.admin` at the callback and at consumption). It gains a `scope` column:
- `admin` challenges (`RequireStepUp`) behave exactly as before.
- `user` challenges (`RequireUserActionStepUp`) prove only the session's own account, with fresh `auth_time`, PKCE and nonce, bound to the exact request.

A grant is consumed only by a route of its own scope. The password step-up stays the local-session path. Every write transaction rechecks the session (`RecheckUserActionTx`).

### 6. An SSO account's first identity is device-only and created on a click
The identity is created in the browser after the user clicks "Set up encryption key" and confirms with KySignOn. It is stored on the server with `wrap_alg='none'` and no wrapped copy, until P5's recovery code. It is not created automatically after sign-in, because the KySignOn dialog would then appear unprompted. `users.password_admin_known` does not block it: nothing is wrapped under that password.

### 7. Device-only identities and passwords
A password neither unlocks nor re-wraps a device-only identity. A password login returns it with `wrapAlg: "none"`, and the browser offers linking. A password change carries no re-wrap for it (both fields present is `409 identity_rewrap_required`). `GET /me/identity` gains the public `wrapAlg`, so the browser knows this before asking for the password.

### 8. Storage: non-extractable key, plain-HTTP fallback, fail closed
- The device key lives in the same vault record as the sealed identity, so "Forget this device" stays one delete (spec §5).
- Plain-HTTP LAN origins have no WebCrypto. They keep today's raw copy (spec §7 P3c), Settings says so, and Yoshi decides whether to keep that (see "Needs Yoshi's decision").
- A missing vault or IndexedDB fails closed: no link request is created, no SSO identity is created, and the workspace holds no identity.
- The device key does **not** protect the copy at rest. The pre-flight showed Chromium writing the raw bytes of a non-extractable key stored in IndexedDB into the profile's LevelDB log, beside the sealed identity. Page script can also call `decrypt` with it. What it does: the stored record holds no plain private key, so a dump of record values (devtools export, a backup of values) does not carry it. The threat model, Settings and the changelog must say only that (see "Needs Yoshi's decision" 3).

### 9. Interrupted creation is reconciled, and a held identity is never overwritten
`settleSSOIdentity` saves the new key on this browser as **pending** (`deviceId ""`) before the `PUT`. The server therefore never accepts a key no browser holds. A later run finishes a pending key the server already lists.

If the vault holds a finished identity that the server no longer lists, `settleSSOIdentity` stops and reports `orphaned`. That state is either an administrator reset or a server lie. The browser replaces its identity only after an explicit "Replace encryption key" and a confirmation.

Two tabs converge because they share the vault record **and** every save is a compare-and-swap against the identity the run read (`storeIdentityKey(…, expected)`, one IndexedDB transaction). Without it, a tab that read an empty vault would overwrite, with its own pending key, an identity another tab had finished and the server had accepted: that key would then exist nowhere.

### 10. The vault copy is checked against the server
The workspace uses its vault copy only while `GET /me/identity` lists the same device ID and public key. When the server is unreachable it still uses the copy offline (`currentCopy`). A mismatch makes the browser stop using the copy. It never deletes it.

### 11. The loss path in P3c is an administrator password reset
No new destructive route is added. An administrator password reset already deletes the identity, its envelopes and, from this phase, its link requests (P1). An SSO-only user who lost every browser asks for that reset, then sets up a new key, and team owners re-share it through the sweep after confirming the new fingerprint. A self-service reset is listed under "Needs Yoshi's decision".

### 12. SSO stewards share keys on a click
Every envelope write and every rotation from an SSO session asks KySignOn. The automatic steward sweep would open that dialog unprompted on every notebook open, so for SSO sessions it only reports. `KySync.deferred` is set, and the notebook shows "Share keys (confirm with KySignOn)". A click runs the same pass with `canWrap: true`. A blocked first key is still explained. Password stewards are unchanged.

### 13. Invitation-time keys stay password-only
The invitation route checks the step-up conditionally (`HasUserStepUp`) inside its handler. Giving it the SSO path would mean a second conditional middleware. Invitations from SSO sessions therefore go out keyless, and the sweep fills the keys after the invitee accepts. The `cannot-wrap` text says so.

### 14. Rate limit and caps reuse what exists
Linking is device pairing, so link creation uses the per-account `pairing_per_hour` rate (default 20 per hour) and adds no config key. It has its own bucket (label `link`), so linking and pairing tokens do not drain each other. The cap of three live requests bounds what one account can hold. Restarting on the same browser replaces that browser's own request, so a reload never fills the cap.

### 15. Collect is a CSRF-protected `POST` that deletes
The spec names `GET …/{id}`; it became `POST …/{id}/collect` (fix round 1, review M3), so a cross-site navigation cannot delete an approved bundle. Polls read without a transaction until a bundle is ready; delivery and deletion then share one transaction (`_txlock=immediate`, a guarded `DELETE … RETURNING`, so two collects serialize and only one sees the bundle). It has its own per-account bucket, `ratelimit.link_poll_per_minute` (default 60). The residual is a response lost after commit: the newcomer sees "ended" and starts again; the bundle is useless without the one-time key in the newcomer tab's memory.

### 16. Any session of the account may cancel
This gives the trusted list a "Not me" button. A request the user did not start is an attack signal, and cancelling it costs the user nothing.

### 17. Migration name
`0024_device_linking.sql` replaces the spec's `0024_link_requests.sql`, because it also carries `sso_stepup.scope`. The spec text changes in Task 11.

### 18. Deferred to P5
- Phone linking, and with it the spec's "device recipients accept their own user's identity as a sender" rule. Only phone clients need that rule, and they pair in P5.
- QR codes.

### 19. Link vectors are generated by a Go test
`internal/teamkeys` stays a reference the server does not import (`doc.go`). The server's own commitment check is three lines, and its test feeds it the vector file.

### 20. A linked browser cannot be revoked separately
All browsers hold the same identity, so revoking one means resetting the identity (ruling 11). This is recorded as a known limit.

## Needs Yoshi's decision

1. **Plain-HTTP origins keep the identity raw in IndexedDB.** This is spec-approved (§7 P3c) and implemented that way, with a Settings warning. The safer alternative is to refuse identities on non-secure origins. That would break team keys for existing LAN `http://` installs, which hold raw copies today. Given decision 3, the HTTP copy is not materially weaker on disk than the HTTPS one. Picked: the spec's behaviour.
2. **No self-service "reset my encryption key" before P5.** A lost or stolen linked browser keeps the identity until an administrator password reset deletes it. An SSO-only user who loses every browser also needs that reset. Picked: no new destructive route in P3c; decide whether a step-up-gated self-service reset should land before P5.
3. **The non-extractable device key is not at-rest protection.** Spec §8 point 2 assumes it is. The pre-flight showed Chromium storing the device key's raw bytes in the same profile as the sealed identity, so a profile copy yields both, and page script can call `decrypt`. Keeping it (as planned, spec-approved) costs about 60 lines and a re-seal migration for one benefit: no plain private key among the record's values. Dropping it keeps today's raw copy everywhere, as on plain HTTP. Picked: implement the spec, with honest wording everywhere (no "protects at rest"); decide whether to keep it.
4. **Whoever operates KyIdentity can create an SSO account's first identity.** A fresh KySignOn login as the user is all `PUT /me/identity` needs from an SSO session, and `password_admin_known` (P1 ruling 9) has no SSO counterpart. For an SSO account with no identity yet, or after an administrator reset, the IdP operator can therefore create one it holds; stewards then wrap team keys to it after a first-contact (TOFU) fingerprint they may not check. Linking needs the user to read out a check code from the attacker's screen, so it falls to social engineering only. Spec §8 point 4 ("zero-knowledge toward whoever operates KyIdentity") holds for accounts that already have an identity, not for creation. Picked: implement §8 as approved and state the limit in the threat model (Task 11); a non-IdP root of trust (an invitation-bound or out-of-band enrolment code) would be a later change.

## Review Focus (likely failure modes and their pinning tests)

1. **The newcomer tab reloads or closes mid-link.** Its one-time key is gone. A reasonable person expects "Link this browser" on that browser to start cleanly, not to hit the three-request cap. Pinned by `TestLinkRequestRefusals`, "the same browser restarting replaces its own request" (Task 4). The unmount cancel in `LinkThisBrowser` is exercised by e2e step 1, where the attempt is restarted.
2. **Two trusted browsers press Approve on one request.** One wins, and the other is told the request is gone, with no second key sent. Pinned by `TestLinkRelayHandsOverOnlyPublicKeys`: a third session's claim is `404` (Task 4).
3. **The vault's device key can no longer open the sealed copy** (partial storage eviction, a copied profile). The expected result is "this browser does not hold your key, link it again", never a crash and never a wrong key. Pinned by `storage.test.ts` "returns nothing for a sealed copy its device key cannot open" (Task 6).
4. **An administrator resets the account while a link is open.** The expected result is that the link fails and nothing stale is installed. Pinned by `TestLinkRequestsDieWithTheIdentity` (Task 5) and `linkFlow.test.ts` "refuses a bundle holding another key than the account's identity" (Task 8).
5. **An SSO user's first set-up is interrupted after the server accepted the key.** The next click is expected to finish it, not to say "link this browser" forever. Pinned by `identity.test.ts` "finishes an identity an interrupted run created" (Task 7).

---

## File Map

| File | Change |
|---|---|
| `internal/storage/migrations/0024_device_linking.sql` | New (Task 1, extended in Task 4) |
| `internal/auth/middleware.go`, `internal/auth/sso_stepup.go` | `RequireUserActionStepUp`, `RecheckUserActionTx`, step-up scope |
| `internal/httpapi/sso_routes.go` | Step-up start/poll/cancel need a session, not an admin |
| `internal/httpapi/identity_routes.go` | Device-only identities; `wrapAlg` in `GET`; `deleteIdentityTx` clears link requests |
| `internal/httpapi/auth_routes.go` | Re-wrap counted only for `aes-256-gcm` identities |
| `internal/httpapi/device_routes.go`, `internal/httpapi/teamkeys_routes.go` | Envelope `PUT` and rotations use `RequireUserActionStepUp` |
| `internal/httpapi/link_routes.go`, `internal/httpapi/router.go` | New relay |
| `internal/httpapi/ratelimit.go`, `kynotes.example.yaml` | `link` bucket |
| `internal/storage/gc.go`, `internal/storage/gc_test.go` | Expired link requests deleted |
| `internal/httpapi/teamkeys_p3c_test.go` | New tests |
| `internal/httpapi/sso_logout_test.go` | `restartRouter` also mounts `IdentityRoutes`, `TeamKeyRoutes` (Task 2) and `LinkRoutes` (Task 4) for the SSO fixture |
| `internal/httpapi/sso_stepup_test.go`, `identity_test.go`, `teamkeys_test.go` | `reauthStartAt`; SSO assertions now expect `sso_step_up_required` |
| `internal/teamkeys/vectors_test.go`, `internal/teamkeys/link_vectors_test.go`, `testdata/protocol/link_vectors.json` | Link vectors |
| `web/src/teamKeys.ts` | Exports `concat`, `idBytes` (`lnk` added), `sameBytes` |
| `web/src/linking.ts`, `linking.test.ts` | New |
| `web/src/storage.ts`, `storage.test.ts` | Sealed vault identity |
| `web/src/identity.ts`, `identity.test.ts`, `web/src/api.ts` | Device-only identities, link API |
| `web/src/linkFlow.ts`, `linkFlow.test.ts`, `web/src/outbound.ts`, `outbound.test.ts` | New flow and gate |
| `web/src/keyService.ts`, `keyService.test.ts` | `deferred` |
| `web/src/components/DeviceLink.tsx`, `web/src/main.tsx`, `web/src/styles.css` | Screens and wiring |
| `web/e2e/team-keys.e2e.ts`, `UI-VERIFICATION.md` | P3c browser steps |
| `internal/web/dist/` | Regenerated bundle |
| `DESIGN.md`, `IMPLEMENTATION_PLAN.md`, `docs/SSO.md` | Changed in the tasks that change contracts (1, 2, 4, 5) |
| The spec, `AGENTS.md`, `CHANGELOG.md` | Task 11 |

## Interfaces

```go
// internal/auth
func RequireUserActionStepUp(db *sql.DB, next http.Handler) http.Handler
func RecheckUserActionTx(tx *sql.Tx, s Session, now time.Time) error
const stepUpAdmin, stepUpUser = "admin", "user" // unexported

// internal/httpapi
const deviceOnlyWrapAlg = "none"
const linkTTL = 10 * time.Minute; const linkMaxPending = 3; const linkBundleBytes = 61; const linkCommitLabel = "kynotes/link-commit/v1"
func LinkRoutes(mux *http.ServeMux, db *sql.DB)
```

```ts
// teamKeys.ts
export function concat(...parts: Uint8Array[]): Uint8Array;
export function idBytes(prefix: "cnt" | "dev" | "usr" | "lnk", value: string): Uint8Array;
export function sameBytes(a: Uint8Array, b: Uint8Array): boolean;

// linking.ts
export const LINK_BUNDLE_BYTES = 61;
export type LinkContext = { userID: string; requestID: string; identityDeviceID: string; approverKey: Uint8Array; newcomerKey: Uint8Array };
export function newLinkKey(): Identity;
export function linkCommitment(newcomerKey: Uint8Array): Uint8Array;
export function checkCode(userID: string, requestID: string, approverKey: Uint8Array, newcomerKey: Uint8Array): string;
export function sealLinkBundle(identityPrivateKey: Uint8Array, approver: Identity, context: LinkContext, nonce?: Uint8Array): Uint8Array;
export function openLinkBundle(bundle: Uint8Array, newcomer: Identity, context: LinkContext): Uint8Array;
export class CheckCodeConfirmation { readonly requestID: string }
export function confirmCheckCode(requestID: string): CheckCodeConfirmation;
export function isCheckCodeConfirmation(value: unknown, requestID: string): value is CheckCodeConfirmation;

// storage.ts
export function identityProtection(): "device-key" | "unprotected";
export function storeIdentityKey(username: string, userID: string, identity: HeldIdentity, expected?: HeldIdentity | null): Promise<boolean>; // expected: compare-and-swap (null: no identity held)
export function loadIdentityRecord(username: string, userID: string): Promise<HeldIdentity | undefined>; // pending (deviceId "") included; throws when unreadable
export function getIdentityKey(username: string, userID: string): Promise<HeldIdentity | undefined>;    // finished only
export function vaultReady(username: string): Promise<boolean>;

// identity.ts
export const DEVICE_ONLY_WRAP = "none";
export type PublicIdentity = { deviceId: string; publicKey: string; fingerprint: string; wrapAlg?: string };
export type DeviceOnlyAPI = Pick<IdentityAPI, "myIdentity"> & { putDeviceOnlyIdentity: (publicKey: string) => Promise<{ deviceId: string }> };
export type IdentityStore = { load: () => Promise<HeldIdentity | undefined>; save: (identity: HeldIdentity, expected?: HeldIdentity | null) => Promise<boolean> };
export type Settled = { kind: "held"; identity: HeldIdentity } | { kind: "link" } | { kind: "orphaned" } | { kind: "unsaved" };
export function settleSSOIdentity(api: DeviceOnlyAPI, store: IdentityStore, replace?: boolean, retried?: boolean): Promise<Settled>;
export type IdentityStatus = "held" | "link" | "create" | "orphaned";
export function identityStatus(local: HeldIdentity | undefined, live: PublicIdentity | undefined): IdentityStatus;
export function currentCopy(local: HeldIdentity | undefined, live: PublicIdentity | undefined | "unreachable"): HeldIdentity | undefined;

// api.ts
export type LinkRequestRow = { id: string; commitment: string; createdAt: string; expiresAt: string; claimed: boolean; newcomerKey: string };
export type LinkState = { state: "pending" | "claimed" | "revealed" | "approved"; expiresAt: string; approverKey?: string; bundle?: string };
export const putDeviceOnlyIdentity: (publicKey: string) => Promise<{ deviceId: string; fingerprint: string }>;
export const createLinkRequest: (commitment: string) => Promise<{ id: string; expiresAt: string }>;
export const linkRequests: () => Promise<LinkRequestRow[]>;
export const claimLinkRequest: (id: string, approverKey: string) => Promise<void>;
export const revealLinkRequest: (id: string, newcomerKey: string) => Promise<void>;
export const approveLinkRequest: (id: string, bundle: string) => Promise<void>; // only outbound.ts calls it
export const collectLinkRequest: (id: string) => Promise<LinkState>;
export const cancelLinkRequest: (id: string) => Promise<void>;

// linkFlow.ts
export class LinkStorageError extends Error {}
export class LinkTamperedError extends Error {}
export type NewcomerAPI = { create: typeof createLinkRequest; collect: typeof collectLinkRequest; reveal: typeof revealLinkRequest; myIdentity: () => Promise<PublicIdentity | undefined> };
export type NewcomerLink = { id: string; key: Identity; expiresAt: string; approverKey?: Uint8Array; code?: string };
export function startNewcomerLink(api: Pick<NewcomerAPI, "create">, canKeep: () => Promise<boolean>): Promise<NewcomerLink>;
export function pollNewcomerLink(api: Pick<NewcomerAPI, "collect" | "reveal">, link: NewcomerLink, userID: string): Promise<{ link: NewcomerLink; bundle?: Uint8Array }>;
export function finishNewcomerLink(link: NewcomerLink, bundle: Uint8Array, confirmation: CheckCodeConfirmation, userID: string, api: Pick<NewcomerAPI, "myIdentity">, save: (identity: HeldIdentity) => Promise<boolean>): Promise<HeldIdentity>;
export type ApproverLink = { id: string; key: Identity; commitment: Uint8Array; newcomerKey?: Uint8Array; code?: string };
export function claimLink(api: { claim: typeof claimLinkRequest }, row: LinkRequestRow): Promise<ApproverLink>;
export function revealedLink(link: ApproverLink, row: LinkRequestRow | undefined, userID: string): ApproverLink;
export function approveLink(link: ApproverLink, confirmation: CheckCodeConfirmation, identity: HeldIdentity, userID: string, stepUp: () => Promise<void>, send?: typeof sendLinkBundle): Promise<void>;

// outbound.ts
export function sendLinkBundle(confirmation: CheckCodeConfirmation, requestID: string, bundle: Uint8Array): Promise<void>;

// keyService.ts
export type KySync = { /* P3b fields */ deferred: boolean };

// components/DeviceLink.tsx
export const linkCodeOf: (id: string) => string;
export function LinkThisBrowser(props: { userID: string; canKeep: () => Promise<boolean>; save: (identity: HeldIdentity) => Promise<boolean>; onLinked: (identity: HeldIdentity) => void }): JSX.Element;
export function LinkRequests(props: { userID: string; held: () => Promise<HeldIdentity | undefined>; stepUp: () => Promise<void> }): JSX.Element;
```

---

### Task 1: Server: user-scope SSO step-up

**Files:** Create `internal/storage/migrations/0024_device_linking.sql`, `internal/httpapi/teamkeys_p3c_test.go`. Modify `internal/auth/middleware.go`, `internal/auth/sso_stepup.go`, `internal/httpapi/sso_routes.go`, `internal/httpapi/sso_stepup_test.go`, `docs/SSO.md`.

**Interfaces:**
- Consumes: `newLogoutFixture`, `roleCallback`, `withCookies`, `reauthAction`, `reauthFixture` and `f.send`, from `sso_logout_test.go`, `sso_app_roles_test.go` and `sso_stepup_test.go`.
- Produces: `auth.RequireUserActionStepUp` and `auth.RecheckUserActionTx`. Test helpers `liveCookies`, `userReauthFixture` and `reauthStartAt(f, cookies, subject, path, body string, roles []string) (string, *http.Request)`.

- [ ] **Step 1: Migration.** Create `internal/storage/migrations/0024_device_linking.sql`:

```sql
-- What an SSO step-up challenge proves: 'admin' (RequireStepUp: verified kynotes.admin) or
-- 'user' (RequireUserActionStepUp: the session's own account). Rows from before are admin.
ALTER TABLE sso_stepup ADD COLUMN scope TEXT NOT NULL DEFAULT 'admin';
```

- [ ] **Step 2: Generalize the fixture.** In `internal/httpapi/sso_stepup_test.go`, replace `reauthStart` with:

```go
func reauthStart(f *logoutFixture, cookies []*http.Cookie) (string, *http.Request) {
	return reauthStartAt(f, cookies, "alice", "/action", `{"target":1}`, []string{sso.AdminAppRole})
}

// reauthStartAt blocks POST path body, starts its challenge and returns the IdP callback that
// proves subject freshly; roles nil sends no app role.
func reauthStartAt(f *logoutFixture, cookies []*http.Cookie, subject, path, body string, roles []string) (string, *http.Request) {
	f.t.Helper()
	blocked := reauthAction(f, cookies, "", path, body)
	var detail struct{ Error struct{ Challenge string } }
	if blocked.Code != 403 || json.Unmarshal(blocked.Body.Bytes(), &detail) != nil || detail.Error.Challenge == "" {
		f.t.Fatalf("challenge: %d %s", blocked.Code, blocked.Body.String())
	}
	id := detail.Error.Challenge
	req := withCookies(httptest.NewRequest("POST", "/api/v1/auth/oidc/step-up", strings.NewReader(`{"challenge":"`+id+`"}`)), cookies)
	res := f.send(req)
	var start struct{ URL string }
	if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &start) != nil {
		f.t.Fatalf("start: %d %s", res.Code, res.Body.String())
	}
	dest, err := url.Parse(start.URL)
	if err != nil {
		f.t.Fatal(err)
	}
	q := dest.Query()
	if q.Get("prompt") != "login" || q.Get("max_age") != "0" || q.Get("acr_values") != "urn:kysignon:acr:password" || q.Get("code_challenge") == "" {
		f.t.Fatal("missing fresh login binding")
	}
	state := q.Get("state")
	now := time.Now().Unix()
	proof := map[string]any{"iss": f.issuer.URL, "aud": "kynotes", "sub": subject, "sid": "fresh-proof", "iat": now, "exp": now + 3600, "nonce": q.Get("nonce"), "auth_time": now, "acr": "urn:kysignon:acr:password", "amr": []string{"pwd"}}
	if roles != nil {
		proof["roles"] = roles
	}
	f.mu.Lock()
	f.proofs[state] = proof
	f.mu.Unlock()
	callback := withCookies(httptest.NewRequest("GET", "/api/v1/auth/oidc/callback?code="+state+"&state="+state, nil), cookies)
	for _, cookie := range res.Result().Cookies() {
		callback.AddCookie(cookie)
	}
	return id, callback
}
```

- [ ] **Step 3: Write the failing tests.** Create `internal/httpapi/teamkeys_p3c_test.go`:

```go
package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/auth"
)

// liveCookies keeps the cookies a login response set (not the ones it cleared).
func liveCookies(res *httptest.ResponseRecorder) []*http.Cookie {
	var out []*http.Cookie
	for _, c := range res.Result().Cookies() {
		if c.Value != "" && c.MaxAge >= 0 {
			out = append(out, c)
		}
	}
	return out
}

// userReauthFixture signs bob in through SSO with no app role and mounts POST /user-action behind
// RequireUserActionStepUp and POST /action behind the admin RequireStepUp.
func userReauthFixture(t *testing.T) (*logoutFixture, []*http.Cookie) {
	f := newLogoutFixture(t)
	login := roleCallback(f, "bob", nil, "")
	if login.Code != 302 {
		t.Fatal(login.Body.String())
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	mux := f.router.(*http.ServeMux)
	mux.Handle("POST /user-action", auth.RequireUserActionStepUp(f.db, ok))
	mux.Handle("POST /action", auth.RequireStepUp(f.db, ok))
	return f, liveCookies(login)
}

func TestSSOUserStepUpNeedsNoAdminRole(t *testing.T) {
	f, cookies := userReauthFixture(t)
	// The admin route stays closed to a non-admin: no challenge is even offered.
	if r := reauthAction(f, cookies, "", "/action", `{"x":1}`); r.Code != 403 || strings.Contains(r.Body.String(), "sso_step_up_required") {
		t.Fatal("a non-admin was offered an admin challenge", r.Code, r.Body.String())
	}
	id, callback := reauthStartAt(f, cookies, "bob", "/user-action", `{"x":1}`, nil)
	if res := f.send(callback); res.Code != 200 {
		t.Fatal("user challenge refused without an admin role", res.Code, res.Body.String())
	}
	if r := reauthAction(f, cookies, id, "/user-action", `{"x":2}`); r.Code != 403 {
		t.Fatal("a grant for one body admitted another", r.Code)
	}
	if r := reauthAction(f, cookies, id, "/user-action", `{"x":1}`); r.Code != 204 {
		t.Fatal(r.Code, r.Body.String())
	}
	if r := reauthAction(f, cookies, id, "/user-action", `{"x":1}`); r.Code != 403 {
		t.Fatal("grant reused", r.Code)
	}
}

func TestSSOStepUpScopeIsBoundToTheGrant(t *testing.T) {
	f, cookies := reauthFixture(t)
	// An admin challenge answered without kynotes.admin is rejected at the callback.
	_, callback := reauthStartAt(f, cookies, "alice", "/action", `{"target":1}`, nil)
	if res := f.send(callback); res.Code != 403 {
		t.Fatal("admin challenge verified without the admin role", res.Code)
	}
	// A verified admin grant relabelled as a user grant no longer opens the admin route.
	id, callback := reauthStart(f, cookies)
	if res := f.send(callback); res.Code != 200 {
		t.Fatal(res.Code, res.Body.String())
	}
	if _, err := f.db.Exec(`UPDATE sso_stepup SET scope='user' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	if r := reauthAction(f, cookies, id, "/action", `{"target":1}`); r.Code != 403 {
		t.Fatal("a user-scope grant opened an admin route", r.Code)
	}
	// And a user route refuses a grant recorded as admin.
	g, userCookies := userReauthFixture(t)
	uid, ucb := reauthStartAt(g, userCookies, "bob", "/user-action", `{"x":1}`, nil)
	if res := g.send(ucb); res.Code != 200 {
		t.Fatal(res.Code, res.Body.String())
	}
	if _, err := g.db.Exec(`UPDATE sso_stepup SET scope='admin' WHERE id=?`, uid); err != nil {
		t.Fatal(err)
	}
	if r := reauthAction(g, userCookies, uid, "/user-action", `{"x":1}`); r.Code != 403 {
		t.Fatal("an admin-scope grant opened a user route", r.Code)
	}
}

```

- [ ] **Step 4: Run the tests to verify they fail.** Run `go test ./internal/httpapi -run 'TestSSOUserStepUpNeedsNoAdminRole|TestSSOStepUpScopeIsBoundToTheGrant|TestSSOStepUp' -count=1`. Expected: build failure (`auth.RequireUserActionStepUp` undefined).

- [ ] **Step 5: Implement in `internal/auth`.** In `middleware.go`, change `RequireStepUp`'s SSO branch to `requireSSOStepUp(db, s, stepUpAdmin, next, w, r)`. After `HasUserStepUp`, add:

```go
// RequireUserActionStepUp gates one-way doors on the caller's own account for every kind of
// session: a local session re-proves its password within StepUpWindow; an SSO session confirms this
// exact request with a fresh KySignOn proof (user scope: no administrator role involved).
func RequireUserActionStepUp(db *sql.DB, next http.Handler) http.Handler {
	return RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := SessionFromContext(r)
		if s.SSOIssuer != "" {
			requireSSOStepUp(db, s, stepUpUser, next, w, r)
			return
		}
		if !freshLocalProof(s) {
			WriteAuthError(w, "step_up_required", "re-enter your password to continue")
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// RecheckUserActionTx repeats, inside the write transaction, what RequireUserActionStepUp admitted.
// An SSO grant was consumed in its own transaction just before; the session must still be live.
func RecheckUserActionTx(tx *sql.Tx, s Session, now time.Time) error {
	if s.SSOIssuer == "" {
		return RecheckUserStepUpTx(tx, s, now)
	}
	_, _, err := liveSessionTx(tx, s, now)
	return err
}
```

In `sso_stepup.go`:

```go
const (
	stepUpAdmin = "admin" // RequireStepUp: the session's verified kynotes.admin ceiling and local admin role
	stepUpUser  = "user"  // RequireUserActionStepUp: the session's own account
)
```

- `requireSSOStepUp(db *sql.DB, s Session, scope string, next http.Handler, w http.ResponseWriter, r *http.Request)`. It passes `scope` to `consumeSSOStepUp`, and inserts with `INSERT INTO sso_stepup(id,session_id,action,scope,created_at,expires_at) VALUES(?,?,?,?,?,?)`.
- `consumeSSOStepUp(ctx, db, s, id, action, scope, requestID string)`. It runs `DELETE FROM sso_stepup WHERE id=? AND session_id=? AND action=? AND scope=? AND verified=1 AND expires_at>? RETURNING proof_sid,proof_iat`, then `liveStepUpSession(tx, s, now, scope)`.
- `liveStepUpSession`:

```go
// liveStepUpSession requires the original still-live session, never a replacement login. Admin
// challenges also need the session's verified administrator ceiling and the local admin role.
func liveStepUpSession(tx *sql.Tx, s Session, now time.Time, scope string) error {
	var count int
	err := tx.QueryRow(`SELECT count(*) FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.user_id=? AND s.revoked_at='' AND s.expires_at>? AND s.hard_expires_at>? AND s.sso_issuer=? AND s.sso_client_id=? AND s.sso_subject=? AND u.status='active' AND (?<>'admin' OR (s.sso_app_admin=1 AND u.role='admin'))`, s.ID, s.UserID, now.Format(time.RFC3339), now.Format(time.RFC3339), s.SSOIssuer, s.SSOClientID, s.SSOSubject, scope).Scan(&count)
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrSSOLoginRejected
	}
	return nil
}
```

- `CompleteSSOStepUp`: delete `|| !identity.AppAdmin` from its first condition. Then, before `liveStepUpSession`:

```go
	var scope string
	if err = tx.QueryRow(`SELECT scope FROM sso_stepup WHERE id=? AND session_id=?`, id, s.ID).Scan(&scope); errors.Is(err, sql.ErrNoRows) {
		return ErrSSOLoginRejected
	} else if err != nil {
		return err
	}
	// Admin challenges need the verified kynotes.admin role; user challenges prove only the account.
	if scope == stepUpAdmin && !identity.AppAdmin {
		return ErrSSOLoginRejected
	}
	if err = liveStepUpSession(tx, s, now, scope); err != nil {
		return err
	}
```

In `internal/httpapi/sso_routes.go`, change the three handlers `POST /api/v1/auth/oidc/step-up`, `GET /api/v1/auth/oidc/step-up/{id}` and `DELETE /api/v1/auth/oidc/step-up/{id}` from `auth.RequireAdmin(db, …)` to `auth.RequireSession(db, …)`. Their queries already bind the challenge to the caller's session.

- [ ] **Step 6: Run the tests to verify they pass.** Run `go test ./internal/httpapi -run 'TestSSO' -count=1 && go test ./internal/auth -count=1`. Expected: PASS. The existing `TestSSOStepUp*` tests cover the admin scope unchanged.

- [ ] **Step 7: Docs.** In `docs/SSO.md`, section "Fresh authorization for backup and recovery actions":
  - Replace "requires current admin and CSRF" with "requires a session and CSRF".
  - Replace "include verified `kynotes.admin`" with "include verified `kynotes.admin` for an admin challenge".
  - Replace "Consumption checks current admin permission," with "Consumption checks the challenge's scope (and, for admin challenges, current admin permission),".
  - Append this paragraph:

```markdown
Challenges carry a scope (migration `0024_device_linking.sql`, `sso_stepup.scope`). `admin`
challenges come from `RequireStepUp` routes and are unchanged. `user` challenges come from
`RequireUserActionStepUp` routes (identity creation, envelope writes, key rotations, device-link
approval): they prove the session's own account with the same fresh-login, PKCE, nonce, assurance
and action-binding rules, and need no `kynotes.admin`. A grant is consumed only by a route of its
own scope.
```

- [ ] **Step 8: Commit.**

```bash
git add internal/storage/migrations/0024_device_linking.sql internal/auth internal/httpapi/sso_routes.go internal/httpapi/sso_stepup_test.go internal/httpapi/teamkeys_p3c_test.go docs/SSO.md
git commit -m "auth: user-scope KySignOn step-up for one-way doors on the caller's own account"
```

### Task 2: Server: device-only identities for SSO sessions; SSO stewards share keys

**Files:** Modify `internal/httpapi/identity_routes.go`, `internal/httpapi/auth_routes.go`, `internal/httpapi/device_routes.go`, `internal/httpapi/teamkeys_routes.go`, `internal/httpapi/identity_test.go`, `internal/httpapi/teamkeys_test.go`, `internal/httpapi/teamkeys_p3c_test.go`, `internal/httpapi/sso_logout_test.go`, `DESIGN.md`, `IMPLEMENTATION_PLAN.md`, `docs/SSO.md`.

**Interfaces:**
- Consumes: Task 1 `RequireUserActionStepUp`, `RecheckUserActionTx`, `liveCookies`. Test helpers `identityBody`, `identityPub`, `identityWrapped`, `envJSON`, `envelopesBody`, `rotationBody`, `mint`, `status` and `quote`.
- Produces: `deviceOnlyWrapAlg = "none"`; test helpers `ssoPerson(f, subject, sid) ([]*http.Cookie, string)`, `ssoDo(f, cookies, subject, method, path, body) *httptest.ResponseRecorder` and `deviceOnlyBody(pub []byte) string`.

- [ ] **Step 1: Write the failing tests.** The SSO fixture's router (`sso_logout_test.go` `restartRouter`) mounts only `SSORoutes`, `AuthRoutes` and `DeviceRoutes`, so `/api/v1/me/identity` and `/key-rotations` would answer 404 there and these tests would fail for the wrong reason. In `restartRouter`, after `DeviceRoutes(mux, f.db, f.cfg)`, add `IdentityRoutes(mux, f.db)` and `TeamKeyRoutes(mux, f.db)`. Then append to `internal/httpapi/teamkeys_p3c_test.go`, adding `encoding/base64`, `encoding/json`, `net/url` and `time` to its imports:

```go
func deviceOnlyBody(pub []byte) string {
	return `{"publicKey":` + quote(base64.StdEncoding.EncodeToString(pub)) + `,"wrapAlg":"none"}`
}

// ssoPerson signs subject in through the fixture's IdP (no app role): its cookies and user ID.
func ssoPerson(f *logoutFixture, subject, sid string) ([]*http.Cookie, string) {
	f.t.Helper()
	res := f.send(f.beginLogin(subject, sid, time.Now()))
	if res.Code != 302 {
		f.t.Fatalf("login %s: %d %s", subject, res.Code, res.Body.String())
	}
	var id string
	if err := f.db.QueryRow(`SELECT id FROM users WHERE username=?`, subject).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	return liveCookies(res), id
}

// ssoDo sends method path body as an SSO session. When the route asks for a KySignOn confirmation it
// completes one for subject (no app role) and retries the identical request with the grant.
func ssoDo(f *logoutFixture, cookies []*http.Cookie, subject, method, path, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	send := func(grant string) *httptest.ResponseRecorder {
		req := withCookies(httptest.NewRequest(method, path, strings.NewReader(body)), cookies)
		req.Header.Set("Content-Type", "application/json")
		if grant != "" {
			req.Header.Set("X-Kynotes-Step-Up", grant)
		}
		return f.send(req)
	}
	first := send("")
	var detail struct{ Error struct{ Code, Challenge string } }
	if first.Code != 403 || json.Unmarshal(first.Body.Bytes(), &detail) != nil || detail.Error.Code != "sso_step_up_required" {
		return first
	}
	start := f.send(withCookies(httptest.NewRequest("POST", "/api/v1/auth/oidc/step-up", strings.NewReader(`{"challenge":"`+detail.Error.Challenge+`"}`)), cookies))
	var begun struct{ URL string }
	if start.Code != 200 || json.Unmarshal(start.Body.Bytes(), &begun) != nil {
		f.t.Fatalf("start: %d %s", start.Code, start.Body.String())
	}
	dest, err := url.Parse(begun.URL)
	if err != nil {
		f.t.Fatal(err)
	}
	q := dest.Query()
	state, now := q.Get("state"), time.Now().Unix()
	f.mu.Lock()
	f.proofs[state] = map[string]any{"iss": f.issuer.URL, "aud": "kynotes", "sub": subject, "sid": "fresh-proof", "iat": now, "exp": now + 3600, "nonce": q.Get("nonce"), "auth_time": now, "acr": "urn:kysignon:acr:password", "amr": []string{"pwd"}}
	f.mu.Unlock()
	callback := withCookies(httptest.NewRequest("GET", "/api/v1/auth/oidc/callback?code="+state+"&state="+state, nil), cookies)
	for _, c := range start.Result().Cookies() {
		callback.AddCookie(c)
	}
	if res := f.send(callback); res.Code != 200 {
		f.t.Fatalf("callback: %d %s", res.Code, res.Body.String())
	}
	return send(detail.Error.Challenge)
}

func TestSSOSessionCreatesDeviceOnlyIdentity(t *testing.T) {
	f := newLogoutFixture(t)
	cookies, bob := ssoPerson(f, "bob", "bob-1")
	// Someone else knows bob's unused password; it wraps nothing here, so it blocks nothing.
	if _, err := f.db.Exec(`UPDATE users SET password_admin_known=1 WHERE id=?`, bob); err != nil {
		t.Fatal(err)
	}
	plain := withCookies(httptest.NewRequest("PUT", "/api/v1/me/identity", strings.NewReader(deviceOnlyBody(identityPub))), cookies)
	plain.Header.Set("Content-Type", "application/json")
	if r := f.send(plain); r.Code != 403 || !strings.Contains(r.Body.String(), "sso_step_up_required") {
		t.Fatal("created without a KySignOn confirmation", r.Code, r.Body.String())
	}
	put := func(body string) int { return ssoDo(f, cookies, "bob", "PUT", "/api/v1/me/identity", body).Code }
	// A password wrap from a session that proved no password, or a wrapped key beside "none": refused.
	if code := put(string(identityBody(identityPub, identityWrapped))); code != 400 {
		t.Fatal("SSO session stored a password wrap", code)
	}
	if code := put(`{"publicKey":` + quote(base64.StdEncoding.EncodeToString(identityPub)) + `,"wrapAlg":"none","wrappedPrivateKey":` + quote(base64.StdEncoding.EncodeToString(identityWrapped)) + `}`); code != 400 {
		t.Fatal("device-only identity carried a server copy", code)
	}
	if code := put(deviceOnlyBody(identityPub)); code != 200 {
		t.Fatal("device-only create", code)
	}
	var alg string
	var wrapped []byte
	if err := f.db.QueryRow(`SELECT wrap_alg,wrapped_private_key FROM user_identities WHERE user_id=?`, bob).Scan(&alg, &wrapped); err != nil || alg != "none" || len(wrapped) != 0 {
		t.Fatalf("stored %q %d bytes: %v", alg, len(wrapped), err)
	}
	get := f.send(withCookies(httptest.NewRequest("GET", "/api/v1/me/identity", nil), cookies))
	if !strings.Contains(get.Body.String(), `"wrapAlg":"none"`) || strings.Contains(get.Body.String(), "wrappedPrivateKey") {
		t.Fatal("GET /me/identity", get.Body.String())
	}
}

func TestDeviceOnlyIdentityIsNeverWrappedByAPassword(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	p.stepUp(t)
	if code, _ := status(t, p.do(t, http.MethodPut, "/api/v1/me/identity", []byte(deviceOnlyBody(identityPub)), true, false)); code != http.StatusBadRequest {
		t.Fatal("a password session created a device-only identity", code)
	}
	id := p.createIdentity(t)
	// As if created from a single sign-on session: no server copy.
	if _, err := p.db.Exec(`UPDATE user_identities SET wrap_alg='none',wrapped_private_key=X'' WHERE user_id=?`, pairUser); err != nil {
		t.Fatal(err)
	}
	if code, body := status(t, p.do(t, http.MethodPost, "/api/v1/auth/login", []byte(`{"username":"pair","authSecret":"`+strings.Repeat("a", 64)+`"}`), false, false)); code != 200 || !strings.Contains(body, `"wrapAlg":"none"`) || strings.Contains(body, base64.StdEncoding.EncodeToString(identityWrapped)) {
		t.Fatalf("login identity: %d %s", code, body)
	}
	change := func(rewrap bool) (int, string) {
		body := `{"currentAuthSecret":"` + strings.Repeat("a", 64) + `","newAuthSecret":"` + strings.Repeat("c", 64) + `","newLoginSalt":"bmV3c2FsdA==","iterations":100000`
		if rewrap {
			body += `,"wrappedIdentityKey":` + quote(base64.StdEncoding.EncodeToString(identityWrapped)) + `,"identityDeviceId":` + quote(id)
		}
		return status(t, p.do(t, http.MethodPost, "/api/v1/auth/password", []byte(body+`}`), true, false))
	}
	if code, body := change(true); code != http.StatusConflict || !strings.Contains(body, "identity_rewrap_required") {
		t.Fatalf("a password wrapped a device-only identity: %d %s", code, body)
	}
	if code, body := change(false); code != http.StatusNoContent {
		t.Fatalf("password change without a re-wrap: %d %s", code, body)
	}
	var alg string
	if err := p.db.QueryRow(`SELECT wrap_alg FROM user_identities WHERE user_id=?`, pairUser).Scan(&alg); err != nil || alg != "none" {
		t.Fatal(alg, err)
	}
}

// ssoTeam creates bob's device-only identity and a team container bob owns at generation 1.
func ssoTeam(t *testing.T) (f *logoutFixture, cookies []*http.Cookie, bob, device, cid string) {
	f = newLogoutFixture(t)
	cookies, bob = ssoPerson(f, "bob", "bob-1")
	if r := ssoDo(f, cookies, "bob", "PUT", "/api/v1/me/identity", deviceOnlyBody(identityPub)); r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	if err := f.db.QueryRow(`SELECT device_id FROM user_identities WHERE user_id=?`, bob).Scan(&device); err != nil {
		t.Fatal(err)
	}
	cid = mint(t, "cnt")
	if _, err := f.db.Exec(`INSERT INTO containers(id,kind,owner_user_id,team_id,created_at,updated_at) VALUES(?,'team',?,'','now','now')`, cid, bob); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at) VALUES(?,?,?,'owner','now')`, mint(t, "mem"), cid, bob); err != nil {
		t.Fatal(err)
	}
	return
}

func TestSSOStewardSharesKeysAfterActionStepUp(t *testing.T) {
	f, cookies, _, device, cid := ssoTeam(t)
	rotate := "/api/v1/containers/" + cid + "/key-rotations"
	body := string(rotationBody(1, envJSON(device, 2, 1)))
	plain := withCookies(httptest.NewRequest("POST", rotate, strings.NewReader(body)), cookies)
	plain.Header.Set("Content-Type", "application/json")
	if r := f.send(plain); r.Code != 403 || !strings.Contains(r.Body.String(), "sso_step_up_required") {
		t.Fatal("rotated without a KySignOn confirmation", r.Code, r.Body.String())
	}
	if r := ssoDo(f, cookies, "bob", "POST", rotate, body); r.Code != 200 {
		t.Fatal("SSO steward rotation", r.Code, r.Body.String())
	}
	// Re-wrapping its own identity envelope takes the same confirmation.
	if r := ssoDo(f, cookies, "bob", "PUT", "/api/v1/containers/"+cid+"/envelopes", string(envelopesBody(envJSON(device, 2, 2)))); r.Code != 204 {
		t.Fatal("SSO envelope write", r.Code, r.Body.String())
	}
}

func TestSSOGrantIsRecheckedInTheWriteTransaction(t *testing.T) {
	f, cookies, bob, device, cid := ssoTeam(t)
	// The session dies in the very transaction that consumes the grant.
	if _, err := f.db.Exec(`CREATE TRIGGER revoke_on_consume AFTER INSERT ON audit_events WHEN NEW.event='auth.sso_step_up.consume' BEGIN UPDATE sessions SET revoked_at='revoked' WHERE user_id='` + bob + `'; END`); err != nil {
		t.Fatal(err)
	}
	if r := ssoDo(f, cookies, "bob", "POST", "/api/v1/containers/"+cid+"/key-rotations", string(rotationBody(1, envJSON(device, 2, 1)))); r.Code == 200 {
		t.Fatal("a session revoked after its grant still rotated")
	}
	var generation int
	if err := f.db.QueryRow(`SELECT key_generation FROM containers WHERE id=?`, cid).Scan(&generation); err != nil || generation != 1 {
		t.Fatal(generation, err)
	}
}
```

In `identity_test.go`:
- Rename `TestUserStepUpRefusesSSOSession` to `TestUserActionStepUpRefusesUngrantedSSOSession`.
- Change its assertion substring from `"step_up_required"` to `"sso_step_up_required"`.

In `teamkeys_test.go` `TestEnvelopeWriteRefusals`, change the `"SSO session"` case's expected code from `"step_up_required"` to `"sso_step_up_required"`.

- [ ] **Step 2: Run the tests to verify they fail.** Run `go test ./internal/httpapi -run 'TestSSOSessionCreatesDeviceOnlyIdentity|TestDeviceOnlyIdentityIsNeverWrappedByAPassword|TestSSOStewardSharesKeysAfterActionStepUp|TestSSOGrantIsRecheckedInTheWriteTransaction|TestUserActionStepUpRefusesUngrantedSSOSession|TestEnvelopeWriteRefusals' -count=1`. Expected: FAIL. The identity `PUT` answers `step_up_required` for SSO sessions, and `none` is a `400` from a local session only by accident.

- [ ] **Step 3: Implement the identity rules.** In `identity_routes.go`:
  - Add `const deviceOnlyWrapAlg = "none" // created by an SSO session: no server copy until P5's recovery code`.
  - In `loadIdentity`, always return `"wrapAlg": alg`. Only `wrappedPrivateKey` stays behind `withWrapped`.
  - Mount `PUT /api/v1/me/identity` on `auth.RequireUserActionStepUp`.
  - Replace the decode and validation block after the JSON decode with:

```go
		sso := s.SSOIssuer != ""
		pub, err := base64.StdEncoding.DecodeString(in.PublicKey)
		var wrapped []byte
		ok := err == nil && len(pub) == 32
		switch {
		case !sso && in.WrapAlg == identityWrapAlg:
			var good bool
			wrapped, good = decodeWrappedIdentity(in.WrappedPrivateKey)
			ok = ok && good
		case sso && in.WrapAlg == deviceOnlyWrapAlg && in.WrappedPrivateKey == "":
			// Nothing an SSO session proves could wrap a key: the identity lives only in browsers.
			wrapped = []byte{}
		default:
			ok = false
		}
		if !ok {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
```

  Keep the original `json.NewDecoder(r.Body).Decode(&in) != nil` check, minus its `in.WrapAlg != identityWrapAlg` clause. In the transaction:
  - Replace `auth.RecheckUserStepUpTx(tx, s, time.Now().UTC())` with `auth.RecheckUserActionTx(tx, s, time.Now().UTC())`.
  - Replace `if adminKnown != 0 {` with `if adminKnown != 0 && !sso { // only a password wrap is readable by whoever knows the password`.
  - Insert `in.WrapAlg` in place of the constant `identityWrapAlg` in the `user_identities` insert.

- [ ] **Step 4: Re-wrap only password-wrapped identities.** In `auth_routes.go`'s password-change transaction, replace the count query with:

```go
			// Only a password-wrapped identity moves with the password; a device-only one is not touched.
			if err := tx.QueryRow(`SELECT COUNT(*) FROM user_identities WHERE user_id=? AND wrap_alg=?`, s.UserID, identityWrapAlg).Scan(&identities); err != nil {
```

  The re-wrap `UPDATE` gains `AND wrap_alg=?` (argument `identityWrapAlg`). The rest is unchanged.

- [ ] **Step 5: SSO stewards.**
  - In `device_routes.go` (`PUT …/envelopes`) and `teamkeys_routes.go` (`POST …/key-rotations`), replace `auth.RequireUserStepUp` with `auth.RequireUserActionStepUp` and `auth.RecheckUserStepUpTx` with `auth.RecheckUserActionTx`.
  - The invitation route in `collab_routes.go` stays on `HasUserStepUp` and `RecheckUserStepUpTx` (ruling 13).

- [ ] **Step 6: Run the tests to verify they pass.** Run `go test ./internal/httpapi -count=1`. Expected: PASS, the identity, envelope, rotation and invitation suites included.

- [ ] **Step 7: Frozen contracts.** In the same change:
  - `IMPLEMENTATION_PLAN.md` §1.8: replace the two rows "Envelope write and key rotation" and "Own identity" with:

```markdown
| Envelope write and key rotation (`PUT .../envelopes`, `POST .../key-rotations`) | required | rejected | CSRF + fresh step-up (`RequireUserActionStepUp`): local `stepup_at` within `StepUpWindow`, or an SSO KySignOn grant bound to this request (user scope); rechecked in the write transaction |
| Own identity (`GET`/`PUT /me/identity`) | required | rejected | `PUT`: CSRF + fresh step-up as above; local sessions create `aes-256-gcm`, SSO sessions `none` (device-only) |
```

  - §1.5 (Device contract) table, row "User identity row": after "(`wrap_alg = aes-256-gcm`, 60 bytes)" add "or `none` (device-only, empty; SSO sessions)".
  - §5.1: the `GET /me/identity` row returns `deviceId, publicKey, fingerprint, wrapAlg`. The `PUT /me/identity` row becomes "session + CSRF + user-action step-up | create only: local `{"publicKey","wrapAlg":"aes-256-gcm","wrappedPrivateKey"}`, SSO `{"publicKey","wrapAlg":"none"}` (each `400` from the other session kind); `409 identity_exists`; `409 password_change_required` while `users.password_admin_known` is set (password wraps only)".
  - §5.2: "No identity is created while it is `1`" becomes "No password-wrapped identity is created while it is `1`; a device-only one is". The password-change bullet reads "exactly when the user has a password-wrapped (`aes-256-gcm`) identity".
  - §5.3: add `TestSSOSessionCreatesDeviceOnlyIdentity`, `TestDeviceOnlyIdentityIsNeverWrappedByAPassword`, `TestSSOStewardSharesKeysAfterActionStepUp`, `TestSSOGrantIsRecheckedInTheWriteTransaction`; rename `TestUserStepUpRefusesSSOSession`.
  - `DESIGN.md` §4 Encryption:
    - Replace "SSO-only users have no password, hence no `userKEK` and no identity yet (open question)." with "An SSO session creates a device-only identity (`wrap_alg = none`) after a KySignOn confirmation of the request; no copy exists on the server until P5's recovery code, and other browsers receive it by device linking. A password never unlocks or re-wraps it."
    - Replace "Envelope writes and rotations need a local password step-up; SSO sessions are refused." with "Envelope writes and rotations need a fresh step-up: a password re-proof for local sessions, a KySignOn confirmation of the exact request for SSO sessions."
  - `DESIGN.md` §4 Teams: "creating it then needs the same password step-up as a direct envelope write" becomes "creating it then needs a local password step-up; invitations from SSO sessions carry no envelopes".
  - `docs/SSO.md`: replace the sentence "SSO sessions cannot create a user identity, write key envelopes or rotate keys (…require a local password step-up)." with "SSO sessions create device-only identities, write key envelopes and rotate keys after a user-scope confirmation; invitations they send carry no envelopes."

- [ ] **Step 8: Commit.**

```bash
git add internal/httpapi DESIGN.md IMPLEMENTATION_PLAN.md docs/SSO.md
git commit -m "server: SSO sessions hold device-only identities and share keys after a KySignOn confirmation"
```

### Task 3: Protocol: link commitment, check code and bundle

**Files:** Modify `internal/teamkeys/vectors_test.go`, `web/src/teamKeys.ts`, `web/src/identity.ts`. Create `internal/teamkeys/link_vectors_test.go`, `testdata/protocol/link_vectors.json` (generated), `web/src/linking.ts`, `web/src/linking.test.ts`.

**Interfaces:**
- Consumes: `x25519`, `hkdf32`, `unhex`, `mustID` and `update`, all in `vectors_test.go`.
- Produces: the `linking.ts` API (see Interfaces), plus `teamKeys.ts` exports `concat`, `idBytes` and `sameBytes`.

- [ ] **Step 1: Go vector generator.** In `vectors_test.go`, change `idPattern` to `` `^(cnt|dev|usr|lnk)_[0-9a-hjkmnp-tv-z]{26}$` ``. Create `internal/teamkeys/link_vectors_test.go`:

```go
package teamkeys

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const linkVectorFile = "../../testdata/protocol/link_vectors.json"

type linkVector struct {
	UserID             string `json:"userId"`
	RequestID          string `json:"requestId"`
	IdentityDeviceID   string `json:"identityDeviceId"`
	IdentityPrivateKey string `json:"identityPrivateKey"`
	ApproverPrivateKey string `json:"approverPrivateKey"`
	ApproverPublicKey  string `json:"approverPublicKey"`
	NewcomerPrivateKey string `json:"newcomerPrivateKey"`
	NewcomerPublicKey  string `json:"newcomerPublicKey"`
	Nonce              string `json:"nonce"`
	Commitment         string `json:"commitment"`
	CheckCode          string `json:"checkCode"`
	Bundle             string `json:"bundle"`
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// link builds one vector the way web/src/linking.ts must: commitment, check code and a sealed
// bundle the newcomer side opens.
func link(t *testing.T, userID, requestID, deviceID, identityPriv, approverPriv, newcomerPriv, nonce string) linkVector {
	mustID(t, "usr", userID)
	mustID(t, "lnk", requestID)
	mustID(t, "dev", deviceID)
	const label = "kynotes/link/v1"
	approverPub := x25519(t, unhex(t, approverPriv), curve25519.Basepoint)
	newcomerPub := x25519(t, unhex(t, newcomerPriv), curve25519.Basepoint)
	commitment := sha256.Sum256(cat([]byte("kynotes/link-commit/v1"), newcomerPub))
	check := sha256.Sum256(cat([]byte("kynotes/link-check/v1"), []byte(userID), []byte(requestID), approverPub, newcomerPub))
	digits := fmt.Sprintf("%06d", binary.BigEndian.Uint32(check[:4])%1_000_000)
	salt := cat(approverPub, newcomerPub)
	aad := cat([]byte(label), []byte(userID), []byte(requestID), []byte(deviceID), approverPub, newcomerPub)
	aead, err := chacha20poly1305.New(hkdf32(t, x25519(t, unhex(t, approverPriv), newcomerPub), salt, label))
	if err != nil {
		t.Fatal(err)
	}
	n := unhex(t, nonce)
	bundle := aead.Seal(cat([]byte{0x01}, n), n, unhex(t, identityPriv), aad)
	if len(bundle) != 61 {
		t.Fatalf("bundle is %d bytes, want 61", len(bundle))
	}
	// The newcomer opens it with its own agreement.
	open, _ := chacha20poly1305.New(hkdf32(t, x25519(t, unhex(t, newcomerPriv), approverPub), salt, label))
	if pt, err := open.Open(nil, n, bundle[13:], aad); err != nil || !bytes.Equal(pt, unhex(t, identityPriv)) {
		t.Fatalf("round trip failed: %v", err)
	}
	return linkVector{userID, requestID, deviceID, identityPriv, approverPriv, hex.EncodeToString(approverPub), newcomerPriv, hex.EncodeToString(newcomerPub), nonce, hex.EncodeToString(commitment[:]), digits[:3] + " " + digits[3:], hex.EncodeToString(bundle)}
}

func TestLinkVectors(t *testing.T) {
	alice := "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	bob := "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
	carol := "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
	dave := "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"
	got, err := json.MarshalIndent(map[string][]linkVector{"links": {
		link(t, "usr_0123456789abcdefghjkmnpqrs", "lnk_00000000000000000000000000", "dev_00000000000000000000000000", carol, alice, bob, "000102030405060708090a0b"),
		link(t, "usr_zyxwvtsrqpnmkjhgfedcba9876", "lnk_tvwxyz0123456789abcdefghjk", "dev_mnpqrstvwxyz0123456789abcd", dave, bob, alice, "0c0d0e0f1011121314151617"),
	}}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *update {
		if err := os.WriteFile(linkVectorFile, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(linkVectorFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale; run go test ./internal/teamkeys -run TestLinkVectors -update", linkVectorFile)
	}
}
```

- [ ] **Step 2: Generate and pin.** Run `go test ./internal/teamkeys -run TestLinkVectors -update && go test ./internal/teamkeys -count=1`. Expected: PASS, and `testdata/protocol/link_vectors.json` exists with two entries.

- [ ] **Step 3: Write the failing TS test.** Create `web/src/linking.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { bytesToHex, hexToBytes as h } from "@noble/ciphers/utils.js";
import vectors from "../../testdata/protocol/link_vectors.json";
import { checkCode, confirmCheckCode, isCheckCodeConfirmation, LINK_BUNDLE_BYTES, linkCommitment, newLinkKey, openLinkBundle, sealLinkBundle, type LinkContext } from "./linking";

const keysOf = (v: (typeof vectors.links)[number]) => ({
  approver: { privateKey: h(v.approverPrivateKey), publicKey: h(v.approverPublicKey) },
  newcomer: { privateKey: h(v.newcomerPrivateKey), publicKey: h(v.newcomerPublicKey) },
});
const contextOf = (v: (typeof vectors.links)[number]): LinkContext => ({ userID: v.userId, requestID: v.requestId, identityDeviceID: v.identityDeviceId, approverKey: h(v.approverPublicKey), newcomerKey: h(v.newcomerPublicKey) });

describe("device link protocol", () => {
  it("matches the Go vectors: commitment, check code and bundle", () => {
    for (const v of vectors.links) {
      const { approver, newcomer } = keysOf(v);
      expect(bytesToHex(linkCommitment(newcomer.publicKey))).toBe(v.commitment);
      expect(checkCode(v.userId, v.requestId, approver.publicKey, newcomer.publicKey)).toBe(v.checkCode);
      const bundle = sealLinkBundle(h(v.identityPrivateKey), approver, contextOf(v), h(v.nonce));
      expect(bundle.length).toBe(LINK_BUNDLE_BYTES);
      expect(bytesToHex(bundle)).toBe(v.bundle);
      expect(bytesToHex(openLinkBundle(bundle, newcomer, contextOf(v)))).toBe(v.identityPrivateKey);
    }
  });

  it("opens nothing bound to another user, request, identity or approver key, or a flipped byte", () => {
    const v = vectors.links[0];
    const { newcomer } = keysOf(v);
    const bundle = h(v.bundle);
    const context = contextOf(v);
    for (const changed of [
      { ...context, userID: `usr_${"z".repeat(26)}` },
      { ...context, requestID: `lnk_${"z".repeat(26)}` },
      { ...context, identityDeviceID: `dev_${"z".repeat(26)}` },
      { ...context, approverKey: newLinkKey().publicKey },
    ]) expect(() => openLinkBundle(bundle, newcomer, changed)).toThrow();
    const flipped = bundle.slice();
    flipped[20] ^= 1;
    expect(() => openLinkBundle(flipped, newcomer, context)).toThrow();
    expect(() => openLinkBundle(bundle.subarray(0, 60), newcomer, context)).toThrow();
  });

  it("changes the check code when either one-time key changes", () => {
    const v = vectors.links[0];
    const { approver, newcomer } = keysOf(v);
    const code = checkCode(v.userId, v.requestId, approver.publicKey, newcomer.publicKey);
    expect(code).toMatch(/^\d{3} \d{3}$/);
    expect(checkCode(v.userId, v.requestId, newLinkKey().publicKey, newcomer.publicKey)).not.toBe(code);
    expect(checkCode(v.userId, v.requestId, approver.publicKey, newLinkKey().publicKey)).not.toBe(code);
    expect(checkCode(v.userId, v.requestId, newcomer.publicKey, approver.publicKey)).not.toBe(code);
  });

  it("accepts only a confirmCheckCode result, for its own request", () => {
    const id = vectors.links[0].requestId;
    const confirmed = confirmCheckCode(id);
    expect(isCheckCodeConfirmation(confirmed, id)).toBe(true);
    expect(isCheckCodeConfirmation(confirmed, vectors.links[1].requestId)).toBe(false);
    expect(isCheckCodeConfirmation({ requestID: id }, id)).toBe(false);
    expect(isCheckCodeConfirmation(Object.create(Object.getPrototypeOf(confirmed)), id)).toBe(false);
  });
});
```

- [ ] **Step 4: Run it to verify it fails.** Run `npm test --prefix web -- linking`. Expected: FAIL (`./linking` not found).

- [ ] **Step 5: Implement.** In `web/src/teamKeys.ts`:
  - Change `ID` to `/^(cnt|dev|usr|lnk)_[0-9a-hjkmnp-tv-z]{26}$/`.
  - Export `idBytes` with `prefix: "cnt" | "dev" | "usr" | "lnk"`.
  - Export `concat`.
  - Add `export const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((value, i) => value === b[i]);`.

  In `identity.ts`, delete the local `sameBytes` and import it from `./teamKeys`. Create `web/src/linking.ts`:

```ts
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdfSha256, sha256 } from "./fallbackCrypto";
import { concat, generateIdentity, idBytes, sameBytes, type Identity } from "./teamKeys";

const LINK_LABEL = "kynotes/link/v1";
const COMMIT_LABEL = "kynotes/link-commit/v1";
const CHECK_LABEL = "kynotes/link-check/v1";
const LINK_VERSION = 0x01;
/** 0x01 | nonce(12) | ChaCha20-Poly1305(identity private key)(48). */
export const LINK_BUNDLE_BYTES = 61;
const encoder = new TextEncoder();

/** What both sides bind: the account, the request, the identity row, and both one-time keys. */
export type LinkContext = { userID: string; requestID: string; identityDeviceID: string; approverKey: Uint8Array; newcomerKey: Uint8Array };

function key32(key: Uint8Array): Uint8Array {
  if (key.length !== 32) throw new Error("invalid link key");
  return key;
}

/** A one-time X25519 key for one link attempt; it lives in memory only. */
export const newLinkKey = (): Identity => generateIdentity();

/** Posted before the approver's key exists, so no one can pick a key to fit a check code later. */
export const linkCommitment = (newcomerKey: Uint8Array): Uint8Array => sha256(concat(encoder.encode(COMMIT_LABEL), key32(newcomerKey)));

/** Six digits over the account, the request and both one-time keys, shown as "123 456" on both screens. */
export function checkCode(userID: string, requestID: string, approverKey: Uint8Array, newcomerKey: Uint8Array): string {
  const digest = sha256(concat(encoder.encode(CHECK_LABEL), idBytes("usr", userID), idBytes("lnk", requestID), key32(approverKey), key32(newcomerKey)));
  const digits = String(new DataView(digest.buffer, digest.byteOffset, 4).getUint32(0) % 1_000_000).padStart(6, "0");
  return `${digits.slice(0, 3)} ${digits.slice(3)}`;
}

const aad = (c: LinkContext) => concat(encoder.encode(LINK_LABEL), idBytes("usr", c.userID), idBytes("lnk", c.requestID), idBytes("dev", c.identityDeviceID), key32(c.approverKey), key32(c.newcomerKey));
const bundleKey = (shared: Uint8Array, c: LinkContext) => hkdfSha256(shared, 32, concat(c.approverKey, c.newcomerKey), encoder.encode(LINK_LABEL));

/** Approver: seals this account's identity private key to the newcomer's one-time key. */
export function sealLinkBundle(identityPrivateKey: Uint8Array, approver: Identity, context: LinkContext, nonce: Uint8Array = randomBytes(12)): Uint8Array {
  if (identityPrivateKey.length !== 32 || nonce.length !== 12 || !sameBytes(approver.publicKey, context.approverKey)) throw new Error("invalid link input");
  // noble's getSharedSecret throws on an all-zero result (low-order point).
  const key = bundleKey(x25519.getSharedSecret(approver.privateKey, key32(context.newcomerKey)), context);
  return concat(Uint8Array.of(LINK_VERSION), nonce, chacha20poly1305(key, nonce, aad(context)).encrypt(identityPrivateKey));
}

/** Newcomer: the identity private key, or a throw for any other bytes, binding or key. */
export function openLinkBundle(bundle: Uint8Array, newcomer: Identity, context: LinkContext): Uint8Array {
  if (bundle.length !== LINK_BUNDLE_BYTES || bundle[0] !== LINK_VERSION || !sameBytes(newcomer.publicKey, context.newcomerKey)) throw new Error("unsupported link bundle");
  const key = bundleKey(x25519.getSharedSecret(newcomer.privateKey, key32(context.approverKey)), context);
  return chacha20poly1305(key, bundle.subarray(1, 13), aad(context)).decrypt(bundle.subarray(13));
}

const confirmations = new WeakSet<CheckCodeConfirmation>();
let mint: (requestID: string) => CheckCodeConfirmation;
/** Proof the user saw one check code on both screens for this request; only confirmCheckCode makes one. */
export class CheckCodeConfirmation {
  private declare readonly brand: true; // nominal: look-alike objects do not type-check
  static {
    mint = (requestID) => {
      const confirmation = new CheckCodeConfirmation(requestID);
      confirmations.add(confirmation);
      return confirmation;
    };
  }
  private constructor(readonly requestID: string) {}
}
/** Call only from the user's own "Codes match" click. */
export const confirmCheckCode = (requestID: string): CheckCodeConfirmation => mint(requestID);
export const isCheckCodeConfirmation = (value: unknown, requestID: string): value is CheckCodeConfirmation =>
  typeof value === "object" && value !== null && confirmations.has(value as CheckCodeConfirmation) && (value as CheckCodeConfirmation).requestID === requestID;
```

- [ ] **Step 6: Run the tests to verify they pass.** Run `npm test --prefix web -- linking teamKeys identity`. Expected: PASS.

- [ ] **Step 7: Commit.**

```bash
git add internal/teamkeys testdata/protocol/link_vectors.json web/src/linking.ts web/src/linking.test.ts web/src/teamKeys.ts web/src/identity.ts
git commit -m "protocol: device-link commitment, check code and bundle with Go vectors"
```

### Task 4: Server: link relay: create, list, claim, reveal, cancel

**Files:** Modify `internal/storage/migrations/0024_device_linking.sql`, `internal/httpapi/router.go`, `internal/httpapi/sso_logout_test.go`, `internal/httpapi/ratelimit.go`, `internal/storage/gc.go`, `internal/storage/gc_test.go`, `kynotes.example.yaml`, `internal/httpapi/teamkeys_p3c_test.go`, `DESIGN.md`, `IMPLEMENTATION_PLAN.md`. Create `internal/httpapi/link_routes.go`.

**Interfaces:**
- Consumes: `testdata/protocol/link_vectors.json` (Task 3). The test helpers `newPairClient`, `createIdentity`, `addUser`, `register`, `mintToken`, `doDeviceOnly`, `status` and `quote`.
- Produces: `LinkRoutes`, `linkHandler`, `linkTx`, `sessionLive`, `b64`, `linkTTL`, `linkMaxPending`, `linkBundleBytes` and `linkCommitLabel`. Test helpers `firstLinkVector(t) (commitment, newcomerKey, approverKey []byte)`, `(p *pairClient) secondSession(t)`, `createLinkRequest(t, p, commitment) string`, `openLink(t) (trusted, newcomer *pairClient, id string)` and `linkPath(id, suffix string) string`.

- [ ] **Step 1: Write the failing tests.** Append to `internal/httpapi/teamkeys_p3c_test.go` (imports: `bytes`, `encoding/hex`, `net/http/cookiejar`, `os`):

```go
// firstLinkVector is links[0] of the shared vector file: the server must accept its commitment.
func firstLinkVector(t *testing.T) (commitment, newcomerKey, approverKey []byte) {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/protocol/link_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Links []struct{ Commitment, NewcomerPublicKey, ApproverPublicKey string } `json:"links"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	decode := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	v := file.Links[0]
	return decode(v.Commitment), decode(v.NewcomerPublicKey), decode(v.ApproverPublicKey)
}

// secondSession signs the pair user in again in a fresh cookie jar: another browser of one account.
func (p *pairClient) secondSession(t *testing.T) *pairClient {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	q := &pairClient{hc: &http.Client{Jar: jar}, db: p.db, url: p.url}
	if code, body := status(t, q.do(t, http.MethodPost, "/api/v1/auth/login", []byte(`{"username":"pair","authSecret":"`+strings.Repeat("a", 64)+`"}`), false, false)); code != http.StatusOK {
		t.Fatalf("second login=%d %s", code, body)
	}
	return q
}

func linkPath(id, suffix string) string { return "/api/v1/me/link-requests/" + id + suffix }

func createLinkRequest(t *testing.T, p *pairClient, commitment []byte) string {
	t.Helper()
	code, body := status(t, p.do(t, http.MethodPost, "/api/v1/me/link-requests", []byte(`{"commitment":`+quote(b64(commitment))+`}`), true, false))
	var out struct{ ID, ExpiresAt string }
	if code != http.StatusOK || json.Unmarshal([]byte(body), &out) != nil || !strings.HasPrefix(out.ID, "lnk_") || out.ExpiresAt == "" {
		t.Fatalf("create=%d %s", code, body)
	}
	return out.ID
}

// openLink: a request from a second session of pair, claimed by the first and revealed.
func openLink(t *testing.T) (trusted, newcomer *pairClient, id string) {
	t.Helper()
	commitment, newcomerKey, approverKey := firstLinkVector(t)
	trusted = newPairClient(t, strings.Repeat("p", 32))
	trusted.createIdentity(t)
	newcomer = trusted.secondSession(t)
	id = createLinkRequest(t, newcomer, commitment)
	if code, body := status(t, trusted.do(t, http.MethodPost, linkPath(id, "/claim"), []byte(`{"approverKey":`+quote(b64(approverKey))+`}`), true, false)); code != http.StatusNoContent {
		t.Fatalf("claim=%d %s", code, body)
	}
	if code, body := status(t, newcomer.do(t, http.MethodPost, linkPath(id, "/reveal"), []byte(`{"newcomerKey":`+quote(b64(newcomerKey))+`}`), true, false)); code != http.StatusNoContent {
		t.Fatalf("reveal=%d %s", code, body)
	}
	return
}

func audited(t *testing.T, p *pairClient, event string) int {
	t.Helper()
	var n int
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event=?`, event).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestLinkRelayHandsOverOnlyPublicKeys(t *testing.T) {
	commitment, newcomerKey, approverKey := firstLinkVector(t)
	trusted := newPairClient(t, strings.Repeat("p", 32))
	trusted.createIdentity(t)
	newcomer := trusted.secondSession(t)
	id := createLinkRequest(t, newcomer, commitment)
	get := func(p *pairClient, path string) (int, string) { return status(t, p.do(t, http.MethodGet, path, nil, false, false)) }
	// The newcomer does not see its own request in the approver list; the trusted session does.
	if _, body := get(newcomer, "/api/v1/me/link-requests"); strings.TrimSpace(body) != "[]" {
		t.Fatal("newcomer listed its own request", body)
	}
	if _, body := get(trusted, "/api/v1/me/link-requests"); !strings.Contains(body, id) || !strings.Contains(body, b64(commitment)) || !strings.Contains(body, `"claimed":false`) || !strings.Contains(body, `"newcomerKey":""`) {
		t.Fatal("trusted list", body)
	}
	claim := func(p *pairClient) int {
		code, _ := status(t, p.do(t, http.MethodPost, linkPath(id, "/claim"), []byte(`{"approverKey":`+quote(b64(approverKey))+`}`), true, false))
		return code
	}
	if claim(newcomer) != http.StatusNotFound {
		t.Fatal("the newcomer claimed its own request")
	}
	if claim(trusted) != http.StatusNoContent {
		t.Fatal("claim")
	}
	if claim(trusted) != http.StatusNotFound {
		t.Fatal("claimed twice")
	}
	third := trusted.secondSession(t)
	if claim(third) != http.StatusNotFound {
		t.Fatal("a second approver claimed a claimed request")
	}
	if _, body := get(third, "/api/v1/me/link-requests"); strings.Contains(body, id) {
		t.Fatal("another session lists a request claimed by someone else", body)
	}
	// The newcomer learns the approver key and nothing else yet.
	if code, body := get(newcomer, linkPath(id, "")); code != 200 || !strings.Contains(body, `"state":"claimed"`) || !strings.Contains(body, b64(approverKey)) || strings.Contains(body, "bundle") {
		t.Fatal("newcomer state", code, body)
	}
	reveal := func(p *pairClient) int {
		code, _ := status(t, p.do(t, http.MethodPost, linkPath(id, "/reveal"), []byte(`{"newcomerKey":`+quote(b64(newcomerKey))+`}`), true, false))
		return code
	}
	if reveal(trusted) != http.StatusNotFound {
		t.Fatal("the approver revealed")
	}
	if reveal(newcomer) != http.StatusNoContent || reveal(newcomer) != http.StatusNotFound {
		t.Fatal("reveal is not once")
	}
	if _, body := get(trusted, "/api/v1/me/link-requests"); !strings.Contains(body, b64(newcomerKey)) || !strings.Contains(body, `"claimed":true`) {
		t.Fatal("revealed key not listed to its approver", body)
	}
	for _, event := range []string{"identity.link.request", "identity.link.claim", "identity.link.reveal"} {
		if audited(t, trusted, event) != 1 {
			t.Fatal("audit", event)
		}
	}
}

func TestLinkRequestRefusals(t *testing.T) {
	commitment, newcomerKey, approverKey := firstLinkVector(t)
	trusted := newPairClient(t, strings.Repeat("p", 32))
	newcomer := trusted.secondSession(t)
	create := func(p *pairClient, value []byte, csrf bool) int {
		code, _ := status(t, p.do(t, http.MethodPost, "/api/v1/me/link-requests", []byte(`{"commitment":`+quote(b64(value))+`}`), csrf, false))
		return code
	}
	if create(newcomer, commitment, true) != http.StatusNotFound {
		t.Fatal("a link request for an account with no identity")
	}
	trusted.createIdentity(t)
	if create(newcomer, commitment[:31], true) != http.StatusBadRequest || create(newcomer, commitment, false) != http.StatusForbidden {
		t.Fatal("malformed commitment or missing CSRF accepted")
	}
	// Another account sees none of it, by any route.
	other := trusted.addUser(t, "other")
	id := createLinkRequest(t, newcomer, commitment)
	for _, call := range [][2]string{{http.MethodPost, "/claim"}, {http.MethodPost, "/reveal"}, {http.MethodGet, ""}, {http.MethodDelete, ""}} {
		if code, _ := status(t, other.do(t, call[0], linkPath(id, call[1]), []byte(`{"approverKey":`+quote(b64(approverKey))+`,"newcomerKey":`+quote(b64(newcomerKey))+`}`), true, false)); code != http.StatusNotFound {
			t.Fatal("another account reached", call, code)
		}
	}
	// Expired requests are gone for everyone.
	if _, err := trusted.db.Exec(`UPDATE link_requests SET expires_at='2000-01-01T00:00:00Z' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	claim := func(p *pairClient, id string) int {
		code, _ := status(t, p.do(t, http.MethodPost, linkPath(id, "/claim"), []byte(`{"approverKey":`+quote(b64(approverKey))+`}`), true, false))
		return code
	}
	if claim(trusted, id) != http.StatusNotFound {
		t.Fatal("expired request claimed")
	}
	if code, _ := status(t, newcomer.do(t, http.MethodGet, linkPath(id, ""), nil, false, false)); code != http.StatusNotFound {
		t.Fatal("expired request collected")
	}
	// A key that does not match the commitment ends the attempt.
	id = createLinkRequest(t, newcomer, commitment)
	if claim(trusted, id) != http.StatusNoContent {
		t.Fatal("claim")
	}
	if code, _ := status(t, newcomer.do(t, http.MethodPost, linkPath(id, "/reveal"), []byte(`{"newcomerKey":`+quote(b64(approverKey))+`}`), true, false)); code != http.StatusBadRequest {
		t.Fatal("a key that does not match its commitment was revealed", code)
	}
	var rows int
	if err := trusted.db.QueryRow(`SELECT COUNT(*) FROM link_requests WHERE id=?`, id).Scan(&rows); err != nil || rows != 0 || audited(t, trusted, "identity.link.refuse") != 1 {
		t.Fatal("refused attempt kept", rows, err)
	}
	// Both sessions must be live: a revoked newcomer cannot be claimed, a revoked approver cannot be revealed to.
	approver := trusted.secondSession(t)
	id = createLinkRequest(t, newcomer, commitment)
	if _, err := trusted.db.Exec(`UPDATE sessions SET revoked_at='x' WHERE id=(SELECT newcomer_session_id FROM link_requests WHERE id=?)`, id); err != nil {
		t.Fatal(err)
	}
	if claim(approver, id) != http.StatusNotFound {
		t.Fatal("claimed for a revoked newcomer session")
	}
	fresh := trusted.secondSession(t)
	id = createLinkRequest(t, fresh, commitment)
	if claim(approver, id) != http.StatusNoContent {
		t.Fatal("claim")
	}
	if _, err := trusted.db.Exec(`UPDATE sessions SET revoked_at='x' WHERE id=(SELECT approver_session_id FROM link_requests WHERE id=?)`, id); err != nil {
		t.Fatal(err)
	}
	if code, _ := status(t, fresh.do(t, http.MethodPost, linkPath(id, "/reveal"), []byte(`{"newcomerKey":`+quote(b64(newcomerKey))+`}`), true, false)); code != http.StatusNotFound {
		t.Fatal("revealed to a revoked approver session", code)
	}
	// At most three live requests per account; the same browser restarting replaces its own.
	if _, err := trusted.db.Exec(`DELETE FROM link_requests`); err != nil {
		t.Fatal(err)
	}
	extra := trusted.secondSession(t)
	for _, p := range []*pairClient{trusted, fresh, extra} {
		createLinkRequest(t, p, commitment)
	}
	if code, body := status(t, trusted.do(t, http.MethodPost, "/api/v1/me/link-requests", []byte(`{"commitment":`+quote(b64(commitment))+`}`), true, false)); code != http.StatusOK {
		t.Fatal("the same browser restarting was refused", code, body)
	}
	fourth := trusted.secondSession(t)
	if code, body := status(t, fourth.do(t, http.MethodPost, "/api/v1/me/link-requests", []byte(`{"commitment":`+quote(b64(commitment))+`}`), true, false)); code != http.StatusConflict || !strings.Contains(body, "already_exists") {
		t.Fatal("a fourth live request", code, body)
	}
	// Any session of the account cancels ("Not me"); once.
	id = createLinkRequest(t, fresh, commitment)
	if code, _ := status(t, trusted.do(t, http.MethodDelete, linkPath(id, ""), nil, true, false)); code != http.StatusNoContent {
		t.Fatal("cancel")
	}
	if code, _ := status(t, trusted.do(t, http.MethodDelete, linkPath(id, ""), nil, true, false)); code != http.StatusNotFound || audited(t, trusted, "identity.link.cancel") != 1 {
		t.Fatal("cancelled twice")
	}
	// Device credentials never reach the relay.
	trusted.deviceID, trusted.deviceSecret, _ = trusted.register(t, trusted.mintToken(t), bytes.Repeat([]byte{7}, 32))
	if code, _ := status(t, trusted.doDeviceOnly(t, http.MethodGet, "/api/v1/me/link-requests", nil)); code != http.StatusUnauthorized {
		t.Fatal("device credential listed link requests", code)
	}
}

func TestLinkCreationIsRateLimitedPerAccount(t *testing.T) {
	commitment, _, _ := firstLinkVector(t)
	trusted := newPairClient(t, strings.Repeat("p", 32))
	trusted.createIdentity(t)
	for i := 0; i < 20; i++ { // config.Defaults: pairing_per_hour 20
		createLinkRequest(t, trusted, commitment)
	}
	res := trusted.do(t, http.MethodPost, "/api/v1/me/link-requests", []byte(`{"commitment":`+quote(b64(commitment))+`}`), true, false)
	if code, body := status(t, res); code != http.StatusTooManyRequests || res.Header.Get("Retry-After") == "" {
		t.Fatal("21st link request in an hour", code, body)
	}
	other := trusted.addUser(t, "other")
	if code, _ := status(t, other.do(t, http.MethodPost, "/api/v1/me/link-requests", []byte(`{"commitment":`+quote(b64(commitment))+`}`), true, false)); code == http.StatusTooManyRequests {
		t.Fatal("another account shares the bucket")
	}
}
```

Append to `internal/storage/gc_test.go`:

```go
func TestGCDeletesExpiredLinkRequests(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	db := s.DB()
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	stamp := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	for _, q := range []string{
		`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES('usr_a','a','h','s',100000,'now','now')`,
		`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,created_at,expires_at,hard_expires_at) VALUES('ses_a','usr_a','t','c','now','` + stamp(time.Hour) + `','` + stamp(time.Hour) + `')`,
		`INSERT INTO link_requests(id,user_id,newcomer_session_id,commitment,created_at,expires_at) VALUES('lnk_old','usr_a','ses_a',zeroblob(32),'now','` + stamp(-time.Minute) + `'),('lnk_live','usr_a','ses_a',zeroblob(32),'now','` + stamp(time.Minute) + `')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := RunGC(db, nil, now, time.Hour, false); err != nil {
		t.Fatal(err)
	}
	var left string
	if err := db.QueryRow(`SELECT group_concat(id) FROM link_requests`).Scan(&left); err != nil || left != "lnk_live" {
		t.Fatalf("left=%q %v, want lnk_live", left, err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail.** Run `go test ./internal/httpapi -run 'TestLink' -count=1; go test ./internal/storage -run TestGCDeletesExpiredLinkRequests -count=1`. Expected: FAIL (404 from the router fallback; `no such table: link_requests`).

- [ ] **Step 3: Migration.** Append to `0024_device_linking.sql`:

```sql
-- Device linking relay (team keys P3c). Public keys, a commitment and one sealed bundle only:
-- nothing the server can open. commitment = SHA-256("kynotes/link-commit/v1" || newcomer_key),
-- posted before the approver's key exists (testdata/protocol/link_vectors.json).
CREATE TABLE link_requests (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 newcomer_session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
 commitment BLOB NOT NULL,
 newcomer_key BLOB,
 approver_session_id TEXT REFERENCES sessions(id) ON DELETE CASCADE,
 approver_key BLOB,
 bundle BLOB,
 created_at TEXT NOT NULL,
 expires_at TEXT NOT NULL
);
CREATE INDEX idx_link_requests_user ON link_requests(user_id, expires_at);
```

- [ ] **Step 4: Implement.** Create `internal/httpapi/link_routes.go`:

```go
package httpapi

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// Device linking relay (team keys P3c, spec §8). A row holds a commitment, two one-time public keys
// and one sealed bundle: nothing the server can open. It belongs to one user and two of that user's
// live sessions, the newcomer that created it and the trusted session that claimed it.
const (
	linkTTL         = 10 * time.Minute
	linkMaxPending  = 3
	linkBundleBytes = 61 // 0x01 | nonce(12) | ChaCha20-Poly1305(identity private key)(48)
	linkCommitLabel = "kynotes/link-commit/v1"
)

var (
	errLinkGone = errors.New("link request gone")
	errLinkBusy = errors.New("too many pending link requests")
)

// Session liveness of the row's other side, at ?1 (now).
const (
	liveNewcomer = ` AND EXISTS(SELECT 1 FROM sessions x WHERE x.id=link_requests.newcomer_session_id AND x.revoked_at='' AND x.expires_at>?1 AND x.hard_expires_at>?1)`
	liveApprover = ` AND EXISTS(SELECT 1 FROM sessions x WHERE x.id=link_requests.approver_session_id AND x.revoked_at='' AND x.expires_at>?1 AND x.hard_expires_at>?1)`
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// readField decodes {"<name>": "<base64>"} of exactly size bytes.
func readField(w http.ResponseWriter, r *http.Request, name string, size int) ([]byte, bool) {
	var in map[string]string
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&in) != nil {
		return nil, false
	}
	b, err := base64.StdEncoding.DecodeString(in[name])
	return b, err == nil && len(b) == size
}

func sessionLive(tx *sql.Tx, s auth.Session, now time.Time) error {
	_, err := auth.RecheckSessionTx(tx, s, now)
	return err
}

// linkHandler: no-store, CSRF on mutations, a well-formed path ID or a uniform 404.
func linkHandler(h func(w http.ResponseWriter, r *http.Request, s auth.Session, id string)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		id := r.PathValue("id")
		if id != "" && ids.Validate("lnk", id) != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		s, _ := auth.SessionFromContext(r)
		h(w, r, s, id)
	})
}

// linkTx runs one relay step after rechecking the caller. Every miss is the same 404, so a caller
// learns nothing about requests that are not its own.
func linkTx(w http.ResponseWriter, r *http.Request, db *sql.DB, s auth.Session, recheck func(*sql.Tx, auth.Session, time.Time) error, step func(tx *sql.Tx, now time.Time) error) bool {
	err := dbTx(db, func(tx *sql.Tx) error {
		now := time.Now().UTC()
		if err := recheck(tx, s, now); err != nil {
			return err
		}
		return step(tx, now)
	})
	switch {
	case err == nil:
		return true
	case errors.Is(err, auth.ErrSessionInvalid):
		auth.WriteAuthError(w, "unauthenticated", "authentication required")
	case errors.Is(err, auth.ErrStepUpInvalid):
		auth.WriteAuthError(w, "step_up_required", "re-enter your password to continue")
	case errors.Is(err, errLinkGone):
		WriteError(w, r, 404, "not_found", "not found")
	case errors.Is(err, errLinkBusy):
		WriteError(w, r, 409, "already_exists", "too many pending link requests; cancel one or wait ten minutes")
	default:
		WriteError(w, r, 500, "internal", "internal server error")
	}
	return false
}

func audit(tx *sql.Tx, r *http.Request, s auth.Session, event, id, outcome, reason string) error {
	return storage.RecordAuditOutcomeTx(tx, s.UserID, event, "", id, outcome, reason, RequestID(r))
}

func LinkRoutes(mux *http.ServeMux, db *sql.DB) {
	session := func(h http.Handler) http.Handler { return auth.RequireSession(db, h) }
	mux.Handle("POST /api/v1/me/link-requests", session(createLink(db)))
	mux.Handle("GET /api/v1/me/link-requests", session(listLinks(db)))
	mux.Handle("POST /api/v1/me/link-requests/{id}/claim", session(claimLink(db)))
	mux.Handle("POST /api/v1/me/link-requests/{id}/reveal", session(revealLink(db)))
	mux.Handle("DELETE /api/v1/me/link-requests/{id}", session(cancelLink(db)))
}

func createLink(db *sql.DB) http.Handler {
	return linkHandler(func(w http.ResponseWriter, r *http.Request, s auth.Session, _ string) {
		commitment, ok := readField(w, r, "commitment", 32)
		if !ok {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		id, err := ids.Mint("lnk")
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		var expires string
		if !linkTx(w, r, db, s, sessionLive, func(tx *sql.Tx, now time.Time) error {
			at := now.Format(time.RFC3339)
			expires = now.Add(linkTTL).Format(time.RFC3339)
			var identities int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM user_identities WHERE user_id=?`, s.UserID).Scan(&identities); err != nil {
				return err
			}
			if identities == 0 {
				return errLinkGone // nothing to link
			}
			// The same browser starting again replaces its earlier request.
			if _, err := tx.Exec(`DELETE FROM link_requests WHERE newcomer_session_id=?`, s.ID); err != nil {
				return err
			}
			var pending int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM link_requests WHERE user_id=? AND expires_at>?`, s.UserID, at).Scan(&pending); err != nil {
				return err
			}
			if pending >= linkMaxPending {
				return errLinkBusy
			}
			if _, err := tx.Exec(`INSERT INTO link_requests(id,user_id,newcomer_session_id,commitment,created_at,expires_at) VALUES(?,?,?,?,?,?)`, id, s.UserID, s.ID, commitment, at, expires); err != nil {
				return err
			}
			return audit(tx, r, s, "identity.link.request", id, "success", "")
		}) {
			return
		}
		writeJSON(w, map[string]string{"id": id, "expiresAt": expires})
	})
}

// listLinks shows the trusted side the account's live requests from other sessions that are
// unclaimed or claimed by the caller, with the newcomer key once revealed.
func listLinks(db *sql.DB) http.Handler {
	return linkHandler(func(w http.ResponseWriter, r *http.Request, s auth.Session, _ string) {
		rows, err := db.Query(`SELECT id,commitment,created_at,expires_at,approver_session_id IS NOT NULL,COALESCE(newcomer_key,X'') FROM link_requests
 WHERE user_id=?1 AND expires_at>?2 AND newcomer_session_id<>?3 AND bundle IS NULL AND (approver_session_id IS NULL OR approver_session_id=?3) ORDER BY created_at,id`, s.UserID, time.Now().UTC().Format(time.RFC3339), s.ID)
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var id, created, expires string
			var commitment, newcomer []byte
			var claimed bool
			if err := rows.Scan(&id, &commitment, &created, &expires, &claimed, &newcomer); err != nil {
				WriteError(w, r, 500, "internal", "internal server error")
				return
			}
			row := map[string]any{"id": id, "commitment": b64(commitment), "createdAt": created, "expiresAt": expires, "claimed": claimed, "newcomerKey": ""}
			if len(newcomer) > 0 {
				row["newcomerKey"] = b64(newcomer)
			}
			out = append(out, row)
		}
		if rows.Err() != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		writeJSON(w, out)
	})
}

func claimLink(db *sql.DB) http.Handler {
	return linkHandler(func(w http.ResponseWriter, r *http.Request, s auth.Session, id string) {
		key, ok := readField(w, r, "approverKey", 32)
		if !ok {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		if !linkTx(w, r, db, s, sessionLive, func(tx *sql.Tx, now time.Time) error {
			res, err := tx.Exec(`UPDATE link_requests SET approver_session_id=?4,approver_key=?5 WHERE id=?2 AND user_id=?3 AND expires_at>?1 AND newcomer_session_id<>?4 AND approver_session_id IS NULL`+liveNewcomer, now.Format(time.RFC3339), id, s.UserID, s.ID, key)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return errLinkGone
			}
			return audit(tx, r, s, "identity.link.claim", id, "success", "")
		}) {
			return
		}
		w.WriteHeader(204)
	})
}

// revealLink takes the newcomer's key after a claim, only if it is the key the request committed to.
func revealLink(db *sql.DB) http.Handler {
	return linkHandler(func(w http.ResponseWriter, r *http.Request, s auth.Session, id string) {
		key, ok := readField(w, r, "newcomerKey", 32)
		if !ok {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		refused := false
		if !linkTx(w, r, db, s, sessionLive, func(tx *sql.Tx, now time.Time) error {
			var commitment []byte
			err := tx.QueryRow(`SELECT commitment FROM link_requests WHERE id=?2 AND user_id=?3 AND newcomer_session_id=?4 AND expires_at>?1 AND approver_key IS NOT NULL AND newcomer_key IS NULL`+liveApprover, now.Format(time.RFC3339), id, s.UserID, s.ID).Scan(&commitment)
			if errors.Is(err, sql.ErrNoRows) {
				return errLinkGone
			}
			if err != nil {
				return err
			}
			want := sha256.Sum256(append([]byte(linkCommitLabel), key...))
			if !bytes.Equal(want[:], commitment) {
				// Not the committed key: this attempt is over.
				refused = true
				if _, err := tx.Exec(`DELETE FROM link_requests WHERE id=?`, id); err != nil {
					return err
				}
				return audit(tx, r, s, "identity.link.refuse", id, "denied", "commitment")
			}
			if _, err := tx.Exec(`UPDATE link_requests SET newcomer_key=? WHERE id=?`, key, id); err != nil {
				return err
			}
			return audit(tx, r, s, "identity.link.reveal", id, "success", "")
		}) {
			return
		}
		if refused {
			WriteError(w, r, 400, "invalid_request", "the key does not match this request")
			return
		}
		w.WriteHeader(204)
	})
}

// cancelLink: any session of the account may end a request ("Not me" on the trusted side).
func cancelLink(db *sql.DB) http.Handler {
	return linkHandler(func(w http.ResponseWriter, r *http.Request, s auth.Session, id string) {
		if !linkTx(w, r, db, s, sessionLive, func(tx *sql.Tx, now time.Time) error {
			res, err := tx.Exec(`DELETE FROM link_requests WHERE id=? AND user_id=?`, id, s.UserID)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return errLinkGone
			}
			return audit(tx, r, s, "identity.link.cancel", id, "success", "")
		}) {
			return
		}
		w.WriteHeader(204)
	})
}
```

The function name `audit` may collide with an existing package symbol. If it does, rename it to `linkAudit` everywhere in this file.

- `router.go`: after `IdentityRoutes(mux, db)`, add `LinkRoutes(mux, db)`. In `sso_logout_test.go` `restartRouter`, add `LinkRoutes(mux, f.db)` after the routes Task 2 added (Task 5's `TestSSOAccountLinksASecondBrowser` runs on that fixture).
- `ratelimit.go`: before the uploads case, add:

```go
		case r.Method == http.MethodPost && path == "/api/v1/me/link-requests":
			// Linking a browser is device pairing: the same per-account hourly budget.
			limit, rate, label = cfg.RateLimit.PairingPerHour, cfg.RateLimit.PairingPerHour, "link"
```

  and add `|| label == "link"` to the per-hour refill condition.

- `gc.go`: after the invitation-envelope delete, add:

```go
	// An expired link request can never complete.
	_, _ = db.Exec(`DELETE FROM link_requests WHERE expires_at<=?`, now.UTC().Format(time.RFC3339))
```

- `kynotes.example.yaml`: change the `pairing_per_hour: 20` line to `pairing_per_hour: 20 # device pairing tokens and browser link requests, per account`.

- [ ] **Step 5: Run the tests to verify they pass.** Run `go test ./internal/httpapi -run 'TestLink' -count=1 && go test ./internal/storage -count=1`. Expected: PASS.

- [ ] **Step 6: Frozen contracts.**
  - `IMPLEMENTATION_PLAN.md` §1.10 table: add the row `| device link request | \`lnk\` |`.
  - §1.8: add the row `| Device link relay (\`/me/link-requests…\`) | required | rejected | CSRF on mutations; approve: fresh step-up (\`RequireUserActionStepUp\`), rechecked in the transaction |`.
  - §5.1: add the create, list, claim, reveal and cancel rows with the shapes in Global Constraints.
  - §5.2: add a bullet, "Link requests: session-only, one user, TTL 10 minutes, at most 3 live per user (`409 already_exists`), a session's new request replaces its own; claim needs the newcomer session live and refuses the newcomer itself; reveal only by the newcomer, only after a claim, only the committed key (`SHA-256("kynotes/link-commit/v1" ‖ key)`; mismatch deletes the row, `400`); every miss is `404`; creation shares `ratelimit.pairing_per_hour`; GC deletes expired rows. Migration `0024_device_linking.sql`".
  - §5.3: add `TestLinkRelayHandsOverOnlyPublicKeys`, `TestLinkRequestRefusals`, `TestLinkCreationIsRateLimitedPerAccount`.
  - `DESIGN.md` §4, after the Encryption subsection, add a subsection:

```markdown
### Device linking

A browser that does not hold the account's identity asks a trusted browser of the same account
for it. The server relays only public keys and one sealed bundle (`/api/v1/me/link-requests`,
migration `0024_device_linking.sql`). The newcomer first posts a commitment to its one-time
X25519 key; the trusted browser claims the request with its own one-time key; the newcomer then
reveals its key, which must match the commitment. Both screens show a six-digit check code over the
account, the request and both keys, and the user confirms it on both. The commitment means a relay
cannot pick a key to fit the code after seeing the other one. Only then is the identity private key
sealed to the newcomer (`kynotes/link/v1`, `testdata/protocol/link_vectors.json`), after a fresh
step-up, and collected once. Requests are per user, single use, expire after ten minutes, need a
live session of that user on both sides, are rate-limited with device pairing and are audited.
```

- [ ] **Step 7: Commit.**

```bash
git add internal/storage internal/httpapi kynotes.example.yaml DESIGN.md IMPLEMENTATION_PLAN.md
git commit -m "server: device link relay with a committed newcomer key"
```

### Task 5: Server: link relay: approve and collect once; identity deletion clears requests

**Files:** Modify `internal/httpapi/link_routes.go`, `internal/httpapi/identity_routes.go`, `internal/httpapi/teamkeys_p3c_test.go`, `IMPLEMENTATION_PLAN.md`.

**Interfaces:**
- Consumes: Task 4 `linkHandler`, `linkTx`, `sessionLive`, `audit`, `b64`, `openLink`, `linkPath`, `firstLinkVector` and `secondSession`. Task 2 `ssoPerson`, `ssoDo` and `deviceOnlyBody`. Task 1 `auth.RequireUserActionStepUp` and `auth.RecheckUserActionTx`.
- Produces: `POST …/{id}/approve` and `GET …/{id}`.

- [ ] **Step 1: Write the failing tests.** Append to `teamkeys_p3c_test.go`:

```go
func TestLinkApprovalNeedsStepUpAndIsCollectedOnce(t *testing.T) {
	trusted, newcomer, id := openLink(t)
	bundle := b64(bytes.Repeat([]byte{6}, linkBundleBytes))
	approve := func(p *pairClient, value string, csrf bool) (int, string) {
		return status(t, p.do(t, http.MethodPost, linkPath(id, "/approve"), []byte(`{"bundle":`+quote(value)+`}`), csrf, false))
	}
	if code, body := status(t, newcomer.do(t, http.MethodGet, linkPath(id, ""), nil, false, false)); code != 200 || !strings.Contains(body, `"state":"revealed"`) || strings.Contains(body, `"bundle"`) {
		t.Fatal("before approval", code, body)
	}
	if _, err := trusted.db.Exec(`UPDATE sessions SET stepup_at=''`); err != nil {
		t.Fatal(err)
	}
	if code, body := approve(trusted, bundle, true); code != 403 || !strings.Contains(body, "step_up_required") {
		t.Fatal("approved without a step-up", code, body)
	}
	trusted.stepUp(t)
	newcomer.stepUp(t)
	if code, _ := approve(newcomer, bundle, true); code != 404 {
		t.Fatal("approved by a session that did not claim", code)
	}
	if code, _ := approve(trusted, b64(bytes.Repeat([]byte{6}, linkBundleBytes-1)), true); code != 400 {
		t.Fatal("short bundle", code)
	}
	if code, _ := approve(trusted, bundle, false); code != 403 {
		t.Fatal("approved without CSRF", code)
	}
	if code, body := approve(trusted, bundle, true); code != 204 {
		t.Fatal("approve", code, body)
	}
	if code, _ := approve(trusted, bundle, true); code != 404 {
		t.Fatal("approved twice", code)
	}
	if code, _ := status(t, trusted.do(t, http.MethodGet, linkPath(id, ""), nil, false, false)); code != 404 {
		t.Fatal("the approver collected", code)
	}
	if code, body := status(t, newcomer.do(t, http.MethodGet, linkPath(id, ""), nil, false, false)); code != 200 || !strings.Contains(body, `"state":"approved"`) || !strings.Contains(body, bundle) {
		t.Fatal("collect", code, body)
	}
	if code, _ := status(t, newcomer.do(t, http.MethodGet, linkPath(id, ""), nil, false, false)); code != 404 {
		t.Fatal("collected twice", code)
	}
	var rows int
	if err := trusted.db.QueryRow(`SELECT COUNT(*) FROM link_requests`).Scan(&rows); err != nil || rows != 0 || audited(t, trusted, "identity.link.approve") != 1 || audited(t, trusted, "identity.link.collect") != 1 {
		t.Fatal("rows or audit", rows, err)
	}
}

func TestLinkApprovalNeedsTheNewcomerLive(t *testing.T) {
	trusted, _, id := openLink(t)
	trusted.stepUp(t)
	if _, err := trusted.db.Exec(`UPDATE sessions SET revoked_at='x' WHERE id=(SELECT newcomer_session_id FROM link_requests WHERE id=?)`, id); err != nil {
		t.Fatal(err)
	}
	if code, _ := status(t, trusted.do(t, http.MethodPost, linkPath(id, "/approve"), []byte(`{"bundle":`+quote(b64(bytes.Repeat([]byte{6}, linkBundleBytes)))+`}`), true, false)); code != 404 {
		t.Fatal("sealed for a revoked newcomer session", code)
	}
}

func TestLinkRequestsDieWithTheIdentity(t *testing.T) {
	trusted, _, id := openLink(t)
	if err := dbTx(trusted.db, func(tx *sql.Tx) error { return deleteIdentityTx(tx, pairUser, pairUser, "") }); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := trusted.db.QueryRow(`SELECT COUNT(*) FROM link_requests WHERE id=?`, id).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("a link request outlived the identity it would carry", rows, err)
	}
}

func TestSSOAccountLinksASecondBrowser(t *testing.T) {
	f := newLogoutFixture(t)
	first, _ := ssoPerson(f, "bob", "bob-1")
	second, _ := ssoPerson(f, "bob", "bob-2")
	if r := ssoDo(f, first, "bob", "PUT", "/api/v1/me/identity", deviceOnlyBody(identityPub)); r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	commitment, newcomerKey, approverKey := firstLinkVector(t)
	send := func(cookies []*http.Cookie, method, path, body string) *httptest.ResponseRecorder {
		req := withCookies(httptest.NewRequest(method, path, strings.NewReader(body)), cookies)
		req.Header.Set("Content-Type", "application/json")
		return f.send(req)
	}
	created := send(second, "POST", "/api/v1/me/link-requests", `{"commitment":`+quote(b64(commitment))+`}`)
	var out struct{ ID string }
	if created.Code != 200 || json.Unmarshal(created.Body.Bytes(), &out) != nil {
		t.Fatal(created.Code, created.Body.String())
	}
	if r := send(first, "POST", linkPath(out.ID, "/claim"), `{"approverKey":`+quote(b64(approverKey))+`}`); r.Code != 204 {
		t.Fatal(r.Code, r.Body.String())
	}
	if r := send(second, "POST", linkPath(out.ID, "/reveal"), `{"newcomerKey":`+quote(b64(newcomerKey))+`}`); r.Code != 204 {
		t.Fatal(r.Code, r.Body.String())
	}
	body := `{"bundle":` + quote(b64(bytes.Repeat([]byte{6}, linkBundleBytes))) + `}`
	if r := send(first, "POST", linkPath(out.ID, "/approve"), body); r.Code != 403 || !strings.Contains(r.Body.String(), "sso_step_up_required") {
		t.Fatal("SSO approval without a KySignOn confirmation", r.Code, r.Body.String())
	}
	if r := ssoDo(f, first, "bob", "POST", linkPath(out.ID, "/approve"), body); r.Code != 204 {
		t.Fatal(r.Code, r.Body.String())
	}
	if r := send(second, "GET", linkPath(out.ID, ""), ""); r.Code != 200 || !strings.Contains(r.Body.String(), `"state":"approved"`) {
		t.Fatal(r.Code, r.Body.String())
	}
}
```

  Add `database/sql` to the test imports.

- [ ] **Step 2: Run the tests to verify they fail.** Run `go test ./internal/httpapi -run 'TestLinkApproval|TestLinkRequestsDieWithTheIdentity|TestSSOAccountLinksASecondBrowser' -count=1`. Expected: FAIL (`/approve` and `GET …/{id}` are not registered; the request survives the identity).

- [ ] **Step 3: Implement.** In `LinkRoutes` add:

```go
	mux.Handle("POST /api/v1/me/link-requests/{id}/approve", auth.RequireUserActionStepUp(db, approveLink(db)))
	mux.Handle("GET /api/v1/me/link-requests/{id}", session(collectLink(db)))
```

and add the handlers:

```go
// approveLink stores the bundle once, from the session that claimed the request, after a fresh
// step-up, while the newcomer session is still live.
func approveLink(db *sql.DB) http.Handler {
	return linkHandler(func(w http.ResponseWriter, r *http.Request, s auth.Session, id string) {
		bundle, ok := readField(w, r, "bundle", linkBundleBytes)
		if !ok {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		if !linkTx(w, r, db, s, auth.RecheckUserActionTx, func(tx *sql.Tx, now time.Time) error {
			res, err := tx.Exec(`UPDATE link_requests SET bundle=?5 WHERE id=?2 AND user_id=?3 AND approver_session_id=?4 AND expires_at>?1 AND newcomer_key IS NOT NULL AND bundle IS NULL`+liveNewcomer, now.Format(time.RFC3339), id, s.UserID, s.ID, bundle)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return errLinkGone
			}
			return audit(tx, r, s, "identity.link.approve", id, "success", "")
		}) {
			return
		}
		w.WriteHeader(204)
	})
}

// collectLink: the newcomer's view of its request. The bundle is delivered once: the row goes in
// the same transaction.
func collectLink(db *sql.DB) http.Handler {
	return linkHandler(func(w http.ResponseWriter, r *http.Request, s auth.Session, id string) {
		var out map[string]string
		if !linkTx(w, r, db, s, sessionLive, func(tx *sql.Tx, now time.Time) error {
			var approver, newcomer, bundle []byte
			var expires string
			err := tx.QueryRow(`SELECT COALESCE(approver_key,X''),COALESCE(newcomer_key,X''),COALESCE(bundle,X''),expires_at FROM link_requests WHERE id=?2 AND user_id=?3 AND newcomer_session_id=?4 AND expires_at>?1`, now.Format(time.RFC3339), id, s.UserID, s.ID).Scan(&approver, &newcomer, &bundle, &expires)
			if errors.Is(err, sql.ErrNoRows) {
				return errLinkGone
			}
			if err != nil {
				return err
			}
			out = map[string]string{"state": "pending", "expiresAt": expires}
			if len(approver) > 0 {
				out["state"], out["approverKey"] = "claimed", b64(approver)
			}
			if len(newcomer) > 0 {
				out["state"] = "revealed"
			}
			if len(bundle) == 0 {
				return nil
			}
			out["state"], out["bundle"] = "approved", b64(bundle)
			if _, err := tx.Exec(`DELETE FROM link_requests WHERE id=?`, id); err != nil {
				return err
			}
			return audit(tx, r, s, "identity.link.collect", id, "success", "")
		}) {
			return
		}
		writeJSON(w, out)
	})
}
```

In `identity_routes.go`, make the first statement of `deleteIdentityTx`:

```go
	// Open link requests would hand out the identity being deleted.
	if _, err := tx.Exec(`DELETE FROM link_requests WHERE user_id=?`, userID); err != nil {
		return err
	}
```

- [ ] **Step 4: Run the tests to verify they pass.** Run `go test ./internal/httpapi -count=1`. Expected: PASS.

- [ ] **Step 5: Frozen contracts.** In `IMPLEMENTATION_PLAN.md`:
  - §5.1: add the approve and collect rows.
  - §5.2: extend the link bullet: "approve only by the claiming session, after a fresh user-action step-up, while the newcomer session is live, once, with exactly 61 bundle bytes; collect only by the newcomer, which deletes the row in the same transaction; deleting the identity (recovery, admin reset) deletes the user's link requests".
  - §5.3: add `TestLinkApprovalNeedsStepUpAndIsCollectedOnce`, `TestLinkApprovalNeedsTheNewcomerLive`, `TestLinkRequestsDieWithTheIdentity`, `TestSSOAccountLinksASecondBrowser`.

- [ ] **Step 6: Commit.**

```bash
git add internal/httpapi IMPLEMENTATION_PLAN.md
git commit -m "server: approve a link after a fresh step-up; the bundle is collected once"
```

### Task 6: Web: the identity sealed under a non-extractable device key

**Files:** Modify `web/src/storage.ts`, `web/src/storage.test.ts`.

**Interfaces:**
- Consumes: `HeldIdentity` (`identity.ts`), `generateIdentity` and `sameBytes` (`teamKeys.ts`).
- Produces: `identityProtection`, `storeIdentityKey(): Promise<boolean>`, `loadIdentityRecord`, `getIdentityKey` (finished identities only) and `vaultReady`.

- [ ] **Step 1: Write the failing tests.** In `web/src/storage.test.ts`:
  - Merge `identityProtection`, `loadIdentityRecord` and `vaultReady` into the existing `./storage` import (line 4). A second import of names it already imports (`clearAllDeviceKeys`, `getIdentityKey`, …) is a duplicate-binding error.
  - Add `afterEach` to the vitest import and `import { generateIdentity } from "./teamKeys";`.
  - Replace the file's `held` fixture (`publicKey` filled with 1s, `privateKey` with 2s) with a real key pair: `const held = { deviceId: "dev_00000000000000000000000000", ...generateIdentity() };`. The new public-key check would otherwise turn four existing `getIdentityKey(...)).toEqual(held)` assertions into `undefined`.
  - Append:

```ts

const vaultRow = (username: string) => new Promise<Record<string, any> | undefined>((resolve, reject) => {
  const open = indexedDB.open("kynotes-web");
  open.onerror = () => reject(open.error);
  open.onsuccess = () => {
    const request = open.result.transaction("keys").objectStore("keys").get(username);
    request.onsuccess = () => { open.result.close(); resolve(request.result); };
    request.onerror = () => reject(request.error);
  };
});
const putVaultRow = (row: Record<string, unknown>) => new Promise<void>((resolve, reject) => {
  const open = indexedDB.open("kynotes-web");
  open.onerror = () => reject(open.error);
  open.onsuccess = () => {
    const tx = open.result.transaction("keys", "readwrite");
    tx.objectStore("keys").put(row);
    tx.oncomplete = () => { open.result.close(); resolve(); };
    tx.onerror = () => reject(tx.error);
  };
});
const contains = (haystack: Uint8Array, needle: Uint8Array) => haystack.some((_, i) => needle.every((byte, j) => haystack[i + j] === byte));

describe("the identity at rest", () => {
  const me = `usr_${"b".repeat(26)}`;
  const held = () => ({ ...generateIdentity(), deviceId: `dev_${"c".repeat(26)}` });
  beforeEach(async () => { vi.stubGlobal("isSecureContext", true); await clearAllDeviceKeys(); await storeDeviceKey("me", "a".repeat(64)); });
  // Not unstubAllGlobals: that would also drop the file-level localStorage stub.
  afterEach(() => { vi.stubGlobal("isSecureContext", undefined); });

  it("keeps the private key sealed under a non-extractable device key, never raw", async () => {
    const identity = held();
    expect(identityProtection()).toBe("device-key");
    expect(await storeIdentityKey("me", me, identity)).toBe(true);
    const stored = (await vaultRow("me"))!.identity;
    expect(stored.privateKey).toBeUndefined();
    expect(stored.deviceKey.extractable).toBe(false);
    expect(contains(stored.sealed, identity.privateKey)).toBe(false);
    expect(await getIdentityKey("me", me)).toEqual(identity);
  });

  it("seals a raw copy an earlier version wrote, on first read", async () => {
    const identity = held();
    const row = (await vaultRow("me"))!;
    await putVaultRow({ ...row, identity: { ...identity, userID: me } });
    expect(await getIdentityKey("me", me)).toEqual(identity);
    const stored = (await vaultRow("me"))!.identity;
    expect(stored.privateKey).toBeUndefined();
    expect(stored.deviceKey.extractable).toBe(false);
  });

  it("keeps the raw key on a plain-HTTP origin, where there is no WebCrypto, and says so", async () => {
    vi.stubGlobal("isSecureContext", false);
    const identity = held();
    expect(identityProtection()).toBe("unprotected");
    expect(await storeIdentityKey("me", me, identity)).toBe(true);
    expect((await vaultRow("me"))!.identity.privateKey).toEqual(identity.privateKey);
    expect(await getIdentityKey("me", me)).toEqual(identity);
  });

  it("returns nothing for a sealed copy its device key cannot open, or one that is not its public key's", async () => {
    const identity = held();
    await storeIdentityKey("me", me, identity);
    const row = (await vaultRow("me"))!;
    const otherKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    await putVaultRow({ ...row, identity: { ...row.identity, deviceKey: otherKey } });
    expect(await getIdentityKey("me", me)).toBeUndefined();
    await storeIdentityKey("me", me, { ...identity, publicKey: generateIdentity().publicKey });
    expect(await getIdentityKey("me", me)).toBeUndefined();
  });

  it("writes with an expected identity only while the vault still holds it", async () => {
    const first = held(), second = held();
    expect(await storeIdentityKey("me", me, first, null)).toBe(true);
    expect(await storeIdentityKey("me", me, second, null)).toBe(false);
    expect(await storeIdentityKey("me", me, second, held())).toBe(false);
    expect(await getIdentityKey("me", me)).toEqual(first);
    expect(await storeIdentityKey("me", me, second, first)).toBe(true);
    expect(await getIdentityKey("me", me)).toEqual(second);
  });

  it("hides a pending identity (no device ID yet) from use, but returns it for reconciliation", async () => {
    const pending = { ...held(), deviceId: "" };
    await storeIdentityKey("me", me, pending);
    expect(await getIdentityKey("me", me)).toBeUndefined();
    expect(await loadIdentityRecord("me", me)).toEqual(pending);
  });

  it("forget this device deletes the sealed identity and its device key together", async () => {
    await storeIdentityKey("me", me, held());
    await clearDeviceKey("me");
    expect(await vaultRow("me")).toBeUndefined();
    expect(await getIdentityKey("me", me)).toBeUndefined();
  });

  it("keeps nothing, and says so, without a vault record", async () => {
    await clearAllDeviceKeys();
    expect(await vaultReady("me")).toBe(false);
    expect(await storeIdentityKey("me", me, held())).toBe(false);
    await storeDeviceKey("me", "a".repeat(64));
    expect(await vaultReady("me")).toBe(true);
  });
});
```

- [ ] **Step 2: Run them to verify they fail.** Run `npm test --prefix web -- storage`. Expected: FAIL (`identityProtection` is not exported; the raw `privateKey` is stored). Run `npm ci --prefix web` first if `web/node_modules` is missing; the pre-flight showed fake-indexeddb 6.2.5 holds a `CryptoKey`, so a `DataCloneError` would mean a different version is installed.

- [ ] **Step 3: Implement.** In `storage.ts`, add `import { x25519 } from "@noble/curves/ed25519.js";` and `import { sameBytes } from "./teamKeys";`. Replace the `VaultRecord` identity field and the identity functions:

```ts
/**
 * The identity as the vault keeps it. Secure contexts: the private key sealed (AES-256-GCM, AAD
 * kynotes/device-identity/v1|<userID>|<deviceId>) under deviceKey, a non-extractable WebCrypto key
 * kept in the same record, so the raw key never rests in IndexedDB and "Forget this device" stays
 * one delete. Plain-HTTP origins have no WebCrypto and keep the raw key, as before. deviceId ""
 * marks an identity created here that the server has not confirmed yet (settleSSOIdentity).
 */
type SealedIdentity = { userID: string; deviceId: string; publicKey: Uint8Array; sealed: Uint8Array; deviceKey: CryptoKey };
type RawIdentity = { userID: string; deviceId: string; publicKey: Uint8Array; privateKey: Uint8Array };
type VaultIdentity = SealedIdentity | RawIdentity;
type VaultRecord = { username: string; authSecret: string; updatedAt: string; identity?: VaultIdentity; pins?: { userID: string; keys: Pins }; keyStates?: { userID: string; byContainer: Record<string, KeyState> } };

/** "device-key": sealed under a key this browser cannot export. "unprotected": a plain-HTTP origin keeps the raw key. */
export const identityProtection = (): "device-key" | "unprotected" =>
  globalThis.isSecureContext === true && typeof globalThis.crypto?.subtle?.generateKey === "function" ? "device-key" : "unprotected";

const identityAAD = (userID: string, deviceId: string) => new TextEncoder().encode(`kynotes/device-identity/v1|${userID}|${deviceId}`);

async function sealForDevice(userID: string, identity: HeldIdentity): Promise<VaultIdentity> {
  const base = { userID, deviceId: identity.deviceId, publicKey: identity.publicKey.slice() };
  if (identityProtection() === "unprotected") return { ...base, privateKey: identity.privateKey.slice() };
  const deviceKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const body = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: identityAAD(userID, identity.deviceId) }, deviceKey, identity.privateKey.slice()));
  const sealed = new Uint8Array(12 + body.length);
  sealed.set(iv);
  sealed.set(body, 12);
  return { ...base, sealed, deviceKey };
}

/** The held identity, or undefined when the copy does not open or is not its public key's. */
async function openForDevice(stored: VaultIdentity): Promise<HeldIdentity | undefined> {
  try {
    const privateKey = "privateKey" in stored ? stored.privateKey
      : new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: stored.sealed.slice(0, 12), additionalData: identityAAD(stored.userID, stored.deviceId) }, stored.deviceKey, stored.sealed.slice(12)));
    return sameBytes(x25519.getPublicKey(privateKey), stored.publicKey) ? { deviceId: stored.deviceId, publicKey: stored.publicKey, privateKey } : undefined;
  } catch {
    return undefined;
  }
}

/** True when the record holds expected for userID (null: holds none), compared by public key. */
const holds = (record: VaultRecord, userID: string, expected: HeldIdentity | null) => {
  const current = record.identity?.userID === userID ? record.identity : undefined;
  return expected === null ? !current : current !== undefined && sameBytes(current.publicKey, expected.publicKey);
};

/**
 * Keeps the identity in the existing vault record. expected makes it a compare-and-swap inside one
 * IndexedDB transaction (sealing happens before it, because WebCrypto awaits would end the
 * transaction): another tab's key is never overwritten. False: nothing was kept (no record, no
 * IndexedDB, or the record no longer holds expected).
 */
export async function storeIdentityKey(username: string, userID: string, identity: HeldIdentity, expected?: HeldIdentity | null): Promise<boolean> {
  const stored = await sealForDevice(userID, identity).catch(() => undefined);
  return stored ? updateRecord(username, (record) => (expected === undefined || holds(record, userID, expected) ? { ...record, identity: stored } : undefined)) : false;
}

/** This browser's identity for userID, a pending one (deviceId "") included. Throws when the vault cannot be read. */
export async function loadIdentityRecord(username: string, userID: string): Promise<HeldIdentity | undefined> {
  const stored = (await readRecord(username))?.identity;
  if (!stored || stored.userID !== userID) return undefined;
  const held = await openForDevice(stored);
  if (held && "privateKey" in stored && identityProtection() === "device-key") {
    // Written raw by an earlier version: sealed now, only while the record still holds that copy.
    const upgraded = await sealForDevice(userID, held).catch(() => undefined);
    if (upgraded) await updateRecord(username, (record) => (record.identity && "privateKey" in record.identity && sameBytes(record.identity.privateKey, stored.privateKey) ? { ...record, identity: upgraded } : undefined));
  }
  return held;
}

/** The identity this browser may use: a finished one only. */
export async function getIdentityKey(username: string, userID: string): Promise<HeldIdentity | undefined> {
  const held = await loadIdentityRecord(username, userID);
  return held?.deviceId ? held : undefined;
}

/** True when this browser can keep an identity: IndexedDB opens and the signed-in account has a vault record. */
export async function vaultReady(username: string): Promise<boolean> {
  try { return Boolean(await readRecord(username)); } catch { return false; }
}
```

  Delete the old `storeIdentityKey`, `getIdentityKey` and `VaultRecord` definitions. Move `readRecord` and `updateRecord` above these functions if TypeScript complains about use before definition (function declarations are hoisted, so it should not). In `rememberAfter`, `await storeIdentityKey(...)` stays; its boolean is ignored there.

- [ ] **Step 4: Run the tests to verify they pass.** Run `npm test --prefix web`. Expected: PASS. Only `storage.test.ts` stores identities through `storage.ts`; its other tests run without the `isSecureContext` stub (Node has no such global), so they take the raw path, and pass because Step 1 made `held` a real key pair.

- [ ] **Step 5: Commit.**

```bash
git add web/src/storage.ts web/src/storage.test.ts
git commit -m "web: keep the identity sealed under a non-extractable device key"
```

### Task 7: Web: identities for SSO sessions and device-only identities

**Files:** Modify `web/src/identity.ts`, `web/src/identity.test.ts`, `web/src/api.ts`, `web/src/api.test.ts`.

**Interfaces:**
- Consumes: `generateIdentity` and `sameBytes` (`teamKeys.ts`); `base64` and `fromBase64` (`crypto.ts`).
- Produces: `DEVICE_ONLY_WRAP`, `PublicIdentity.wrapAlg`, `DeviceOnlyAPI`, `IdentityStore`, `Settled`, `settleSSOIdentity`, `IdentityStatus`, `identityStatus`, `currentCopy`, plus the `api.ts` link functions and types (see Interfaces).

- [ ] **Step 1: Write the failing tests.** Append to `web/src/identity.test.ts`. It already has `userID` and `keys`, where `keys(fill)` is a **function** returning `LoginKeys`: pass `keys(1)`, never `keys`. Merge the new `./identity` names into its existing `./identity` import (a second import of `ensureIdentity`, `rewrapIdentity` or `IdentityAPI` is a duplicate binding), and keep its `base64` import from `./crypto`.

```ts
// Merged into the existing imports (base64 and ensureIdentity/rewrapIdentity are already imported):
//   ./identity: currentCopy, DEVICE_ONLY_WRAP, identityStatus, settleSSOIdentity, type HeldIdentity, type IdentityStore
import { generateIdentity } from "./teamKeys";

const dev = `dev_${"d".repeat(26)}`;
const heldOf = (deviceId = dev): HeldIdentity => ({ ...generateIdentity(), deviceId });
const publicOf = (held: HeldIdentity, deviceId = held.deviceId) => ({ deviceId, publicKey: base64(held.publicKey), fingerprint: "" });
/** A vault in memory that records the order of saves; expected makes a save a compare-and-swap, like storage.ts. */
function vault(initial?: HeldIdentity, keeps = true) {
  let stored = initial;
  const saves: HeldIdentity[] = [];
  const store: IdentityStore = {
    load: async () => stored,
    save: async (identity, expected) => {
      saves.push(identity);
      if (expected !== undefined && (expected === null ? stored !== undefined : !stored || base64(stored.publicKey) !== base64(expected.publicKey))) return false;
      if (keeps) stored = identity;
      return keeps;
    },
  };
  return { store, saves, get: () => stored };
}

describe("device-only identities", () => {
  it("are never unlocked or re-wrapped by a password", async () => {
    const api = { myIdentity: vi.fn(async () => ({ deviceId: dev, publicKey: base64(generateIdentity().publicKey), fingerprint: "", wrapAlg: DEVICE_ONLY_WRAP })), putMyIdentity: vi.fn(), stepUp: vi.fn() };
    const record = { deviceId: dev, publicKey: "", fingerprint: "", wrapAlg: DEVICE_ONLY_WRAP, wrappedPrivateKey: "" };
    expect(await ensureIdentity(api, userID, keys(1), record)).toBeUndefined();
    expect(api.putMyIdentity).not.toHaveBeenCalled();
    expect(await rewrapIdentity(api, userID, keys(1), new Uint8Array(32), undefined)).toBeUndefined();
    expect(api.stepUp).not.toHaveBeenCalled();
  });
});

describe("settleSSOIdentity", () => {
  it("keeps the new key on this browser before the server learns it", async () => {
    const v = vault();
    const order: string[] = [];
    const api = { myIdentity: async () => undefined, putDeviceOnlyIdentity: vi.fn(async (publicKey: string) => { order.push(`put ${publicKey}`); return { deviceId: dev }; }) };
    const saving = v.store.save;
    v.store.save = async (identity) => { order.push(`save ${identity.deviceId || "pending"}`); return saving(identity); };
    const settled = await settleSSOIdentity(api, v.store);
    expect(settled.kind).toBe("held");
    expect(order).toEqual(["save pending", `put ${base64(v.saves[0].publicKey)}`, `save ${dev}`]);
    expect(v.get()!.deviceId).toBe(dev);
  });

  it("creates nothing when this browser cannot keep it, or cannot read its vault", async () => {
    const api = { myIdentity: async () => undefined, putDeviceOnlyIdentity: vi.fn(async () => ({ deviceId: dev })) };
    expect((await settleSSOIdentity(api, vault(undefined, false).store)).kind).toBe("unsaved");
    await expect(settleSSOIdentity(api, { load: async () => { throw new Error("blocked"); }, save: async () => true })).rejects.toThrow("blocked");
    expect(api.putDeviceOnlyIdentity).not.toHaveBeenCalled();
  });

  it("finishes an identity an interrupted run created", async () => {
    const pending = heldOf("");
    const v = vault(pending);
    const api = { myIdentity: async () => publicOf(pending, dev), putDeviceOnlyIdentity: vi.fn() };
    expect(await settleSSOIdentity(api, v.store)).toEqual({ kind: "held", identity: { ...pending, deviceId: dev } });
    expect(api.putDeviceOnlyIdentity).not.toHaveBeenCalled();
  });

  it("links rather than creates when another browser holds the account's identity", async () => {
    const api = { myIdentity: async () => publicOf(heldOf()), putDeviceOnlyIdentity: vi.fn() };
    expect((await settleSSOIdentity(api, vault().store)).kind).toBe("link");
    expect(api.putDeviceOnlyIdentity).not.toHaveBeenCalled();
  });

  it("never replaces an identity this browser holds unless asked", async () => {
    const mine = heldOf();
    const v = vault(mine);
    const api = { myIdentity: async () => undefined, putDeviceOnlyIdentity: vi.fn(async () => ({ deviceId: `dev_${"e".repeat(26)}` })) };
    expect((await settleSSOIdentity(api, v.store)).kind).toBe("orphaned");
    expect(api.putDeviceOnlyIdentity).not.toHaveBeenCalled();
    const replaced = await settleSSOIdentity(api, v.store, true);
    expect(replaced.kind).toBe("held");
    expect(base64(v.get()!.publicKey)).not.toBe(base64(mine.publicKey));
  });

  it("never overwrites a key another tab kept after this run read the vault", async () => {
    const theirs = heldOf();
    const v = vault();
    let loads = 0;
    // This run reads an empty vault; the other tab then finishes its identity before this run writes.
    const store: IdentityStore = { load: async () => (loads++ === 0 ? undefined : v.get()), save: v.store.save };
    await v.store.save(theirs);
    const api = { myIdentity: vi.fn(async () => (loads > 1 ? publicOf(theirs) : undefined)), putDeviceOnlyIdentity: vi.fn() };
    expect(await settleSSOIdentity(api, store)).toEqual({ kind: "held", identity: theirs });
    expect(v.get()).toBe(theirs);
    expect(api.putDeviceOnlyIdentity).not.toHaveBeenCalled();
  });

  it("adopts the identity another tab created meanwhile", async () => {
    const v = vault();
    let live: ReturnType<typeof publicOf> | undefined;
    const api = {
      myIdentity: async () => live,
      putDeviceOnlyIdentity: vi.fn(async () => { live = publicOf(v.get()!, dev); throw Object.assign(new Error("exists"), { code: "identity_exists" }); }),
    };
    expect((await settleSSOIdentity(api, v.store)).kind).toBe("held");
  });
});

describe("which identity this browser may use", () => {
  it("is the vault copy only while the server lists it, or cannot be asked", () => {
    const mine = heldOf();
    expect(identityStatus(mine, publicOf(mine))).toBe("held");
    expect(identityStatus(undefined, publicOf(mine))).toBe("link");
    expect(identityStatus(heldOf(), publicOf(mine))).toBe("link");
    expect(identityStatus(undefined, undefined)).toBe("create");
    expect(identityStatus(heldOf(""), undefined)).toBe("create");
    expect(identityStatus(mine, undefined)).toBe("orphaned");
    expect(currentCopy(mine, publicOf(mine))).toBe(mine);
    expect(currentCopy(mine, "unreachable")).toBe(mine);
    expect(currentCopy(mine, publicOf(heldOf()))).toBeUndefined();
    expect(currentCopy(mine, undefined)).toBeUndefined();
    expect(currentCopy(heldOf(""), "unreachable")).toBeUndefined();
  });
});
```

  In `api.test.ts`, add a case to the existing request-shape tests, using the file's `fetch` stub:

```ts
  it("sends device-only identities and link calls in the documented shapes", async () => {
    await putDeviceOnlyIdentity("cHVi");
    await createLinkRequest("Y29t");
    await claimLinkRequest(`lnk_${"a".repeat(26)}`, "YXBw");
    await revealLinkRequest(`lnk_${"a".repeat(26)}`, "bmV3");
    const bodies = fetches.mock.calls.map(([url, init]) => `${init?.method} ${url} ${init?.body}`);
    expect(bodies).toEqual([
      `PUT /api/v1/me/identity {"publicKey":"cHVi","wrapAlg":"none"}`,
      `POST /api/v1/me/link-requests {"commitment":"Y29t"}`,
      `POST /api/v1/me/link-requests/lnk_${"a".repeat(26)}/claim {"approverKey":"YXBw"}`,
      `POST /api/v1/me/link-requests/lnk_${"a".repeat(26)}/reveal {"newcomerKey":"bmV3"}`,
    ]);
  });
```

  `api.test.ts` has no shared `fetches` stub. Put this case in its own `describe` with `afterEach(() => { vi.unstubAllGlobals(); })`, and open the `it` with the same stubs `acceptInvitation`'s test uses (`csrfToken()` reads `document.cookie`):

```ts
    vi.stubGlobal("document", { cookie: "" });
    const fetches = vi.fn(async (_path: string, _init?: RequestInit) => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetches);
```

  Extend the file's `./api` import with the four functions.

- [ ] **Step 2: Run them to verify they fail.** Run `npm test --prefix web -- identity api`. Expected: FAIL (missing exports).

- [ ] **Step 3: Implement.** In `identity.ts`:

```ts
/** wrapAlg of an identity created from a single sign-on session: no server copy (P5 adds a recovery code). */
export const DEVICE_ONLY_WRAP = "none";
export type PublicIdentity = { deviceId: string; publicKey: string; fingerprint: string; wrapAlg?: string };
```

  Add `const unlock = (record: IdentityRecord, keys: LoginKeys, userID: string) => (record.wrapAlg === DEVICE_ONLY_WRAP ? undefined : openIdentity(record, keys.userKEK, userID));`. In `ensureIdentity`, replace the three `openIdentity(…, keys.userKEK, userID)` calls with `unlock(…, keys, userID)`, and append to its doc comment: "Undefined for a device-only identity: this browser must be linked." In `rewrapIdentity`, after `if (!live) return undefined;` add `if (live.wrapAlg === DEVICE_ONLY_WRAP) return undefined; // nothing on the server is wrapped under the password`. Append:

```ts
export type DeviceOnlyAPI = Pick<IdentityAPI, "myIdentity"> & { putDeviceOnlyIdentity: (publicKey: string) => Promise<{ deviceId: string }> };
/**
 * This browser's vault copy: load includes a pending one (deviceId "") and throws when unreadable.
 * save is false when nothing was kept; with expected it writes only while the vault still holds
 * that identity (null: none), so two tabs never overwrite each other's key.
 */
export type IdentityStore = { load: () => Promise<HeldIdentity | undefined>; save: (identity: HeldIdentity, expected?: HeldIdentity | null) => Promise<boolean> };
export type Settled = { kind: "held"; identity: HeldIdentity } | { kind: "link" } | { kind: "orphaned" } | { kind: "unsaved" };

/**
 * Creates a single sign-on account's identity on this browser (device-only), or finishes one an
 * interrupted run created. The key is kept here, pending, before the server learns it, so a lost
 * response never leaves an identity no browser holds. A held identity the server no longer lists is
 * replaced only with replace (the user's explicit choice); another browser's identity means linking.
 */
export async function settleSSOIdentity(api: DeviceOnlyAPI, store: IdentityStore, replace = false, retried = false): Promise<Settled> {
  const local = await store.load();
  const live = await api.myIdentity();
  if (live) {
    if (!local || !sameBytes(local.publicKey, fromBase64(live.publicKey))) return { kind: "link" };
    const identity = { ...local, deviceId: live.deviceId };
    // A save that fails leaves the pending copy, which the next run finishes.
    if (local.deviceId !== live.deviceId) await store.save(identity, local);
    return { kind: "held", identity };
  }
  if (local?.deviceId && !replace) return { kind: "orphaned" };
  const pending = local && !local.deviceId ? local : { ...generateIdentity(), deviceId: "" };
  // Compare-and-swap against what this run read: a key another tab kept meanwhile is never overwritten.
  if (pending !== local && !(await store.save(pending, local ?? null))) return retried ? { kind: "unsaved" } : settleSSOIdentity(api, store, false, true);
  try {
    const { deviceId } = await api.putDeviceOnlyIdentity(base64(pending.publicKey));
    const identity = { ...pending, deviceId };
    await store.save(identity, pending);
    return { kind: "held", identity };
  } catch (error) {
    // Another tab of this browser created one meanwhile: settle against it once.
    if ((error as { code?: string }).code === "identity_exists" && !retried) return settleSSOIdentity(api, store, false, true);
    throw error;
  }
}

export type IdentityStatus = "held" | "link" | "create" | "orphaned";
/** What this browser can do: use its copy, be linked, create (or finish) one, or replace an orphan. */
export function identityStatus(local: HeldIdentity | undefined, live: PublicIdentity | undefined): IdentityStatus {
  if (!live) return local?.deviceId ? "orphaned" : "create";
  if (!local || !sameBytes(local.publicKey, fromBase64(live.publicKey))) return "link";
  return local.deviceId === live.deviceId ? "held" : "create";
}

/** The vault copy may seal and open keys only while the server lists it as this account's identity, or cannot be reached. */
export function currentCopy(local: HeldIdentity | undefined, live: PublicIdentity | undefined | "unreachable"): HeldIdentity | undefined {
  if (!local?.deviceId) return undefined;
  if (live === "unreachable") return local;
  return identityStatus(local, live) === "held" ? local : undefined;
}
```

  `generateIdentity` is already imported from `./teamKeys`, and Task 3 imported `sameBytes`; add nothing twice. In `api.ts`:

```ts
export const putDeviceOnlyIdentity = (publicKey: string) => request<{ deviceId: string; fingerprint: string }>("/api/v1/me/identity", { method: "PUT", body: JSON.stringify({ publicKey, wrapAlg: "none" }) });
/** A device-link request as the trusted side lists it; newcomerKey is "" until revealed to this session. */
export type LinkRequestRow = { id: string; commitment: string; createdAt: string; expiresAt: string; claimed: boolean; newcomerKey: string };
/** The newcomer's view of its request; bundle once, after approval. */
export type LinkState = { state: "pending" | "claimed" | "revealed" | "approved"; expiresAt: string; approverKey?: string; bundle?: string };
const linkURL = (id: string, suffix = "") => `/api/v1/me/link-requests/${encodeURIComponent(id)}${suffix}`;
export const createLinkRequest = (commitment: string) => request<{ id: string; expiresAt: string }>("/api/v1/me/link-requests", { method: "POST", body: JSON.stringify({ commitment }) });
export const linkRequests = () => request<LinkRequestRow[]>("/api/v1/me/link-requests");
export const claimLinkRequest = (id: string, approverKey: string) => request<void>(linkURL(id, "/claim"), { method: "POST", body: JSON.stringify({ approverKey }) });
export const revealLinkRequest = (id: string, newcomerKey: string) => request<void>(linkURL(id, "/reveal"), { method: "POST", body: JSON.stringify({ newcomerKey }) });
/** Only outbound.ts sendLinkBundle calls this (outbound.test.ts). */
export const approveLinkRequest = (id: string, bundle: string) => request<void>(linkURL(id, "/approve"), { method: "POST", body: JSON.stringify({ bundle }) });
export const collectLinkRequest = (id: string) => request<LinkState>(linkURL(id, "/collect"), { method: "POST" });
export const cancelLinkRequest = (id: string) => request<void>(linkURL(id), { method: "DELETE" });
```

- [ ] **Step 4: Run the tests to verify they pass.** Run `npm test --prefix web`. Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add web/src/identity.ts web/src/identity.test.ts web/src/api.ts web/src/api.test.ts
git commit -m "web: device-only identities for single sign-on, reconciled and never overwritten"
```

### Task 8: Web: the link flow and its outbound gate

**Files:** Create `web/src/linkFlow.ts`, `web/src/linkFlow.test.ts`. Modify `web/src/outbound.ts`, `web/src/outbound.test.ts`.

**Interfaces:**
- Consumes: Task 3 `linking.ts`, Task 7 `api.ts` link functions and types, `publicKeyBytes` (`pins.ts`), `sameBytes` (`teamKeys.ts`).
- Produces: the `linkFlow.ts` API and `sendLinkBundle` (see Interfaces).

- [ ] **Step 1: Write the failing tests.** Create `web/src/linkFlow.test.ts`:

```ts
import { describe, expect, it, vi } from "vitest";
import { base64, fromBase64 } from "./crypto";
import type { LinkRequestRow, LinkState } from "./api";
import { approveLink, claimLink, finishNewcomerLink, LinkStorageError, LinkTamperedError, pollNewcomerLink, revealedLink, startNewcomerLink } from "./linkFlow";
import { confirmCheckCode, linkCommitment, newLinkKey, sealLinkBundle, type CheckCodeConfirmation } from "./linking";
import { generateIdentity } from "./teamKeys";

const me = `usr_${"a".repeat(26)}`;
const dev = `dev_${"b".repeat(26)}`;
const identity = { ...generateIdentity(), deviceId: dev };
const live = { deviceId: dev, publicKey: base64(identity.publicKey), fingerprint: "" };

/** An honest relay in memory, recording both sides' calls in order. */
function relay() {
  const calls: string[] = [];
  let row: LinkRequestRow | undefined;
  let state: LinkState = { state: "pending", expiresAt: "" };
  const newcomer = {
    create: async (commitment: string) => { calls.push("create"); row = { id: `lnk_${"c".repeat(26)}`, commitment, createdAt: "", expiresAt: "", claimed: false, newcomerKey: "" }; return { id: row.id, expiresAt: "" }; },
    collect: async () => { calls.push("collect"); return state; },
    reveal: async (_id: string, key: string) => { calls.push("reveal"); row = { ...row!, newcomerKey: key }; state = { ...state, state: "revealed" }; },
    myIdentity: async () => live,
  };
  const approver = { claim: async (_id: string, key: string) => { calls.push("claim"); row = { ...row!, claimed: true }; state = { state: "claimed", approverKey: key, expiresAt: "" }; } };
  const send = vi.fn(async (_c: CheckCodeConfirmation, _id: string, bundle: Uint8Array) => { calls.push("send"); state = { ...state, state: "approved", bundle: base64(bundle) }; });
  return { calls, newcomer, approver, send, row: () => row!, setRow: (next: LinkRequestRow) => { row = next; }, setApproverKey: (key: string) => { state = { ...state, approverKey: key }; } };
}
const stepUp = (calls: string[]) => async () => { calls.push("step-up"); };

describe("device linking", () => {
  it("shows one code on both sides; the key moves only after both users confirmed", async () => {
    const r = relay();
    const save = vi.fn(async () => true);
    let link = await startNewcomerLink(r.newcomer, async () => true);
    let approver = await claimLink(r.approver, r.row());
    ({ link } = await pollNewcomerLink(r.newcomer, link, me));
    approver = revealedLink(approver, r.row(), me);
    expect(link.code).toMatch(/^\d{3} \d{3}$/);
    expect(approver.code).toBe(link.code);
    await approveLink(approver, confirmCheckCode(approver.id), identity, me, stepUp(r.calls), r.send);
    const { bundle } = await pollNewcomerLink(r.newcomer, link, me);
    await expect(finishNewcomerLink(link, bundle!, undefined as never, me, r.newcomer, save)).rejects.toThrow();
    expect(save).not.toHaveBeenCalled();
    const held = await finishNewcomerLink(link, bundle!, confirmCheckCode(link.id), me, r.newcomer, save);
    expect(held).toEqual(identity);
    expect(r.calls).toEqual(["create", "claim", "collect", "reveal", "step-up", "send", "collect"]);
  });

  it("shows different codes when the relay swaps the approver's key", async () => {
    const r = relay();
    let link = await startNewcomerLink(r.newcomer, async () => true);
    let approver = await claimLink(r.approver, r.row());
    r.setApproverKey(base64(newLinkKey().publicKey));
    ({ link } = await pollNewcomerLink(r.newcomer, link, me));
    approver = revealedLink(approver, r.row(), me);
    expect(link.code).not.toBe(approver.code);
  });

  it("refuses an approver key that changes after the code was shown", async () => {
    const r = relay();
    let link = await startNewcomerLink(r.newcomer, async () => true);
    await claimLink(r.approver, r.row());
    ({ link } = await pollNewcomerLink(r.newcomer, link, me));
    r.setApproverKey(base64(newLinkKey().publicKey));
    await expect(pollNewcomerLink(r.newcomer, link, me)).rejects.toBeInstanceOf(LinkTamperedError);
  });

  it("reveals the newcomer key only after the approver's key arrived", async () => {
    const r = relay();
    let link = await startNewcomerLink(r.newcomer, async () => true);
    ({ link } = await pollNewcomerLink(r.newcomer, link, me));
    expect(r.calls).toEqual(["create", "collect"]);
    expect(link.code).toBeUndefined();
    await claimLink(r.approver, r.row());
    ({ link } = await pollNewcomerLink(r.newcomer, link, me));
    expect(r.calls).toEqual(["create", "collect", "claim", "collect", "reveal"]);
  });

  it("refuses a newcomer key that does not match the commitment seen before claiming", async () => {
    const r = relay();
    await startNewcomerLink(r.newcomer, async () => true);
    const approver = await claimLink(r.approver, r.row());
    const other = newLinkKey();
    // A relay that rewrote the commitment after the claim, to match its own key: still refused.
    r.setRow({ ...r.row(), commitment: base64(linkCommitment(other.publicKey)), newcomerKey: base64(other.publicKey) });
    expect(() => revealedLink(approver, r.row(), me)).toThrow(LinkTamperedError);
  });

  it("creates no request when this browser cannot keep the key", async () => {
    const r = relay();
    await expect(startNewcomerLink(r.newcomer, async () => false)).rejects.toBeInstanceOf(LinkStorageError);
    expect(r.calls).toEqual([]);
  });

  it("refuses a bundle holding another key than the account's identity, and keeps nothing it could not store", async () => {
    const r = relay();
    let link = await startNewcomerLink(r.newcomer, async () => true);
    const approver = await claimLink(r.approver, r.row());
    ({ link } = await pollNewcomerLink(r.newcomer, link, me));
    const forged = sealLinkBundle(generateIdentity().privateKey, approver.key, { userID: me, requestID: link.id, identityDeviceID: dev, approverKey: approver.key.publicKey, newcomerKey: link.key.publicKey });
    const save = vi.fn(async () => true);
    await expect(finishNewcomerLink(link, forged, confirmCheckCode(link.id), me, r.newcomer, save)).rejects.toThrow(/not your account's encryption key/);
    expect(save).not.toHaveBeenCalled();
    const honest = sealLinkBundle(identity.privateKey, approver.key, { userID: me, requestID: link.id, identityDeviceID: dev, approverKey: approver.key.publicKey, newcomerKey: link.key.publicKey });
    await expect(finishNewcomerLink(link, honest, confirmCheckCode(link.id), me, r.newcomer, async () => false)).rejects.toBeInstanceOf(LinkStorageError);
  });

  it("sends nothing, and asks for no step-up, without a confirmation for this request", async () => {
    const r = relay();
    let link = await startNewcomerLink(r.newcomer, async () => true);
    let approver = await claimLink(r.approver, r.row());
    ({ link } = await pollNewcomerLink(r.newcomer, link, me));
    approver = revealedLink(approver, r.row(), me);
    await expect(approveLink(approver, confirmCheckCode(`lnk_${"z".repeat(26)}`), identity, me, stepUp(r.calls), r.send)).rejects.toThrow();
    expect(r.calls).not.toContain("step-up");
    expect(r.send).not.toHaveBeenCalled();
    expect(fromBase64(r.row().newcomerKey)).toEqual(link.key.publicKey);
  });
});
```

  Append to `web/src/outbound.test.ts`:
  - Add `approveLinkRequest` to the `raw` regex in "only outbound.ts reaches the ciphertext upload API functions".
  - Add, inside `describe("outbound ciphertext gate", …)`:

```ts
  it("lets a link bundle leave only with that request's check-code confirmation", async () => {
    const id = `lnk_${"a".repeat(26)}`;
    const bundle = new Uint8Array(61);
    expect(() => sendLinkBundle({ requestID: id } as never, id, bundle)).toThrow(/check codes/);
    expect(() => sendLinkBundle(confirmCheckCode(`lnk_${"b".repeat(26)}`), id, bundle)).toThrow(/check codes/);
    expect(fetches).not.toHaveBeenCalled();
    await sendLinkBundle(confirmCheckCode(id), id, bundle);
    expect((fetches.mock.calls[0] as unknown as [string])[0]).toBe(`/api/v1/me/link-requests/${id}/approve`);
  });
```

  with `import { sendLinkBundle } from "./outbound";` (extend the existing import) and `import { confirmCheckCode } from "./linking";`.

- [ ] **Step 2: Run them to verify they fail.** Run `npm test --prefix web -- linkFlow outbound`. Expected: FAIL (`./linkFlow` not found; `sendLinkBundle` not exported).

- [ ] **Step 3: Implement.** Create `web/src/linkFlow.ts`:

```ts
import { x25519 } from "@noble/curves/ed25519.js";
import { base64, fromBase64 } from "./crypto";
import type { claimLinkRequest, collectLinkRequest, createLinkRequest, LinkRequestRow, revealLinkRequest } from "./api";
import type { HeldIdentity, PublicIdentity } from "./identity";
import { checkCode, isCheckCodeConfirmation, linkCommitment, newLinkKey, openLinkBundle, sealLinkBundle, type CheckCodeConfirmation } from "./linking";
import { sendLinkBundle } from "./outbound";
import { publicKeyBytes } from "./pins";
import { sameBytes, type Identity } from "./teamKeys";

export class LinkStorageError extends Error {
  constructor() { super("This browser cannot keep an encryption key (site storage is blocked or unavailable), so it cannot be linked."); this.name = "LinkStorageError"; }
}
export class LinkTamperedError extends Error {
  constructor() { super("The other browser's key changed while linking. Nothing was linked; start again on both browsers."); this.name = "LinkTamperedError"; }
}

export type NewcomerAPI = { create: typeof createLinkRequest; collect: typeof collectLinkRequest; reveal: typeof revealLinkRequest; myIdentity: () => Promise<PublicIdentity | undefined> };
/** One attempt on the browser being linked. Its one-time key lives only here, in memory. */
export type NewcomerLink = { id: string; key: Identity; expiresAt: string; approverKey?: Uint8Array; code?: string };

/** Starts a link; refuses before any request when this browser could not keep the identity. */
export async function startNewcomerLink(api: Pick<NewcomerAPI, "create">, canKeep: () => Promise<boolean>): Promise<NewcomerLink> {
  if (!(await canKeep())) throw new LinkStorageError();
  const key = newLinkKey();
  const { id, expiresAt } = await api.create(base64(linkCommitment(key.publicKey)));
  return { id, key, expiresAt };
}

/**
 * One poll. When the approver's key first arrives, this browser reveals its own (committed to at
 * start) and computes the check code; an approver key that changes after that is refused.
 * bundle: once the approver sent it. It is opened only by finishNewcomerLink.
 */
export async function pollNewcomerLink(api: Pick<NewcomerAPI, "collect" | "reveal">, link: NewcomerLink, userID: string): Promise<{ link: NewcomerLink; bundle?: Uint8Array }> {
  const state = await api.collect(link.id);
  if (link.approverKey) {
    if (state.approverKey && !sameBytes(publicKeyBytes(state.approverKey), link.approverKey)) throw new LinkTamperedError();
    return { link, bundle: state.bundle ? fromBase64(state.bundle) : undefined };
  }
  if (!state.approverKey) return { link };
  const approverKey = publicKeyBytes(state.approverKey);
  await api.reveal(link.id, base64(link.key.publicKey));
  return { link: { ...link, approverKey, code: checkCode(userID, link.id, approverKey, link.key.publicKey) } };
}

/**
 * Opens the bundle only after this browser's own user confirmed the code, only when it carries the
 * identity the server lists for the account, and keeps it sealed for this browser.
 */
export async function finishNewcomerLink(link: NewcomerLink, bundle: Uint8Array, confirmation: CheckCodeConfirmation, userID: string, api: Pick<NewcomerAPI, "myIdentity">, save: (identity: HeldIdentity) => Promise<boolean>): Promise<HeldIdentity> {
  if (!isCheckCodeConfirmation(confirmation, link.id) || !link.approverKey) throw new Error("Compare the check codes on both screens first.");
  const live = await api.myIdentity();
  if (!live) throw new Error("Your account has no encryption key to link.");
  const privateKey = openLinkBundle(bundle, link.key, { userID, requestID: link.id, identityDeviceID: live.deviceId, approverKey: link.approverKey, newcomerKey: link.key.publicKey });
  const publicKey = x25519.getPublicKey(privateKey);
  if (!sameBytes(publicKey, publicKeyBytes(live.publicKey))) throw new Error("The key sent is not your account's encryption key. Nothing was linked.");
  const identity = { deviceId: live.deviceId, publicKey, privateKey };
  if (!(await save(identity))) throw new LinkStorageError();
  return identity;
}

/** One attempt on the trusted browser. commitment is the one listed before this browser's key was sent. */
export type ApproverLink = { id: string; key: Identity; commitment: Uint8Array; newcomerKey?: Uint8Array; code?: string };

export async function claimLink(api: { claim: typeof claimLinkRequest }, row: LinkRequestRow): Promise<ApproverLink> {
  const commitment = fromBase64(row.commitment);
  if (commitment.length !== 32) throw new LinkTamperedError();
  const key = newLinkKey();
  await api.claim(row.id, base64(key.publicKey));
  return { id: row.id, key, commitment };
}

/** Takes the newcomer's revealed key, only if it matches the commitment seen before claiming. */
export function revealedLink(link: ApproverLink, row: LinkRequestRow | undefined, userID: string): ApproverLink {
  if (link.newcomerKey || !row?.newcomerKey) return link;
  const newcomerKey = publicKeyBytes(row.newcomerKey);
  if (!sameBytes(linkCommitment(newcomerKey), link.commitment)) throw new LinkTamperedError();
  return { ...link, newcomerKey, code: checkCode(userID, link.id, link.key.publicKey, newcomerKey) };
}

/** Seals the identity to the newcomer and sends it, after the user confirmed the code and a fresh step-up. */
export async function approveLink(link: ApproverLink, confirmation: CheckCodeConfirmation, identity: HeldIdentity, userID: string, stepUp: () => Promise<void>, send: typeof sendLinkBundle = sendLinkBundle): Promise<void> {
  if (!isCheckCodeConfirmation(confirmation, link.id)) throw new Error("Compare the check codes on both screens first.");
  if (!link.newcomerKey) throw new Error("The other browser has not answered yet.");
  const bundle = sealLinkBundle(identity.privateKey, link.key, { userID, requestID: link.id, identityDeviceID: identity.deviceId, approverKey: link.key.publicKey, newcomerKey: link.newcomerKey });
  await stepUp();
  await send(confirmation, link.id, bundle);
}
```

  In `outbound.ts`:
  - Add `approveLinkRequest` to the `./api` import.
  - Add `import { base64 } from "./crypto";` and `import { isCheckCodeConfirmation, type CheckCodeConfirmation } from "./linking";`.
  - Append:

```ts
/** A device-link bundle leaves only with the user's confirmation that both screens showed one check code for that request. */
export function sendLinkBundle(confirmation: CheckCodeConfirmation, requestID: string, bundle: Uint8Array): Promise<void> {
  if (!isCheckCodeConfirmation(confirmation, requestID)) throw new Error("Compare the check codes on both screens first.");
  return approveLinkRequest(requestID, base64(bundle));
}
```

- [ ] **Step 4: Run the tests to verify they pass.** Run `npm test --prefix web`. Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add web/src/linkFlow.ts web/src/linkFlow.test.ts web/src/outbound.ts web/src/outbound.test.ts
git commit -m "web: device link flow; the bundle leaves only with a confirmed check code"
```

### Task 9: Web: SSO stewards share keys on request

**Files:** Modify `web/src/keyService.ts`, `web/src/keyService.test.ts`.

**Interfaces:**
- Consumes: `syncContainerKeys` and its test helpers `user`, `server`, `memoryStore`, `as`, `never` and `shown`.
- Produces: `KySync.deferred: boolean`. It is true when a caller that may not wrap (`canWrap: false`) would mint or wrap.

- [ ] **Step 1: Write the failing test.** Append to `keyService.test.ts`:

```ts
describe("a steward who shares only on request (single sign-on)", () => {
  it("writes nothing, reports the waiting work, and shares it when asked", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor");
    const { state, api } = server([owner, editor]);
    const quiet = await syncContainerKeys(api, cnt, as(owner, false), memoryStore(), never);
    expect(quiet.deferred).toBe(true);
    expect(quiet.minted).toBe(false);
    expect(api.rotate).not.toHaveBeenCalled();
    expect(api.stepUp).not.toHaveBeenCalled();
    const asked = await syncContainerKeys(api, cnt, as(owner, true), memoryStore(), never);
    expect(asked.minted).toBe(true);
    expect(asked.deferred).toBe(false);
    expect(state.generation).toBe(2);
  });

  it("still explains a first key that waits for a member without an identity", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor", false);
    const { api } = server([owner, editor]);
    const result = await syncContainerKeys(api, cnt, as(owner, false), memoryStore(), never);
    expect(result.plan).toEqual({ kind: "blocked", waitingFor: [shown(editor)] });
    expect(result.deferred).toBe(false);
  });
});
```

- [ ] **Step 2: Run it to verify it fails.** Run `npm test --prefix web -- keyService`. Expected: FAIL (`deferred` is undefined; the blocked plan is `idle` for `canWrap: false`).

- [ ] **Step 3: Implement.**
  - In `KySync`, add `deferred: boolean` with the doc line "/** A caller that may not wrap (canWrap false) would mint or wrap now: the UI offers to share on request. */".
  - Inside `pass`, replace `plan` with:

```ts
    let deferred = false;
    // planSweep itself is idle for a caller who is not a steward with an identity.
    const plan = (opened: OpenedKeyring): SweepPlan => {
      if (!me) return { kind: "idle" };
      const next = planSweep({ container, me: caller.userId, members, envelopes, ring: opened.ring });
      const grants = next.kind === "wrap" ? next.grants.filter((grant) => !opened.conflicts.includes(grant.generation)) : [];
      const work: SweepPlan = next.kind !== "wrap" ? next : grants.length ? { kind: "wrap", grants } : { kind: "idle" };
      // A caller that may not wrap only reports the work; a blocked first key writes nothing, so it is still explained.
      deferred = !caller.canWrap && (work.kind === "mint" || work.kind === "wrap");
      return caller.canWrap || work.kind === "blocked" ? work : { kind: "idle" };
    };
```

  - Add `deferred` to the object `result(…)` builds: `({ container, changed, …, envelopes: seen, deferred, ...rest })`, and add `"deferred"` to the `Omit<Pass, …>` list of `result`'s `rest` parameter. Without it every `result(…)` call fails to type-check for a missing `deferred`.
  - In the rollback early return, add `deferred: false`.
  - Add `deferred` to `Pass` (it is part of `KySync`).

  If an existing test asserts `plan.kind === "idle"` for a blocked never-shared container with `canWrap: false`, change it to expect `"blocked"`: that is the intended change.

- [ ] **Step 4: Run the tests to verify they pass.** Run `npm test --prefix web`. Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add web/src/keyService.ts web/src/keyService.test.ts
git commit -m "web: a steward who cannot wrap silently reports deferred key work"
```

### Task 10: Web: the link screens and their wiring

**Files:** Create `web/src/components/DeviceLink.tsx`. Modify `web/src/main.tsx`, `web/src/styles.css`.

**Interfaces:**
- Consumes: Tasks 6–9. `confirmSSOAction` runs through `api.ts` `actionFetch` on any `sso_step_up_required` response, so SSO confirmations need no extra code.
- Produces: `linkCodeOf`, `LinkThisBrowser` and `LinkRequests`. The UI strings below are relied on by Task 12:
  - The banner text "This browser does not hold your encryption key".
  - Buttons "Link this browser", "Codes match", "Codes differ", "Codes match — send key", "Approve…", "Not me", "Set up encryption key", "Replace encryption key", "Share keys (confirm with KySignOn)".
  - Classes `.link-code` and `.check-code`; card IDs `#link-this-browser` and `#link-devices`.
  - The status texts "Linked. This browser now holds your encryption key." and "This link request ended".

- [ ] **Step 1: Components.** Create `web/src/components/DeviceLink.tsx`:

```tsx
import { useEffect, useRef, useState } from "react";
import { APIRequestError, cancelLinkRequest, claimLinkRequest, collectLinkRequest, createLinkRequest, linkRequests, myIdentity, revealLinkRequest, type LinkRequestRow } from "../api";
import type { HeldIdentity } from "../identity";
import { approveLink, claimLink, finishNewcomerLink, LinkTamperedError, pollNewcomerLink, revealedLink, startNewcomerLink, type ApproverLink, type NewcomerLink } from "../linkFlow";
import { confirmCheckCode, type CheckCodeConfirmation } from "../linking";

/** The six characters people match to pick the right request on the trusted browser; identification only. */
export const linkCodeOf = (id: string) => id.slice(-6).toUpperCase();
const POLL_MS = 2000;
const ENDED = "This link request ended: it was cancelled on the other browser or expired. Start again.";
const DIFFERED = "Linking cancelled: the codes differed. Someone may be interfering; start again on both browsers.";
const errorText = (error: unknown) => (error instanceof Error ? error.message : "Linking failed.");
const pause = () => new Promise((resolve) => setTimeout(resolve, POLL_MS));

/** On a browser without the identity: asks a trusted browser of the same account to send it. */
export function LinkThisBrowser({ userID, canKeep, save, onLinked }: { userID: string; canKeep: () => Promise<boolean>; save: (identity: HeldIdentity) => Promise<boolean>; onLinked: (identity: HeldIdentity) => void }) {
  const [link, setLink] = useState<NewcomerLink>();
  const [confirmed, setConfirmed] = useState(false);
  const [status, setStatus] = useState("");
  const attempt = useRef(0);
  // confirmation: minted by this user's own "Codes match" click, never by the poll loop.
  const state = useRef<{ link?: NewcomerLink; bundle?: Uint8Array; confirmation?: CheckCodeConfirmation }>({});
  const api = { create: createLinkRequest, collect: collectLinkRequest, reveal: revealLinkRequest, myIdentity };
  const show = (next?: NewcomerLink) => { state.current.link = next; setLink(next); };
  const reset = () => { attempt.current += 1; state.current = {}; setLink(undefined); setConfirmed(false); };
  // Leaving the screen abandons the attempt: polling stops and the request is cancelled.
  useEffect(() => () => {
    attempt.current += 1;
    const id = state.current.link?.id;
    if (id) void cancelLinkRequest(id).catch(() => undefined);
  }, []);

  /** Runs once both the bundle has arrived and this screen's user confirmed the code. */
  async function finish() {
    const { link: current, bundle, confirmation } = state.current;
    if (!current || !bundle || !confirmation) return;
    reset();
    try {
      onLinked(await finishNewcomerLink(current, bundle, confirmation, userID, api, save));
    } catch (error) {
      setStatus(errorText(error));
    }
  }
  async function begin() {
    reset();
    const mine = attempt.current;
    setStatus("");
    try {
      show(await startNewcomerLink(api, canKeep));
      while (attempt.current === mine) {
        await pause();
        if (attempt.current !== mine) return;
        const next = await pollNewcomerLink(api, state.current.link!, userID);
        show(next.link);
        if (next.bundle) {
          state.current.bundle = next.bundle;
          await finish();
          return;
        }
      }
    } catch (error) {
      if (attempt.current !== mine) return;
      const id = state.current.link?.id;
      const ended = error instanceof APIRequestError && error.code === "not_found";
      reset();
      if (id && !ended) void cancelLinkRequest(id).catch(() => undefined);
      setStatus(ended ? ENDED : errorText(error));
    }
  }
  function confirm() {
    const current = state.current.link;
    if (!current?.code) return;
    state.current.confirmation = confirmCheckCode(current.id);
    setConfirmed(true);
    void finish();
  }
  function differ() {
    const id = state.current.link?.id;
    reset();
    setStatus(DIFFERED);
    if (id) void cancelLinkRequest(id).catch(() => undefined);
  }
  return (
    <section id="link-this-browser" className="config-card">
      <h2>Link this browser</h2>
      {!link && (
        <>
          <p className="config-muted">This browser does not hold your encryption key, so it cannot open team notebooks. A browser where you already use KyNotes can send it here; KyNotes only relays it encrypted.</p>
          <button onClick={() => void begin()}>Link this browser</button>
        </>
      )}
      {link && !link.code && <p>On a browser that holds your key, open Settings → Link another browser and approve request <code className="link-code">{linkCodeOf(link.id)}</code>. Waiting…</p>}
      {link?.code && (
        <>
          <p>Check code: <code className="check-code">{link.code}</code></p>
          <p className="config-muted">The other browser shows a check code too. Continue only if both show the same six digits.</p>
          {confirmed ? <p>Waiting for the other browser to send the key…</p> : (
            <div className="link-actions">
              <button onClick={confirm}>Codes match</button>
              <button className="secondary" onClick={differ}>Codes differ</button>
            </div>
          )}
        </>
      )}
      {status && <p role="status" className="link-status">{status}</p>}
    </section>
  );
}

/** On a browser that holds the identity: lists the account's link requests and sends the key to one after both screens matched. */
export function LinkRequests({ userID, held, stepUp }: { userID: string; held: () => Promise<HeldIdentity | undefined>; stepUp: () => Promise<void> }) {
  const [rows, setRows] = useState<LinkRequestRow[]>([]);
  const [active, setActive] = useState<ApproverLink>();
  const [status, setStatus] = useState("");
  const activeRef = useRef<ApproverLink>();
  const keep = (next?: ApproverLink) => { activeRef.current = next; setActive(next); };
  async function drop(id: string | undefined, message: string) {
    keep(undefined);
    setStatus(message);
    if (id) await cancelLinkRequest(id).catch(() => undefined);
  }
  useEffect(() => {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      try {
        const next = await linkRequests();
        if (stopped) return;
        setRows(next);
        const open = activeRef.current;
        if (open && !open.newcomerKey) {
          const row = next.find((entry) => entry.id === open.id);
          if (row) keep(revealedLink(open, row, userID));
          else { keep(undefined); setStatus(ENDED); }
        }
      } catch (error) {
        if (!stopped) {
          if (error instanceof LinkTamperedError) await drop(activeRef.current?.id, error.message);
          else setStatus(errorText(error));
        }
      }
      if (!stopped) timer = setTimeout(() => void tick(), POLL_MS);
    };
    timer = setTimeout(() => void tick(), 0);
    return () => { stopped = true; clearTimeout(timer); };
  }, [userID]);
  async function approve(row: LinkRequestRow) {
    setStatus("");
    try { keep(await claimLink({ claim: claimLinkRequest }, row)); } catch (error) { setStatus(errorText(error)); }
  }
  async function send() {
    const link = activeRef.current;
    const identity = await held();
    if (!link) return;
    if (!identity) { await drop(link.id, "This browser no longer holds your encryption key."); return; }
    try {
      await approveLink(link, confirmCheckCode(link.id), identity, userID, stepUp);
      keep(undefined);
      setStatus("Key sent. Finish on the other browser.");
    } catch (error) {
      setStatus(errorText(error));
    }
  }
  return (
    <section id="link-devices" className="config-card">
      <h2>Link another browser</h2>
      <p className="config-muted">Approve only a request you started yourself, on a browser in front of you. Both screens then show a check code; send your key only if they match.</p>
      {!active && (rows.length ? rows.map((row) => (
        <div className="pin-row" key={row.id}>
          <span>Request <code className="link-code">{linkCodeOf(row.id)}</code> · started {new Date(row.createdAt).toLocaleTimeString()}</span>
          <button onClick={() => void approve(row)}>Approve…</button>
          <button className="secondary" onClick={() => void drop(row.id, "Request cancelled.")}>Not me</button>
        </div>
      )) : <p className="config-muted">No browser is asking to be linked.</p>)}
      {active && !active.code && <p>Waiting for request <code className="link-code">{linkCodeOf(active.id)}</code> to answer…</p>}
      {active?.code && (
        <>
          <p>Check code: <code className="check-code">{active.code}</code></p>
          <div className="link-actions">
            <button onClick={() => void send()}>Codes match — send key</button>
            <button className="secondary" onClick={() => void drop(active.id, DIFFERED)}>Codes differ</button>
          </div>
        </>
      )}
      {status && <p role="status" className="link-status">{status}</p>}
    </section>
  );
}
```

- [ ] **Step 2: Login settles the identity before entering.** In `main.tsx`, replace `settleIdentity` with:

```ts
/** Opens or creates the identity after a password sign-in and keeps it on this browser; failures stay silent (the workspace offers linking). */
async function settleIdentity(username: string, userID: string, keys: LoginKeys, fromLogin?: IdentityRecord): Promise<void> {
  try {
    const identity = await ensureIdentity(identityAPI, userID, keys, fromLogin);
    if (identity) await storeIdentityKey(username, userID, identity);
  } catch { /* the workspace shows what this browser can do instead */ }
}
```

  At the three login call sites, await it before entering:
  - In `submitSetup`, replace `onLogin({ username: name, authSecret, user: result.user });` followed by `settleIdentity(name, result.user.id, keys);` with `await settleIdentity(name, result.user.id, keys);` followed by `onLogin({ username: name, authSecret, user: result.user });`.
  - Do the same in both password branches of `submit`, with `result.identity` passed.
  - In the password-change handler, change `if (!rewrapped) settleIdentity(name, userID, newKeys);` to `if (!rewrapped) void settleIdentity(name, userID, newKeys);`.

  The workspace then checks a settled vault when it mounts.

- [ ] **Step 3: Texts.**
  - `INVITE_WITHOUT_KEYS["cannot-wrap"]` becomes `"The invitation carries no keys: this browser cannot share keys at invitation time (it holds no encryption key, or you signed in with single sign-on). A team owner's browser shares them after the person joins."`.
  - In `keyNoticeFor`, the blocked line becomes `` `This notebook is not end-to-end shared yet: ${plan.waitingFor.join(", ")} must first sign in to KyNotes once and set up an encryption key.` ``.

- [ ] **Step 4: Workspace identity state.**
  - Imports: add `myIdentity` and `putDeviceOnlyIdentity` to the `./api` import list; add `currentCopy, identityStatus, settleSSOIdentity, type IdentityStatus, type IdentityStore` to the `./identity` import; add `identityProtection, loadIdentityRecord, vaultReady` to the `./storage` import; add `import { LinkRequests, LinkThisBrowser } from "./components/DeviceLink";`.
  - Replace the `identityRef`/`heldIdentity` block with:

```ts
  const identityRef = useRef<HeldIdentity | undefined>(undefined);
  /** The vault copy, used only while the server lists it as this account's identity (or cannot be reached). */
  async function heldIdentity() {
    if (!identityRef.current) {
      const local = await getIdentityKey(auth.username, auth.user.id).catch(() => undefined);
      const live = local ? await myIdentity().catch(() => "unreachable" as const) : undefined;
      identityRef.current = currentCopy(local, live);
    }
    return identityRef.current;
  }
  // What this browser can do about the account's identity; "unknown" until checked.
  const [identityState, setIdentityState] = useState<IdentityStatus | "unknown">("unknown");
  async function refreshIdentity() {
    identityRef.current = undefined;
    const [local, live] = await Promise.all([loadIdentityRecord(auth.username, auth.user.id).catch(() => undefined), myIdentity()]);
    setIdentityState(identityStatus(local, live));
  }
  useEffect(() => { void refreshIdentity().catch(() => undefined); }, []);
  /** A single sign-on account's key: created (or an orphan replaced) only on the user's click, confirmed with KySignOn. */
  async function setUpSSOIdentity(replace: boolean) {
    if (replace && !confirm("Replace this browser's encryption key with a new one? Team owners must share their notebooks' keys with you again, and colleagues are asked to trust your new key.")) return;
    try {
      const store: IdentityStore = { load: () => loadIdentityRecord(auth.username, auth.user.id), save: (identity, expected) => storeIdentityKey(auth.username, auth.user.id, identity, expected) };
      const settled = await settleSSOIdentity({ myIdentity, putDeviceOnlyIdentity }, store, replace);
      if (settled.kind === "unsaved") setError("This browser cannot keep an encryption key (site storage is blocked or unavailable), so none was created.");
      await refreshIdentity();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to set up the encryption key");
    }
  }
```

  - In `keyAPI`, set `stepUp: auth.sso ? async () => {} : async () => { await stepUp(auth.authSecret); },`, with the comment `// SSO sessions confirm each protected request with KySignOn (actionFetch); there is no session-wide step-up.`
  - Add `const [keyDeferred, setKeyDeferred] = useState(false);`.
  - Change `syncKeys` to `async function syncKeys(container: Container, background = false, superseded: () => boolean = () => false, share = false)`. Its caller becomes `{ userId: auth.user.id, identity: await heldIdentity(), canWrap: !auth.sso || share }`. Next to `setKeyMembers(…)`, add `setKeyDeferred(result.deferred);`.
  - Add:

```ts
  /** An SSO steward's explicit "share keys": the same pass, allowed to write (each write asks KySignOn). */
  async function shareKeysNow() {
    const open = selectedRef.current;
    if (!open) return;
    try { adoptGenerations(await syncKeys(open, false, () => false, true)); } catch (err) { setError(err instanceof Error ? err.message : "Unable to share keys"); }
  }
```

  - In the list header, after the `keyNotice` line, add:

```tsx
                {!queueMode && keyDeferred && <div className="workspace-kind" role="status">Members are waiting for this notebook's keys. <button className="quiet" onClick={() => void shareKeysNow()}>Share keys (confirm with KySignOn)</button></div>}
                {identityState === "link" && <div className="conflict-banner" role="status">This browser does not hold your encryption key, so team notebooks stay locked here. <button onClick={() => setView("settings")}>Link this browser</button></div>}
                {auth.sso && identityState === "create" && <div className="conflict-banner" role="status">Set up your encryption key so team owners can share notebooks with you. <button onClick={() => void setUpSSOIdentity(false)}>Set up encryption key</button></div>}
                {auth.sso && identityState === "orphaned" && <div className="conflict-banner" role="status">The server no longer lists the encryption key this browser holds (an administrator reset removes it). <button onClick={() => void setUpSSOIdentity(true)}>Replace encryption key</button></div>}
```

  - Pass four more props to `<SettingsView …>`: `identityState={identityState} heldIdentity={heldIdentity} stepUp={keyAPI.stepUp} onLinked={(identity) => { identityRef.current = identity; void refreshIdentity(); }}`.

- [ ] **Step 5: Settings.**
  - Add the four props to `SettingsView`'s destructuring and type: `identityState: IdentityStatus | "unknown"; heldIdentity: () => Promise<HeldIdentity | undefined>; stepUp: () => Promise<void>; onLinked: (identity: HeldIdentity) => void;`.
  - Add `const [justLinked, setJustLinked] = useState(false);`.
  - Make the fingerprint effect depend on `[username, userID, identityState]`.
  - Add `<a href="#link-devices">Link a browser</a>` to the user settings nav.
  - In `#device`, replace the missing-fingerprint text with `"This browser holds no encryption key for team notebooks. Link it from a browser that does (below)."`, and after the fingerprint paragraph add:

```tsx
              {ownFingerprint && <p className="config-muted">{identityProtection() === "device-key" ? "This browser stores it encrypted under a browser key that pages cannot export. Anyone who can read this browser's profile on disk can still recover it: use \"Forget this device\" on shared computers." : "This site is not served over HTTPS, so this browser stores the key unencrypted on disk. Use \"Forget this device\" on shared computers."}</p>}
              {justLinked && <p role="status">Linked. This browser now holds your encryption key.</p>}
```

  - After the `#device` section, add:

```tsx
            {identityState === "link" && <LinkThisBrowser userID={userID} canKeep={() => vaultReady(username)} save={(identity) => storeIdentityKey(username, userID, identity)} onLinked={(identity) => { setJustLinked(true); onLinked(identity); }} />}
            {identityState === "held" && <LinkRequests userID={userID} held={heldIdentity} stepUp={stepUp} />}
```

- [ ] **Step 6: Styles.** Append to `web/src/styles.css`:

```css
.check-code { font-size: 1.5rem; letter-spacing: .12em; }
.link-actions { display: flex; flex-wrap: wrap; gap: 8px; }
.link-status { overflow-wrap: anywhere; }
```

- [ ] **Step 7: Type-check and test.** Run `cd web && npm test && npm run build`. Expected: PASS and a clean build.

- [ ] **Step 8: Commit.**

```bash
git add web/src/components/DeviceLink.tsx web/src/main.tsx web/src/styles.css
git commit -m "web: link screens, SSO key set-up and share-on-request"
```

### Task 11: Embedded bundle, spec, DOX, SSO doc and changelog

**Files:** `internal/web/dist/`, `docs/superpowers/specs/2026-10-07-team-keys-design.md`, `AGENTS.md`, `CHANGELOG.md`.

- [ ] **Step 1: Bundle.** Run `npm run build --prefix web && rm -rf internal/web/dist && cp -r web/dist internal/web/dist && diff -qr web/dist internal/web/dist && go test ./internal/web`.

- [ ] **Step 2: Spec.**
  - §5 Server, first bullet: after "P3b adds `memberships.invited_by` as `0023`", add "; P3c adds `sso_stepup.scope` and `link_requests` as `0024`".
  - §6: replace the "**SSO users:**" bullet with "**SSO users:** an SSO session creates a device-only identity after a user-scope KySignOn confirmation (P3c) and other browsers receive it by device linking; no server copy exists until P5's recovery code. Losing every browser needs an administrator password reset (it deletes the identity) until P5. Whoever operates KyIdentity can log in as the user, so it can create the first identity of an SSO account that has none, or a replacement after an administrator reset; stewards' first-contact fingerprints are the only check (P1's `password_admin_known` guard has no SSO counterpart). It can also start a link request, which succeeds only if the user approves it and confirms a check code read from the attacker's screen."
  - §6: replace the "**At-rest browser cache:**" bullet with "**At-rest browser cache:** in secure contexts the identity private key is stored in IndexedDB encrypted under a non-extractable WebCrypto key kept in the same vault record; plain-HTTP origins keep it raw and Settings says so. This is not at-rest protection: Chromium writes the non-extractable key's bytes into the same profile (pre-flight, 2026-10-08), so a copy of the profile yields both, and page script can call `decrypt`. It only keeps the raw key out of the record's plain values. "Forget this device" deletes the record; the bytes may remain on disk until the browser compacts its storage."
  - §7 P3c bullet:
    - Replace the route list with the seven routes of this plan's Global Constraints.
    - Replace `0024_link_requests.sql` with `0024_device_linking.sql`.
    - Replace "The sealed bundle reuses the envelope construction with label `kynotes/link/v1` and AAD binding user ID and request ID" with "The bundle has its own format (`kynotes/link/v1`, AAD binding user, request, identity row and both one-time keys); the newcomer commits to its key before the approver's key exists".
    - Replace "a device recipient accepts its own user's identity as a sender in addition to the §6 rules" with "(deferred to P5 with phone linking)".
    - Append "(plan: `docs/superpowers/plans/2026-10-08-team-keys-p3c.md`)".
  - §7 P3a known limits, first bullet: replace "Steward work (mint, backfill, re-mint) runs only when a steward with a local password session opens the notebook or removes a member. A member added without an identity reads only until P3c." with "Steward work (mint, backfill, re-mint) runs when a steward with a local password session opens the notebook or removes a member, or when an SSO steward clicks "Share keys"."
  - After the "**P3b as built.**" block, add a "**P3c as built.** Resolved ambiguities:" block. Record resolved ambiguities 1–20 above as numbered one-line items, then a "Known limits:" list:
    - A linked browser cannot be revoked separately; resetting the identity (administrator password reset) is the only way.
    - SSO-only accounts have no server copy of their identity until P5; losing every browser means an administrator reset and re-sharing.
    - Plain-HTTP origins keep the identity raw in IndexedDB.
    - Invitations from SSO sessions carry no keys; the sweep fills them after the invitee accepts.
    - SSO stewards share keys only on a click; every write asks KySignOn.
    - The check code is six digits: a relay in the middle succeeds with probability 10^-6 per attempt, each failure visible.
    - The device key is not at-rest protection (see §6).
    - An SSO step-up binds at most 64 KiB of request body (`stepUpAction`); an SSO steward's rotation or wrap larger than that (roughly 250 envelopes) answers 413. `ponytail:` upgrade path: split `putEnvelopes` into batches, one confirmation each.
    - A password recovery or administrator reset deletes a device-only identity too, although no password wraps it.
    - Whoever operates KyIdentity can create an SSO account's first identity (see §6).

- [ ] **Step 3: `AGENTS.md`.**
  - In the "Team keys P1" bullet, replace "(create-only, `auth.RequireUserStepUp`: local session + `stepup_at`, SSO refused)" with "(create-only, `auth.RequireUserActionStepUp`: a local password step-up creates `aes-256-gcm`, an SSO KySignOn confirmation creates device-only `wrap_alg='none'`)".
  - Run `grep -n "SSO" AGENTS.md`. In every team-keys line that says SSO sessions are refused for identity creation, envelope writes or rotations, replace that with the user-scope confirmation. Invitation envelopes stay local-password.
  - The P1 bullet's verify list names `TestUserStepUpRefusesSSOSession`; rename it to `TestUserActionStepUpRefusesUngrantedSSOSession` (Task 2).
  - After the "Team keys P3b" bullet, add:

```markdown
- Team keys P3c: device linking and SSO identities. Server: `auth.RequireUserActionStepUp` (local password
  step-up, or a `user`-scope KySignOn grant bound to the request; `sso_stepup.scope`, migration
  `0024_device_linking.sql`) gates `PUT /me/identity` (SSO sessions create device-only `wrap_alg='none'`
  identities; a password never unlocks or re-wraps them), envelope `PUT` and key rotations;
  `internal/httpapi/link_routes.go` relays `/api/v1/me/link-requests` (create with a commitment, list, claim,
  reveal, approve after step-up, collect once, cancel): per user, 10-minute TTL, 3 live, both sessions live,
  session-only, own `link` bucket at the `pairing_per_hour` rate, audited `identity.link.*`, GC'd, deleted
  with the identity.
  Web: `linking.ts` (commitment, six-digit check code, 61-byte bundle; `testdata/protocol/link_vectors.json`
  from `internal/teamkeys`), `linkFlow.ts` (newcomer and approver steps; the newcomer opens a bundle only
  after its own confirmation and only for the listed identity), `outbound.ts` `sendLinkBundle` (only with
  a `CheckCodeConfirmation`), `storage.ts` (identity encrypted under a non-extractable device key in the
  vault record, which is not at-rest protection; plain HTTP raw; no vault, no identity; compare-and-swap
  writes), `identity.ts` (`settleSSOIdentity` keeps a pending
  key before the PUT and never overwrites a held identity without "Replace"; `currentCopy` uses the vault
  copy only while the server lists it), `keyService.ts` `deferred` (SSO stewards share on a click),
  `components/DeviceLink.tsx`. Verify `TestSSOUserStepUp*`, `TestSSOStepUpScopeIsBoundToTheGrant`,
  `TestSSOSessionCreatesDeviceOnlyIdentity`, `TestDeviceOnlyIdentityIsNeverWrappedByAPassword`,
  `TestSSOStewardSharesKeysAfterActionStepUp`, `TestSSOGrantIsRecheckedInTheWriteTransaction`, `TestLink*`,
  `TestSSOAccountLinksASecondBrowser`, `TestGCDeletesExpiredLinkRequests`, `go test ./internal/teamkeys`,
  `npm test` (linking, linkFlow, storage, identity, keyService, outbound) and `npm run e2e --prefix web`.
```

- [ ] **Step 4: `CHANGELOG.md`.** Under Unreleased, first:

```markdown
- Team keys phase 3c: link a new browser to your account from one you already use. Both screens
  show a six-digit check code; your encryption key moves only after you confirm it matches on both,
  and KyNotes relays it encrypted. Accounts that sign in only through single sign-on can now set up
  an encryption key (confirmed with KySignOn), receive team keys, and, as team owners, share them
  with "Share keys". Browsers on HTTPS store your key encrypted under a browser key that pages
  cannot export; this does not protect it from someone who can read the browser's profile on disk,
  so use "Forget this device" on shared computers (plain-HTTP sites store it unencrypted, and
  Settings says so). Link requests are limited at the device-pairing rate
  (`ratelimit.pairing_per_hour`, own bucket). Migration `0024` adds `link_requests` and the step-up scope.
```

- [ ] **Step 5: DOX closeout.** Re-read `../AGENTS.md`, then `AGENTS.md`.
  - `internal/backup/AGENTS.md` is unchanged: capsules copy the whole database, so link requests are included, expire within minutes and hold no key material.
  - `FRONTEND_IMPLEMENTATION_PLAN.md` is unchanged: it has no identity or linking text.

  Note both in the PR.

- [ ] **Step 6: Commit.**

```bash
git add -A
git commit -m "docs: team keys P3c contracts, spec and DOX; embedded bundle"
```

### Task 12: Browser check: link a second browser of the same account

**Files:** Modify `web/e2e/team-keys.e2e.ts`, `UI-VERIFICATION.md`.

**Interfaces:**
- Consumes: the Task 10 UI strings, the existing helpers `person`, `signIn`, `openTeam`, `readPage`, `ownSettings` and `withDialog`, and the constants `TEAM` and `OWN`.

- [ ] **Step 1: Helpers.** Replace `Vault` and `vaultOf`. The identity is now sealed, and is opened in the page with its device key, as the app does it:

```ts
type Vault = { authSecret: string; sealed: boolean; extractable?: boolean; identity?: { deviceId: string; publicKey: number[]; privateKey: number[] } };

/** This browser's keys vault record; a sealed identity is opened in the page with its device key. Never creates the database. */
function vaultOf(page: Page) {
  return page.evaluate(() => new Promise<Vault | null>((resolve, reject) => {
    const open = indexedDB.open("kynotes-web");
    open.onupgradeneeded = () => open.transaction!.abort(); // not created yet: leave it to the app
    open.onerror = () => resolve(null);
    open.onsuccess = () => {
      const db = open.result;
      if (!db.objectStoreNames.contains("keys")) { db.close(); resolve(null); return; }
      const all = db.transaction("keys").objectStore("keys").getAll();
      all.onsuccess = async () => {
        db.close();
        type Stored = { userID: string; deviceId: string; publicKey: Uint8Array; privateKey?: Uint8Array; sealed?: Uint8Array; deviceKey?: CryptoKey };
        const row = (all.result as Array<{ authSecret: string; identity?: Stored }>)[0];
        if (!row) { resolve(null); return; }
        const stored = row.identity;
        if (!stored) { resolve({ authSecret: row.authSecret, sealed: false }); return; }
        try {
          const privateKey = stored.sealed && stored.deviceKey
            ? new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: stored.sealed.slice(0, 12), additionalData: new TextEncoder().encode(`kynotes/device-identity/v1|${stored.userID}|${stored.deviceId}`) }, stored.deviceKey, stored.sealed.slice(12)))
            : stored.privateKey!;
          resolve({ authSecret: row.authSecret, sealed: Boolean(stored.sealed), extractable: stored.deviceKey?.extractable, identity: { deviceId: stored.deviceId, publicKey: [...stored.publicKey], privateKey: [...privateKey] } });
        } catch (error) { reject(error); }
      };
    };
  }));
}

/** Removes the identity from this browser's vault, as on a browser that never held it. */
const dropVaultIdentity = (page: Page) => page.evaluate(() => new Promise<void>((resolve, reject) => {
  const open = indexedDB.open("kynotes-web");
  open.onerror = () => reject(open.error);
  open.onsuccess = () => {
    const tx = open.result.transaction("keys", "readwrite");
    const store = tx.objectStore("keys");
    const all = store.getAll();
    all.onsuccess = () => { for (const row of all.result as Array<Record<string, unknown>>) { delete row.identity; store.put(row); } };
    tx.oncomplete = () => { open.result.close(); resolve(); };
    tx.onerror = () => reject(tx.error);
  };
}));

const LINK_BANNER = /This browser does not hold your encryption key/;

/** Starts a link on second (from the workspace banner the first time), approves it in editor's Settings, and returns both check codes. */
async function linkOnce(editor: Person, second: Person, fromBanner: boolean) {
  if (fromBanner) await second.page.locator(".conflict-banner").getByRole("button", { name: "Link this browser" }).click();
  await second.page.locator("#link-this-browser").getByRole("button", { name: "Link this browser" }).click();
  const request = (await second.page.locator("#link-this-browser .link-code").textContent())!.trim();
  await editor.page.goto("about:blank");
  await editor.page.goto("/");
  await editor.page.getByRole("button", { name: "Settings" }).click();
  await editor.page.locator("#link-devices .pin-row", { hasText: request }).getByRole("button", { name: "Approve…" }).click();
  const code = async (page: Page) => {
    const shown = page.locator(".check-code");
    await expect(shown).toBeVisible({ timeout: 30_000 });
    return (await shown.textContent())!.trim();
  };
  return { editor: await code(editor.page), second: await code(second.page) };
}
```

- [ ] **Step 2: The P3c steps.** In the test, create a fifth person `const second = await person(browser);`, add it to the `unexpected` check loop, and pass it to `scenario`. At the end of `scenario`, after the P3b call, add `await p3c(editor, second, cid);`. Then add:

```ts
async function p3c(editor: Person, second: Person, cid: string) {
  // A second browser of the editor's account that does not hold the key (as a single sign-on browser would not).
  await signIn(second.page, "editor", OWN);
  await expect.poll(() => vaultOf(second.page), { timeout: 30_000 }).toMatchObject({ identity: expect.anything() });
  await dropVaultIdentity(second.page);
  await second.page.goto("about:blank");
  await second.page.goto(`/#/${cid}`);
  await expect(second.page.getByText(LINK_BANNER)).toBeVisible();
  await expect(second.page.locator(".workspace-title")).toHaveText(`Notebook ${cid.slice(4, 10)}`);

  // 1. A relay that swaps the approver's one-time key: the two screens show different codes, and no key leaves.
  const sent: string[] = [];
  editor.page.on("request", (request) => { if (/\/api\/v1\/me\/link-requests\/lnk_[0-9a-z]+\/approve$/.test(request.url())) sent.push(request.url()); });
  await editor.page.route("**/api/v1/me/link-requests/*/claim", (route) => route.continue({ postData: JSON.stringify({ approverKey: Buffer.alloc(32, 9).toString("base64") }) }));
  let codes = await linkOnce(editor, second, true);
  expect(codes.editor).not.toBe(codes.second);
  await editor.page.getByRole("button", { name: "Codes differ" }).click();
  await expect(second.page.getByText(/This link request ended/)).toBeVisible({ timeout: 30_000 });
  expect(sent).toEqual([]);
  await editor.page.unroute("**/api/v1/me/link-requests/*/claim");

  // 2. The honest link: one code on both screens, confirmed on both; the key arrives sealed for this browser.
  codes = await linkOnce(editor, second, false);
  expect(codes.second).toBe(codes.editor);
  await second.page.getByRole("button", { name: "Codes match", exact: true }).click();
  await editor.page.getByRole("button", { name: "Codes match — send key" }).click();
  await expect(second.page.getByText("Linked. This browser now holds your encryption key.")).toBeVisible({ timeout: 30_000 });
  expect(sent).toHaveLength(1);
  const linked = (await vaultOf(second.page))!;
  expect(linked).toMatchObject({ sealed: true, extractable: false });
  expect(linked.identity!.privateKey).toEqual((await vaultOf(editor.page))!.identity!.privateKey);

  // 3. The linked browser opens the team's keys: it reads what the owner wrote; both show one fingerprint.
  await openTeam(second.page, TEAM, cid);
  await expect(second.page.getByText(LINK_BANNER)).toHaveCount(0);
  await readPage(second.page, "Owner page", ["owner comment"]);
  expect((await ownSettings(second.page)).fingerprint).toBe((await ownSettings(editor.page)).fingerprint);

  // 4. Forget this device deletes the sealed key and its device key together.
  await second.page.getByRole("button", { name: "Settings" }).click();
  await second.page.getByRole("button", { name: "Forget this device & sign out" }).click();
  await expect.poll(() => vaultOf(second.page)).toBeNull();
}
```

  Selectors follow the Task 10 strings. If the UI moved, fix the selectors only, never the assertions. If the editor is no longer a member of `TEAM` at this point in the P3b scenario, make `p3c` link the owner's account instead (sign `second` in as `owner` with `OWN`), keeping every assertion.

- [ ] **Step 3: Run.** After Task 11's bundle sync, run `npm run e2e --prefix web`. Expected: `1 passed`. Each run needs a fresh server.

- [ ] **Step 4: Visual pass (Playwright MCP, scratch server only).** Check at 1280×900 and 390×844, in Busnes Light and Dark:
  - The link banner.
  - The newcomer card while waiting (request code) and with the check code (both buttons).
  - The "Link another browser" card with one request row and with the check code.
  - The SSO "Set up encryption key" banner (render it by stubbing `session` with `sso: true` in a scratch run).
  - Nothing may overflow at 390 px, and the check code must stay on one line.

  Save the screenshots next to the existing ones as `docs/team-keys-p3c-*.png`. Add a "Team keys P3c" section to `UI-VERIFICATION.md` with the capture conditions, matching the P3b section.

- [ ] **Step 5: Commit.**

```bash
git add web/e2e/team-keys.e2e.ts UI-VERIFICATION.md docs
git commit -m "web: browser check for linking a second browser of one account"
```

### Task 13: Final verification

- [ ] **Step 1:** Run `go build ./... && go vet ./... && test -z "$(gofmt -l .)" && go test -race ./... && govulncheck ./...`.
- [ ] **Step 2:** Run `cd web && npm test && npm run build && node src/ky-ui/check-vendor.mjs && cd .. && diff -qr web/dist internal/web/dist && npm run e2e --prefix web`.
- [ ] **Step 3: Mutations.** Start from a clean tree. Apply each mutation alone, run the named test, confirm it fails, then revert it with `git checkout -- <file>`. Rebuild and re-sync the bundle before each e2e mutation. Paste the failures into the PR.

| Mutation | Must fail |
|---|---|
| `sso_stepup.go` `CompleteSSOStepUp`: delete `if scope == stepUpAdmin && !identity.AppAdmin { … }` | `TestSSOStepUpScopeIsBoundToTheGrant` |
| `CompleteSSOStepUp`: `scope == stepUpAdmin &&` → `true &&` | `TestSSOUserStepUpNeedsNoAdminRole` |
| `consumeSSOStepUp`: drop ` AND scope=?` (and its argument) | `TestSSOStepUpScopeIsBoundToTheGrant` |
| `sso_routes.go`: step-up start back to `auth.RequireAdmin` | `TestSSOUserStepUpNeedsNoAdminRole` |
| `RecheckUserActionTx`: SSO branch `return nil` | `TestSSOGrantIsRecheckedInTheWriteTransaction` |
| `identity_routes.go`: SSO case accepts `identityWrapAlg` too | `TestSSOSessionCreatesDeviceOnlyIdentity` |
| `identity_routes.go`: `adminKnown != 0 && !sso` → `adminKnown != 0` | `TestSSOSessionCreatesDeviceOnlyIdentity` |
| `auth_routes.go`: count all identities (drop `AND wrap_alg=?`) | `TestDeviceOnlyIdentityIsNeverWrappedByAPassword` |
| `teamkeys_routes.go` rotation: `RequireUserActionStepUp` → `RequireUserStepUp` | `TestSSOStewardSharesKeysAfterActionStepUp` |
| `claimLink`: drop ` AND newcomer_session_id<>?4` | `TestLinkRelayHandsOverOnlyPublicKeys` |
| `claimLink`: drop ` AND approver_session_id IS NULL` | `TestLinkRelayHandsOverOnlyPublicKeys` |
| `claimLink`: drop `+liveNewcomer` | `TestLinkRequestRefusals` |
| `claimLink`: drop ` AND user_id=?3` | `TestLinkRequestRefusals` |
| `claimLink`: drop ` AND expires_at>?1` | `TestLinkRequestRefusals` |
| `revealLink`: skip the commitment comparison | `TestLinkRequestRefusals` |
| `revealLink`: drop ` AND newcomer_session_id=?4` | `TestLinkRelayHandsOverOnlyPublicKeys` |
| `revealLink`: drop `+liveApprover` | `TestLinkRequestRefusals` |
| `createLink`: delete the `pending >= linkMaxPending` check | `TestLinkRequestRefusals` |
| `createLink`: delete the same-session `DELETE` | `TestLinkRequestRefusals` |
| `createLink`: delete the `identities == 0` check | `TestLinkRequestRefusals` |
| `approveLink` route: `RequireUserActionStepUp` → `session` | `TestLinkApprovalNeedsStepUpAndIsCollectedOnce` |
| `approveLink`: drop ` AND approver_session_id=?4` | `TestLinkApprovalNeedsStepUpAndIsCollectedOnce` |
| `approveLink`: drop ` AND bundle IS NULL` | `TestLinkApprovalNeedsStepUpAndIsCollectedOnce` |
| `approveLink`: drop `+liveNewcomer` | `TestLinkApprovalNeedsTheNewcomerLive` |
| `collectLink`: skip the `DELETE` | `TestLinkApprovalNeedsStepUpAndIsCollectedOnce` |
| `collectLink`: drop ` AND newcomer_session_id=?4` | `TestLinkApprovalNeedsStepUpAndIsCollectedOnce` |
| `ratelimit.go`: delete the `link` case | `TestLinkCreationIsRateLimitedPerAccount` |
| `gc.go`: delete the `link_requests` delete | `TestGCDeletesExpiredLinkRequests` |
| `deleteIdentityTx`: delete the `link_requests` delete | `TestLinkRequestsDieWithTheIdentity` |
| `linking.ts` `checkCode`: drop `key32(approverKey)` from the hash | `linking.test.ts` "matches the Go vectors…" and "changes the check code…" |
| `linking.ts` `aad`: drop `idBytes("lnk", c.requestID)` | `linking.test.ts` "matches the Go vectors…" |
| `pollNewcomerLink`: skip the changed-approver-key check | `linkFlow.test.ts` "refuses an approver key that changes after the code was shown" |
| `pollNewcomerLink`: reveal before `if (!state.approverKey) return` | `linkFlow.test.ts` "reveals the newcomer key only after the approver's key arrived" |
| `revealedLink`: compare with `fromBase64(row.commitment)` instead of `link.commitment` | `linkFlow.test.ts` "refuses a newcomer key that does not match the commitment seen before claiming" |
| `finishNewcomerLink`: skip the confirmation check | `linkFlow.test.ts` "shows one code on both sides…" |
| `finishNewcomerLink`: skip the public key comparison | `linkFlow.test.ts` "refuses a bundle holding another key…" |
| `startNewcomerLink`: skip `canKeep` | `linkFlow.test.ts` "creates no request when this browser cannot keep the key" |
| `approveLink`: skip its own confirmation check | `linkFlow.test.ts` "sends nothing, and asks for no step-up…" |
| `sendLinkBundle`: skip `isCheckCodeConfirmation` | `outbound.test.ts` "lets a link bundle leave only with that request's check-code confirmation" |
| `linkFlow.ts` imports `approveLinkRequest` from `./api` and calls it | `outbound.test.ts` "only outbound.ts reaches the ciphertext upload API functions" |
| `storage.ts` `sealForDevice`: always return the raw `privateKey` | `storage.test.ts` "keeps the private key sealed…" |
| `storage.ts` `generateKey(…, false, …)` → `true` | `storage.test.ts` "keeps the private key sealed…" |
| `storage.ts` `openForDevice`: skip the public key comparison | `storage.test.ts` "returns nothing for a sealed copy…" |
| `storage.ts` `getIdentityKey`: return pending identities | `storage.test.ts` "hides a pending identity…" |
| `storage.ts` `storeIdentityKey`: ignore `expected` | `storage.test.ts` "writes with an expected identity only while the vault still holds it" |
| `settleSSOIdentity`: pending save without `local ?? null` | `identity.test.ts` "never overwrites a key another tab kept after this run read the vault" |
| `settleSSOIdentity`: `if (local?.deviceId && !replace)` → `if (false)` | `identity.test.ts` "never replaces an identity this browser holds unless asked" |
| `settleSSOIdentity`: `PUT` before saving the pending key | `identity.test.ts` "keeps the new key on this browser before the server learns it" |
| `currentCopy`: return `local` whenever it has a device ID | `identity.test.ts` "is the vault copy only while the server lists it…" |
| `ensureIdentity`: `unlock` → `openIdentity` | `identity.test.ts` "are never unlocked or re-wrapped by a password" |
| `keyService.ts` `plan`: `return caller.canWrap \|\| … ? work : idle` → `return work` | `keyService.test.ts` "writes nothing, reports the waiting work…" |
| `DeviceLink.tsx` "Codes differ" on the approver calls `send()` | e2e step 1 (`sent` is not empty) |

Expected survivors (record them in the PR if they survive):
- `liveStepUpSession`'s admin clause in `consumeSSOStepUp`. `RequireAdmin` runs first on every admin route, so only a race between the two would reach it; it is defence in depth.
- Dropping the server-side commitment check while the approver-side check stays. `TestLinkRequestRefusals` fails, but the e2e does not: the approver's own check is the user-facing gate, and the server's is defence in depth.

- [ ] **Step 4:** Open the PR with the `pull-request` skill, stacked on `feat/team-keys-p3b` (PR #40). In the body, include:
  - The resolved ambiguities and the four items needing Yoshi's decision.
  - The mutation evidence and the e2e result.
  - The docs left unchanged, and why.
  - The SSO-only e2e gap: the browser check links a password account whose browser has no key. The SSO paths are proven by the Go `ssoDo` tests against a real OIDC fixture and by the vitest flow tests, because e2e has no IdP.
