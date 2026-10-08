# Team Keys: Remove the Legacy Login-Derived Content Key — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every notebook, personal and team, is keyed by a random container key from the moment it is created, and the login-derived key (`HKDF(authSecret, containerID)`) never reads or writes content again, in the browser, on the server's rules, or in the probe.

**Architecture:** Three cuts, server first. (1) The server accepts a content write, a name, or an envelope only for a container that already has a key (`shared_generation > 0`), creation carries no name, and the write header moves to `shared-v2` so tabs still holding the login-key read path are refused. (2) The web client loses P4 (the `/legacy` review, closure, reopen), the pre-P5 shims (owner-unknown entries, the login-key ownership proof, the password-change re-seal), and finally the login key itself: `readKeys` returns only the container key for the row's generation, and `KeyRef` becomes a branded type that only `keyring.ts` can mint. (3) The probe and the e2e follow, and the docs drop every residual that no longer exists.

**Tech Stack:** Go 1.26 (`net/http`, SQLite via `modernc`), TypeScript/React (Vite, vitest, fake-indexeddb, `@noble/ciphers`/`@noble/curves`), `@playwright/test`. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-07-team-keys-design.md` (§0–§8 and every "as built" block). This plan implements a decision recorded on top of it:

> **User decision (Yoshi, 2026-10-08).** KyNotes has never been live, so breaking changes are allowed. Every notebook, personal and team, uses only container keys from the moment it is created. The login-derived key must never read or write content again. Delete P4's pre-sharing review and closure machinery (`/legacy`, the review dialog, closure and reopen, the reopen mark, the "not end-to-end verified" labels), `legacyRow` and the legacy branch of `readKeys`, and the pre-P5 compatibility shims (re-sealing old cache, queue and upload entries; the "reload old tabs" upgrade notes).

**Where:** worktree `/home/yoshi/git/busnes.app/kynotes-server-teamkeys5`, branch `feat/team-keys-p5`, on top of `eddff1d` (P5 Tasks 1–10). This plan replaces P5 Task 11 (the e2e, stopped) and P5 Task 12 (verification, not run). Read `.superpowers/sdd/2026-10-08-team-keys-p5/progress.md` first.

**Evidence status:** not prototyped. Line numbers and code were read from `eddff1d`. No block has been compiled or run; each task's own test step is the first proof. If a block does not compile, fix the code and keep the test's assertions.

---

## Global Constraints

| Item | Exact value |
|---|---|
| Content keys | Only container keys (`CK[container, generation]`, random 32 bytes, minted by `POST /containers/{id}/key-rotations`) and the identity's waiting key (`HKDF-SHA256(identity.privateKey, salt = empty, info = "kynotes/waiting/v1", 32)`, generation `0`, local only) ever seal or open content. `authSecret` keeps only: the login verifier (`kynotes/auth/v1`), local step-up, the vault "device key" record, and the shared PBKDF2 pass that yields `userKEK` (`kynotes/user-kek/v1`) |
| `KeyRef` | `Uint8Array & { readonly [contentKey]: true }`, made only by `asContentKey(bytes)` (crypto.ts, refuses length ≠ 32). Non-test callers of `asContentKey` live only in `web/src/keyring.ts`. No non-test file casts `as KeyRef` |
| Read rule | `readKeys(container, ring, generation, floor)` returns `[ring.get(generation)]` when `generation` is an integer ≥ `max(container.sharedGeneration, floor.shared)` > 0 and the ring holds it, else `[]`. Nothing else is ever tried. `ownCopyKeys(…, waiting)` adds exactly one case: a `WAITING_GENERATION` (0) entry this browser stored opens only with `waiting` |
| Server write rule | Object save, comment create, attachment finalize, container meta `PATCH` and envelope `PUT` need `shared_generation > 0`; otherwise `409 already_exists` "key rotation incomplete". Content writes and meta `PATCH` also need `X-Kynotes-Key-Scheme: shared-v2` (`409 already_exists` "this notebook uses shared keys: reload the page" otherwise). The device-row gate (`missingEnvelopesSQL`) is gone |
| Creation | `POST /api/v1/containers` and `POST /api/v1/admin/teams` refuse a non-empty `metaCiphertext` with `400 invalid_request`. A container is created at `key_generation = 1`, `shared_generation = 0`; its first rotation makes generation 2 its first keyed generation (`shared_generation = 2`) |
| Removed routes | `GET /api/v1/containers/{id}/legacy` and `PUT /api/v1/comments/{id}`, with their rate-limit case. Unregistered: an unauthenticated request gets `404`/`405`, never `401` |
| Migrations | None added, none edited. `0021`–`0022` are on `master` (do not touch). `0023`–`0025` exist only on unmerged branches and all still carry meaning (`invited_by`, link requests and step-up scope, the recovery copy), so they stay as they are. `containers.shared_generation` and `object_versions.author_user_id` (both `0022`) stay |
| Local store | IndexedDB `kynotes-web` version **6**. Upgrading from any version below 6 deletes and recreates the `notes`, `pending` and `uploads` stores (keyPaths `["owner","id"]`, `["owner","id"]`, `"uploadId"`) and removes `localStorage["kynotes-pending-saves"]`. The `keys` vault store is kept. `PendingSave.owner` is required |
| Key memory | `KeyFloor = { shared?: number; generation?: number }`; `KeyState = KeyFloor & { mark: number; digests: Record<number, string> }`. Stored `closed`/`reopened` from older builds are ignored on read and dropped on the next write |
| Header value | `X-Kynotes-Key-Scheme: shared-v2` (Go `keySchemeShared`, web `KEY_SCHEME`) |
| Error codes | No new codes. Existing messages unchanged |
| UI strings removed | `UNVERIFIED`, `UNVERIFIED_SIDE_EFFECT`, `UNVERIFIED_SUBPAGES`, "Not verified", " · not verified", the whole LegacyReview copy (`LEGACY_CLOSED`, `checkFailure`, `shareOutcomeText`, …), `PASSWORD_CHANGE_NOTE`, `passwordChangeWarning(n)`, `passwordChangedStatus(n)`, and the Unsent edits "owner unknown"/"older edit(s)" paragraphs. Every other string is unchanged |
| Unchanged (checked) | Envelope v2, link bundle, recovery code and copy, `openKeyring`, pins, `guardContainer`, `writeKey`, `waitingKey`, `planSweep`, `createNamed`, the rotation route, the identity routes, `password_admin_known`, `CanvasPage.tsx`, `document.ts` (its "legacy" is the Tiptap body format, unrelated) |
| Out of scope | Removing the SSO "master password" prompt (see Resolved ambiguity 10); phone pairing; D-P5-1/D-P5-2 |

## Inventory

Decisions: **delete**, **simplify** (keep the thing, drop the legacy part), **keep**. Lines are at `eddff1d`.

### Uses of `authSecret` that stay (real work)

| Where | What | Decision |
|---|---|---|
| `web/src/crypto.ts:71-109` | `deriveLoginKeys`/`deriveAuthSecret`: one PBKDF2 pass, `authSecret` (verifier) and `userKEK` | keep |
| `web/src/api.ts:76-150` | `setupInit`, `login`, `createAdminUser`, `stepUp` send it | keep (login proof) |
| `web/src/identity.ts:16-74`, `web/src/recovery.ts:282-294` | step-up before identity create/re-wrap/reset | keep |
| `web/src/storage.ts:211-236,251,300-325` | vault "device key" (`storeDeviceKey`, `getDeviceKey`, `vaultReady`, "only beside a device key") | keep (silent step-up, one-click return) |
| `web/src/main.tsx:176,210,239,256,392-433,836,3047-3087,3163` | `AuthState.authSecret`, login/setup, step-up, password change, admin user create | keep |
| `cmd/kynotes-probe/main.go:186-215,336-360` | login, step-up, password change | keep (and the probe gains `userKEK`, Task 3) |

### Does anything else still need the login-derived content key?

| Candidate | Finding | Decision |
|---|---|---|
| Personal container names from before the container key | P5 `createNamed` (`main.tsx:1597-1612`) mints before naming; the server stored names at creation only because the route accepted `metaCiphertext`. After Task 1 the server refuses a name at creation and while unkeyed | nothing left |
| Admin-created team names | P5 ruling 18: minted and named by `createNamed` (`main.tsx:1639`). `AdminTeams` still *reads* never-shared names with the login key (`main.tsx:3238-3274`) | simplify: admin pages show only names the workspace decrypted (`knownNames`) |
| Waiting key | `keyring.ts:227` `waitingKey` is identity-derived; `localKeyFor` (`main.tsx:726`) never falls back to the login key | nothing left |
| Waiting edits from before P5 | `passwordChange.ts:35-75` `resealWaitingEdits` re-seals login-key queue entries | delete (Task 5 drops those entries) |
| Unstamped queue and cache entries | `stuckEdits.ts:47-58` `drainable`, `storage.ts:114-132` `getNote(…, opensLegacy)`: the login key proves ownership | delete (Task 5) |
| Name re-seal after a mint | `main.tsx:944-947` tries the login key to compare with the shown name | simplify: container keys only |
| SSO sessions' typed "master password" | `main.tsx:423-427` derives an `authSecret` the server never verifies; it was the SSO user's legacy content key. Afterwards it only creates the vault record | keep, out of scope (Resolved ambiguity 10) |
| Probe content | `cmd/kynotes-probe` writes at generation 1 of a never-keyed container (device gate) | simplify: keyed from creation (Task 3) |

### Server

| Where | What | Decision |
|---|---|---|
| `internal/httpapi/teamkeys_routes.go:31-34` | `keySchemeHeader`, `keySchemeShared = "shared-v1"` | simplify: `"shared-v2"`, comment rewritten |
| `teamkeys_routes.go:168-189` | `putGenerationTx` legacy branch (`shared == 0` → current generation) | simplify: unkeyed → `errKeyRotationIncomplete` |
| `teamkeys_routes.go:274-320` | `PUT /api/v1/comments/{id}` (only caller: P4 re-seal) | delete |
| `teamkeys_routes.go:321-385` | `GET /api/v1/containers/{id}/legacy` | delete |
| `teamkeys_routes.go:414-417` | `missingEnvelopesSQL` (device gate for unkeyed containers) | delete |
| `teamkeys_routes.go:420-453` | `checkWriteGate` legacy branch | simplify |
| `teamkeys_routes.go:604-631` | `legacyListMax`, `legacyRows` | delete |
| `internal/httpapi/ratelimit.go:104-107` | `legacy` bucket case (reuses `link_poll_per_minute`) | delete |
| `internal/httpapi/container_routes.go:64-67,84,102` | create stores client `metaCiphertext` | simplify: refuse non-empty, store empty |
| `container_routes.go:130-150` | meta `PATCH`: no header and no generation needed while `shared == 0` | simplify: header always, `shared > 0` and current generation always |
| `internal/httpapi/admin_routes.go:41-68` | `POST /admin/teams` stores client `metaCiphertext` | simplify: refuse non-empty, store empty |
| `container_routes.go:19-40`, `admin_routes.go:71-86` | `sharedGeneration` in responses | keep (0 = no key yet; the client's rollback floor) |
| `internal/storage/migrations/0022_team_keys.sql` | `shared_generation`, `author_user_id` | keep (on master) |
| `internal/storage/migrations/0023`–`0025` | inviter, link requests/scope, recovery copy | keep |

### Web

| Where | What | Decision |
|---|---|---|
| `web/src/crypto.ts:32,158-162` | `hexBytes`, `KeyRef = Uint8Array`, `legacyKeyRef` | delete `legacyKeyRef` (and `hexBytes` if unused); brand `KeyRef`, add `asContentKey` |
| `web/src/keyring.ts:30-37` | `KeyState.reopened` | delete |
| `keyring.ts:38-54` | `KeyFloor.closed`, `closedOf` | delete |
| `keyring.ts:56-81` | `ReopenConfirmation`, `confirmReopenLegacy`, `isReopenConfirmation`, `consumeReopenConfirmation` | delete |
| `keyring.ts:89-93` | `mergeFloor` closure handling | simplify |
| `keyring.ts:213-217` | `WAITING_GENERATION` comment ("login-derived key only before P5") | simplify comment |
| `keyring.ts:229-234` | `legacyKeys` | delete |
| `keyring.ts:236-252` | `readKeys` legacy branch and `legacy` parameter | simplify |
| `keyring.ts:254-261` | `localReadKeys` | delete; replaced by `ownCopyKeys` (waiting key only) |
| `keyring.ts:263-271` | `legacyRow` | delete |
| `keyring.ts:273-275` | `movesLabelledSubpage` | delete |
| `keyring.ts:277-281` | `copyableConflicts` | delete |
| `keyring.ts:15,346` | `Keyring`, `newContainerKey` | simplify: `KeyRef` values via `asContentKey` |
| `web/src/migration.ts` (392 lines), `migration.test.ts` | P4 review, approval, re-seal, auto-close | delete |
| `web/src/components/LegacyReview.tsx` (196), `LegacyReview.test.tsx` | review dialog, banner, Stop/Show again | delete |
| `web/src/floors.ts:14-77,88-98,106` | closure epochs, `adoptStored`, `setClosureReader`, `closeFloorIn`, `reopenFloorIn`, closure in messages | delete; raise-only floors stay |
| `web/src/observe.ts:4,29-52` | `ClosureSink`, `Closed`, `closeLegacy` | delete |
| `web/src/storage.ts:3` | imports `closedOf`, `consumeReopenConfirmation`, `ReopenConfirmation` | delete |
| `storage.ts:10-27` | optional `owner`, `UNKNOWN`, `keyOf`/`toRow`/`fromRow` | simplify: owner required |
| `storage.ts:29-39,41-66` | v5 `ownerKeyed` upgrade, `localStorage` queue import | delete; v6 upgrade |
| `storage.ts:114-132` | `getNote(…, opensLegacy)` claim of owner-unknown rows | simplify |
| `storage.ts:134-143` | `ownerUnknownNotes` | delete |
| `storage.ts:153-163,169-196` | owner-unknown handling in `pendingSaves`/`replaceQueuedSave` | simplify |
| `storage.ts:300` | comment naming `closeLegacyStored` | simplify comment |
| `storage.ts:412-438` | `getKeyState`/`storeKeyState` carry `closed`/`reopened` | simplify |
| `storage.ts:440-457,459-496` | `updateKeyState`, `ClosureStored`, `closeLegacyStored`, `reopenLegacy` | delete |
| `web/src/drain.ts:1-55` | `legacy` parameter, `legacyRow`, unstamped branch, `localReadKeys` | simplify |
| `web/src/stuckEdits.ts:12-77` | `unowned`/`unknown`/`sealed`, `drainable`, `unknownDrafts`, `opensLegacy` | simplify/delete |
| `web/src/passwordChange.ts:1-75` | `legacyAtRisk`, `passwordChangeWarning`, `PASSWORD_CHANGE_NOTE`, `passwordChangedStatus`, `resealWaitingEdits`, acknowledgement | delete; keep `passwordChangeProblem(next, confirmation)` |
| `web/src/api.ts:11-14,251` | comments mentioning `legacyRow`/legacy key | simplify comments |
| `api.ts:30` | `KEY_SCHEME = "shared-v1"` | simplify: `"shared-v2"` |
| `api.ts:188-210` | `LegacyRows`, `wireID`, `isID`, `legacyRows` | delete |
| `api.ts:229-230` | `rewriteComment` | delete |
| `api.ts:275` | `detachAttachment` (only caller: `migrationAPI`) | delete |
| `web/src/outbound.ts:49-52` | `sendCommentRewrite` | delete |
| `web/src/components/UnsentEdits.tsx` | `legacyKey` prop, owner-unknown lists | simplify |
| `web/src/components/SectionTabs.tsx` | `unverified` prop | delete |
| `web/src/styles.css:371-379` | `.legacy-*` rules | delete |
| `web/src/main.tsx:17,70,77-80,101,128-129` | imports of the removed symbols | delete |
| `main.tsx:187-188,196-199` | `PlainComment.unverified`, `UNVERIFIED*` | delete |
| `main.tsx:682-684` | `legacy`, `ownsCached` | delete |
| `main.tsx:706-715` | `readKeysFor` (legacy), `localReadKeysFor`, `legacyRowFor` | simplify `readKeysFor`; replace `localReadKeysFor` by `ownCopyKeysFor`; delete `legacyRowFor` |
| `main.tsx:744-762` | `unverified` set, `markLegacy`, `legacyCheck`, `legacyOutcome` | delete |
| `main.tsx:850-853` | `closureSink`, `setClosureReader` effect | delete |
| `main.tsx:944-951` | `resealName` tries `legacyKeys` | simplify |
| `main.tsx:1309-1349` | `readContainerObjects` `legacyRead`, `ownsCached` | simplify |
| `main.tsx:1367-1459` | `reviewAPI`, `checkLegacy`, `stopLegacy`, `migrationAPI`, `shareLegacy`, `reopenLegacyReads`, closure reload effect | delete |
| `main.tsx:1476-1479,1495,1498` | load resets/`markLegacy`/`checkLegacy` call | delete |
| `main.tsx:1566,1723,1918` | comment label, `markLegacy` after saves | delete |
| `main.tsx:1795-1801` | `drainable` with the login key, owner stamping | simplify |
| `main.tsx:1866,2293` | `readyToSend`/`attachmentStep` `legacy` argument | simplify |
| `main.tsx:1937-1945,1971-1977` | `explicit` parameter of `updateStructure`/`placePage` (exists only for labels) | delete parameter and the `, false` arguments at its callers |
| `main.tsx:1964-1969` | `otherTabDraft` (`ownsCached`, `localReadKeysFor`) | simplify |
| `main.tsx:2127-2130` | `movesLabelledSubpage` refusal | delete |
| `main.tsx:2194-2196,2210-2249` | `markLegacy` after reload; `copyableConflicts`, `unverifiedKept` | simplify: copy every unresolved conflict |
| `main.tsx:2669,2701-2705,2799,2873-2874,2943,2980` | `unverified` prop, banner, labels | delete |
| `main.tsx:3008-3013,3028,3047-3100` | `legacyKey`, `teamKeys`, `atRisk`, `waiting` props; password warning, acknowledgement, re-seal | simplify |
| `main.tsx:3238-3274` | `AdminTeams` login-key name reads | simplify |
| `main.tsx:3491-3554,3682` | `SettingsView` `legacyKey`, `teamKeys`, `exportWaiting` | simplify |
| `web/src/legacyWiring.test.ts` | P4 wiring tests (lines 15-91) and the acknowledgement test (145-153) | delete those; rename file to `workspaceWiring.test.ts` |
| `web/src/document.ts`, `CanvasPage.tsx`, `BlockNoteEditor.tsx`, `pages.ts` | "legacy" Tiptap/markdown body formats | keep (unrelated) |

### Probe and tests

| Where | What | Decision |
|---|---|---|
| `cmd/kynotes-probe/main.go:95-148` | `takeOverPassword` detects an administrator-set password with an empty envelope `PUT` on an unkeyed container | simplify: detect it on identity creation |
| `main.go:186-206` | `changePassword` never re-wraps ("never creates a password-wrapped identity") | simplify: re-wraps the probe identity |
| `main.go:404-453` | device envelope at generation 1 of an unkeyed container, sender = the device | simplify: generation 2, sender = the probe identity |
| `main.go:479-485,579` | saves and finalize at generation 1, header `shared-v1` absent | simplify: generation 2, `shared-v2` |
| `internal/httpapi/teamkeys_p4_test.go` | `TestLegacyRows*` | delete |
| `teamkeys_test.go:526-551` | `TestLegacyContainersKeepTheDeviceGate` | delete |
| `teamkeys_test.go:573,597-625,738` | `TestCommentRewriteIsAuthorOnly` and rewrite cases | delete |
| `teamkeys_p3_test.go:34-75,91-127,186-188` | legacy cases (no header on unkeyed, generation-1 envelope PUT, rename without generation) | simplify |
| `integration_test.go`, `commit_share_test.go`, `upload_contract_test.go`, `privacy_test.go`, `device_contract_test.go`, `admin_team_test.go`, and every `teamkeys*_test.go` site that writes before rotating | write to unkeyed containers | simplify: `keyForTest` or rotate first |
| `web/e2e/team-keys.e2e.ts:714-949` | P4 scenario (`p4`, forged rows, closure, reopen, `/legacy` interception) | delete |
| `team-keys.e2e.ts:443-461` | P3b step 3 expects an administrator reset to delete the identity (false since P5 ruling 13) | rewrite around the self-service reset |
| `team-keys.e2e.ts:486-488` | stranded edit sealed with the login key | simplify: waiting key |

## Resolved ambiguities

### 1. `sharedGeneration` stays; its meaning narrows to "first keyed generation"
Every container is still created at generation 1 with no key, and the first rotation makes generation 2 its first keyed generation. Creating with a key in one request would change `POST /containers`, `POST /admin/teams` and the creation path in the client for no security gain: an unkeyed container can hold nothing (Resolved ambiguity 2). So the column (on `master` in `0022`), the wire field, the client floor and `guardContainer` stay. `0` now means "no key yet, nothing can be written", not "legacy". The floor still matters: a server that reports `0` or an older generation for a container this device saw keyed gets no key and paused writes.

### 2. The server refuses every write to a container without a key, and creation takes no name
`checkWriteGate`, the meta `PATCH` and envelope `PUT` refuse `shared_generation = 0`; `POST /containers` and `POST /admin/teams` refuse a non-empty `metaCiphertext`. The server cannot check what a client sealed with, but a refusal makes "nothing exists before the first key" a server invariant, so no stale or buggy tab can leave login-key ciphertext behind. The device gate for never-rotated containers (`missingEnvelopesSQL`) goes with it. Envelope `PUT` on an unkeyed container is refused too: keys are minted only by rotation.

### 3. `X-Kynotes-Key-Scheme` stays, at `shared-v2`, on every write
It was a stale-tab tripwire. Bumping the value refuses every tab still running a P3a–P5 bundle, the bundles that read with the login key and can re-seal a login-key row under a container key. It is now required on every content write and name change, which falls out of rule 2 (every writable container is keyed). Removing it would save four lines and lose that refusal.

### 4. `PUT /comments/{id}` is deleted; attach/detach and `author_user_id` stay
The comment rewrite route existed only for P4's re-seal, and no UI edits comments. Attach and detach are frozen-contract routes with other uses. `author_user_id` is on `master`, written on every save and harmless; dropping it needs a migration for nothing.

### 5. No migration
Nothing in the schema is legacy-only. `0021`–`0022` are on `master`; `0023`–`0025` carry live features. An existing development database keeps its old rows; rows sealed with a login key never open again (the server-side counterpart of Resolved ambiguity 6). The CHANGELOG tells testers to start from a fresh data directory.

### 6. The browser's cache, queue and pending uploads are dropped once
Entries from earlier builds may be sealed with the login key, and the only way to tell is to try it, which is the trial decryption this plan removes. KyNotes was never live, so the IndexedDB v6 upgrade deletes and recreates those three stores and keeps the vault (identities, pins, key memory). This is the one destructive effect; it touches only development browsers, and the CHANGELOG says so. `owner` becomes required, so the owner-unknown lists and the login-key ownership proof go.

### 7. Waiting copies open only with the waiting key, through one function
`readKeys` never returns the waiting key, so a server row labelled generation 0 opens with nothing. `ownCopyKeys` is the one path to the waiting key and is used only for entries this browser stored itself. A browser with no identity keeps no local copy and cannot edit (unchanged from P5).

### 8. `KeyRef` is branded, and the guard is the type system plus a scan
A test that greps for `legacyKeyRef` would miss a new `HKDF(authSecret, …)`. With a branded `KeyRef`, any byte array reaching `encryptNote` and friends must pass `asContentKey`, whose non-test callers are pinned to `keyring.ts`, and no non-test file may cast `as KeyRef`. The scan also pins `authSecret` to the files that do login work.

### 9. A password change no longer warns about content
Nothing depends on the password any more: container keys are wrapped to the identity, and the identity's password copy is re-wrapped in the change's transaction. The acknowledgement checkbox, the count and both notes go. `passwordChangeProblem` keeps only the mismatch check.

### 10. The SSO "master password" prompt stays for now
An SSO session without a cached device key still types a password, which derives an `authSecret` the server never verifies (`main.tsx:423-427`). It was the SSO user's legacy content key. Afterwards it only creates the vault record that `storeIdentityKey` and `vaultReady` require. Removing it changes the sign-in flow and the vault's record semantics, so it is a follow-up, not part of this cut.

### 11. Admin pages never decrypt team names
The admin's browser holds team keys only as a member. `AdminTeams` shows names the workspace already decrypted (`knownNames`) and "Unnamed" otherwise; it no longer opens anything with the login key.

### 12. The probe gets a real, password-wrapped identity
The probe must now write to a keyed container, so it needs an identity. It derives `userKEK` with `derive.AuthSecret(password, salt, iterations, "kynotes/user-kek/v1")` (the same PBKDF2 and HKDF the browser runs), wraps a fresh X25519 key with new `teamkeys.SealIdentity` (pinned by the existing identity vectors), and unwraps it on later runs from the login response. A device-only identity on the probe account is a clear error, not a silent bypass.

### 13. Stored closures are ignored, not migrated
Old vault records may carry `closed` and `reopened`. `getKeyState` returns only the four current fields and `storeKeyState` writes only those, so they disappear on the next write. No upgrade code.

### 14. The name re-seal after a re-mint compares only with container keys
`resealName` still re-seals the shown name under the new generation after a removal. It now compares that name only with names the ring's container keys open.

## Pending decisions

**Disappear** (no longer exist):
- P4 decision (1): per-device closure instead of a steward marker.
- P4 decision (2): auto-close trusts the server's list (and its P5 extension to personal notebooks).
- Every P4 known limit, the P5 limits that came from P4 (the 1000-row cap, per-open attachment downloads, "never-shared rows are not labelled", the password-change warning counting notebooks, pre-P5 queue entries under a changed password), and the §6 read-downgrade residual.
- P3c decision (2) was already resolved by P5.

**Remain for Yoshi** (unrelated to the legacy key; unchanged):
- P3c (1) raw identity on plain-HTTP origins; (3) the device-key layer; (4) an IdP operator can create an SSO account's first identity.
- D-P5-1: an administrator reset or account recovery keeps the identity.
- D-P5-2: the stricter "never password-wrap after a reset" option, not built.

**New:** none blocking. Follow-up offered: remove the SSO master-password prompt (Resolved ambiguity 10).

## Review Focus

1. **A tab still open on a P5 build after the upgrade.** It sends `shared-v1` and must get `409` "reload the page" on every write, and its IndexedDB open at version 5 fails rather than reading the recreated stores. Pinned in Task 1 (`TestEveryWriteNeedsTheCurrentKeyScheme`) and Task 5 (storage test "a v5 database opens at v6 with empty stores and its vault").
2. **A container whose creation died before its first key** (`createKeyed` could not delete it). The server must refuse every write, envelope and name there, and the owner's next open must mint. Pinned in Task 1 (`TestUnkeyedContainerRefusesEveryWrite`) and Task 6 (keyring test "an unkeyed container has no read key for any generation").
3. **A server row labelled generation 0, missing, non-integer, or below the first keyed generation.** No key at all, not the waiting key. Pinned in Task 6 (keyring tests).
4. **A browser with no identity** (no IndexedDB, or an administrator-set password): it must neither edit nor keep a local copy. Pinned in Task 6 (`ownCopyKeys` without `waiting`) and the existing `localKeyFor` wiring test.
5. **The probe on an account whose identity has no password copy** (after an administrator reset). It must stop with a named error and change nothing. Pinned by Task 3 Step 6's third run against such an account.

---

## Task 1: Server — a container takes writes only once it has a key

**Files:**
- Modify: `internal/httpapi/teamkeys_routes.go:31-34,168-189,414-453`
- Modify: `internal/httpapi/container_routes.go:55-103,104-163`
- Modify: `internal/httpapi/admin_routes.go:34-69`
- Modify: `web/src/api.ts:30`
- Create: `internal/httpapi/teamkeys_keyed_test.go`
- Modify (tests): `internal/httpapi/teamkeys_test.go`, `teamkeys_p3_test.go`, `integration_test.go`, `commit_share_test.go`, `upload_contract_test.go`, `privacy_test.go`, `device_contract_test.go`, `admin_team_test.go`, plus any other test `go test ./internal/httpapi/` names
- Modify (docs, frozen contract): `IMPLEMENTATION_PLAN.md:361,1259,1406,1692-1700,1742`, `DESIGN.md:203-230`

**Interfaces:**
- Consumes: `newTeam`, `tm.rotate`, `pairClient.save/comment/attach/do/rawWrite/stepUp`, `envJSON`, `status`, `mint`, `envelopeAlg`, `ownIdentityEnvelopeSQL`.
- Produces: `keyForTest(t *testing.T, db *sql.DB, cid string, users ...string) int64` (test helper, returns the keyed generation); `keySchemeShared == "shared-v2"`; `checkWriteGate(q rowQuerier, cid, userID string, requested int64, scheme string) error` (same signature, no device rule).

- [ ] **Step 1: Write the failing tests.** Create `internal/httpapi/teamkeys_keyed_test.go`:

```go
package httpapi

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// keyForTest gives cid a container key the way a first rotation leaves it, straight in the
// database, for tests whose subject is not the key rules: an identity row for each user that has
// none, one envelope each at the current generation, and shared_generation set to it.
func keyForTest(t *testing.T, db *sql.DB, cid string, users ...string) int64 {
	t.Helper()
	var generation int64
	if err := db.QueryRow(`UPDATE containers SET shared_generation=key_generation WHERE id=? RETURNING key_generation`, cid).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	for _, user := range users {
		var device string
		err := db.QueryRow(`SELECT id FROM devices WHERE user_id=? AND platform='identity' AND revoked_at=''`, user).Scan(&device)
		if errors.Is(err, sql.ErrNoRows) {
			device = mint(t, "dev")
			_, err = db.Exec(`INSERT INTO devices(id,user_id,public_key,fingerprint,secret_hash,platform,created_at) VALUES(?,?,?,?,'identity:test','identity','now')`, device, user, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), "test-"+device)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO key_envelopes(id,container_id,device_id,key_generation,alg,envelope,created_at) VALUES(?,?,?,?,?,?,'now')`, mint(t, "env"), cid, device, generation, envelopeAlg, bytes.Repeat([]byte{1}, 93)); err != nil {
			t.Fatal(err)
		}
	}
	return generation
}

func TestUnkeyedContainerRefusesEveryWrite(t *testing.T) {
	tm := newTeam(t)
	// The object row holds no ciphertext until a save, so creating it is not a content write.
	res := tm.editor.do(t, http.MethodPost, "/api/v1/containers/"+tm.id+"/objects", []byte(`{"kind":"note"}`), true, false)
	data, _ := io.ReadAll(res.Body)
	res.Body.Close()
	var object struct{ ID string }
	if res.StatusCode != http.StatusOK || json.Unmarshal(data, &object) != nil {
		t.Fatalf("create object=%d %s", res.StatusCode, data)
	}
	if _, code := tm.editor.save(t, tm.id, object.ID, 1); code != http.StatusConflict {
		t.Fatalf("save without a key=%d", code)
	}
	if _, code := tm.editor.comment(t, object.ID, 1); code != http.StatusConflict {
		t.Fatalf("comment without a key=%d", code)
	}
	if code := tm.editor.attach(t, tm.id, 1); code != http.StatusConflict {
		t.Fatalf("attachment without a key=%d", code)
	}
	if code, body := status(t, tm.editor.do(t, http.MethodPatch, "/api/v1/containers/"+tm.id, []byte(`{"metaCiphertext":"Y3Q=","baseVersion":0,"keyGeneration":1}`), true, false)); code != http.StatusConflict || !strings.Contains(body, "key rotation incomplete") {
		t.Fatalf("name without a key=%d %s", code, body)
	}
	tm.owner.stepUp(t)
	if code, body := status(t, tm.owner.do(t, http.MethodPut, "/api/v1/containers/"+tm.id+"/envelopes", []byte(`{"envelopes":[`+envJSON(tm.editorID, 1, 1)+`]}`), true, false)); code != http.StatusConflict {
		t.Fatalf("envelope without a key=%d %s", code, body)
	}
	// The first rotation is the only way in; afterwards the same writes pass at generation 2.
	tm.rotate(t, tm.id, 1)
	if _, code := tm.editor.save(t, tm.id, object.ID, 2); code != http.StatusOK {
		t.Fatalf("save after the first key=%d", code)
	}
	if _, code := tm.editor.comment(t, object.ID, 2); code != http.StatusOK {
		t.Fatalf("comment after the first key=%d", code)
	}
	if code := tm.editor.attach(t, tm.id, 2); code != http.StatusOK {
		t.Fatalf("attachment after the first key=%d", code)
	}
}

func TestEveryWriteNeedsTheCurrentKeyScheme(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	oid, code := tm.editor.save(t, tm.id, "", 2)
	if code != http.StatusOK {
		t.Fatalf("save=%d", code)
	}
	for _, scheme := range []string{"", "shared-v1"} {
		headers := map[string]string{"X-Kynotes-Key-Generation": "2", "X-Kynotes-Base-Version": "1"}
		if scheme != "" {
			headers[keySchemeHeader] = scheme
		}
		if code, body := tm.editor.rawWrite(t, http.MethodPut, "/api/v1/objects/"+oid, headers, "ciphertext"); code != http.StatusConflict || !strings.Contains(body, "reload") {
			t.Fatalf("save with scheme %q=%d %s", scheme, code, body)
		}
	}
	headers := map[string]string{"X-Kynotes-Key-Generation": "2", "X-Kynotes-Base-Version": "1", keySchemeHeader: "shared-v2"}
	if code, body := tm.editor.rawWrite(t, http.MethodPut, "/api/v1/objects/"+oid, headers, "ciphertext"); code != http.StatusOK {
		t.Fatalf("save with shared-v2=%d %s", code, body)
	}
}

func TestContainerCreationTakesNoName(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	if code, body := status(t, p.do(t, http.MethodPost, "/api/v1/containers", []byte(`{"kind":"workbook","metaCiphertext":"Y3Q="}`), true, false)); code != http.StatusBadRequest {
		t.Fatalf("create with a name=%d %s", code, body)
	}
	code, body := status(t, p.do(t, http.MethodPost, "/api/v1/containers", []byte(`{"kind":"workbook","metaCiphertext":""}`), true, false))
	if code != http.StatusOK || !strings.Contains(body, `"sharedGeneration":0`) || !strings.Contains(body, `"metaCiphertext":""`) {
		t.Fatalf("create without a name=%d %s", code, body)
	}
}
```

In `admin_team_test.go`, rename `TestAdminTeamCreationCreatesOwnerAndAuditEvent` to `TestAdminTeamCreationTakesNoNameAndCreatesOwner`. Before its existing request, add a request with the old named body and require `http.StatusBadRequest`; change the existing request body to `{}`; change the stored-metadata check to `len(stored) != 0` ("stored team metadata must be empty"). Keep the owner and audit checks.

- [ ] **Step 2: Run them to verify they fail.**

Run: `go test ./internal/httpapi/ -run 'TestUnkeyedContainerRefusesEveryWrite|TestEveryWriteNeedsTheCurrentKeyScheme|TestContainerCreationTakesNoName|TestAdminTeamCreationTakesNoNameAndCreatesOwner' -count=1`
Expected: FAIL (`save without a key=200`, `save with scheme "shared-v1"=200`, `create with a name=200`).

- [ ] **Step 3: The gate.** In `teamkeys_routes.go` replace lines 31-34 with:

```go
// keySchemeHeader marks a write from a client that seals content only with container keys.
// Every content write and name change must carry it; a tab from an older build is refused
// and told to reload.
const keySchemeHeader, keySchemeShared = "X-Kynotes-Key-Scheme", "shared-v2"
```

Replace `putGenerationTx` (168-189) with:

```go
// putGenerationTx is the generation a PUT envelope targets: any generation from shared_generation
// to current that already holds an envelope, so stewards backfill history for newcomers. Keys are
// minted only by key-rotations, so a container without a key yet takes no envelope here.
func putGenerationTx(tx *sql.Tx, cid string, current, requested int64) (int64, error) {
	var shared int64
	if err := tx.QueryRow(`SELECT shared_generation FROM containers WHERE id=?`, cid).Scan(&shared); err != nil {
		return 0, err
	}
	if shared == 0 {
		return 0, errKeyRotationIncomplete
	}
	if requested < shared || requested > current {
		return 0, errGenerationMoved
	}
	var held bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM key_envelopes WHERE container_id=? AND key_generation=?)`, cid, requested).Scan(&held); err != nil {
		return 0, err
	}
	if !held {
		return 0, errKeyRotationIncomplete
	}
	return requested, nil
}
```

Delete `missingEnvelopesSQL` (414-417) and replace `checkWriteGate` (420-453) with:

```go
// checkWriteGate admits a content write by userID into cid at generation requested: the writer
// sends keySchemeShared, the container has a key (shared_generation > 0), requested is its current
// generation and the writer's own identity holds an envelope there. Call it before streaming a
// body and again inside the write transaction.
func checkWriteGate(q rowQuerier, cid, userID string, requested int64, scheme string) error {
	var generation, shared int64
	err := q.QueryRow(`SELECT c.key_generation,c.shared_generation FROM containers c JOIN memberships m ON m.container_id=c.id AND m.user_id=? AND m.revoked_at='' WHERE c.id=?`, userID, cid).Scan(&generation, &shared)
	if errors.Is(err, sql.ErrNoRows) {
		return errNotMember
	}
	if err != nil {
		return err
	}
	if scheme != keySchemeShared {
		return errStaleClient
	}
	if shared == 0 || requested != generation {
		return errKeyRotationIncomplete
	}
	var admitted bool
	if err := q.QueryRow(ownIdentityEnvelopeSQL, userID, cid, generation).Scan(&admitted); err != nil {
		return err
	}
	if !admitted {
		return errKeyRotationIncomplete
	}
	return nil
}
```

- [ ] **Step 4: Creation and names.** In `container_routes.go` create handler, replace the `meta` decode (lines 64-67) with a refusal, and store an empty name:

```go
		// A notebook has no name until its first key exists: the owner's browser seals it then.
		if in.Meta != "" {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
```

In the `INSERT INTO containers(...)` replace the `meta` argument with `[]byte{}`; in the response map replace `in.Meta` with `""`. Delete the now-unused `meta, e :=` line and keep `e` declared where the transaction needs it (`var e error` before `e = dbTx(...)`).

In the meta `PATCH` handler (130-150) replace the two checks with:

```go
			if !current {
				return errStaleClient
			}
			// A name is sealed with the current generation only, so readers never need an older key;
			// a container without a key has no name to seal.
			if shared == 0 || in.KeyGeneration == nil || *in.KeyGeneration != generation {
				return errKeyRotationIncomplete
			}
```

Update the struct comment on `KeyGeneration` to "The generation the name was sealed with; required." In `admin_routes.go` `POST /admin/teams`, replace the decode-and-length check and the base64 decode with:

```go
		var in struct {
			MetaCiphertext string `json:"metaCiphertext"`
		}
		// The team has no name until its owner's browser mints its first key and seals one.
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.MetaCiphertext != "" {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
```

Store `[]byte{}` as `meta_ciphertext` and return `"metaCiphertext": ""`. An empty body (`{}`) decodes fine.

- [ ] **Step 5: The web header.** In `web/src/api.ts:30` set `export const KEY_SCHEME = "shared-v2";`.

- [ ] **Step 6: Run the new tests.**

Run: `go test ./internal/httpapi/ -run 'TestUnkeyedContainerRefusesEveryWrite|TestEveryWriteNeedsTheCurrentKeyScheme|TestContainerCreationTakesNoName|TestAdminTeamCreationTakesNoNameAndCreatesOwner' -count=1`
Expected: PASS.

- [ ] **Step 7: Move the other tests onto keyed containers.** Run `go test ./internal/httpapi/ -count=1 2>&1 | grep -E '^(--- FAIL|    .*_test.go)'`. Every failure is a test that writes to an unkeyed container, sends a name at creation, or sends no `shared-v2`. Fix each with the matching rule, never by weakening an assertion:
  - Delete `TestLegacyContainersKeepTheDeviceGate` (`teamkeys_test.go:526-551`): its subject no longer exists; `TestUnkeyedContainerRefusesEveryWrite` replaces it.
  - In `teamkeys_test.go`/`teamkeys_p3_test.go` tests that save, comment or attach at generation 1 before `tm.rotate(t, tm.id, 1)`: move `tm.rotate(t, tm.id, 1)` before the first write and write at generation 2. Where the test is about a later rotation (`TestNewContentRefusedUntilRotationEnvelopesExist` and similar), rotate once at the start and shift every expected generation by one (`1→2`, `2→3`).
  - In `TestSharedContainerRefusesStaleClientWrites` (`teamkeys_p3_test.go:34`): delete the "Never shared" block (lines 37-42) and rotate before the first save; keep the stale cases.
  - `teamkeys_p3_test.go:91-93` ("legacy-era envelope at generation 1") and `125-127` ("Legacy containers keep today's rule"): delete; `TestUnkeyedContainerRefusesEveryWrite` covers the refusal. `186-188` ("Never shared: a name without a generation is accepted"): change the expectation to `409`.
  - Tests that seed a container with `seedContainer` or create one over HTTP and then write or `PUT` envelopes without testing key rules (`integration_test.go`, `commit_share_test.go`, `upload_contract_test.go`, `privacy_test.go`, `device_contract_test.go`): call `keyForTest(t, <db>, cid, <writing user IDs>...)` right after the container exists, send the generation it returns instead of `1`, and in hand-built requests add `req.Header.Set(keySchemeHeader, keySchemeShared)`. Creation bodies that carry a name use `"metaCiphertext":""`.

- [ ] **Step 8: Frozen-contract docs in the same change.** In `IMPLEMENTATION_PLAN.md`:
  - line 361 (`already_exists` row): replace "a shared container written without `X-Kynotes-Key-Scheme: shared-v1`" with "a content write or name change without `X-Kynotes-Key-Scheme: shared-v2`".
  - line 1259 (envelope `PUT` row): replace "legacy containers: the current generation only; shared containers: any generation" with "a container without a key refuses every envelope (`409 already_exists`, `key rotation incomplete`); otherwise any generation".
  - line 1406 (object `PUT` row): replace "`X-Kynotes-Key-Scheme` (shared containers)" with "`X-Kynotes-Key-Scheme: shared-v2`".
  - The `POST /api/v1/containers` and `POST /api/v1/admin/teams` rows: add "`metaCiphertext` must be empty (`400`); the name is sealed after the first key".
  - lines 1692-1700 (**Write gate**): replace the paragraph with: "**Write gate**: new content (object save, comment create, attachment finalize) and container names need a live membership, `X-Kynotes-Key-Scheme: shared-v2` (else `409 already_exists`, `this notebook uses shared keys: reload the page`), a container that has a key (`shared_generation > 0`, set by its first rotation), the current `key_generation`, and an envelope for the writer's own live identity at it. A failed gate is `409 already_exists` with message `key rotation incomplete`. The gate runs before the body streams and again in the write transaction. Object saves record the session user in `object_versions.author_user_id`."
  - line 1742: replace `TestLegacyContainersKeepTheDeviceGate` with `TestUnkeyedContainerRefusesEveryWrite`, `TestEveryWriteNeedsTheCurrentKeyScheme`, `TestContainerCreationTakesNoName`.

  In `DESIGN.md` replace "The save gate depends on whether the container has ever rotated (`containers.shared_generation`). Until it has, every member's paired device needs an envelope at the current generation, as before. Afterwards, the writer's own identity needs one." (lines 204-207) with "A container has no key until its first rotation (`containers.shared_generation`, the first keyed generation); until then it takes no content, name or envelope, and it is created without a name. Afterwards a write needs the writer's own identity to hold an envelope at the current generation." Replace the sentence "Shared containers refuse content writes that lack the `X-Kynotes-Key-Scheme: shared-v1` header, so a page loaded before shared keys cannot write." (228-230) with "Every content write and name change carries `X-Kynotes-Key-Scheme: shared-v2`; a tab from an older build is refused and told to reload."

- [ ] **Step 9: Run the server suite.**

Run: `go build ./... && go vet ./... && test -z "$(gofmt -l .)" && go test -race ./internal/... -count=1`
Expected: PASS.

- [ ] **Step 10: Commit.**

```bash
git add internal/httpapi web/src/api.ts IMPLEMENTATION_PLAN.md DESIGN.md
git commit -m "server: a notebook takes content, names and envelopes only once it has a key"
```

---

## Task 2: Server — delete the legacy review route and the comment rewrite route

**Files:**
- Modify: `internal/httpapi/teamkeys_routes.go:274-385,604-631`
- Modify: `internal/httpapi/ratelimit.go:104-107`
- Delete: `internal/httpapi/teamkeys_p4_test.go`
- Modify: `internal/httpapi/teamkeys_test.go` (`TestCommentRewriteIsAuthorOnly` and the rewrite cases at 573 and 738), `teamkeys_p3_test.go:55-57` (the "comment rewrite" case)
- Modify: `internal/httpapi/contracts_test.go`
- Modify (docs): `IMPLEMENTATION_PLAN.md:441,1261,1717-1733,1760,1786`, `internal/config` docs for `link_poll_per_minute` if they mention legacy lists

**Interfaces:**
- Consumes: `testRouter(maxBytes int) http.Handler` (`contracts_test.go`).
- Produces: nothing new.

- [ ] **Step 1: Write the failing guard test.** Append to `internal/httpapi/contracts_test.go`:

```go
// The legacy review and the comment re-seal served only the login-derived content key, which is
// gone. A registered route would answer 401 to an unauthenticated request through its session
// middleware; an unregistered one never reaches it.
func TestRemovedLegacyRoutesStayGone(t *testing.T) {
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/containers/cnt_0123456789abcdefghjkmnpqrs/legacy"},
		{http.MethodPut, "/api/v1/comments/cmt_0123456789abcdefghjkmnpqrs"},
	} {
		w := httptest.NewRecorder()
		testRouter(1024).ServeHTTP(w, httptest.NewRequest(route.method, route.path, strings.NewReader("{}")))
		if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s=%d, want an unregistered route", route.method, route.path, w.Code)
		}
	}
}
```

(Add `"strings"` to the imports if missing.)

- [ ] **Step 2: Run it to verify it fails.**

Run: `go test ./internal/httpapi/ -run TestRemovedLegacyRoutesStayGone -count=1`
Expected: FAIL with `GET /api/v1/containers/…/legacy=401`.

- [ ] **Step 3: Delete the routes.** In `teamkeys_routes.go` delete the `PUT /api/v1/comments/{id}` handler (274-320), the comment block and handler for `GET /api/v1/containers/{id}/legacy` (321-385), and `legacyListMax`/`legacyRows` (604-631). Remove imports that become unused (`strings` if only the legacy query used it). In `ratelimit.go` delete the `/legacy` case (104-107).

- [ ] **Step 4: Delete their tests.** `git rm internal/httpapi/teamkeys_p4_test.go`. In `teamkeys_test.go` delete `TestCommentRewriteIsAuthorOnly` (597-625) and the rewrite request at 573 and 738 together with the assertion each belongs to. In `teamkeys_p3_test.go` delete the `"comment rewrite"` entry (55-57); the `cmt` variable it used may become unused (delete it then).

- [ ] **Step 5: Run the server suite.**

Run: `go build ./... && go vet ./... && go test -race ./internal/... -count=1`
Expected: PASS, including `TestRemovedLegacyRoutesStayGone`.

- [ ] **Step 6: Contract docs.** In `IMPLEMENTATION_PLAN.md` delete the `/legacy` row (1261), the **Comment rewrite** bullet (1717-1718), the **Legacy review** bullet (1719), the P3a **Known limit** bullet (1726-1733), and `TestCommentRewriteIsAuthorOnly` (1760). In line 441 replace "device-link collect polls and legacy-row lists, per account, separate buckets" with "device-link collect polls, per account". In 1786 remove any mention of the legacy-row list bucket. In `DESIGN.md` remove `PUT /comments/{id}` wherever it is listed. Run `grep -n 'comments/{id}\|/legacy\b' IMPLEMENTATION_PLAN.md DESIGN.md` and expect no output.

- [ ] **Step 7: Commit.**

```bash
git add -A internal/httpapi IMPLEMENTATION_PLAN.md DESIGN.md
git commit -m "server: remove the legacy review and comment re-seal routes"
```

---

## Task 3: Probe — key the probe's notebook from creation

**Files:**
- Create: `internal/teamkeys/identity.go`, `internal/teamkeys/identity_test.go`
- Modify: `cmd/kynotes-probe/main.go:25-40,61-67,95-148,150-215,336-360,404-453,479-485,579` and every other `"1"`/`keyGeneration":1` content generation in it

**Interfaces:**
- Consumes: `teamkeys.SealEnvelope`, `teamkeys.OpenEnvelope`, `derive.AuthSecret` (`github.com/Busnes-app/ky-primitives/derive`), the vectors in `testdata/protocol/envelope_vectors.json` (`login[].userKEK`, `identity[]`).
- Produces:
  - `teamkeys.UserKEK(password, loginSalt string, iterations int) ([]byte, error)`
  - `teamkeys.SealIdentity(userKEK, privateKey []byte, userID string) ([]byte, error)` (random nonce)
  - `teamkeys.OpenIdentity(userKEK, wrapped []byte, userID string) ([]byte, error)`

- [ ] **Step 1: Write the failing vector test.** Create `internal/teamkeys/identity_test.go`:

```go
package teamkeys

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestIdentityWrapAgreesWithVectors(t *testing.T) {
	raw, err := os.ReadFile(vectorFile)
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	for _, l := range v.Login {
		kek, err := UserKEK(l.Password, l.LoginSalt, l.Iterations)
		if err != nil || hex.EncodeToString(kek) != l.UserKEK {
			t.Fatalf("userKEK=%x err=%v, want %s", kek, err, l.UserKEK)
		}
	}
	for _, i := range v.Identity {
		kek, priv := unhex(t, i.UserKEK), unhex(t, i.PrivateKey)
		sealed, err := sealIdentity(kek, priv, i.UserID, unhex(t, i.Nonce))
		if err != nil || hex.EncodeToString(sealed) != i.Wrapped {
			t.Fatalf("sealed=%x err=%v", sealed, err)
		}
		opened, err := OpenIdentity(kek, unhex(t, i.Wrapped), i.UserID)
		if err != nil || !bytes.Equal(opened, priv) {
			t.Fatalf("opened=%x err=%v", opened, err)
		}
		if _, err := OpenIdentity(kek, unhex(t, i.Wrapped), "usr_zzzzzzzzzzzzzzzzzzzzzzzzzz"); err == nil {
			t.Fatal("opened under another user's AAD")
		}
	}
	wrapped, err := SealIdentity(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), "usr_0123456789abcdefghjkmnpqrs")
	if err != nil || len(wrapped) != 60 {
		t.Fatalf("random-nonce wrap=%d bytes err=%v", len(wrapped), err)
	}
}
```

- [ ] **Step 2: Run it to verify it fails.**

Run: `go test ./internal/teamkeys/ -run TestIdentityWrapAgreesWithVectors -count=1`
Expected: FAIL (`undefined: UserKEK`).

- [ ] **Step 3: Implement.** Create `internal/teamkeys/identity.go`:

```go
package teamkeys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/Busnes-app/ky-primitives/derive"
)

const identityLabel = "kynotes/identity/v1"

// UserKEK is the key that wraps the identity under the password: the browser's deriveLoginKeys
// (one PBKDF2 pass, HKDF label "kynotes/user-kek/v1"). The server never sees it.
func UserKEK(password, loginSalt string, iterations int) ([]byte, error) {
	secret, err := derive.AuthSecret(password, loginSalt, iterations, "kynotes/user-kek/v1")
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(secret)
}

func identityAEAD(userKEK []byte, userID string) (cipher.AEAD, []byte, error) {
	if len(userKEK) != 32 || !validID("usr", userID) {
		return nil, nil, errors.New("teamkeys: invalid identity input")
	}
	block, err := aes.NewCipher(userKEK)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	return aead, append([]byte(identityLabel), userID...), err
}

func sealIdentity(userKEK, privateKey []byte, userID string, nonce []byte) ([]byte, error) {
	aead, aad, err := identityAEAD(userKEK, userID)
	if err != nil {
		return nil, err
	}
	if len(privateKey) != 32 || len(nonce) != aead.NonceSize() {
		return nil, errors.New("teamkeys: invalid identity input")
	}
	return aead.Seal(append([]byte{}, nonce...), nonce, privateKey, aad), nil
}

// SealIdentity is web/src/teamKeys.ts wrapIdentity: nonce(12) ‖ AES-256-GCM(userKEK, privateKey,
// "kynotes/identity/v1" ‖ userID), 60 bytes.
func SealIdentity(userKEK, privateKey []byte, userID string) ([]byte, error) {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return sealIdentity(userKEK, privateKey, userID, nonce)
}

// OpenIdentity reverses SealIdentity.
func OpenIdentity(userKEK, wrapped []byte, userID string) ([]byte, error) {
	aead, aad, err := identityAEAD(userKEK, userID)
	if err != nil {
		return nil, err
	}
	if len(wrapped) != aead.NonceSize()+32+aead.Overhead() {
		return nil, errors.New("teamkeys: invalid wrapped identity")
	}
	return aead.Open(nil, wrapped[:aead.NonceSize()], wrapped[aead.NonceSize():], aad)
}
```

`validID` exists in `envelope.go:29`. Update `internal/teamkeys/doc.go` to say the probe also imports it (the server still does not).

- [ ] **Step 4: Run the vectors.**

Run: `go test ./internal/teamkeys/ -count=1`
Expected: PASS.

- [ ] **Step 5: The probe.** In `cmd/kynotes-probe/main.go`:
  - Add fields to `client`: `userID, loginSalt, identityDevice string`, `identityKey *ecdh.PrivateKey`, `generation int64`.
  - In `login()`, store `p.loginSalt = params.LoginSalt`, then parse the login body instead of only checking the status:

```go
	var session struct {
		User     struct{ ID string `json:"id"` } `json:"user"`
		Identity *struct {
			DeviceID          string `json:"deviceId"`
			WrapAlg           string `json:"wrapAlg"`
			WrappedPrivateKey string `json:"wrappedPrivateKey"`
		} `json:"identity"`
	}
	if err = decode(res, &session); err != nil {
		return err
	}
	p.userID = session.User.ID
	p.identityKey, p.identityDevice = nil, ""
	if session.Identity == nil || session.Identity.WrapAlg != "aes-256-gcm" {
		return nil // none yet, or no password copy: identity() decides
	}
	kek, err := teamkeys.UserKEK(p.password, p.loginSalt, p.iterations)
	if err != nil {
		return err
	}
	wrapped, err := base64.StdEncoding.DecodeString(session.Identity.WrappedPrivateKey)
	if err != nil {
		return err
	}
	raw, err := teamkeys.OpenIdentity(kek, wrapped, p.userID)
	if err != nil {
		return fmt.Errorf("unwrap the probe identity: %w", err)
	}
	if p.identityKey, err = ecdh.X25519().NewPrivateKey(raw); err != nil {
		return err
	}
	p.identityDevice = session.Identity.DeviceID
	return nil
```

  (Keep the `401 → errInvalidCredentials` branch before the decode. Check the field names against `loadIdentity` in `identity_routes.go:60-80` and the login handler in `auth_routes.go`; the browser reads the same body in `api.ts` `login`.)
  - Replace `takeOverPassword` (95-148) with `identity()`, which keeps the take-over file logic unchanged and swaps only the detection:

```go
// identity makes sure the probe account holds a password-wrapped identity this run can use: it
// was unwrapped at login, or it is created now. If an administrator set the password, creating
// it is refused (409 password_change_required), and the password is taken over first, as a user
// would. An identity without a password copy cannot be used here and stops the run.
func (p *client) identity() error {
	if p.identityKey != nil {
		return nil
	}
	res, err := p.request(http.MethodGet, "/api/v1/me/identity", nil, nil, false)
	if err != nil {
		return err
	}
	if res.StatusCode == http.StatusOK {
		res.Body.Close()
		return errors.New("the probe account has an encryption key without a password copy (an administrator reset); reset it in Settings or use a fresh account")
	}
	res.Body.Close()
	for attempt := 0; attempt < 2; attempt++ {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		kek, err := teamkeys.UserKEK(p.password, p.loginSalt, p.iterations)
		if err != nil {
			return err
		}
		wrapped, err := teamkeys.SealIdentity(kek, key.Bytes(), p.userID)
		if err != nil {
			return err
		}
		if err = p.stepUp(); err != nil {
			return err
		}
		body, _ := json.Marshal(map[string]string{"publicKey": base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), "wrapAlg": "aes-256-gcm", "wrappedPrivateKey": base64.StdEncoding.EncodeToString(wrapped)})
		res, err := p.request(http.MethodPut, "/api/v1/me/identity", body, nil, false)
		if err != nil {
			return err
		}
		b, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			return err
		}
		if res.StatusCode == http.StatusOK {
			var out struct{ DeviceID string `json:"deviceId"` }
			if err = json.Unmarshal(b, &out); err != nil || out.DeviceID == "" {
				return fmt.Errorf("identity create: %s", b)
			}
			p.identityKey, p.identityDevice = key, out.DeviceID
			return nil
		}
		var e struct{ Error struct{ Code string `json:"code"` } `json:"error"` }
		if attempt > 0 || res.StatusCode != http.StatusConflict || json.Unmarshal(b, &e) != nil || e.Error.Code != "password_change_required" {
			return fmt.Errorf("identity create: status %d: %s", res.StatusCode, strings.TrimSpace(string(b)))
		}
		if err = p.takeOver(); err != nil {
			return err
		}
	}
	return errors.New("identity create: unreachable")
}
```

  and move the old take-over tail (the temp password, the take-over file, `changePassword`, `p.takenOver = true`, the "operator-set password taken over" line) into `takeOver() error`.
  - Add `keyContainer()` and run it after `identity()`:

```go
// keyContainer creates the probe's notebook and gives it its first key, as a browser does at
// creation: generation 1 holds nothing, and the first rotation makes generation 2 its first key.
func (p *client) keyContainer() error {
	res, err := p.request(http.MethodPost, "/api/v1/containers", []byte(`{"kind":"workbook","metaCiphertext":""}`), nil, false)
	if err != nil {
		return err
	}
	var container struct{ ID string `json:"id"` }
	if err = decode(res, &container); err != nil {
		return err
	}
	p.containerID = container.ID
	p.contentKey = make([]byte, 32)
	if _, err = rand.Read(p.contentKey); err != nil {
		return err
	}
	sealed, err := teamkeys.SealEnvelope(p.contentKey, p.identityKey.PublicKey().Bytes(), p.containerID, 2, p.identityDevice, p.identityKey, p.identityDevice)
	if err != nil {
		return err
	}
	if err = p.stepUp(); err != nil {
		return err
	}
	body := []byte(fmt.Sprintf(`{"expectedGeneration":1,"envelopes":[{"deviceId":%q,"keyGeneration":2,"alg":%q,"envelope":%q}]}`, p.identityDevice, envelopeAlg, base64.StdEncoding.EncodeToString(sealed)))
	res, err = p.request(http.MethodPost, "/api/v1/containers/"+p.containerID+"/key-rotations", body, nil, false)
	if err != nil {
		return err
	}
	var rotated struct{ KeyGeneration int64 `json:"keyGeneration"` }
	if err = decode(res, &rotated); err != nil {
		return err
	}
	if rotated.KeyGeneration != 2 {
		return fmt.Errorf("first key at generation %d, want 2", rotated.KeyGeneration)
	}
	p.generation = 2
	return nil
}
```

  (add `contentKey []byte` to `client`).
  - Steps list: `p.login, p.identity, p.keyContainer, p.pair, p.envelope, p.selectContainer, p.saveAndRead, p.conflict, p.upload, p.dedup, p.download, p.preview, p.catchUp, p.deleteAndGC`. Update the comment above it: the take-over runs before pairing (inside `identity`).
  - `envelope()`: seal `p.contentKey` (not a fresh key) at `p.generation` for the paired device with sender `p.identityKey`/`p.identityDevice`, and open it with `teamkeys.OpenEnvelope(raw, p.deviceKey, p.containerID, uint32(p.generation), p.deviceID, p.identityKey.PublicKey().Bytes())`. The `PUT` body uses `"keyGeneration":%d` with `p.generation`. Keep the "second envelope for one recipient is 409" check and `len(envelopes) != 1`: a device credential's `GET /containers/{id}/envelopes` returns only its own rows (`device_routes.go:113-117`).
  - `save()` and every content request: replace the hard-coded `"1"`/`"keyGeneration":1` with `p.generation`. In `request()`, set `X-Kynotes-Key-Scheme: shared-v2` on every non-device request (`req.Header.Set("X-Kynotes-Key-Scheme", "shared-v2")`).
  - `changePassword(password)`: after deriving the new salt and `secret`, when `p.identityKey != nil` also derive `kek, _ := teamkeys.UserKEK(password, loginSalt, p.iterations)`, `wrapped, _ := teamkeys.SealIdentity(kek, p.identityKey.Bytes(), p.userID)` (handle errors), and add `"identityDeviceId": p.identityDevice, "wrappedIdentityKey": base64(wrapped)` to the body. Set `p.loginSalt = loginSalt` on success. Replace its doc comment with "changePassword uses the user's own change route and re-wraps the probe identity under the new password in the same request."

- [ ] **Step 6: Run the probe twice against a throwaway server, then against a device-only identity.**

```bash
go build ./... && go vet ./cmd/... && test -z "$(gofmt -l .)"
probe_data=$(mktemp -d)
cp testdata/config-good/kynotes.yaml "$probe_data/"
docker build -t kynotes-server:probe .
auth='{"authSecret":"b9eb85992f985b432a3feaf4f5ea0b7b7960a5da42c640a3b9d93a83fc5bef1d","loginSalt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":100000}'
printf '%s' "$auth" | docker run -i --rm --user "$(id -u):$(id -g)" -v "$probe_data:/data" kynotes-server:probe user add --config /data/kynotes.yaml --username probe
docker run -d --name kynotes-probe-server --user "$(id -u):$(id -g)" -p 8080:8080 -v "$probe_data:/data" kynotes-server:probe --config /data/kynotes.yaml
go run ./cmd/kynotes-probe -url http://127.0.0.1:8080 -username probe -password 'correct horse battery staple' -config /data/kynotes.yaml -server docker
go run ./cmd/kynotes-probe -url http://127.0.0.1:8080 -username probe -password 'correct horse battery staple' -config /data/kynotes.yaml -server docker
docker rm -f kynotes-probe-server
```

Expected: both runs print `step 1 ok` … `step 14 ok`, "probe device revoked", and the first also "operator-set password taken over" and "original password restored". The second run unwraps the identity from the login response (no take-over line). Wait for `/healthz` before the first `go run` the way `ci.yml` does (`for i in $(seq 1 30); do curl -fsS http://127.0.0.1:8080/healthz >/dev/null && break; sleep 1; done`).

Then prove the named failure, as an administrator reset leaves the account (there is no CLI reset, so strip the copy directly while the server is stopped):

```bash
docker stop kynotes-probe-server
sqlite3 "$probe_data/kynotes.sqlite" "UPDATE user_identities SET wrap_alg='none', wrapped_private_key=X''"
docker start kynotes-probe-server
go run ./cmd/kynotes-probe -url http://127.0.0.1:8080 -username probe -password 'correct horse battery staple' -config /data/kynotes.yaml -server docker
docker rm -f kynotes-probe-server
rm -rf "$probe_data"
```

Expected: `step 2 failed: the probe account has an encryption key without a password copy …` and exit status 1. (Move the earlier `docker rm -f kynotes-probe-server` line to here.)

- [ ] **Step 7: Commit.**

```bash
git add internal/teamkeys cmd/kynotes-probe
git commit -m "probe: a password-wrapped identity and a notebook keyed from creation"
```

---

## Task 4: Web — delete the pre-sharing review, closure and reopen

After this task the login key still reads (Task 6 removes it); nothing closes or reopens any more, and the password-change warning that counted closures goes with them. The e2e is not run again until Task 8.

**Files:**
- Delete: `web/src/migration.ts`, `web/src/migration.test.ts`, `web/src/components/LegacyReview.tsx`, `web/src/components/LegacyReview.test.tsx`
- Modify: `web/src/keyring.ts:30-93,229-261`, `web/src/floors.ts`, `web/src/observe.ts`, `web/src/storage.ts:3,300,412-496`, `web/src/api.ts:188-210,229-230,275`, `web/src/outbound.ts:49-52`, `web/src/passwordChange.ts`, `web/src/styles.css:371-379`, `web/src/main.tsx` (see Inventory), `web/src/legacyWiring.test.ts:15-91,145-153`
- Modify (tests): `keyring.test.ts`, `floors.test.ts`, `observe.test.ts`, `storage.test.ts`, `api.test.ts`, `outbound.test.ts`, `drain.test.ts`, `passwordChange.test.ts`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `keyring.ts`: `type KeyFloor = { shared?: number; generation?: number }`; `type KeyState = KeyFloor & { mark: number; digests: Record<number, string> }`; `mergeFloor<T extends KeyFloor>(floor: KeyFloor | undefined, next: T): T`; `readKeys(container, ring, legacy, generation, floor): KeyRef[]` (legacy still present until Task 6, no closure); `localReadKeys(...)` (unchanged signature, no closure).
  - `floors.ts`: `floorOf`, `raiseFloorIn`, `publishFloor`, `clearFloors`, `useFloors` (no closure exports).
  - `passwordChange.ts`: `passwordChangeProblem(next: string, confirmation: string): string | undefined` only.

- [ ] **Step 1: Write the failing tests.** In `keyring.test.ts` add:

```ts
it("a floor carries only generations: a stored closure from an older build is dropped", () => {
  const merged = mergeFloor({ shared: 2, generation: 3, closed: 2 } as KeyFloor, { shared: 2, generation: 4 });
  expect(merged).toEqual({ shared: 2, generation: 4 });
});
```

In `storage.test.ts` add (using the file's existing fake-indexeddb setup and helpers):

```ts
it("key memory keeps only generations, mark and digests", async () => {
  await storeKeyState("alice", "usr_0123456789abcdefghjkmnpqrs", CID, { mark: 2, digests: { 2: "aa" }, shared: 2, generation: 2, closed: 2, reopened: true } as KeyState);
  expect(await getKeyState("alice", "usr_0123456789abcdefghjkmnpqrs", CID)).toEqual({ mark: 2, digests: { 2: "aa" }, shared: 2, generation: 2 });
});
```

(`CID` is a valid `cnt_` ID constant; reuse the file's own if it has one.) Create `web/src/noLegacyReview.test.ts`:

```ts
import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const read = (path: string) => readFileSync(new URL(path, import.meta.url), "utf8");

describe("the pre-sharing review is gone", () => {
  it("has no review, closure or reopen code left", () => {
    expect(existsSync(new URL("./migration.ts", import.meta.url))).toBe(false);
    expect(existsSync(new URL("./components/LegacyReview.tsx", import.meta.url))).toBe(false);
    for (const file of ["./main.tsx", "./keyring.ts", "./floors.ts", "./observe.ts", "./storage.ts", "./api.ts", "./outbound.ts"]) {
      expect(read(file), file).not.toMatch(/closedOf|closeLegacy|reopenLegacy|ReopenConfirmation|setClosureReader|closeFloorIn|reopenFloorIn|legacyRows|rewriteComment|sendCommentRewrite|\/legacy\b/);
    }
  });
});
```

- [ ] **Step 2: Run them to verify they fail.**

Run: `cd web && npx vitest run src/keyring.test.ts src/storage.test.ts src/noLegacyReview.test.ts`
Expected: FAIL (`closed: 2` survives the merge; `closed`/`reopened` come back from storage; `migration.ts` exists).

- [ ] **Step 3: Delete the files.** `git rm web/src/migration.ts web/src/migration.test.ts web/src/components/LegacyReview.tsx web/src/components/LegacyReview.test.tsx`.

- [ ] **Step 4: keyring.ts.** Delete `closedOf`, `reopenConfirmations`, `mintReopen`, `ReopenConfirmation`, `confirmReopenLegacy`, `isReopenConfirmation`, `consumeReopenConfirmation`, `legacyKeys`. Replace the `KeyState`/`KeyFloor` comments and types (30-44) with:

```ts
/**
 * What this device remembers per container: the highest generation it accepted from itself or a
 * current steward, the SHA-256 (hex) of every key it accepted (a different key for a known
 * generation is refused even after a reload), and the floor. All of it only rises.
 */
export type KeyState = KeyFloor & { mark: number; digests: Record<number, string> };
/** The highest sharedGeneration and keyGeneration this device has seen for a container; absent is 0. Only rises. */
export type KeyFloor = { shared?: number; generation?: number };
```

Replace `mergeFloor` with:

```ts
/** Add-only merge of a floor into this device's in-memory one: no field ever falls. Only the two generations survive. */
export const mergeFloor = <T extends KeyFloor>(floor: KeyFloor | undefined, next: T): T =>
  ({ shared: Math.max(floor?.shared ?? 0, next.shared ?? 0), generation: Math.max(floor?.generation ?? 0, next.generation ?? 0) }) as T;
```

In `readKeys` replace both `return legacyKeys(floor, legacy);` with `return [legacy];`. In `localReadKeys` replace `{ ...floor, closed: 0 }` with `floor` and update its comment to "readKeys for an entry this browser wrote to IndexedDB itself; a waiting entry may try the identity's waiting key first." Update the `readKeys` comment: delete "until this device closes legacy reads (legacyKeys)" and "or review (migration.ts)".

- [ ] **Step 5: floors.ts.** Replace the file with:

```ts
import { useSyncExternalStore } from "react";
import { mergeFloor, type KeyFloor } from "./keyring";

/**
 * This tab's one in-memory sharing floor per container, shared by every component. Add-only: a
 * floor only rises until clearFloors (sign-out). Key decisions read floorOf at decision time.
 */
let floors: Readonly<Record<string, KeyFloor>> = {};
/** Peer raises for containers this tab has not loaded: never a loaded floor, only a minimum applied on load. */
let pending: Record<string, KeyFloor> = {};
const listeners = new Set<() => void>();
const changed = () => { for (const listener of listeners) listener(); };
const merge = (containerID: string, floor: KeyFloor) => {
  const minimum = pending[containerID];
  if (minimum) delete pending[containerID];
  floors = { ...floors, [containerID]: mergeFloor(mergeFloor(floors[containerID], floor), minimum ?? {}) };
  changed();
};

/**
 * Other tabs of this origin hear every raise: numbers only, nothing secret. A message is a server
 * claim relayed by a peer: validated here and merged add-only. For a container this tab has not
 * loaded it is kept as a minimum applied when the stored floor loads; it never makes a floor known.
 * A forged one can at most raise a floor (denial of service, never a key).
 */
const channel = typeof BroadcastChannel === "undefined" ? null : new BroadcastChannel("kynotes-floors");
const containerIDPattern = /^cnt_[0-9abcdefghjkmnpqrstvwxyz]{26}$/;
const count = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;
if (channel) channel.onmessage = (event: MessageEvent) => {
  const { containerID, shared, generation } = (event.data ?? {}) as Record<string, unknown>;
  if (typeof containerID !== "string" || !containerIDPattern.test(containerID)) return;
  if (!count(shared) || !count(generation)) return;
  if (floors[containerID]) merge(containerID, { shared, generation });
  else pending[containerID] = mergeFloor(pending[containerID], { shared, generation });
};

/** undefined: not loaded in this tab, so no key. */
export const floorOf = (containerID: string): KeyFloor | undefined => floors[containerID];
/** Raises this tab's floor, then tells the others. */
export function raiseFloorIn(containerID: string, floor: KeyFloor): void {
  merge(containerID, floor);
  const { shared = 0, generation = 0 } = floors[containerID];
  channel?.postMessage({ containerID, shared, generation });
}
/** loaded false (storage unreadable): only a floor this tab already holds may rise; unknown stays unknown. */
export function publishFloor(containerID: string, floor: KeyFloor, loaded: boolean): void {
  if (loaded || floors[containerID]) raiseFloorIn(containerID, floor);
}
export function clearFloors(): void {
  floors = {};
  pending = {};
  changed();
}
const subscribe = (listener: () => void) => { listeners.add(listener); return () => { listeners.delete(listener); }; };
/** Re-renders the caller when any floor rises. */
export const useFloors = () => useSyncExternalStore(subscribe, () => floors);
```

- [ ] **Step 6: observe.ts, storage.ts, api.ts, outbound.ts.**
  - `observe.ts`: delete the `ClosureStored` import, `closeFloorIn` from the floors import, `ClosureSink`, `Closed` and `closeLegacy` (29-52).
  - `storage.ts`: delete the `closedOf`/`consumeReopenConfirmation`/`ReopenConfirmation` import, `updateKeyState`, `ClosureStored`, `closeLegacyStored`, `reopenLegacy`. Replace `getKeyState`'s return with `const state = record && statesOf(record, userID)[containerID]; return state ? { mark: state.mark, digests: state.digests, shared: state.shared, generation: state.generation } : { mark: 0, digests: {} };` (drop `undefined` fields so `toEqual` holds: build the object and delete keys whose value is `undefined`, or spread `...(state.shared !== undefined ? { shared: state.shared } : {})` for both). In `storeKeyState` delete the `closed` and `reopened` lines and replace its comment's last two sentences with nothing. Line 300's comment becomes "Only beside a device key."
  - `api.ts`: delete `LegacyRows`, `wireID`, `isID` (if nothing else uses them), `legacyRows`, `rewriteComment`, `detachAttachment`.
  - `outbound.ts`: delete `sendCommentRewrite` and `rewriteComment` from its import.

- [ ] **Step 7: passwordChange.ts.** Replace the file with:

```ts
/** Why the change form may not be submitted yet, or undefined when it may. */
export function passwordChangeProblem(next: string, confirmation: string): string | undefined {
  if (!next || next !== confirmation) return "New passwords do not match.";
  return undefined;
}
```

`resealWaitingEdits` goes too: Task 5 drops every entry it re-sealed. In `main.tsx` `PasswordSettings`: delete the `warning`, `acknowledged` state, the acknowledgement checkbox and both notes in the JSX, the `atRisk` and `waiting` props, the `resealWaitingEdits` call, and set `setStatus("Password changed.")` after `onAuthSecret(newKeys.authSecret)`. Call `passwordChangeProblem(next, confirmation)`. In `SettingsView`, delete the `atRisk` and `waiting` props it passes through, and in `Workspace` delete `atRisk={legacyAtRisk(items, floorOf)}` and `waiting={() => waitingRef.current}`.

- [ ] **Step 8: main.tsx.** Delete, by symbol (line numbers in the Inventory): imports of `legacyRows`, `detachAttachment`, `closedOf`, `type ReopenConfirmation`, `checkFailure`/`LEGACY_CLOSED`/`LegacyReviewBanner`/`shareOutcomeText`, everything from `./migration`, `reopenFloorIn`/`setClosureReader` (keep `clearFloors`, `floorOf`, `raiseFloorIn`, `useFloors`), `closeLegacy`/`type Closed`/`type ClosureSink`, `closeLegacyStored`/`reopenLegacy`, `sendCommentRewrite`, `legacyAtRisk`/`PASSWORD_CHANGE_NOTE`/`passwordChangedStatus`/`passwordChangeWarning`/`resealWaitingEdits`; the `legacyCheck` and `legacyOutcome` state; `closureSink` and the `setClosureReader` effect; `reviewAPI`, `checkLegacy`, `stopLegacy`, `migrationAPI`, `shareLegacy`, `reopenLegacyReads`; the `closedNow`/`closedBefore` effect; `setLegacyCheck(undefined)`, `setLegacyOutcome(…)` and `void checkLegacy(keyed, superseded)` in `loadContainer`; the `<LegacyReviewBanner …/>` block (2701-2705). Keep the `unverified` labels for now (Task 6). Delete the `.legacy-*` rules from `styles.css` (371-379) after `grep -n 'legacy-' web/src/*.tsx web/src/components/*.tsx` shows no user.

- [ ] **Step 9: The tests that covered deleted code.** Delete: the "workspace pre-sharing wiring" `describe` (`legacyWiring.test.ts:15-91`) and its "asks for the password-change acknowledgement only while login-key items remain" test (145-153); every `floors.test.ts` test about closures (57-165); `observe.test.ts` tests "closes legacy reads…", "a user's Stop closes in memory…", "an automatic close changes nothing…" (79-118); `storage.test.ts` tests of `closeLegacyStored`/`reopenLegacy`/closure preservation; `keyring.test.ts` tests of `closedOf`, `ReopenConfirmation` and `legacyKeys`, and the AdminTeams/"callers of confirmReopenLegacy" structure checks that name deleted symbols; `api.test.ts` `legacyRows` tests; `outbound.test.ts` `sendCommentRewrite` tests; `passwordChange.test.ts` tests of the deleted functions (keep and adapt the mismatch test to two arguments). Any remaining test that builds a `KeyFloor` with `closed` drops the field.

- [ ] **Step 10: Run the web suite.**

Run: `cd web && npm test && npm run build`
Expected: PASS, including the three new tests.

- [ ] **Step 11: Commit.**

```bash
git add -A web/src
git commit -m "web: remove the pre-sharing review, closure and reopen"
```

---

## Task 5: Web — local stores hold only container-key or waiting-key ciphertext

**Files:**
- Modify: `web/src/storage.ts:9-196`, `web/src/stuckEdits.ts`, `web/src/drain.ts:14-34`, `web/src/components/UnsentEdits.tsx`, `web/src/main.tsx` (`ownsCached`, `getNote` calls, `drainQueue`, `SettingsView`/`UnsentEdits` props)
- Modify (tests): `storage.test.ts`, `stuckEdits.test.ts`, `drain.test.ts`, `components/UnsentEdits.test.tsx` (if present)

**Interfaces:**
- Consumes: Task 4's storage.
- Produces:
  - `storage.ts`: `type PendingSave = CachedNote & { owner: string }`; `getNote(owner: string, id: string): Promise<CachedNote | undefined>`; `pendingSaves(): Promise<PendingSave[]>`; `replaceQueuedSave(expected: PendingSave, next?: PendingSave): Promise<boolean>` (same owner and id only); `queueSave(note: PendingSave)`.
  - `stuckEdits.ts`: `unsentEdits(queued: PendingSave[], live: ReadonlySet<string> | undefined, owner: string): PendingSave[]`; `exportUnsent` unchanged; `stuckSaves` unchanged.
  - `UnsentEdits({ username, userID, keysFor }: { username: string; userID: string; keysFor: (item: PendingSave) => KeyRef[] })`.

- [ ] **Step 1: Write the failing tests.** In `storage.test.ts`:

```ts
it("a v5 database opens at v6 with empty stores and its vault", async () => {
  // A v5 database as earlier builds left it: an owner-unknown queue entry, a cached page, an upload and a vault record.
  await new Promise<void>((resolve, reject) => {
    const open = indexedDB.open("kynotes-web", 5);
    open.onupgradeneeded = () => {
      const db = open.result;
      db.createObjectStore("notes", { keyPath: ["owner", "id"] }).put({ owner: "", id: "obj_a", containerID: CID, version: 1, payload: new Uint8Array(1), updatedAt: "t" });
      db.createObjectStore("pending", { keyPath: ["owner", "id"] }).put({ owner: "usr_x", id: "obj_b", containerID: CID, version: 1, payload: new Uint8Array(1), updatedAt: "t", keyGeneration: 0 });
      db.createObjectStore("uploads", { keyPath: "uploadId" }).put({ uploadId: "upl_c" });
      db.createObjectStore("keys", { keyPath: "username" }).put({ username: "alice", authSecret: "a".repeat(64), updatedAt: "t" });
    };
    open.onsuccess = () => { open.result.close(); resolve(); };
    open.onerror = () => reject(open.error);
  });
  localStorage.setItem("kynotes-pending-saves", "{}");
  expect(await pendingSaves()).toEqual([]);
  expect(await pendingUploads()).toEqual([]);
  expect(await getNote("", "obj_a")).toBeUndefined();
  expect(await getDeviceKey("alice")).toBe("a".repeat(64));
  expect(localStorage.getItem("kynotes-pending-saves")).toBeNull();
});
```

(The test must start from a deleted database: call `indexedDB.deleteDatabase("kynotes-web")` in its setup if the file's `beforeEach` does not.) In `stuckEdits.test.ts` replace the owner-unknown tests with:

```ts
it("lists only this account's edits for notebooks no longer listed", () => {
  const mine = { id: "obj_a", containerID: LOST, owner: "usr_me" } as PendingSave;
  const live = { id: "obj_b", containerID: LIVE, owner: "usr_me" } as PendingSave;
  const theirs = { id: "obj_c", containerID: LOST, owner: "usr_other" } as PendingSave;
  expect(unsentEdits([mine, live, theirs], new Set([LIVE]), "usr_me")).toEqual([mine]);
  expect(unsentEdits([mine], undefined, "usr_me")).toEqual([]);
});
```

(`LOST`/`LIVE` are two valid `cnt_` IDs.)

- [ ] **Step 2: Run them to verify they fail.**

Run: `cd web && npx vitest run src/storage.test.ts src/stuckEdits.test.ts`
Expected: FAIL (the v5 rows survive; `unsentEdits` returns an object).

- [ ] **Step 3: storage.ts.** Replace lines 9-66 with:

```ts
export type CachedNote = { id: string; containerID: string; version: number; payload: Uint8Array; updatedAt: string; keyGeneration?: number };
/** owner: the user ID that queued it. The cache and queue are keyed by [owner, id], so one account never reads or replaces another's. */
export type PendingSave = CachedNote & { owner: string };
export type PendingUpload = { uploadId: string; containerID: string; objectID: string; objectVersion: number; keyGeneration: number; chunkBytes: number; nextChunk: number; payload: Uint8Array; metadataCiphertext: string; name: string; type: string; size: number };

const OWNED = ["owner", "id"];

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(databaseName, 6);
    request.onupgradeneeded = (event) => {
      const db = request.result;
      // Version 6: content is sealed only with container keys or the identity's waiting key. Rows from
      // earlier builds may be sealed with the login key, which nothing opens any more: dropped, not tried.
      if (event.oldVersion < 6) {
        for (const name of [storeName, "pending", "uploads"]) if (db.objectStoreNames.contains(name)) db.deleteObjectStore(name);
        localStorage.removeItem("kynotes-pending-saves");
      }
      if (!db.objectStoreNames.contains(storeName)) db.createObjectStore(storeName, { keyPath: OWNED });
      if (!db.objectStoreNames.contains("pending")) db.createObjectStore("pending", { keyPath: OWNED });
      if (!db.objectStoreNames.contains("uploads")) db.createObjectStore("uploads", { keyPath: "uploadId" });
      if (!db.objectStoreNames.contains("keys")) db.createObjectStore("keys", { keyPath: "username" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Unable to open local note store"));
  });
}
```

Replace `getNote` (114-132) with `export const getNote = (owner: string, id: string) => getRow([owner, id]);` and delete `ownerUnknownNotes`. `queueSave(note: PendingSave)`. In `pendingSaves`, resolve `request.result as PendingSave[]` (no `fromRow`) and fix its comment to "Every account's queued saves." Replace `replaceQueuedSave` with:

```ts
/**
 * Replaces (or, with next undefined, deletes) the queued save expected only while it is still the
 * entry the caller read: a save that replaced it meanwhile is never overwritten. next keeps its owner and id.
 */
export async function replaceQueuedSave(expected: PendingSave, next?: PendingSave): Promise<boolean> {
  let same = false;
  await write("pending", (store) => {
    const key = [expected.owner, expected.id];
    const read = store.get(key);
    read.onsuccess = guarded(store.transaction, () => {
      const current = read.result as PendingSave | undefined;
      same = Boolean(current && current.updatedAt === expected.updatedAt && current.version === expected.version && current.keyGeneration === expected.keyGeneration);
      if (!same) return;
      if (next) store.put({ ...next, owner: expected.owner, id: expected.id });
      else store.delete(key);
    });
  });
  return same;
}
```

- [ ] **Step 4: stuckEdits.ts.** Replace everything above `exportUnsent` with:

```ts
import type { CachedNote, PendingSave } from "./storage";

/**
 * Queued edits whose notebook the server no longer lists for this account: they can never be
 * sent. An unknown list (offline, server error) yields none, so an outage never offers sendable
 * work for deletion.
 */
export function stuckSaves(queued: PendingSave[], live: ReadonlySet<string> | undefined): PendingSave[] {
  return live ? queued.filter((item) => !live.has(item.containerID)) : [];
}

/**
 * The signed-in account's edits that will not be sent: its own, for notebooks no longer listed.
 * ponytail: queued saves only; pending uploads for lost notebooks are not listed. Upgrade: list them the same way.
 */
export const unsentEdits = (queued: PendingSave[], live: ReadonlySet<string> | undefined, owner: string): PendingSave[] =>
  stuckSaves(queued.filter((item) => item.owner === owner), live);
```

- [ ] **Step 5: drain.ts.** In `readyToSend` replace the two-branch `keys` with `const keys = localReadKeys(container, ring, legacy, item.keyGeneration, floor!, waiting);` and delete the comment sentences about unstamped entries and `drainable` ("The owner stamp proves …" through "the legacy closure applies to it."). Keep "The server cannot write the queue."

- [ ] **Step 6: UnsentEdits.tsx.** Replace the component with:

```tsx
import { useEffect, useState } from "react";
import { decryptObject, type KeyRef } from "../crypto";
import { downloadFile } from "../download";
import { openFirst, type KeyState } from "../keyring";
import { listContainers } from "../observe";
import { deleteNote, getKeyState, pendingSaves, replaceQueuedSave, storeKeyState, type PendingSave } from "../storage";
import { exportUnsent, unsentEdits } from "../stuckEdits";

/**
 * This account's edits queued on this device for notebooks it can no longer open: export (decrypted in
 * this browser, only on a click) and discard (asks first). keysFor: the keys this browser holds for an
 * edit (its notebook's container key for that generation, or the waiting key for a waiting edit).
 */
export function UnsentEdits({ username, userID, keysFor }: { username: string; userID: string; keysFor: (item: PendingSave) => KeyRef[] }) {
  const [unsent, setUnsent] = useState<PendingSave[]>([]);
  const open = (item: PendingSave) => openFirst(keysFor(item), (key) => decryptObject(key, item.containerID, item.payload));
  async function find(): Promise<PendingSave[]> {
    // Through the observer, like every container read: the generations it reports raise this device's floor.
    const sink = { load: (id: string) => getKeyState(username, userID, id), save: (id: string, state: KeyState) => storeKeyState(username, userID, id, state) };
    const live = await listContainers(sink).then((list) => new Set(list.map((entry) => entry.id)), () => undefined);
    return unsentEdits(await pendingSaves().catch(() => []), live, userID);
  }
  const load = async () => setUnsent(await find());
  useEffect(() => { void load(); }, [userID]);
  if (!unsent.length) return null;
  async function exportAll() {
    const file = await exportUnsent(unsent, (item) => open(item as PendingSave));
    if (file.unreadable === unsent.length) {
      alert("None of these edits can be opened in this browser: they are sealed with a notebook key it no longer holds.");
      return;
    }
    downloadFile("kynotes-unsent-edits.json", file.json, "application/json");
    if (file.unreadable) alert(`${file.unreadable} edit(s) are sealed with a notebook key this browser no longer holds and were left out.`);
  }
  async function discard() {
    if (!confirm(`Delete ${unsent.length} unsent edit(s) from this browser? They belong to notebooks you can no longer open and cannot be recovered afterwards. Export them first if you need them.`)) return;
    // Re-checked now: a notebook listed again (re-invited), or an unavailable list, deletes nothing.
    const still = new Set((await find()).map((item) => item.id));
    for (const item of unsent) {
      // Only the entry the user saw: a newer save of the same page stays queued.
      if (still.has(item.id) && await replaceQueuedSave(item)) await deleteNote(userID, item.id);
    }
    await load();
  }
  return (
    <section id="unsent-edits" className="config-card">
      <h2>Unsent edits</h2>
      <p className="config-muted">{unsent.length} edit(s) on this device belong to notebooks you can no longer open, so they can never be saved.</p>
      <p className="config-muted">The export is decrypted in this browser and saved as an unencrypted file. Store it somewhere safe and delete it when done.</p>
      <button type="button" onClick={() => void exportAll()}>Export unsent edits</button>
      <button type="button" className="secondary danger" onClick={() => void discard()}>Discard unsent edits</button>
    </section>
  );
}
```

- [ ] **Step 7: main.tsx.** Delete `ownsCached` and pass no third argument to every `getNote(auth.user.id, …)` (1329, 1334, 1966). In `drainQueue` replace the `drainable` block (1795-1801) with:

```ts
      // Only this account's edits: another account's entry could be sent, misattributed, to a notebook both share.
      const queued = (await pendingSaves()).filter((item) => item.owner === auth.user.id);
```

and delete `drainable` and `replaceQueuedSave` from the imports if now unused. In `SettingsView` rename the `teamKeys` prop to `keysFor` and drop `legacyKey`: the `Workspace` passes `keysFor={(item) => { const container = items.find((entry) => entry.id === item.containerID); return [legacy, ...(container ? localReadKeysFor(container, item.keyGeneration) : [])]; }}` (Task 6 removes `legacy`); `exportWaiting` uses `openFirst(keysFor(item), …)`; `<UnsentEdits username={username} userID={userID} keysFor={keysFor} />`. `queueSave` calls already pass `owner: auth.user.id`.

- [ ] **Step 8: Adapt the remaining tests.** `drain.test.ts`: delete the unstamped-entry tests; every `PendingSave` fixture gets `owner`. `storage.test.ts`: delete the owner-unknown claim, `ownerUnknownNotes`, the v5 re-keying and the `localStorage` import tests. `stuckEdits.test.ts`: delete `drainable`/`unknownDrafts` tests.

- [ ] **Step 9: Run the web suite.**

Run: `cd web && npm test && npm run build`
Expected: PASS.

- [ ] **Step 10: Commit.**

```bash
git add -A web/src
git commit -m "web: the local cache and queue start empty and hold only this account's container-key edits"
```

---

## Task 6: Web — the login key never opens content

**Files:**
- Modify: `web/src/crypto.ts:32,158-162`, `web/src/keyring.ts:1-20,213-281,346`, `web/src/keyService.ts` (keys it puts in rings), `web/src/drain.ts`, `web/src/api.ts:11-14,251`, `web/src/main.tsx` (Inventory rows marked Task 6: `legacy`, `readKeysFor`, `localReadKeysFor`, `legacyRowFor`, `unverified`, `markLegacy`, `UNVERIFIED*`, `explicit`, `copyableConflicts`, `movesLabelledSubpage`, `resealName`, `AdminTeams`, `SettingsView` `keysFor`), `web/src/components/SectionTabs.tsx`
- Rename: `web/src/legacyWiring.test.ts` → `web/src/workspaceWiring.test.ts`
- Create: `web/src/contentKeys.test.ts`
- Modify (tests): `keyring.test.ts`, `drain.test.ts`, `keyService.test.ts`, `outbound.test.ts`, `observe.test.ts`, `crypto.test.ts`, `pages.test.ts`, `components/SectionTabs.test.tsx` (if present), and any test `tsc` flags for the `KeyRef` brand

**Interfaces:**
- Consumes: Tasks 4–5.
- Produces:
  - `crypto.ts`: `type KeyRef = Uint8Array & { readonly [contentKey]: true }`; `asContentKey(bytes: Uint8Array): KeyRef`. No `legacyKeyRef`.
  - `keyring.ts`: `type Keyring = ReadonlyMap<number, KeyRef>`; `readKeys(container: Pick<KeyedContainer, "sharedGeneration">, ring: Keyring, generation: number | undefined, floor: KeyFloor): KeyRef[]`; `ownCopyKeys(container: Pick<KeyedContainer, "sharedGeneration">, ring: Keyring, generation: number | undefined, floor: KeyFloor, waiting?: KeyRef): KeyRef[]`; `newContainerKey(): KeyRef`; `waitingKey(identity): KeyRef`. No `legacyRow`, `localReadKeys`, `movesLabelledSubpage`, `copyableConflicts`.
  - `drain.ts`: `queuedSaveStep(floor: KeyFloor | undefined, generation: number | undefined, write: WriteKey | undefined): "send" | "reseal" | "wait"`; `readyToSend(item, container, floor, write, ring, waiting?)`; `attachmentStep(job, container, floor, write, ring, waiting?)`.
  - `main.tsx`: `readKeysFor(container, generation)` (server rows) and `ownCopyKeysFor(container: Container | undefined, generation)` (this browser's copies).

- [ ] **Step 1: Write the failing tests.** Create `web/src/contentKeys.test.ts`:

```ts
import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { asContentKey } from "./crypto";
import { ownCopyKeys, readKeys, WAITING_GENERATION } from "./keyring";

const root = new URL(".", import.meta.url);
/** Every non-test source file under web/src, vendored ky-ui excluded. */
const sources = (readdirSync(root, { recursive: true }) as string[])
  .filter((file) => /\.(ts|tsx)$/.test(file) && !/\.test\.tsx?$/.test(file) && !file.startsWith("ky-ui"))
  .map((file) => ({ file, text: readFileSync(new URL(file, root), "utf8") }));
const using = (pattern: RegExp) => sources.filter(({ text }) => pattern.test(text)).map(({ file }) => file).sort();

describe("content keys", () => {
  it("only keyring.ts makes content keys, and nothing casts to one", () => {
    expect(using(/asContentKey\(/)).toEqual(["crypto.ts", "keyring.ts"]); // crypto.ts: the definition
    expect(using(/as KeyRef\b/)).toEqual(["crypto.ts"]);
  });

  it("no login-derived content key or legacy read path exists", () => {
    expect(using(/legacyKeyRef|legacyKeys|legacyRow|localReadKeys|copyableConflicts|movesLabelledSubpage|unverified|UNVERIFIED|hexBytes\(auth/)).toEqual([]);
  });

  it("authSecret appears only where it does login work, never on a line with content crypto", () => {
    const allowed = ["api.ts", "components/RecoveryCode.tsx", "crypto.ts", "identity.ts", "main.tsx", "recovery.ts", "stepup.ts", "storage.ts"];
    for (const file of using(/authsecret/i)) expect(allowed).toContain(file);
    for (const { file, text } of sources.filter(({ text }) => /authsecret/i.test(text))) {
      for (const line of text.split("\n").filter((value) => /authsecret/i.test(value))) {
        expect(line, file).not.toMatch(/encrypt(Note|Comment|Attachment|ContainerMeta)|decrypt(Object|Note|Comment|Attachment|ContainerMeta)|KeyRef|readKeys|ownCopyKeys|openFirst/);
      }
    }
  });

  it("server rows are read with readKeysFor; only this browser's own copies may use the waiting key", () => {
    const main = readFileSync(new URL("./main.tsx", root), "utf8");
    const calls = main.split("\n").filter((line) => line.includes("ownCopyKeysFor(") && !line.includes("const ownCopyKeysFor"));
    expect(calls.length).toBeGreaterThan(0);
    for (const line of calls) expect(line).toMatch(/cached|item\./);
  });
});

describe("readKeys", () => {
  const k2 = asContentKey(new Uint8Array(32).fill(2));
  const ring = new Map([[2, k2]]);
  it("opens a row only with its own generation's container key", () => {
    expect(readKeys({ sharedGeneration: 2 }, ring, 2, {})).toEqual([k2]);
    for (const generation of [undefined, 0, 1, 1.5, 3, -1]) expect(readKeys({ sharedGeneration: 2 }, ring, generation, {})).toEqual([]);
  });
  it("an unkeyed container has no read key for any generation, and the floor wins over a lower report", () => {
    expect(readKeys({ sharedGeneration: 0 }, ring, 2, {})).toEqual([]);
    expect(readKeys({ sharedGeneration: 0 }, ring, 2, { shared: 3 })).toEqual([]);
  });
  it("a waiting copy opens only with the waiting key, and only through ownCopyKeys", () => {
    const waiting = asContentKey(new Uint8Array(32).fill(7));
    expect(readKeys({ sharedGeneration: 2 }, ring, WAITING_GENERATION, {})).toEqual([]);
    expect(ownCopyKeys({ sharedGeneration: 2 }, ring, WAITING_GENERATION, {}, waiting)).toEqual([waiting]);
    expect(ownCopyKeys({ sharedGeneration: 2 }, ring, WAITING_GENERATION, {})).toEqual([]);
    expect(ownCopyKeys({ sharedGeneration: 2 }, ring, 2, {}, waiting)).toEqual([k2]);
  });
  it("refuses a content key that is not 32 bytes", () => {
    expect(() => asContentKey(new Uint8Array(31))).toThrow();
  });
});
```

If the line check fires on a line that does only login work (a type signature that happens to name `KeyRef` beside `authSecret`), split the line; do not loosen the pattern.

- [ ] **Step 2: Run it to verify it fails.**

Run: `cd web && npx vitest run src/contentKeys.test.ts`
Expected: FAIL (`asContentKey` is not exported; `legacyKeyRef` is found).

- [ ] **Step 3: crypto.ts.** Replace lines 158-162 with:

```ts
declare const contentKey: unique symbol;
/** A container key, or the identity's waiting key: the only input content subkeys derive from. Made only in keyring.ts. */
export type KeyRef = Uint8Array & { readonly [contentKey]: true };
export function asContentKey(bytes: Uint8Array): KeyRef {
  if (bytes.length !== 32) throw new Error("invalid content key");
  return bytes as KeyRef;
}
```

Delete `hexBytes` (line 32) if `tsc` reports it unused.

- [ ] **Step 4: keyring.ts.** Import `asContentKey`. Set `export type Keyring = ReadonlyMap<number, KeyRef>;`. Where `openKeyring` adds an unwrapped key to the ring, wrap it: `asContentKey(key)`. `newContainerKey = (): KeyRef => asContentKey(randomBytes(32))`. `waitingKey` returns `asContentKey(hkdfSha256(…))`. Rewrite the `WAITING_GENERATION` comment: "Generation 0 marks a local edit made while the current key is missing. It is sealed with the identity's waitingKey, stays on this device (server generations start at 1 and the queue never sends it) and is re-sealed for the current key once that key arrives." Delete `legacyRow`, `localReadKeys`, `movesLabelledSubpage`, `copyableConflicts`, `sharedFloor` (inline it). Replace `readKeys` with:

```ts
/**
 * The one key a server row may be read with: the container key of the row's own generation, at or
 * above the first keyed generation (the higher of the server's report and this device's floor).
 * A missing, malformed, waiting or older generation gets no key; nothing else is ever tried.
 */
export function readKeys(container: Pick<KeyedContainer, "sharedGeneration">, ring: Keyring, generation: number | undefined, floor: KeyFloor): KeyRef[] {
  const shared = Math.max(container.sharedGeneration, floor.shared ?? 0);
  if (shared === 0 || generation === undefined || !Number.isInteger(generation) || generation < shared) return [];
  const key = ring.get(generation);
  return key ? [key] : [];
}

/** Keys for a copy this browser stored itself (cache, queue, upload): the waiting key for a waiting entry, otherwise readKeys. */
export const ownCopyKeys = (container: Pick<KeyedContainer, "sharedGeneration">, ring: Keyring, generation: number | undefined, floor: KeyFloor, waiting?: KeyRef): KeyRef[] =>
  generation === WAITING_GENERATION ? (waiting ? [waiting] : []) : readKeys(container, ring, generation, floor);
```

Fix every `Map<number, Uint8Array>` that becomes a `Keyring` in `keyService.ts` the same way (`tsc` names them).

- [ ] **Step 5: drain.ts.** Replace `queuedSaveStep`, `readyToSend` and `attachmentStep` with:

```ts
/** What the queue drain may do with an entry sealed at generation: send it only when it is sealed for the current write key; otherwise re-seal it under write, or wait while there is no write key. */
export function queuedSaveStep(floor: KeyFloor | undefined, generation: number | undefined, write: WriteKey | undefined): "send" | "reseal" | "wait" {
  if (!write || !floor) return "wait";
  return generation === write.generation ? "send" : "reseal";
}

/**
 * The queued save as it may be uploaded now: itself, a copy re-sealed under write, or undefined to keep it
 * queued. Stale ciphertext is never returned. The entry opens with ownCopyKeys: its own generation's key,
 * or the waiting key for a waiting edit. The server cannot write the queue.
 */
export async function readyToSend(item: PendingSave, container: KeyedContainer, floor: KeyFloor | undefined, write: WriteKey | undefined, ring: Keyring, waiting?: KeyRef): Promise<PendingSave | undefined> {
  const step = queuedSaveStep(floor, item.keyGeneration, write);
  if (step !== "reseal") return step === "send" ? item : undefined;
  const payload = await openFirst(ownCopyKeys(container, ring, item.keyGeneration, floor!, waiting), (key) => decryptObject(key, item.containerID, item.payload));
  if (!payload) return undefined;
  return { ...item, payload: await encryptNote(write!.key, item.containerID, payload), keyGeneration: write!.generation };
}
```

and in `attachmentStep` drop `legacy`, call `queuedSaveStep(floor, job.keyGeneration, write)` and `ownCopyKeys(container, ring, job.keyGeneration, floor!, waiting)`. Fix the imports.

- [ ] **Step 6: main.tsx, keys.** Delete `legacy` (682). Replace `readKeysFor`/`localReadKeysFor`/`legacyRowFor` (706-715) with:

```ts
  /** Keys a server row may be read with: its own generation's container key, never a default. */
  const readKeysFor = (container: Container, generation: number | undefined) => {
    const floor = floorFor(container);
    return floor ? readKeys(container, ringsRef.current[container.id] ?? noKeys, generation, floor) : [];
  };
  /** Keys for a copy this browser stored itself (cache, queue): as readKeysFor, plus the waiting key for a waiting edit. A notebook no longer listed has no container key here. */
  const ownCopyKeysFor = (container: Container | undefined, generation: number | undefined): KeyRef[] => {
    const floor = container && floorFor(container);
    if (container && !floor) return [];
    return ownCopyKeys(container ?? { sharedGeneration: 0 }, (container && ringsRef.current[container.id]) ?? noKeys, generation, floor ?? NO_FLOOR, waitingRef.current);
  };
```

Then: every `localReadKeysFor(c, g)` → `ownCopyKeysFor(c, g)` (cache reads at 1330, 1337, 1967); `readyToSend(…, legacy, waitingRef.current)` → `readyToSend(…, waitingRef.current)` (1866); `attachmentStep` the same (2293); `keysFor={(item) => ownCopyKeysFor(items.find((entry) => entry.id === item.containerID), item.keyGeneration)}`. In `readContainerObjects`, drop `legacyRead` from the return type and body, and simplify `useCache` to `Boolean(cached && cached.version >= object.version)`.

- [ ] **Step 7: main.tsx, labels.** Delete `PlainComment.unverified`, `UNVERIFIED`, `UNVERIFIED_SIDE_EFFECT`, `UNVERIFIED_SUBPAGES`, the `unverified` state, `unverifiedRef`, `markLegacy` and every call to it, the `unverified` prop on `<SectionTabs>` (and its prop and rendering in `components/SectionTabs.tsx`), the "Not verified" row label (2799), the selected-page banner (2873-2874), the comment suffix (2943) and the attachment suffix (2980). Delete the `explicit` parameter from `updateStructure` and `placePage` and their guard blocks (1939-1945, 1971-1977); remove the `false` argument at every caller (`grep -n 'updateStructure(.*, false)\|placePage(.*, false)' web/src/main.tsx`). Delete the `movesLabelledSubpage` refusal (2127-2130). In the conflict reload, replace the `copyableConflicts` line with `const copyable = (await objectConflicts(open.id)).filter((item) => !item.resolved);` and delete `unverifiedKept` and its error branch (2247), keeping the `!failed && !unreadable` condition.

- [ ] **Step 8: main.tsx, names.** In `resealName` replace the `opened([...(floor ? legacyKeys(floor, legacy) : []), ...ring.values()])` call and its two comment lines with `if ((await opened([...ring.values()])) !== name) return [current, "This notebook's name changed while its keys were shared. Rename it so every member can read it."];` and delete the now-unused `floor`. Change the comment on the `else` branch to "Not shown (the list could not open it: a re-mint another browser deferred). Only container keys this browser accepted may supply it, newest first." In `AdminTeams`, delete the `authSecret` prop, `legacy`, `floorSink`, `teamNames` state and the decryption loop: `reload` sets only `setTeams(await listAdminTeams(sink))` with a `sink` built the way `floorSink` was (the list must still pass the observer); names render from `knownNames[entry.id]` (as now) and fall back to the existing unnamed text; the `useEffect` depends on `[]`. Remove `authSecret={authSecret}` where `SettingsView` renders `AdminTeams`, and the `authSecret` prop from `SettingsView` if nothing else uses it there. Fix `api.ts` comments: line 11-14 becomes "A row generation from the server: a non-negative safe integer, else undefined, which readKeys never opens." and line 251 "A missing or malformed generation stays undefined so readKeys finds no key."

- [ ] **Step 9: Rename and adapt the tests.** `git mv web/src/legacyWiring.test.ts web/src/workspaceWiring.test.ts` and in it: the `describe("workspace keys after P5")` "seals waiting edits with the identity…" test expects `ownCopyKeysFor` instead of `localReadKeysFor`; delete assertions that mention `legacy`. In `keyring.test.ts` delete the `legacyRow`, `localReadKeys`, `movesLabelledSubpage`, `copyableConflicts` and "readKeys … legacy" tests and the AdminTeams login-key token count; keep the structure tests "no key module compares kind or reads teamId" and "main.tsx gives every notebook a key pass…". In every test file, ring values and content keys come from `asContentKey(...)` (tests may call it; the guard checks non-test files only). `drain.test.ts`: drop the `legacy` argument and the legacy-row cases; keep "a waiting edit survives a password change…" against `ownCopyKeys`. `crypto.test.ts`: delete `legacyKeyRef` tests; content round-trips use `asContentKey(randomBytes(32))`.

- [ ] **Step 10: Run the web suite.**

Run: `cd web && npm test && npm run build && node src/ky-ui/check-vendor.mjs`
Expected: PASS, including `contentKeys.test.ts`.

- [ ] **Step 11: Rebuild the embedded bundle.**

Run: `npm run build --prefix web && rm -rf internal/web/dist && cp -r web/dist internal/web/dist && diff -qr web/dist internal/web/dist && go test ./internal/web/ -count=1`
Expected: no diff output; PASS.

- [ ] **Step 12: Commit.**

```bash
git add -A web/src internal/web/dist
git commit -m "web: content opens only with container keys; the login key and its labels are gone"
```

---

## Task 7: Docs — the spec, DESIGN, IMPLEMENTATION_PLAN, AGENTS and CHANGELOG (DOX pass)

**Files:**
- Modify: `docs/superpowers/specs/2026-10-07-team-keys-design.md` (§0, §2, §4, §5, §6, §7 "as built" blocks, §8 last paragraph)
- Modify: `DESIGN.md:160-253`, `IMPLEMENTATION_PLAN.md` (any line `grep` still finds), `AGENTS.md:369,390,403,408-461,539-540,593-658`, `CHANGELOG.md:1-80`, `UI-VERIFICATION.md` (P4 section header note only)
- Modify: `.superpowers/sdd/2026-10-08-team-keys-p5/progress.md` (one ledger line)

**Interfaces:** none (documentation).

- [ ] **Step 1: Write the failing doc check.** Run:

```bash
grep -nE 'legacyKeyRef|legacyRow|localReadKeys|closeLegacy|reopenLegacy|LegacyReview|migration\.ts|/legacy\b|pre-sharing items|Show older items|not end-to-end verified|shared-v1|Reload open KyNotes tabs|legacyAtRisk|resealWaitingEdits|PASSWORD_CHANGE_NOTE|owner unknown' AGENTS.md DESIGN.md IMPLEMENTATION_PLAN.md CHANGELOG.md docs/superpowers/specs/2026-10-07-team-keys-design.md
```

Expected: many matches (the failing state).

- [ ] **Step 2: The spec.** Edit `docs/superpowers/specs/2026-10-07-team-keys-design.md`:
  - Status line: append "Legacy login-derived content key removed 2026-10-08 (user decision, see §9)."
  - §0 F1/F2: append to each "(closed: no content key derives from `authSecret` since the 2026-10-08 removal)".
  - §2 "Choosing a key on read": replace the paragraph with "**Choosing a key on read:** the client takes the row's `keyGeneration` (required) and the container's `sharedGeneration` (its first keyed generation; the higher of the server's report and this device's floor). A row opens only with `CK[keyGeneration]`, and only when `keyGeneration ≥ sharedGeneration > 0`. Nothing else is tried: no other generation's key and no login-derived key. A waiting edit this browser stored (generation 0) opens only with its waiting key."
  - §2 first bullet: replace "(a CK, or a legacy `authSecret`)" with "(a CK, or the identity's waiting key for local copies)".
  - §4: replace the section body with: "Superseded 2026-10-08. KyNotes was never live, so nothing is migrated: every container is keyed at creation (`createNamed`), the server refuses content, names and envelopes before the first key, and rows sealed with a login key by development builds never open. Browsers drop their local cache, queue and pending uploads once (IndexedDB v6)."
  - §5 Server: in the migrations bullet, replace "P4 adds no migration, only the read-only `GET /containers/{id}/legacy`" with "P4's read-only `GET /containers/{id}/legacy` was removed with the legacy key"; delete the `PUT /comments/{id}` route bullet and its "Rule changes" mention; replace "**The save gate becomes …**" with "**The save gate:** a container with a key (`shared_generation > 0`), `X-Kynotes-Key-Scheme: shared-v2`, the current generation, and the writer's own identity envelope at it. Containers without a key take no content, name or envelope."
  - §5 Client `storage.ts` bullet: replace "alongside `authSecret` (still needed for legacy decryption)" with "alongside `authSecret` (the device key used for silent step-up)".
  - §6: delete the bullet "**Read downgrade (closed per device in P4)**" entirely. In "Plaintext keys" replace "This closes F1 for migrated content. Legacy content remains derivable from `authSecret` until it is re-encrypted." with "No content key derives from `authSecret`, so F1 is closed for all content." In "Sharing-state rollback" replace "so that writers fall back to the login key it can derive, or seal under a generation a removed member still holds" with "so that writers seal under a generation a removed member still holds" and delete "the legacy key is never selected and".
  - §7 phase headings: under **P4 as built**, replace the body (rulings 1-21, decisions, known limits) with "Removed 2026-10-08 (§9): the review, closure, reopen and labels no longer exist, and its two pending decisions and every known limit went with them." Under **P5 as built**: rulings 1-2 become "1. The login key never seals or opens content (§9). 2. Personal notebooks are keyed at creation; there is nothing to migrate (§9)." Ruling 5: delete "A password change re-seals pre-P5 queued edits onto it; on a browser with no identity a local-only re-seal under the new login key is the `ponytail:` limit." Ruling 6: replace with "6. A password change needs no content warning: container keys are wrapped to the identity, whose password copy the change re-wraps." Known limits: delete the first bullet ("A never-shared notebook …"), "Edits queued before the upgrade …", "The password change warning counts …", "P4 decision (2) …" and "A personal notebook with more than 1000 listed rows …". P3a ruling 1 and P3a ruling 8, P3b ruling 12: append "(superseded 2026-10-08, §9)". P3a "Known limits" N3: append "Resolved by §9: no login-key copies remain." **P4.** and **P5.** phase descriptions at the end: append "(see §9)".
  - §8 last paragraph: unchanged except "(P5, awaiting Yoshi …; D-P5-2)" stays.
  - Add **§9** at the end:

```markdown
## 9. Decision 2026-10-08: no legacy login-derived content key (owner-approved)

KyNotes has never been live, so breaking changes are allowed. Every notebook, personal and team, uses only container keys from the moment it is created; the login-derived key (`HKDF(authSecret, containerID)`) never reads or writes content. Plan: `docs/superpowers/plans/2026-10-08-team-keys-remove-legacy.md`.

As built. Resolved ambiguities:
  1. `sharedGeneration` stays and means the first keyed generation (0: no key yet, nothing can be written). A container is created at generation 1 with no key; its first rotation makes generation 2 its first key.
  2. The server refuses content writes, names and envelopes for a container without a key, and creation takes no name (`400`). The device gate for never-rotated containers is gone.
  3. `X-Kynotes-Key-Scheme` stays at `shared-v2`, required on every content write and name change, so tabs from builds that read with the login key are refused.
  4. `GET /containers/{id}/legacy` and `PUT /comments/{id}` are removed; `author_user_id` and attach/detach stay.
  5. No migration is added or edited.
  6. The browser's cache, queue and pending uploads are dropped once (IndexedDB v6); queue entries always carry their owner.
  7. `readKeys` returns only the container key of the row's generation; `ownCopyKeys` adds the waiting key for this browser's own waiting copies only.
  8. `KeyRef` is branded; only `keyring.ts` mints content keys (`contentKeys.test.ts`).
  9. A password change needs no content warning.
  10. The SSO master-password prompt stays; it now only creates the vault record (follow-up: remove it).
  11. Administrator pages never decrypt team names.
  12. The probe holds a password-wrapped identity and keys its notebook at creation.
  13. Stored closures from older builds are ignored and dropped on the next write.
  14. The name re-seal after a re-mint compares only with container keys.

  Decisions that disappeared: P4 (1) per-device closure; P4 (2) auto-close trusts the server's list. Residuals that disappeared: §6 read downgrade (and forged pre-sharing rows), every P4 known limit, the P5 limits inherited from P4.

  Known limits: development databases keep rows sealed with a login key, which never open; development browsers lose unsent local edits once at the upgrade.
```

- [ ] **Step 3: DESIGN.md.** Replace the paragraph that begins "The web client seals every container's content with its container key and never with the login-derived key" (lines 211-231, through "…when keys arrive; … re-sealed by a password change in the same browser.") with:

```markdown
The web client seals and opens every container's content only with its container keys; no content key
derives from the login secret. A notebook gets its first key when it is created (team keys P5; a
notebook whose first key was never minted is read-only until its owner's next open mints it, and only
once the owner's identity is recoverable: a password copy or a recovery-code copy exists). A row opens
only with the key of its own generation, at or above the container's first keyed generation
(`sharedGeneration`); a missing, malformed or older generation gets no key, so it fails closed. A
member without the current key cannot change anything there: pages, sections, groups, moves, deletes,
comments, attachments and conflict copies are disabled and their handlers refuse, so no empty object
is created. Edits already in progress when the key went missing wait in the encrypted local queue at
generation 0, sealed with a key derived from the identity (HKDF label `kynotes/waiting/v1`), are never
uploaded at that generation, and are resealed under the current key when keys arrive.
```

Keep the following sentences (header, meta `PATCH`, conflicts, envelopes, pins, floors) with the edits from Task 1, and in "so a server cannot roll a shared notebook back to the login key or an older generation" drop "to the login key or" → "back to an older generation". Line 168: "and reads rows at or above `shared_generation` only with that generation's key" stays.

- [ ] **Step 4: AGENTS.md.** Delete the "Team keys P4" bullet (593-631) entirely. Then:
  - 369: replace "`legacyAtRisk` counts notebooks that may hold login-key items (`web/src/passwordChange.ts`)." with nothing (delete the sentence).
  - 390 and 403: replace "then the legacy device rule while `shared_generation=0` or" with "then a key (`shared_generation > 0`) and"; replace `TestLegacyContainersKeepTheDeviceGate` with `TestUnkeyedContainerRefusesEveryWrite`, `TestEveryWriteNeedsTheCurrentKeyScheme`, `TestContainerCreationTakesNoName`.
  - 408-461 (Team keys P3a web): replace the sentences about legacy reads, `legacyKeyRef`, `legacyRow`, labels, `movesLabelledSubpage`, legacy conflict copies, `resealWaitingEdits` and `legacyAtRisk` with: "`readKeys` opens a row only with the container key of its own generation at or above the first keyed generation; `ownCopyKeys` adds the identity's waiting key for this browser's own generation-0 copies only. `KeyRef` is branded and minted only in `keyring.ts` (`asContentKey`); `contentKeys.test.ts` fails if any other file mints or casts one, or if `authSecret` meets content crypto."
  - 539-540 (P3b unsent edits): replace the owner-unknown sentences with "Queue and cache entries always carry their owner; Unsent edits lists this account's edits for notebooks it lost (export, discard)."
  - 633-658 (P5): replace "then migrated by the P4 …" through the P4 references with "keyed at creation"; delete `LegacyReview` and `passwordChange` from its verify list; add `contentKeys` and `workspaceWiring`.
  - Add a bullet after the P5 bullet:

```markdown
- Team keys, legacy key removed (2026-10-08, spec §9): no content key derives from `authSecret`. Server: a
  container takes content, names and envelopes only once it has a key (`checkWriteGate`, meta `PATCH`,
  `putGenerationTx`), creation takes no name, and every write carries `X-Kynotes-Key-Scheme: shared-v2`;
  `GET /containers/{id}/legacy` and `PUT /comments/{id}` are gone (`TestRemovedLegacyRoutesStayGone`). Web:
  IndexedDB v6 dropped earlier cache, queue and uploads once; `readKeys`/`ownCopyKeys` are the only key
  choices; `contentKeys.test.ts` guards the brand. Probe: password-wrapped identity
  (`teamkeys.UserKEK`/`SealIdentity`/`OpenIdentity`), notebook keyed at creation. Verify
  `TestUnkeyedContainerRefusesEveryWrite`, `TestEveryWriteNeedsTheCurrentKeyScheme`,
  `TestContainerCreationTakesNoName`, `TestIdentityWrapAgreesWithVectors`, `npm test` (contentKeys,
  keyring, drain, storage, stuckEdits, workspaceWiring) and `npm run e2e --prefix web`.
```

  - Child DOX Index entries that name `legacyWiring.test.ts` → `workspaceWiring.test.ts`.

- [ ] **Step 5: CHANGELOG.md.** Under "Unreleased": delete the "Team keys phase 4" entry. Replace the "Team keys phase 5" entry's sentence "Each notebook gets its key when you create it or first open it after this update. You then review and seal your older items, as in team notebooks." with "Each notebook gets its key when you create it." Delete the P3b sentence "**Reload open KyNotes tabs after updating:** … until it is reloaded." and the P3a sentence "Browser tabs opened before this release must be reloaded to write to a shared notebook (`409 already_exists`)." and the P1 sentences "Changing the password still makes existing notes unreadable; the form now says so and requires an explicit acknowledgement." and "Recovery and administrator password reset delete the identity." (superseded by P5). Add at the top of "Unreleased":

```markdown
- Notebooks are keyed only by their own encryption keys, from the moment they are created; no notebook
  content is ever sealed or opened with a key derived from your password (KyNotes was never released, so
  this is not a migration). The server refuses to store content, a name or a key for a notebook until its
  first key exists, and creating a notebook no longer accepts a name. Every write now carries
  `X-Kynotes-Key-Scheme: shared-v2`. `GET /api/v1/containers/{id}/legacy` and `PUT /api/v1/comments/{id}`
  are removed. Development data: rows written by earlier builds with a password-derived key no longer
  open (start from a fresh data directory), and each browser clears its local note cache, unsent-edit
  queue and pending uploads once on its first load of this version. `kynotes-probe` now creates a
  password-wrapped encryption key for its account and keys its notebook before writing.
```

- [ ] **Step 6: UI-VERIFICATION.md.** Under the P4 section heading add one line: "Superseded 2026-10-08: the review, closure and labels these captures show were removed (spec §9)." Do not edit the P4 records.

- [ ] **Step 7: progress ledger.** Append to `.superpowers/sdd/2026-10-08-team-keys-p5/progress.md`: "Plan 2026-10-08-team-keys-remove-legacy.md supersedes P5 Tasks 11-12 (legacy key removed; P4 decisions 1-2 gone)."

- [ ] **Step 8: Run the doc check again.** Re-run the Step 1 `grep`. Expected: matches only in the spec's §9, §7 "superseded" notes, `UI-VERIFICATION.md`'s P4 records and this plan. Any other match is stale text: fix it.

- [ ] **Step 9: Commit.**

```bash
git add AGENTS.md DESIGN.md IMPLEMENTATION_PLAN.md CHANGELOG.md UI-VERIFICATION.md docs/superpowers/specs/2026-10-07-team-keys-design.md .superpowers/sdd/2026-10-08-team-keys-p5/progress.md
git commit -m "docs: no legacy login-derived content key (spec §9, DOX pass)"
```

---

## Task 8: E2E — keyed from creation, password change, recovery restore, self-service reset

**Files:**
- Modify: `web/e2e/team-keys.e2e.ts` (delete 714-949 `p4` and its helpers; rewrite 443-461 and 486-488; add `p5`; adapt imports, `shoot`, `scenario`, the test's `finally`)
- Modify: `UI-VERIFICATION.md` (new "Legacy key removed" section)

**Interfaces:**
- Consumes: `person`, `withDialog`, `signIn`, `changeOwnPassword`, `takeOverPassword`, `vaultOf`, `openTeam`, `writePage`, `readPage`, `serverCopy`, `heldKeys`, `titleOf`, `containerOf`, `ownSettings`; `decryptContainerMeta`, `fromBase64`, `asContentKey`, `type KeyRef` (`../src/crypto`); `waitingKey` (`../src/keyring`); `newRecoveryCode` (`../src/recovery`).
- Produces: `loginKey(authSecret: string): KeyRef` (test-only negative control), `typeBack`, `resetOwnKey`, `storageHolds`, `p5`.

- [ ] **Step 1: Delete the P4 scenario.** Delete from `const LEGACY_TEAM` (714) to the end of `p4` (949), keeping `pageRow` (774) and `shoot` (777-798), and delete `await p4(owner, editor, second, senders);` from `scenario` (358). In `shoot`, add a `phase: string` parameter and write `${dir}/team-keys-${phase}-${state}-${scheme}-${form}.png`. Add a run-wide guard right after the four `person(...)` calls in the test:

```ts
  // The legacy review route is gone: no browser may ever ask for it.
  const legacyCalls: string[] = [];
  for (const who of [owner, editor, newcomer, shared, second]) who.page.on("request", (request) => { if (/\/legacy(\?|$)/.test(new URL(request.url()).pathname)) legacyCalls.push(request.url()); });
```

and in the `finally`, `expect(legacyCalls).toEqual([]);`.

- [ ] **Step 2: The login key as a negative control only.** Replace `legacyKeyRef` in the `../src/crypto` import with `asContentKey`, `decryptContainerMeta`, and add:

```ts
/** The key the server could derive from what it sees at sign-in. Test-only: content must never open with it. */
const loginKey = (authSecret: string) => Uint8Array.from(Buffer.from(authSecret, "hex")) as KeyRef;
```

Lines 273 and 288 use `loginKey((await vaultOf(…))!.authSecret)`. In `heldKeys` wrap the unwrapped key: `asContentKey(unwrapEnvelope(…))`.

- [ ] **Step 3: P3b step 3 through the self-service reset.** Add after `takeOverPassword`:

```ts
/** Types back the group the dialog names from code, then saves. */
async function typeBack(scope: Locator, code: string) {
  const label = (await scope.locator("label.field span").filter({ hasText: /^Type group [1-7] of 7 from your saved copy$/ }).textContent())!;
  const group = Number(/group ([1-7])/.exec(label)![1]);
  await scope.getByLabel(label).fill(code.split("-")[group - 1].toLowerCase());
  await scope.getByRole("button", { name: "Save recovery code" }).click();
}

const RECOVERY_SAVED = "Recovery code saved. Keep it somewhere safe.";
const RECOVERY_RESTORED = "Restored. This browser now holds your encryption key.";
const RECOVERY_TYPO = "Check the recovery code: a character is wrong or missing.";
const RECOVERY_WRONG = "This recovery code does not open your key. Check it and try again.";
const RESET_HELD = "This browser holds your encryption key, so you do not need a reset to get it back: save a recovery code instead. Reset only if a browser that holds your key was lost or stolen.";
const RESET_DONE = "Your encryption key was reset. Team owners share their notebooks' keys with you again when they next open them.";

/** The user's own reset in Settings, from a browser that holds the key; returns the new recovery code. */
async function resetOwnKey(who: Person) {
  await who.page.getByRole("button", { name: "Settings" }).click();
  const card = who.page.locator("#identity-reset");
  who.expected.push({ type: "confirm", text: RESET_HELD });
  await withDialog(who, { type: "prompt", text: /^Reset your encryption key\?/, answer: "RESET" }, () => card.getByRole("button", { name: "Reset encryption key…" }).click());
  const code = (await card.locator(".recovery-code").textContent())!.trim();
  await card.getByRole("button", { name: "I saved it" }).click();
  await typeBack(card, code);
  await expect(card.getByText(RESET_DONE)).toBeVisible({ timeout: 30_000 });
  await who.page.getByRole("button", { name: "← Workspace" }).click();
  return code;
}
```

(The strings are copied from `components/RecoveryCode.tsx:15-21` and `recovery.ts:24-25`; check them against the source before the run.) In `p3b` step 3 keep the administrator authorization and reset, change the alert regex to `/^Password reset\. .*keeps its encryption key/`, then replace from `await owner.page.goto("about:blank");` through `expect(renewed.fingerprint).not.toBe(newcomerOwn.fingerprint);` with:

```ts
  await owner.page.goto("about:blank");
  // 3. The administrator reset keeps the newcomer's key; only the newcomer's own reset replaces it.
  const oldDevice = (await vaultOf(newcomer.page))!.identity!.deviceId;
  await signIn(newcomer.page, "newcomer", TEMPORARY);
  await takeOverPassword(newcomer.page);
  expect((await vaultOf(newcomer.page))!.identity!.deviceId).toBe(oldDevice);
  await resetOwnKey(newcomer);
  await expect.poll(async () => (await vaultOf(newcomer.page))?.identity?.deviceId, { timeout: 30_000 }).not.toBe(oldDevice);
  await openTeam(editor.page, TEAM, cid);
  await expect(editor.page.locator(".member-row", { hasText: "newcomer" })).toContainText("waiting for key");
  const renewed = await ownSettings(newcomer.page);
  expect(renewed.fingerprint).not.toBe(newcomerOwn.fingerprint);
  await shoot(newcomer.page, "reset", newcomer.page.locator(".workspace-title"), "legacy-removed");
```

Steps 4-6 of `p3b` stay.

- [ ] **Step 4: P3b step 5, a stranded waiting edit.** Replace the `stranded` line (488) with:

```ts
  const held = (await vaultOf(newcomer.page))!.identity!;
  const stranded = await encryptNote(waitingKey({ privateKey: Uint8Array.from(held.privateKey) }), lost, { type: "page", title: "Stranded edit", body: "[]" });
```

(import `waitingKey` from `../src/keyring`). The entry keeps `keyGeneration: 0` and its `owner`, so Unsent edits opens it with the waiting key. The rest of step 5 is unchanged.

- [ ] **Step 5: The new scenario.** Add after `p3c`, and call `extra.push(...(await p5(owner, editor, browser, cid)))` at the end of `scenario` (thread `browser` and an `extra: Person[]` array from the test into `scenario`, and add `...extra` to the `finally` check):

```ts
const NEW_OWN = "newer horse battery staple";
const RESET_TEMPORARY = "reset horse battery staple";

/** True when any storage this page can see (IndexedDB, localStorage, sessionStorage, the URL) holds needle. */
const storageHolds = (page: Page, needle: string) => page.evaluate(async (text) => {
  const dumps: string[] = [location.href, JSON.stringify({ ...localStorage }), JSON.stringify({ ...sessionStorage })];
  for (const info of await indexedDB.databases()) {
    const db = await new Promise<IDBDatabase>((resolve, reject) => { const open = indexedDB.open(info.name!); open.onsuccess = () => resolve(open.result); open.onerror = () => reject(open.error); });
    for (const name of [...db.objectStoreNames]) {
      const rows = await new Promise<unknown[]>((resolve) => { const all = db.transaction(name).objectStore(name).getAll(); all.onsuccess = () => resolve(all.result); });
      dumps.push(JSON.stringify(rows, (_, value) => (value instanceof Uint8Array || ArrayBuffer.isView(value) ? new TextDecoder().decode(value as Uint8Array) : value)));
    }
    db.close();
  }
  return dumps.some((dump) => dump.includes(text) || dump.includes(text.replaceAll("-", "")));
}, needle);

async function p5(owner: Person, editor: Person, browser: Browser, cid: string) {
  const editorKey = (await vaultOf(editor.page))!.identity!;
  const senders = new Map([[editorKey.deviceId, Uint8Array.from(editorKey.publicKey)]]);

  // 1. A new personal notebook is keyed before anything is written: its name and pages open only with
  //    its container key, never with the key the server could derive from the login.
  await withDialog(editor, { type: "prompt", text: "Notebook name", answer: "Keyed Notebook" }, () => editor.page.getByRole("button", { name: "＋ New notebook" }).click());
  await expect(editor.page.locator(".workspace-title")).toHaveText("Keyed Notebook");
  const nid = containerOf(editor.page);
  await writePage(editor.page, "Keyed page", "keyed comment");
  const copy = await serverCopy(editor.page, "Keyed page");
  const keys = await heldKeys(editor.page, nid, senders);
  expect(copy.generation).toBe(2);
  await expect(titleOf(keys.get(copy.generation)!, nid, copy.bytes)).resolves.toBe("Keyed page");
  const login = loginKey((await vaultOf(editor.page))!.authSecret);
  await expect(titleOf(login, nid, copy.bytes)).rejects.toThrow();
  const meta = await editor.page.evaluate(async (id) => ((await (await fetch("/api/v1/containers")).json()) as Array<{ id: string; metaCiphertext: string }>).find((entry) => entry.id === id)!.metaCiphertext, nid);
  await expect(decryptContainerMeta(keys.get(2)!, nid, fromBase64(meta))).resolves.toEqual({ name: "Keyed Notebook" });
  await expect(decryptContainerMeta(login, nid, fromBase64(meta))).rejects.toThrow();
  await expect(editor.page.getByText(/not verified|not end-to-end verified/i)).toHaveCount(0);
  await shoot(editor.page, "keyed", editor.page.locator(".workspace-title"), "legacy-removed");

  // 2. The editor saves a recovery code: shown once, typed back, never sent, never stored.
  const sentBodies: string[] = [];
  editor.page.on("request", (request) => { if (/\/api\/v1\/me\/identity\/recovery$/.test(request.url())) sentBodies.push(request.postData() ?? ""); });
  await editor.page.getByRole("button", { name: "Settings" }).click();
  await editor.page.locator("#recovery").getByRole("button", { name: "Create recovery code" }).click();
  const code = (await editor.page.locator(".recovery-code").textContent())!.trim();
  expect(code).toMatch(/^([0-9A-HJKMNP-TV-Z]{4}-){6}[0-9A-HJKMNP-TV-Z]{4}$/);
  await editor.page.getByRole("button", { name: "I saved it" }).click();
  await expect(editor.page.locator(".recovery-code")).toHaveCount(0);
  await typeBack(editor.page.locator("#recovery"), code);
  await expect(editor.page.getByText(RECOVERY_SAVED)).toBeVisible({ timeout: 30_000 });
  expect(sentBodies).toHaveLength(1);
  expect(sentBodies[0]).not.toContain(code);
  expect(sentBodies[0]).not.toContain(code.replaceAll("-", ""));
  expect(await storageHolds(editor.page, code)).toBe(false);

  // 3. A password change keeps content: another browser signs in with the new password and reads it.
  await changeOwnPassword(editor.page, OWN, NEW_OWN);
  await editor.page.getByRole("button", { name: "← Workspace" }).click();
  const after = await person(browser);
  await signIn(after.page, "editor", NEW_OWN);
  await openTeam(after.page, "Keyed Notebook", nid);
  await readPage(after.page, "Keyed page", ["keyed comment"]);
  await openTeam(after.page, TEAM, cid);
  await readPage(after.page, "Owner page", ["owner comment"]);

  // 4. An administrator reset keeps the key: a fresh browser with no trusted device restores it with
  //    the code, sends no link request, and keeps the code out of storage and the address bar.
  await owner.page.getByRole("button", { name: "Admin" }).click();
  const users = owner.page.locator("#users");
  await users.getByLabel("Confirm your password").fill(OWN);
  await users.getByRole("button", { name: "Authorize user creation and password resets" }).click();
  await expect(users.getByText("Password confirmed for ten minutes.")).toBeVisible();
  const row = owner.page.locator(".admin-user", { has: owner.page.locator("strong", { hasText: /^editor$/ }) });
  owner.expected.push({ type: "prompt", text: /^New temporary password for editor/, answer: RESET_TEMPORARY });
  await withDialog(owner, { type: "alert", text: /^Password reset\. .*keeps its encryption key/ }, () => row.getByRole("button", { name: "Reset password" }).click());
  await owner.page.getByRole("button", { name: "← Workspace" }).click();
  const restored = await person(browser);
  const linkWrites: string[] = [];
  restored.page.on("request", (request) => { if (request.method() !== "GET" && /\/api\/v1\/me\/link-requests/.test(request.url())) linkWrites.push(request.url()); });
  await signIn(restored.page, "editor", RESET_TEMPORARY);
  await restored.page.getByRole("button", { name: "Settings" }).click();
  await changeOwnPassword(restored.page, RESET_TEMPORARY, OWN);
  const restore = restored.page.locator("#recovery-restore");
  const fetches: string[] = [];
  restored.page.on("request", (request) => { if (/\/recovery\/fetch$/.test(request.url())) fetches.push(request.url()); });
  await restore.getByLabel("Recovery code").fill(code.slice(0, -1));
  await restore.getByRole("button", { name: "Restore" }).click();
  await expect(restore.getByText(RECOVERY_TYPO)).toBeVisible();
  expect(fetches).toEqual([]);
  await restore.getByLabel("Recovery code").fill(newRecoveryCode().code);
  await restore.getByRole("button", { name: "Restore" }).click();
  await expect(restore.getByText(RECOVERY_WRONG)).toBeVisible({ timeout: 30_000 });
  await restore.getByLabel("Recovery code").fill(` ${code.toLowerCase()} `);
  await restore.getByRole("button", { name: "Restore" }).click();
  await expect(restored.page.getByText(RECOVERY_RESTORED)).toBeVisible({ timeout: 30_000 });
  const back = (await vaultOf(restored.page))!.identity!;
  expect(back.publicKey).toEqual(editorKey.publicKey);
  expect(back.privateKey).toEqual(editorKey.privateKey);
  expect(linkWrites).toEqual([]);
  expect(restored.page.url()).not.toContain(code);
  expect(await storageHolds(restored.page, code)).toBe(false);
  await restored.page.getByRole("button", { name: "← Workspace" }).click();
  await openTeam(restored.page, "Keyed Notebook", nid);
  await readPage(restored.page, "Keyed page", ["keyed comment"]);
  await openTeam(restored.page, TEAM, cid);
  await readPage(restored.page, "Owner page", ["owner comment"]);
  await shoot(restored.page, "restored", restored.page.locator(".workspace-title"), "legacy-removed");
  return [after, restored];
}
```

Import `newRecoveryCode` from `../src/recovery`. `changeOwnPassword` no longer needs its acknowledgement checkbox branch: delete the two `ack` lines (the checkbox no longer exists, Task 4). `changeOwnPassword` fills the Settings form, so open Settings before calling it where the page is on the workspace (as `takeOverPassword` does). The name `＋ New notebook` and the prompt text come from `main.tsx` `newWorkspace`; check them before the run.

- [ ] **Step 6: Run it.**

Run: `npm run build --prefix web && rm -rf internal/web/dist && cp -r web/dist internal/web/dist && npm run e2e --prefix web`
Expected: PASS.

- [ ] **Step 7: Mutation-prove the new assertions.** For each, apply alone, rebuild and re-sync the bundle (Step 6's first three commands), run `npm run e2e --prefix web`, confirm the named assertion fails, then `git checkout -- <file>`:

| Mutation | Must fail |
|---|---|
| `keyring.ts` `readKeys`: `return [ring.values().next().value]` when the generation is missing | none expected in the e2e (unit-tested in Task 6); record as an e2e survivor |
| `main.tsx` `createNamed`: name with `asContentKey(Uint8Array.from(Buffer.from(auth.authSecret, "hex")))` instead of `write.key` (cast in place to bypass the guard) | e2e step 1 (`decryptContainerMeta(login, …)` resolves) and `contentKeys.test.ts` |
| `components/RecoveryCode.tsx`: `sessionStorage.setItem("x", code)` after showing the code | e2e step 2 (`storageHolds`) |
| `identity.ts` `rewrapIdentity`: send no `wrappedIdentityKey` | e2e step 3 (the new browser cannot read) |
| A `fetch("/api/v1/containers/" + id + "/legacy")` added to `loadContainer` | the run-wide `legacyCalls` check |

- [ ] **Step 8: Screenshots.** Run `KYNOTES_E2E_SHOTS=/tmp/kynotes-legacy-removed-shots npm run e2e --prefix web`. Look at every `team-keys-legacy-removed-*` capture at 390 px and 1280 px, in both schemes: no "Not verified" label, no review banner, the workspace title and Settings cards fit. Add a "Legacy key removed (2026-10-08)" section to `UI-VERIFICATION.md` listing each file and what it shows, as the P4 section does.

- [ ] **Step 9: Commit.**

```bash
git add web/e2e/team-keys.e2e.ts UI-VERIFICATION.md internal/web/dist
git commit -m "e2e: notebooks keyed from creation, a password change, a recovery-code restore and a self-service reset"
```

---

## Task 9: Final verification and mutation table (replaces P5 Task 12)

- [ ] **Step 1: Server.** Run `go build ./... && go vet ./... && test -z "$(gofmt -l .)" && go test -race ./... && govulncheck ./...`. Expected: PASS, no vulnerabilities.

- [ ] **Step 2: Web.** Run `cd web && npm test && npm run build && node src/ky-ui/check-vendor.mjs && cd .. && diff -qr web/dist internal/web/dist && npm run e2e --prefix web`. Expected: PASS, no diff.

- [ ] **Step 3: Probe.** Repeat Task 3 Step 6 (two clean runs on one data directory). Expected: both PASS.

- [ ] **Step 4: Mutations.** From a clean tree, apply each mutation alone, run the named check, confirm it fails, then `git checkout -- <file>`. Before each e2e mutation rebuild and re-sync the bundle. Paste each failure into the PR.

| Mutation | Must fail |
|---|---|
| `checkWriteGate`: drop `shared == 0 \|\|` | `TestUnkeyedContainerRefusesEveryWrite` (save, comment, attachment) |
| `checkWriteGate`: drop the `scheme != keySchemeShared` check | `TestEveryWriteNeedsTheCurrentKeyScheme` |
| `keySchemeShared = "shared-v1"` (server only) | `TestEveryWriteNeedsTheCurrentKeyScheme`; e2e (every write 409) |
| Meta `PATCH`: drop `shared == 0 \|\|` | `TestUnkeyedContainerRefusesEveryWrite` (name) |
| `putGenerationTx`: `if shared == 0 { return current, nil }` | `TestUnkeyedContainerRefusesEveryWrite` (envelope) |
| `POST /containers`: accept a non-empty `metaCiphertext` | `TestContainerCreationTakesNoName` |
| `POST /admin/teams`: accept a non-empty `metaCiphertext` | `TestAdminTeamCreationTakesNoNameAndCreatesOwner` |
| Re-register `GET /api/v1/containers/{id}/legacy` (`auth.RequireSession`, 204) | `TestRemovedLegacyRoutesStayGone` |
| Re-register `PUT /api/v1/comments/{id}` | `TestRemovedLegacyRoutesStayGone` |
| `teamkeys.OpenIdentity`: AAD without the user ID | `TestIdentityWrapAgreesWithVectors` |
| `teamkeys.UserKEK`: label `kynotes/auth/v1` | `TestIdentityWrapAgreesWithVectors` |
| Probe `keyContainer`: skip the rotation | Task 3 Step 6 (step 3 or the first save fails with 409) |
| Probe `changePassword`: omit `wrappedIdentityKey` | Task 3 Step 6 (`409 identity_rewrap_required` at the take-over) |
| `crypto.ts`: re-add `export const legacyKeyRef = (s: string) => asContentKey(Uint8Array.from(s.match(/../g)!.map((h) => parseInt(h, 16))))` | `contentKeys.test.ts` ("no login-derived…" and "only keyring.ts makes content keys") |
| `main.tsx`: `const k = Uint8Array.from([]) as KeyRef;` anywhere | `contentKeys.test.ts` ("nothing casts") |
| `main.tsx`: one `encryptNote(asContentKey(…authSecret…))` line | `contentKeys.test.ts` (authSecret line check and asContentKey callers) |
| `readKeys`: drop `generation < shared \|\|` | `contentKeys.test.ts` "opens a row only with its own generation's container key" (generation 1) |
| `readKeys`: drop `shared === 0 \|\|` | "an unkeyed container has no read key…" |
| `readKeys`: `Math.max(container.sharedGeneration, 0)` (ignore the floor) | "…and the floor wins over a lower report" |
| `readKeys`: return the waiting key for generation 0 (add a `waiting` param and pass it from `readKeysFor`) | "a waiting copy opens only with the waiting key, and only through ownCopyKeys"; the `ownCopyKeysFor` structure check if routed through it |
| `ownCopyKeys`: drop the `WAITING_GENERATION` branch | "a waiting copy opens only…"; `drain.test.ts` "a waiting edit survives a password change…"; e2e P3b step 5 (export unreadable) |
| `asContentKey`: accept any length | "refuses a content key that is not 32 bytes" |
| `storage.ts` upgrade: drop the `oldVersion < 6` deletion | `storage.test.ts` "a v5 database opens at v6 with empty stores and its vault" |
| `storage.ts` upgrade: also delete the `keys` store | same (`getDeviceKey` undefined) |
| `getKeyState`: return the stored object as is | `storage.test.ts` "key memory keeps only generations, mark and digests" |
| `mergeFloor`: spread `...next` | `keyring.test.ts` "a floor carries only generations…" |
| `unsentEdits`: drop the owner filter | `stuckEdits.test.ts` "lists only this account's edits…" |
| `drainQueue`: drop the owner filter | `workspaceWiring.test.ts` (add the assertion there if none fails: `expect(block("  async function drainQueue(")).toContain('item.owner === auth.user.id')`) |
| `floors.ts` message handler: accept `closed` and keep it | `floors.test.ts` (existing "malformed and lower messages are ignored", extended with a `closed` field expecting `{ shared, generation }` only) |
| e2e mutations of Task 8 Step 7 | as listed there |

Expected survivors (record them in the PR): the e2e cannot see a wrong-key fallback inside `readKeys` (unit-tested); the storage-error `500` paths of the changed server routes (no fault injection).

- [ ] **Step 5: DOX closeout.** Re-run the Task 7 Step 1 `grep` and check that every changed path's nearest `AGENTS.md` (root; `internal/backup/AGENTS.md` and `internal/mirror/AGENTS.md` are untouched by this plan) describes it. Record in the PR which docs were left unchanged and why (`internal/backup/AGENTS.md`, `internal/mirror/AGENTS.md`: no backup or mirror change; `FRONTEND_IMPLEMENTATION_PLAN.md`: its "reload" lines are about browser reloads, not legacy keys; `docs/SSO.md`: its "legacy" is the SCIM envelope).

- [ ] **Step 6: Hand-off.** Do not push or open a PR without Yoshi's go-ahead. Write the hand-off (resolved ambiguities, the pending decisions that disappeared and those that remain, the mutation evidence, the e2e result, the one destructive effect on development browsers) and mirror it to myslop with the `myslop-handoff` skill.
