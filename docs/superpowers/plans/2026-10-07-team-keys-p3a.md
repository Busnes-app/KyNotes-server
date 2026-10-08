# Team Keys Phase 3a (Shared Team Keys in the Web Client) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Team notebooks become end-to-end shared for members who hold an identity. An owner or admin's browser mints each container key through `key-rotations`, wraps it for every member (history included), re-mints after a removal, and pins colleagues' keys on first use. Every browser reads with trial decryption (container keys, then the legacy login key) and writes a shared container only with its current container key. Members waiting for a key get a read-only notebook instead of a legacy write.

**Architecture:** `crypto.ts` helpers take a `KeyRef` (32 bytes of HKDF input: a container key, or `legacyKeyRef(authSecret)`) instead of the login secret, so the ciphertext layout and labels stay frozen. New `keyring.ts` holds the pure rules: open envelopes into a generation → key map, pick the write key, order read keys, plan a steward sweep. New `keyService.ts` runs one sweep against an injected API (tested with an in-memory server). New `pins.ts` holds trust-on-first-use pins and local fingerprints; pins live in the IndexedDB vault record. `main.tsx` routes every content key through `readKeysFor`/`writeKeyFor` and calls `syncKeys` when a team container opens, after a removal, and when a write meets a retired generation. Three small server changes close what the client cannot: containers report `sharedGeneration`, shared containers refuse writes without the `X-Kynotes-Key-Scheme: shared-v1` header (stale tabs), and envelope `PUT` may backfill older shared generations but never mint one.

**Tech Stack:** TypeScript/React (Vite, vitest, fake-indexeddb), `@noble/curves`/`@noble/ciphers` (already pinned), Go 1.26 for three route changes, `@playwright/test` 1.63.0 (new devDependency) for the three-browser check.

**Spec:** `docs/superpowers/specs/2026-10-07-team-keys-design.md` §1–§4, §6, §7 (P3 and its decomposition), §8. Conventions follow `docs/superpowers/plans/2026-10-07-team-keys-p2.md`.

**Prototype evidence (2026-10-07, scratch copy outside the repo):** every code block below was applied to a copy of `feat/team-keys-p3` at `ae1c200`. `npx tsc --noEmit`, `npx vitest run` (20 files, 197 tests) and `vite build` passed; `go vet ./...` and `gofmt -l` were clean; `go test -race ./...` passed except `TestRestoreCapsuleWithStdinSharesPreservesLoginAndRevokesSessions`, which refuses a data dir under `/tmp` and fails only because the scratch copy lived there. The Task 6 replacement list reproduces the prototype's `main.tsx` from the Task 2 state (one cosmetic difference in `newWorkspace`). The Task 8 Playwright run passed against the prototype server (8.4 s) and passed again on two further fresh servers. Mutations listed in Task 9 each failed their named test; one did not: dropping the immediate re-mint in `removeTeamMember` still passes the browser run, because the owner's next save meets `409` and `rekeyQueued` re-mints (defence in depth, recorded below).

---

## Global Constraints

| Item | Exact value |
|---|---|
| Content key input | `KeyRef = Uint8Array` (32 bytes). `HKDF-SHA256(ikm = KeyRef, salt = containerID, info = <existing label>)`. Labels and `iv ‖ ct+tag` layout unchanged. `legacyKeyRef(authSecret)` is the hex-decoded login secret, so legacy ciphertext opens unchanged (fixture in Task 2) |
| Write key | `sharedGeneration === 0` → legacy key at `keyGeneration`. Otherwise the container key at exactly `keyGeneration`, or **no write** (key wait). Never fall back to the legacy key in a shared container. An absent `sharedGeneration` counts as shared (`=== 0` only) |
| Read keys | row generation's key first, then other held keys newest first, then legacy; AES-GCM failure moves to the next key |
| Mint | Only through `POST /containers/{id}/key-rotations`, only by an owner/admin with an identity and a local password session (`!auth.sso`). First mint (never shared) only when every member has a visible identity; otherwise `blocked` with their names. After a removal the empty current generation is re-minted for members with identities |
| Wrap | `PUT .../envelopes` with every generation in `[sharedGeneration, keyGeneration]` this browser holds, for each member missing it. Only keys this browser unwrapped (P2 rule 7). One retry after `409 already_exists`, from a fresh container read |
| Pins | `{userId → publicKey base64}` in the vault record `pins: {userID, keys}`. First sight pins; a changed key needs `confirm()` showing the locally computed fingerprint (SHA-256 hex, groups of four); declining shares nothing |
| Server: containers | `GET /api/v1/containers`, `POST /api/v1/containers`, `GET /api/v1/admin/teams`, `POST /api/v1/admin/teams` include `sharedGeneration` (int) |
| Server: stale clients | `checkWriteGate(q, cid, user, generation, scheme)`. When `shared_generation > 0`, `scheme != "shared-v1"` → `409 already_exists` "this notebook uses shared keys: reload the page". Header `X-Kynotes-Key-Scheme`. The web client sends it on every mutating `request()` |
| Server: envelope PUT | `putGenerationTx`: legacy containers target the current generation (unchanged). Shared containers accept `shared_generation ≤ g ≤ key_generation` only when an envelope already exists at `g` (else `409 already_exists` "key rotation incomplete"); outside the range `409` "key generation changed". All other P2 rules (`insertEnvelopeTx`) unchanged |
| Error codes | No new codes |
| Scope | Team containers (`kind === "team"` or `teamId`). Personal notebooks stay legacy until P5. Invitation-time wrapping, device linking and SSO identities are P3b/P3c |
| Out of scope (checked) | `CanvasPage.tsx` (no crypto), sealed share links (random per-link key, plaintext re-sealed), `identity.ts`, `teamKeys.ts`, mobile/probe clients (no shared container until a web steward rotates; the probe never writes a shared container) |

## Resolved ambiguities (record in the spec in Task 7)

1. **Stale legacy tab after rotation.** The server cannot tell legacy ciphertext from container-key ciphertext. A tab loaded before P3a would read the new generation, find its own identity envelope (a steward wrapped it) and pass the P2 gate with login-key ciphertext nobody else can read. P3a adds a client marker: shared containers refuse writes without `X-Kynotes-Key-Scheme: shared-v1`. A current tab with a retired generation gets `409 already_exists` and re-keys: `saveNow`/`writeObject` queue the change and `drainQueue` → `rekeyQueued` decrypts it with any held key and re-seals it at the current generation; uploads re-seal once at finalize; comments ask to send again.
2. **Members without an identity (SSO-only, awaiting a password change).** The first mint waits until every member has one, and the steward sees who is missing. Once a team is shared, a member added without an identity is read-only ("waiting for keys") until P3c gives SSO users identities. SSO sessions never wrap: `RequireUserStepUp` refuses them, so `canWrap` is false and no step-up is attempted.
3. **Removal and the shared gate.** In a shared container, P2's removal bumps to a generation with no envelopes. The removing browser re-mints at once for the team and each child it knows; any steward's next open does the same; a write that meets the retired generation re-mints through the re-key path. `PUT` can no longer mint that empty generation, so two stewards cannot split it. A legacy container stays legacy after removal; the next steward open enables sharing if everyone has an identity.
4. **History for newcomers.** P2 accepted envelopes only at the current generation, so a member who joined after a rotation could not read older shared content. Stewards now backfill any shared generation that already has an envelope. Generations before `shared_generation` (legacy, where phones may hold device-gate envelopes) stay closed.
5. **Name of a newly shared container.** The minting steward re-seals the existing name under the new key when it can decrypt it. Admin pages hold no keys: `AdminTeams` reads only legacy names and refuses to rename a shared team.
6. **Pins storage.** In the vault record, so "Forget this device" clears them with the keys (spec §6). Without IndexedDB nothing is pinned; every key looks first-seen.

## Review Focus (likely failure modes and their pinning tests)

1. **A legacy write into a shared container.** The worst bug: content only its author can read, silently. Pinned by `keyring.test.ts` "writes legacy containers with the login key and shared ones only with the current key" (mutation: fall back to `legacy` when the ring lacks the key) and `TestSharedContainerRefusesStaleClientWrites` (save, comment, comment rewrite without the header are 409 and store nothing; legacy containers unaffected; mutation: drop the scheme check).
2. **SSO or not-yet-keyed members locked out by the first mint.** Pinned by `keyring.test.ts` "mints the first key only when every member has an identity" and `keyService.test.ts` "does not share a never-shared container while a member has no identity" (no step-up, no rotation). Mutation: always plan `mint`.
3. **Split generations.** Two stewards hold different keys for one generation. Pinned by `keyService.test.ts` "re-reads and re-plans once when another steward rotated first" (one key at generation 2, no second rotation; mutation: rethrow instead of retry) and `TestSharedGenerationIsMintedOnlyByRotation` (PUT into the empty post-removal generation is 409 and inserts nothing; mutation: drop the `held` check).
4. **Key substitution and history leaks.** A server-swapped colleague key must not receive a key silently, and backfill must not open legacy generations. Pinned by `keyService.test.ts` "stops at a changed colleague key unless the user confirms it" (mutation: skip the confirm) and `TestStewardBackfillsSharedHistoryOnly` (generation 1 holds a legacy envelope and stays closed; future generations closed; editors cannot wrap for others; mutation: drop `requested < shared`).
5. **Cross-user reading and forward secrecy in a real browser.** Pinned by `web/e2e/team-keys.e2e.ts` with three isolated browser contexts (owner, editor, newcomer): pages, comments and an attachment (downloaded bytes compared) cross all three; the newcomer reads content written before joining; after removal, the keys the newcomer held open the old page (control) and none opens the new one, whose generation the newcomer never held; the editor reads both.

Also check: `keyring.test.ts` "main.tsx key wiring" (exactly two `legacyKeyRef(` call sites, no `encrypt*/decrypt*(authSecret` anywhere) and `crypto.test.ts` "opens legacy ciphertext through legacyKeyRef".

---

## File Map

| File | Change |
|---|---|
| `internal/httpapi/teamkeys_routes.go` | `keySchemeHeader`, `errStaleClient`, `putGenerationTx`; `checkWriteGate` takes the scheme |
| `internal/httpapi/device_routes.go` | envelope `PUT` targets `putGenerationTx` |
| `internal/httpapi/object_routes.go`, `collab_routes.go`, `upload_routes.go` | pass `r.Header.Get(keySchemeHeader)` to both gate calls |
| `internal/httpapi/container_routes.go`, `admin_routes.go` | `sharedGeneration` in container and admin team JSON |
| `internal/httpapi/teamkeys_p3_test.go` | new: four P3a server tests |
| `internal/httpapi/device_contract_test.go`, `teamkeys_test.go` | helpers send the header (they model a current client) |
| `web/src/crypto.ts`, `crypto.test.ts` | `KeyRef`, `legacyKeyRef`; legacy fixture |
| `web/src/keyring.ts`, `keyring.test.ts` | new: pure key rules, sweep planner, wiring gate |
| `web/src/pins.ts`, `pins.test.ts` | new: TOFU pins and fingerprints |
| `web/src/keyService.ts`, `keyService.test.ts` | new: one sweep against an injected API |
| `web/src/storage.ts`, `storage.test.ts` | `getPins`/`storePins` in the vault record |
| `web/src/api.ts` | `sharedGeneration`, key-scheme header, envelope/rotation/identity calls, object `keyGeneration` |
| `web/src/main.tsx` | Task 2 (mechanical `legacy`), Task 6 (keyring wiring, re-key paths, key-wait UI, Settings fingerprint) |
| `web/package.json`, `package-lock.json`, `web/playwright.config.ts`, `web/e2e/server.sh`, `web/e2e/team-keys.e2e.ts`, `.gitignore` | three-browser check |
| `.github/workflows/ci.yml` | run the three-browser check in `test` |
| `internal/web/dist/` | regenerated bundle |
| `DESIGN.md`, `IMPLEMENTATION_PLAN.md`, the spec, `AGENTS.md`, `CHANGELOG.md` | contract and DOX updates |

## Interfaces

```ts
// crypto.ts
export type KeyRef = Uint8Array;                                   // 32-byte HKDF input
export const legacyKeyRef: (authSecret: string) => KeyRef;
// encryptNote, decryptNote, decryptObject, encrypt/decryptContainerMeta, encrypt/decryptComment,
// encrypt/decryptAttachment, encrypt/decryptAttachmentMetadata: first parameter is now `key: KeyRef`.

// keyring.ts (pure)
export type Envelope = { deviceId: string; keyGeneration: number; alg: string; envelope: string };
export type KeyedContainer = { id: string; keyGeneration: number; sharedGeneration: number };
export type Keyring = ReadonlyMap<number, Uint8Array>;
export type WriteKey = { key: KeyRef; generation: number };
export type Member = { userId: string; username: string; role: string };
export type MemberKey = Member & { identity?: Pick<PublicIdentity, "deviceId" | "publicKey"> };
export type SweepPlan = { kind: "idle" } | { kind: "blocked"; waitingFor: string[] }
  | { kind: "mint"; recipients: MemberKey[] } | { kind: "wrap"; grants: Array<{ member: MemberKey; generation: number }> };
export function openKeyring(containerID: string, envelopes: Envelope[], identity: HeldIdentity | undefined): Keyring;
export function writeKey(container: KeyedContainer, ring: Keyring, legacy: KeyRef): WriteKey | undefined;
export function readKeys(ring: Keyring, legacy: KeyRef, hint?: number): KeyRef[];
export function openFirst<T>(keys: KeyRef[], open: (key: KeyRef) => Promise<T>): Promise<T>;
export function planSweep(input: { container: KeyedContainer; me: string; members: MemberKey[]; envelopes: Envelope[]; ring: Keyring }): SweepPlan;
export function sealFor(member: MemberKey, containerID: string, generation: number, key: Uint8Array): Envelope;
export const newContainerKey: () => Uint8Array;

// pins.ts
export type Pins = Record<string, string>;                         // userId → publicKey (base64)
export type PinChange = { member: MemberKey; pinned: string };
export function comparePins(pins: Pins, members: MemberKey[]): { fresh: MemberKey[]; changed: PinChange[] };
export function fingerprint(publicKey: string): Promise<string>;   // "abcd ef01 …"

// keyService.ts
export type KeyAPI = { container; envelopes; members; userIdentity; stepUp; putEnvelopes; rotate };  // see Task 5
export type KeySync = { container: KeyedContainer; ring: Keyring; plan: SweepPlan | { kind: "untrusted"; members: string[] }; minted: boolean };
export function syncContainerKeys(api: KeyAPI, containerID: string, me: { userId: string; identity?: HeldIdentity; canWrap: boolean },
  pins: { load(): Promise<Pins>; save(pins: Pins): Promise<void> }, confirmChanged: (changes: PinChange[]) => boolean | Promise<boolean>): Promise<KeySync>;

// storage.ts
export function getPins(username: string, userID: string): Promise<Pins>;
export function storePins(username: string, userID: string, keys: Pins): Promise<void>;

// api.ts
Container.sharedGeneration: number; AdminTeam.sharedGeneration?: number; KEY_SCHEME = "shared-v1";
containerEnvelopes(id): Promise<Envelope[]>; putEnvelopes(id, envelopes): Promise<void>;
rotateKeys(id, expectedGeneration, envelopes): Promise<{ keyGeneration: number }>;
userIdentity(userID): Promise<PublicIdentity | undefined>;          // 404 → undefined
readObject(id) → { bytes, version, keyGeneration }
```

```go
// internal/httpapi/teamkeys_routes.go
const keySchemeHeader, keySchemeShared = "X-Kynotes-Key-Scheme", "shared-v1"
func checkWriteGate(q rowQuerier, cid, userID string, requested int64, scheme string) error
func putGenerationTx(tx *sql.Tx, cid string, current, requested int64) (int64, error)
```

---

### Task 1: Server — `sharedGeneration`, stale-client refusal, history backfill

**Files:** Modify `internal/httpapi/teamkeys_routes.go`, `device_routes.go`, `object_routes.go`, `collab_routes.go`, `upload_routes.go`, `container_routes.go`, `admin_routes.go`, `device_contract_test.go`, `teamkeys_test.go`. Create `internal/httpapi/teamkeys_p3_test.go`.

- [ ] **Step 1: Make the test helpers a current client.** In `device_contract_test.go` `(*pairClient).do`, after the `Content-Type` block add:

```go
	req.Header.Set(keySchemeHeader, keySchemeShared) // a current web client
```

In `teamkeys_test.go`: in `(*pairClient).save` after `req.Header.Set("X-Kynotes-Base-Version", ...)` add `req.Header.Set(keySchemeHeader, keySchemeShared)`; in `saveRacing` add `keySchemeHeader: keySchemeShared` to the header map; in `TestRemovedMemberCannotWriteAnywhereInTheTeam` change `checkWriteGate(tm.owner.db, tm.child, tm.editor.id, g)` to `checkWriteGate(tm.owner.db, tm.child, tm.editor.id, g, keySchemeShared)`.

- [ ] **Step 2: Write the failing tests.** Create `internal/httpapi/teamkeys_p3_test.go`:

```go
package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// rawWrite sends an authorized content write without the key-scheme header, as a
// tab loaded before team keys would.
func (p *pairClient) rawWrite(t *testing.T, method, path string, headers map[string]string, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, p.url+path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, c := range p.hc.Jar.Cookies(req.URL) {
		req.AddCookie(c)
		if c.Name == "csrf_token" {
			req.Header.Set("X-CSRF-Token", c.Value)
		}
	}
	res, err := p.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return status(t, res)
}

func TestSharedContainerRefusesStaleClientWrites(t *testing.T) {
	tm := newTeam(t)
	oid, _ := tm.editor.save(t, tm.id, "", 1)
	cmt, _ := tm.editor.comment(t, oid, 1)
	// Never shared: a client without the header keeps working (personal notebooks, old tabs).
	legacy := map[string]string{"X-Kynotes-Key-Generation": "1", "X-Kynotes-Base-Version": "1"}
	if code, body := tm.editor.rawWrite(t, http.MethodPut, "/api/v1/objects/"+oid, legacy, "ciphertext"); code != http.StatusOK {
		t.Fatalf("legacy container without header=%d %s", code, body)
	}
	tm.rotate(t, tm.id, 1)
	stale := map[string]string{"X-Kynotes-Key-Generation": "2", "X-Kynotes-Base-Version": "2"}
	for name, write := range map[string]func() (int, string){
		"save": func() (int, string) {
			return tm.editor.rawWrite(t, http.MethodPut, "/api/v1/objects/"+oid, stale, "ciphertext")
		},
		"comment": func() (int, string) {
			return tm.editor.rawWrite(t, http.MethodPost, "/api/v1/objects/"+oid+"/comments", nil, `{"bodyCiphertext":"Y3Q=","keyGeneration":2}`)
		},
		"comment rewrite": func() (int, string) {
			return tm.editor.rawWrite(t, http.MethodPut, "/api/v1/comments/"+cmt, nil, `{"bodyCiphertext":"Y3Q=","keyGeneration":2}`)
		},
	} {
		if code, body := write(); code != http.StatusConflict || !strings.Contains(body, "reload") {
			t.Fatalf("%s from a stale client=%d %s", name, code, body)
		}
	}
	var versions int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM object_versions WHERE object_id=? AND key_generation=2`, oid).Scan(&versions); err != nil || versions != 0 {
		t.Fatalf("stale write stored %d versions: %v", versions, err)
	}
	if _, code := tm.editor.save(t, tm.id, oid, 2); code != http.StatusOK {
		t.Fatalf("current client=%d", code)
	}
	if code := tm.editor.attach(t, tm.id, 2); code != http.StatusOK {
		t.Fatalf("current client upload=%d", code)
	}
}

// joinTeam adds an editor with an identity to the team after it rotated.
func (tm team) joinTeam(t *testing.T, name string) (member, string) {
	t.Helper()
	m := tm.owner.addUser(t, name)
	if _, err := tm.owner.db.Exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at) VALUES(?,?,?,'editor','now')`, mint(t, "mem"), tm.id, m.id); err != nil {
		t.Fatal(err)
	}
	return m, m.createIdentity(t)
}

func TestStewardBackfillsSharedHistoryOnly(t *testing.T) {
	tm := newTeam(t)
	put := func(c *pairClient, items ...string) (int, string) {
		return status(t, c.do(t, http.MethodPut, "/api/v1/containers/"+tm.id+"/envelopes", envelopesBody(items...), true, false))
	}
	tm.owner.stepUp(t)
	// A legacy-era envelope at generation 1 (the device gate's kind) must not open generation 1 to backfill.
	if code, body := put(tm.owner, envJSON(tm.editorID, 1, 1)); code != http.StatusNoContent {
		t.Fatalf("legacy envelope=%d %s", code, body)
	}
	tm.rotate(t, tm.id, 1) // shared from generation 2
	tm.rotate(t, tm.id, 2)
	newcomer, newcomerID := tm.joinTeam(t, "newcomer")
	tm.owner.stepUp(t)
	for _, g := range []int64{1, 4} { // before sharing, and not yet minted
		if code, body := put(tm.owner, envJSON(newcomerID, g, 1)); code != http.StatusConflict {
			t.Fatalf("backfill at %d=%d %s", g, code, body)
		}
	}
	tm.editor.stepUp(t)
	if code, _ := put(tm.editor.pairClient, envJSON(newcomerID, 2, 1)); code != http.StatusForbidden {
		t.Fatalf("editor wrapped for a colleague=%d", code)
	}
	if code, body := put(tm.owner, envJSON(newcomerID, 2, 1), envJSON(newcomerID, 3, 1)); code != http.StatusNoContent {
		t.Fatalf("backfill=%d %s", code, body)
	}
	if code, _ := put(tm.owner, envJSON(newcomerID, 2, 2)); code != http.StatusConflict {
		t.Fatalf("second wrap at an old generation=%d", code)
	}
	if _, code := newcomer.save(t, tm.id, "", 3); code != http.StatusOK {
		t.Fatalf("newcomer save=%d", code)
	}
}

func TestSharedGenerationIsMintedOnlyByRotation(t *testing.T) {
	tm := newTeam(t)
	tm.owner.stepUp(t)
	put := func(cid string, items ...string) (int, string) {
		return status(t, tm.owner.do(t, http.MethodPut, "/api/v1/containers/"+cid+"/envelopes", envelopesBody(items...), true, false))
	}
	// Legacy containers keep today's rule: the first envelope at the current generation is a PUT.
	if code, body := put(tm.child, envJSON(tm.editorID, 1, 1)); code != http.StatusNoContent {
		t.Fatalf("legacy first envelope=%d %s", code, body)
	}
	tm.rotate(t, tm.id, 1)
	if code, body := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id+"/members/"+tm.admin.id, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("remove=%d %s", code, body)
	}
	tm.owner.stepUp(t)
	if code, body := put(tm.id, envJSON(tm.ownerID, 3, 1), envJSON(tm.editorID, 3, 1)); code != http.StatusConflict || !strings.Contains(body, "key rotation incomplete") {
		t.Fatalf("mint by PUT after removal=%d %s", code, body)
	}
	if n := countEnvelopes(t, tm.owner, tm.id, 3); n != 0 {
		t.Fatalf("PUT minted %d envelopes", n)
	}
	body := rotationBody(3, envJSON(tm.ownerID, 4, 1), envJSON(tm.editorID, 4, 1))
	if code, out := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/containers/"+tm.id+"/key-rotations", body, true, false)); code != http.StatusOK {
		t.Fatalf("rotate=%d %s", code, out)
	}
}

func TestContainersReportSharedGeneration(t *testing.T) {
	tm := newTeam(t)
	shared := func() map[string]int64 {
		res := tm.editor.do(t, http.MethodGet, "/api/v1/containers", nil, false, false)
		var list []struct {
			ID               string `json:"id"`
			SharedGeneration *int64 `json:"sharedGeneration"`
		}
		data, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if err := json.Unmarshal(data, &list); err != nil {
			t.Fatal(err)
		}
		out := map[string]int64{}
		for _, c := range list {
			if c.SharedGeneration == nil {
				t.Fatalf("container %s without sharedGeneration: %s", c.ID, data)
			}
			out[c.ID] = *c.SharedGeneration
		}
		return out
	}
	if got := shared(); got[tm.id] != 0 || got[tm.child] != 0 {
		t.Fatalf("before rotation: %v", got)
	}
	tm.rotate(t, tm.id, 1)
	if got := shared(); got[tm.id] != 2 || got[tm.child] != 0 {
		t.Fatalf("after rotation: %v", got)
	}
	code, created := status(t, tm.editor.do(t, http.MethodPost, "/api/v1/containers", []byte(`{"kind":"workbook","metaCiphertext":""}`), true, false))
	if code != http.StatusOK || !strings.Contains(created, `"sharedGeneration":0`) {
		t.Fatalf("create=%d %s", code, created)
	}
}
```

- [ ] **Step 3: Run them.** `go test ./internal/httpapi -run 'TestSharedContainerRefusesStaleClientWrites|TestStewardBackfillsSharedHistoryOnly|TestSharedGenerationIsMintedOnlyByRotation|TestContainersReportSharedGeneration'`. Expected: compile errors (`keySchemeHeader`, `keySchemeShared`, the five-argument `checkWriteGate` undefined).

- [ ] **Step 4: Implement.** In `teamkeys_routes.go`:

Add to the error `var` block `errStaleClient = errors.New("stale client")`, and after the block:

```go
// keySchemeHeader marks a write from a client that seals shared containers with
// their container key. A shared container refuses writes without it, so a tab
// loaded before team keys cannot store login-key ciphertext at a shared generation.
const keySchemeHeader, keySchemeShared = "X-Kynotes-Key-Scheme", "shared-v1"
```

In `writeTeamKeyError`, after the `errKeyRotationIncomplete` case:

```go
	case errors.Is(err, errStaleClient):
		WriteError(w, r, 409, "already_exists", "this notebook uses shared keys: reload the page")
```

Before `ownIdentityEnvelopeSQL`:

```go
// putGenerationTx is the generation a PUT envelope targets. Legacy containers
// (shared_generation=0) keep the current generation, as before. A shared
// container accepts any generation from shared_generation to current that
// already holds an envelope: stewards backfill history for newcomers, but a key
// is minted only by key-rotations, never by PUT (no split generations).
func putGenerationTx(tx *sql.Tx, cid string, current, requested int64) (int64, error) {
	var shared int64
	if err := tx.QueryRow(`SELECT shared_generation FROM containers WHERE id=?`, cid).Scan(&shared); err != nil {
		return 0, err
	}
	if shared == 0 {
		return current, nil
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

Change `checkWriteGate`'s comment and signature to:

```go
// checkWriteGate admits a content write by userID into cid at generation
// requested. Containers that never rotated keep the legacy device rule; once
// rotated, the writer must send keySchemeShared and its own identity needs an
// envelope at the current generation. Call it before streaming a body and again
// inside the write transaction.
func checkWriteGate(q rowQuerier, cid, userID string, requested int64, scheme string) error {
```

and its shared branch to:

```go
	} else {
		if scheme != keySchemeShared {
			return errStaleClient
		}
		err = q.QueryRow(ownIdentityEnvelopeSQL, userID, cid, generation).Scan(&admitted)
	}
```

Pass `r.Header.Get(keySchemeHeader)` as the new last argument at every `checkWriteGate` call: `teamkeys_routes.go` (comment rewrite), `object_routes.go` (2), `collab_routes.go` (2), `upload_routes.go` (2). `grep -n 'checkWriteGate(' internal/httpapi/*.go | grep -v _test` must show seven calls, all with it.

In `device_routes.go`, envelope `PUT`, replace the loop body:

```go
			for _, v := range in.Envelopes {
				target, err := putGenerationTx(tx, cid, generation, v.KeyGeneration)
				if err != nil {
					return err
				}
				if err := insertEnvelopeTx(tx, cid, target, s.UserID, role, v, now.Format(time.RFC3339)); err != nil {
					return err
				}
			}
```

In `container_routes.go`: append `,c.shared_generation` to both `SELECT` lists of `GET /api/v1/containers` (after `c.key_generation`), scan it into a new `shared int64` and add `"sharedGeneration": shared` to the row map; add `"sharedGeneration": 0` to the `POST /api/v1/containers` response. In `admin_routes.go`: add `"sharedGeneration": 0` to the `POST /admin/teams` response, and `shared_generation` to the `GET /admin/teams` query, scan (`sharedGeneration int64`) and row map.

- [ ] **Step 5: Pass.** `go test ./internal/httpapi -count=1 && go vet ./... && test -z "$(gofmt -l .)"`. Expected: PASS, including every P2 test.

- [ ] **Step 6: Commit.** `git add internal/httpapi/teamkeys_p3_test.go && git commit -am "httpapi: team keys P3a server rules (sharedGeneration, stale clients, history backfill)"`

### Task 2: `KeyRef` in `crypto.ts`, mechanical `legacy` in `main.tsx`

Behaviour-preserving: every content key is still the login-derived one, now named.

**Files:** Modify `web/src/crypto.ts`, `web/src/crypto.test.ts`, `web/src/main.tsx`.

- [ ] **Step 1: Write the failing tests.** In `crypto.test.ts`, add `legacyKeyRef` and `fromBase64` to the import from `./crypto`, wrap both `secret` constants in `legacyKeyRef(...)`, and append:

```ts
describe("content keys", () => {
  // Ciphertext produced by the pre-P3 encryptNote("5a"×32, "cnt_legacyfixture", …): legacy rows must still open.
  const LEGACY_NOTE = "rSmf1huCgm2R/XQ9P8xstlQUmhhtrDyMHSVLtqGStWeMMUQfiWjT8DyXkU++Hdsmu5W+e8C+j7yGvElvE6ECcyGFADwleuCMbA==";
  it("opens legacy ciphertext through legacyKeyRef", async () => {
    await expect(decryptNote(legacyKeyRef("5a".repeat(32)), "cnt_legacyfixture", fromBase64(LEGACY_NOTE))).resolves.toEqual({ title: "Legacy", body: "written before P3" });
  });
  it("keys content by the container key, never across keys or containers", async () => {
    const ck = new Uint8Array(32).fill(7);
    const sealed = await encryptNote(ck, "cnt_a", { title: "T", body: "B" });
    await expect(decryptNote(ck, "cnt_a", sealed)).resolves.toEqual({ title: "T", body: "B" });
    await expect(decryptNote(new Uint8Array(32).fill(8), "cnt_a", sealed)).rejects.toThrow();
    await expect(decryptNote(ck, "cnt_b", sealed)).rejects.toThrow();
  });
  it("refuses a key that is not 32 bytes", async () => {
    await expect(encryptNote(new Uint8Array(16), "cnt_a", { title: "", body: "" })).rejects.toThrow("invalid content key");
  });
});
```

- [ ] **Step 2: Run.** `cd web && npx vitest run src/crypto.test.ts`. Expected: FAIL (`legacyKeyRef` is not exported).

- [ ] **Step 3: Implement in `crypto.ts`.** Replace `deriveObjectKeyBytes` with:

```ts
/** HKDF input for content subkeys: a container key (CK) or, for legacy rows, the login secret's bytes. */
export type KeyRef = Uint8Array;

/** The pre-team-keys content key input. Only legacy reads and personal notebooks use it. */
export const legacyKeyRef = (authSecret: string): KeyRef => hexBytes(authSecret);

function deriveObjectKeyBytes(key: KeyRef, containerID: string, info: string): Uint8Array {
  if (key.length !== 32) throw new Error("invalid content key");
  return hkdfSha256(key, 32, encoder.encode(containerID), encoder.encode(info));
}
```

In every function from `encryptContainerMeta` through `decryptObject`: the first parameter becomes `key: KeyRef`, every `deriveObjectKeyBytes(authSecret, …)` becomes `const subkey = deriveObjectKeyBytes(key, …)` with `encryptWithKey(subkey, …)`/`decryptWithKey(subkey, …)`, and `encryptWithInfo(authSecret, …)`/`decryptWithInfo(authSecret, …)` pass `key`. `encryptSharePayload`/`decryptSharePayload` are untouched. Afterwards `grep -n authSecret web/src/crypto.ts` shows only `LoginKeys`, `deriveLoginKeys`, `deriveAuthSecret` and `legacyKeyRef`.

- [ ] **Step 4: `main.tsx`, mechanically.** Run from the repository root:

```bash
perl -0pi -e 's/((?:en|de)crypt\w*\(\s*)auth\.authSecret\b/${1}legacy/g; s/((?:en|de)crypt\w*\(\s*)authSecret\b/${1}legacy/g' web/src/main.tsx
```

Then add `legacyKeyRef,` after `fromBase64,` in the `./crypto` import; after the line `const markDirty = (value: boolean) => { dirtyRef.current = value; setDirty(value); };` insert

```tsx
  // The login-derived content key: legacy rows, personal notebooks, and (until team keys) everything.
  const legacy = useMemo(() => legacyKeyRef(auth.authSecret), [auth.authSecret]);
```

and replace the first line of `AdminTeams` with

```tsx
function AdminTeams({ users, authSecret }: { users: AdminUser[]; authSecret: string }) {
  // Admin pages hold no team keys: only names still under this account's legacy key are readable here.
  const legacy = legacyKeyRef(authSecret);
```

- [ ] **Step 5: Pass.** `cd web && npx tsc --noEmit && npx vitest run`. Expected: PASS. `grep -nE '(en|de)crypt\w*\(\s*(auth\.)?authSecret' src/main.tsx` prints nothing.

- [ ] **Step 6: Commit.** `git commit -am "web: content crypto takes a KeyRef; legacy key named in main.tsx"`

### Task 3: `keyring.ts` — the pure key rules

**Files:** Create `web/src/keyring.ts`, `web/src/keyring.test.ts`.

- [ ] **Step 1: Write the failing tests.** `web/src/keyring.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { base64, decryptNote, encryptNote, legacyKeyRef } from "./crypto";
import { newContainerKey, openFirst, openKeyring, planSweep, readKeys, sealFor, writeKey, type Envelope, type MemberKey } from "./keyring";
import { generateIdentity } from "./teamKeys";

const cnt = `cnt_${"a".repeat(26)}`;
const dev = (c: string) => `dev_${c.repeat(26)}`;
const person = (name: string, c: string, role = "editor") => {
  const id = generateIdentity();
  const held = { ...id, deviceId: dev(c) };
  const member: MemberKey = { userId: `usr_${c.repeat(26)}`, username: name, role, identity: { deviceId: dev(c), publicKey: base64(id.publicKey) } };
  return { held, member };
};
const legacy = legacyKeyRef("5a".repeat(32));

describe("keyring", () => {
  it("opens only this identity's envelopes, by generation, and skips rows it cannot open", () => {
    const owner = person("owner", "b", "owner");
    const editor = person("editor", "c");
    const k2 = newContainerKey();
    const k3 = newContainerKey();
    const rows: Envelope[] = [sealFor(owner.member, cnt, 2, k2), sealFor(editor.member, cnt, 2, k2), sealFor(owner.member, cnt, 3, k3)];
    const forged = { ...sealFor(owner.member, cnt, 4, k3), keyGeneration: 5 }; // AAD binds the generation
    const ring = openKeyring(cnt, [...rows, forged], owner.held);
    expect([...ring.keys()].sort()).toEqual([2, 3]);
    expect(ring.get(3)).toEqual(k3);
    expect(openKeyring(cnt, rows, undefined).size).toBe(0);
  });

  it("writes legacy containers with the login key and shared ones only with the current key", () => {
    const k3 = newContainerKey();
    const ring = new Map([[3, k3]]);
    expect(writeKey({ id: cnt, keyGeneration: 4, sharedGeneration: 0 }, ring, legacy)).toEqual({ key: legacy, generation: 4 });
    expect(writeKey({ id: cnt, keyGeneration: 3, sharedGeneration: 2 }, ring, legacy)).toEqual({ key: k3, generation: 3 });
    // Waiting for keys: never fall back to the legacy key in a shared container.
    expect(writeKey({ id: cnt, keyGeneration: 4, sharedGeneration: 2 }, ring, legacy)).toBeUndefined();
  });

  it("reads with the row's generation first, then newest, then legacy", async () => {
    const [k2, k3, k4] = [newContainerKey(), newContainerKey(), newContainerKey()];
    const ring = new Map([[2, k2], [4, k4], [3, k3]]);
    expect(readKeys(ring, legacy, 3)).toEqual([k3, k4, k2, legacy]);
    expect(readKeys(ring, legacy)).toEqual([k4, k3, k2, legacy]);
    const old = await encryptNote(legacy, cnt, { title: "L", body: "" });
    await expect(openFirst(readKeys(ring, legacy, 4), (key) => decryptNote(key, cnt, old))).resolves.toEqual({ title: "L", body: "" });
    await expect(openFirst([k2, k3], (key) => decryptNote(key, cnt, old))).rejects.toThrow();
  });
});

describe("planSweep", () => {
  const owner = person("owner", "b", "owner");
  const editor = person("editor", "c");
  const container = (keyGeneration: number, sharedGeneration: number) => ({ id: cnt, keyGeneration, sharedGeneration });

  it("mints the first key only when every member has an identity", () => {
    const sso: MemberKey = { userId: `usr_${"d".repeat(26)}`, username: "sso-user", role: "editor" };
    const base = { me: owner.member.userId, envelopes: [], ring: new Map() };
    expect(planSweep({ ...base, container: container(1, 0), members: [owner.member, editor.member, sso] })).toEqual({ kind: "blocked", waitingFor: ["sso-user"] });
    expect(planSweep({ ...base, container: container(1, 0), members: [owner.member, editor.member] })).toEqual({ kind: "mint", recipients: [owner.member, editor.member] });
  });

  it("never acts for a non-steward or a steward without an identity", () => {
    const base = { container: container(1, 0), envelopes: [], ring: new Map() };
    expect(planSweep({ ...base, me: editor.member.userId, members: [owner.member, editor.member] }).kind).toBe("idle");
    expect(planSweep({ ...base, me: owner.member.userId, members: [{ ...owner.member, identity: undefined }, editor.member] }).kind).toBe("idle");
  });

  it("re-mints after a removal emptied the current generation, skipping members without identities", () => {
    const k2 = newContainerKey();
    const envelopes = [sealFor(owner.member, cnt, 2, k2), sealFor(editor.member, cnt, 2, k2)];
    const sso: MemberKey = { userId: `usr_${"d".repeat(26)}`, username: "sso-user", role: "editor" };
    expect(planSweep({ container: container(3, 2), me: owner.member.userId, members: [owner.member, editor.member, sso], envelopes, ring: new Map([[2, k2]]) }))
      .toEqual({ kind: "mint", recipients: [owner.member, editor.member] });
  });

  it("wraps every held generation for a member missing it, and nothing it does not hold", () => {
    const newcomer = person("newcomer", "e");
    const [k2, k4] = [newContainerKey(), newContainerKey()];
    const envelopes = [sealFor(owner.member, cnt, 2, k2), sealFor(editor.member, cnt, 2, k2), sealFor(owner.member, cnt, 4, k4), sealFor(editor.member, cnt, 4, k4)];
    // Generation 3 was emptied by a removal and never held; generation 1 predates sharing.
    const plan = planSweep({ container: container(4, 2), me: owner.member.userId, members: [owner.member, editor.member, newcomer.member], envelopes, ring: new Map([[2, k2], [4, k4]]) });
    expect(plan).toEqual({ kind: "wrap", grants: [{ member: newcomer.member, generation: 2 }, { member: newcomer.member, generation: 4 }] });
    expect(planSweep({ container: container(4, 2), me: owner.member.userId, members: [owner.member, editor.member], envelopes, ring: new Map([[2, k2], [4, k4]]) }).kind).toBe("idle");
  });
});

describe("main.tsx key wiring", () => {
  it("derives the legacy key in exactly two places and never hands content crypto the login secret", () => {
    const main = import.meta.glob<string>("./main.tsx", { query: "?raw", import: "default", eager: true })["./main.tsx"];
    // Workspace (legacy reads, personal notebooks) and AdminTeams (admin-created names).
    expect(main.match(/legacyKeyRef\(/g)).toHaveLength(2);
    expect(main).not.toMatch(/(?:en|de)crypt\w*\(\s*(?:auth\.)?authSecret\b/);
  });
});
```

- [ ] **Step 2: Run.** `npx vitest run src/keyring.test.ts`. Expected: FAIL (module `./keyring` not found). The wiring test at the end already holds after Task 2 (two `legacyKeyRef(` calls, no login secret in content crypto); it guards Task 6.

- [ ] **Step 3: Implement.** `web/src/keyring.ts`:

```ts
import { randomBytes } from "@noble/ciphers/utils.js";
import { base64, fromBase64, type KeyRef } from "./crypto";
import type { HeldIdentity, PublicIdentity } from "./identity";
import { ENVELOPE_ALG, unwrapEnvelope, wrapEnvelope } from "./teamKeys";

/** An envelope as written, and as read back from GET /containers/{id}/envelopes (every recipient's row for a session). */
export type Envelope = { deviceId: string; keyGeneration: number; alg: string; envelope: string };
/** The fields of a container that decide its keys. */
export type KeyedContainer = { id: string; keyGeneration: number; sharedGeneration: number };
/** Container keys this browser unwrapped, by generation. */
export type Keyring = ReadonlyMap<number, Uint8Array>;
export type WriteKey = { key: KeyRef; generation: number };
export type Member = { userId: string; username: string; role: string };
/** A member and its identity, when it has one the server shows us. */
export type MemberKey = Member & { identity?: Pick<PublicIdentity, "deviceId" | "publicKey"> };

export function openKeyring(containerID: string, envelopes: Envelope[], identity: HeldIdentity | undefined): Keyring {
  const ring = new Map<number, Uint8Array>();
  if (!identity) return ring;
  for (const row of envelopes) {
    if (row.deviceId !== identity.deviceId || row.alg !== ENVELOPE_ALG) continue;
    try {
      ring.set(row.keyGeneration, unwrapEnvelope(fromBase64(row.envelope), identity.privateKey, containerID, row.keyGeneration, identity.deviceId));
    } catch { /* A row this identity cannot open is someone else's mistake, never a key. */ }
  }
  return ring;
}

/**
 * The key new content in this container is sealed with. Legacy containers keep the
 * login-derived key. A shared container needs the container key at its current
 * generation; undefined means "waiting for keys" and nothing may be written.
 */
export function writeKey(container: KeyedContainer, ring: Keyring, legacy: KeyRef): WriteKey | undefined {
  if (container.sharedGeneration === 0) return { key: legacy, generation: container.keyGeneration };
  const key = ring.get(container.keyGeneration);
  return key && { key, generation: container.keyGeneration };
}

/** Keys to try on read: the row's own generation first, then newest first, then legacy. */
export function readKeys(ring: Keyring, legacy: KeyRef, hint?: number): KeyRef[] {
  const first = hint === undefined ? undefined : ring.get(hint);
  const rest = [...ring.entries()].filter(([generation]) => generation !== hint).sort(([a], [b]) => b - a).map(([, key]) => key);
  return [...(first ? [first] : []), ...rest, legacy];
}

/** Runs open with each key in turn; AES-GCM authentication makes a wrong key fail, not misread. */
export async function openFirst<T>(keys: KeyRef[], open: (key: KeyRef) => Promise<T>): Promise<T> {
  let last: unknown = new Error("no content key");
  for (const key of keys) {
    try { return await open(key); } catch (error) { last = error; }
  }
  throw last;
}

export type SweepPlan =
  | { kind: "idle" }
  | { kind: "blocked"; waitingFor: string[] }
  | { kind: "mint"; recipients: MemberKey[] }
  | { kind: "wrap"; grants: Array<{ member: MemberKey; generation: number }> };

const isSteward = (role: string) => role === "owner" || role === "admin";

/**
 * What an owner or admin's browser must do so every member holds the container keys.
 * - Never shared: mint the first key, but only once every member has an identity, so
 *   no member (SSO-only users, accounts awaiting a password change) is locked out.
 * - Shared, current generation empty (after a removal): mint the next key.
 * - Otherwise wrap every generation this browser holds for each member missing it,
 *   so newcomers read history and members whose identity was reset get back in.
 * Only keys this browser unwrapped are ever wrapped (P2 rule 7).
 */
export function planSweep(input: { container: KeyedContainer; me: string; members: MemberKey[]; envelopes: Envelope[]; ring: Keyring }): SweepPlan {
  const { container, me, members, envelopes, ring } = input;
  const self = members.find((member) => member.userId === me);
  if (!self?.identity || !isSteward(self.role)) return { kind: "idle" };
  const keyed = members.filter((member) => member.identity);
  if (container.sharedGeneration === 0) {
    const waitingFor = members.filter((member) => !member.identity).map((member) => member.username);
    return waitingFor.length ? { kind: "blocked", waitingFor } : { kind: "mint", recipients: keyed };
  }
  if (!envelopes.some((row) => row.keyGeneration === container.keyGeneration)) return { kind: "mint", recipients: keyed };
  const held = new Set(envelopes.map((row) => `${row.deviceId}:${row.keyGeneration}`));
  const grants = keyed.flatMap((member) => [...ring.keys()]
    .filter((generation) => generation >= container.sharedGeneration && generation <= container.keyGeneration)
    .filter((generation) => !held.has(`${member.identity!.deviceId}:${generation}`))
    .map((generation) => ({ member, generation })));
  return grants.length ? { kind: "wrap", grants } : { kind: "idle" };
}

export function sealFor(member: MemberKey, containerID: string, generation: number, key: Uint8Array): Envelope {
  const identity = member.identity!;
  return { deviceId: identity.deviceId, keyGeneration: generation, alg: ENVELOPE_ALG, envelope: base64(wrapEnvelope(key, fromBase64(identity.publicKey), containerID, generation, identity.deviceId)) };
}

/** 32 bytes from the platform CSPRNG; noble throws rather than fall back to Math.random. */
export const newContainerKey = (): Uint8Array => randomBytes(32);
```

- [ ] **Step 4: Pass.** `npx tsc --noEmit && npx vitest run src/keyring.test.ts`. Expected: PASS (8 tests).

- [ ] **Step 5: Commit.** `git add web/src/keyring.ts web/src/keyring.test.ts && git commit -m "web: keyring rules for team keys"`

### Task 4: Pins and fingerprints

**Files:** Create `web/src/pins.ts`, `web/src/pins.test.ts`. Modify `web/src/storage.ts`, `web/src/storage.test.ts`.

- [ ] **Step 1: Write the failing tests.** `web/src/pins.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { comparePins, fingerprint } from "./pins";

const member = (id: string, publicKey?: string) => ({ userId: id, username: id, role: "editor", identity: publicKey ? { deviceId: "dev", publicKey } : undefined });

describe("pins", () => {
  it("separates first-seen and changed keys and ignores members without one", () => {
    const result = comparePins({ a: "K1", b: "K2" }, [member("a", "K1"), member("b", "K9"), member("c", "K3"), member("d")]);
    expect(result.fresh.map((entry) => entry.userId)).toEqual(["c"]);
    expect(result.changed).toEqual([{ member: member("b", "K9"), pinned: "K2" }]);
  });
  it("computes the fingerprint from the key, in groups of four", async () => {
    // SHA-256 of 32 zero bytes.
    expect(await fingerprint(btoa(String.fromCharCode(...new Uint8Array(32))))).toBe("66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925".match(/.{4}/g)!.join(" "));
  });
});
```

In `storage.test.ts`, add `getPins` and `storePins` to the import from `./storage`, then append:

```ts
describe("colleague key pins", () => {
  beforeEach(clearAllDeviceKeys);
  it("keeps pins per signed-in user and clears them with the device", async () => {
    await storeDeviceKey("alice", "a".repeat(64));
    await storePins("alice", userID, { usr_b: "key" });
    expect(await getPins("alice", userID)).toEqual({ usr_b: "key" });
    expect(await getPins("alice", "usr_zzzzzzzzzzzzzzzzzzzzzzzzzz")).toEqual({});
    await storeIdentityKey("alice", userID, held);
    await storeDeviceKey("alice", "b".repeat(64));
    expect(await getPins("alice", userID)).toEqual({ usr_b: "key" });
    await clearDeviceKey("alice");
    expect(await getPins("alice", userID)).toEqual({});
  });
});
```

- [ ] **Step 2: Run.** `npx vitest run src/pins.test.ts src/storage.test.ts`. Expected: FAIL (missing module and exports).

- [ ] **Step 3: Implement.** `web/src/pins.ts`:

```ts
import { digestSha256Hex } from "./crypto";
import type { MemberKey } from "./keyring";

/** Trust-on-first-use pins: colleague user ID → identity public key (standard base64). */
export type Pins = Record<string, string>;
export type PinChange = { member: MemberKey; pinned: string };

/** Splits keyed members into first-seen and changed; unchanged pins are neither. */
export function comparePins(pins: Pins, members: MemberKey[]): { fresh: MemberKey[]; changed: PinChange[] } {
  const fresh: MemberKey[] = [];
  const changed: PinChange[] = [];
  for (const member of members) {
    const key = member.identity?.publicKey;
    if (!key) continue;
    const pinned = pins[member.userId];
    if (pinned === undefined) fresh.push(member);
    else if (pinned !== key) changed.push({ member, pinned });
  }
  return { fresh, changed };
}

/** Computed locally from the key, never taken from the server: SHA-256, hex in groups of four. */
export async function fingerprint(publicKey: string): Promise<string> {
  const raw = Uint8Array.from(atob(publicKey), (char) => char.charCodeAt(0));
  return (await digestSha256Hex(raw)).match(/.{4}/g)!.join(" ");
}
```

In `storage.ts`: add `import type { Pins } from "./pins";` after the identity import; extend `VaultRecord` with `pins?: { userID: string; keys: Pins }`; insert before `clearDeviceKey`:

```ts
/** Colleague key pins live in the vault record, so "Forget this device" clears them too. */
export async function getPins(username: string, userID: string): Promise<Pins> {
  const db = await openDatabase();
  const record = await new Promise<VaultRecord | undefined>((resolve, reject) => {
    const request = db.transaction("keys").objectStore("keys").get(username);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  db.close();
  return record?.pins?.userID === userID ? record.pins.keys : {};
}

/** Replaces the pins of an existing vault record; without one (no IndexedDB) pins are not kept. */
export async function storePins(username: string, userID: string, keys: Pins): Promise<void> {
  const db = await openDatabase();
  await new Promise<void>((resolve, reject) => {
    const transaction = db.transaction("keys", "readwrite");
    const store = transaction.objectStore("keys");
    const read = store.get(username);
    read.onsuccess = () => {
      const record = read.result as VaultRecord | undefined;
      if (record) store.put({ ...record, pins: { userID, keys } });
    };
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
  db.close();
}
```

- [ ] **Step 4: Pass.** `npx tsc --noEmit && npx vitest run src/pins.test.ts src/storage.test.ts`. Expected: PASS.

- [ ] **Step 5: Commit.** `git add -A web/src && git commit -m "web: trust-on-first-use pins for colleague identity keys"`

### Task 5: `keyService.ts` and the API calls

**Files:** Create `web/src/keyService.ts`, `web/src/keyService.test.ts`. Modify `web/src/api.ts`.

- [ ] **Step 1: Write the failing tests.** `web/src/keyService.test.ts` (an in-memory server with the P2/P3a envelope rules):

```ts
import { describe, expect, it, vi } from "vitest";
import { base64 } from "./crypto";
import type { PublicIdentity } from "./identity";
import type { Envelope, Member } from "./keyring";
import { syncContainerKeys, type KeyAPI } from "./keyService";
import type { Pins } from "./pins";
import { generateIdentity } from "./teamKeys";

const cnt = `cnt_${"a".repeat(26)}`;
const user = (name: string, c: string, role: string, withIdentity = true) => {
  const id = generateIdentity();
  return {
    member: { userId: `usr_${c.repeat(26)}`, username: name, role } as Member,
    held: withIdentity ? { ...id, deviceId: `dev_${c.repeat(26)}` } : undefined,
    public: withIdentity ? { deviceId: `dev_${c.repeat(26)}`, publicKey: base64(id.publicKey), fingerprint: "" } as PublicIdentity : undefined,
  };
};
type User = ReturnType<typeof user>;
const conflict = () => Object.assign(new Error("conflict"), { code: "already_exists" });

/** In-memory server with the P2/P3a envelope rules that matter to the client. */
function server(users: User[], generation = 1, shared = 0) {
  const state = { generation, shared, envelopes: [] as Envelope[], members: users };
  const accept = (rows: Envelope[], at: (row: Envelope) => boolean) => {
    for (const row of rows) {
      if (!at(row) || state.envelopes.some((e) => e.deviceId === row.deviceId && e.keyGeneration === row.keyGeneration)) throw conflict();
    }
    state.envelopes.push(...rows);
  };
  const api: KeyAPI = {
    container: async () => ({ id: cnt, keyGeneration: state.generation, sharedGeneration: state.shared }),
    envelopes: async () => state.envelopes.map((row) => ({ ...row })),
    members: async () => state.members.map((entry) => entry.member),
    userIdentity: async (id) => state.members.find((entry) => entry.member.userId === id)?.public,
    stepUp: vi.fn(async () => {}),
    putEnvelopes: vi.fn(async (_cid, rows) => accept(rows, (row) => row.keyGeneration >= state.shared && row.keyGeneration <= state.generation && state.envelopes.some((e) => e.keyGeneration === row.keyGeneration))),
    rotate: vi.fn(async (_cid, expected, rows) => {
      if (expected !== state.generation) throw conflict();
      state.generation += 1;
      state.shared ||= state.generation;
      accept(rows, (row) => row.keyGeneration === state.generation);
      return { keyGeneration: state.generation };
    }),
  };
  return { state, api };
}
const memoryPins = (initial: Pins = {}) => { let pins = initial; return { load: async () => pins, save: async (next: Pins) => { pins = next; }, get: () => pins }; };
const as = (u: User, canWrap = true) => ({ userId: u.member.userId, identity: u.held, canWrap });

describe("syncContainerKeys", () => {
  it("mints once every member has an identity, and every member opens the same key", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor");
    const { state, api } = server([owner, editor]);
    const pins = memoryPins();
    const result = await syncContainerKeys(api, cnt, as(owner), pins, () => false);
    expect(result.minted).toBe(true);
    expect(result.container).toEqual({ id: cnt, keyGeneration: 2, sharedGeneration: 2 });
    const theirs = await syncContainerKeys(api, cnt, as(editor), memoryPins(), () => false);
    expect(theirs.ring.get(2)).toEqual(result.ring.get(2));
    expect(pins.get()).toEqual({ [editor.member.userId]: editor.public!.publicKey });
    expect(state.envelopes).toHaveLength(2);
  });

  it("does not share a never-shared container while a member has no identity", async () => {
    const owner = user("owner", "b", "owner"), sso = user("sso", "c", "editor", false);
    const { api } = server([owner, sso]);
    const result = await syncContainerKeys(api, cnt, as(owner), memoryPins(), () => false);
    expect(result.plan).toEqual({ kind: "blocked", waitingFor: ["sso"] });
    expect(api.rotate).not.toHaveBeenCalled();
    expect(api.stepUp).not.toHaveBeenCalled();
  });

  it("re-mints after a removal and wraps history for a newcomer", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor"), newcomer = user("new", "d", "editor");
    const { state, api } = server([owner, editor]);
    await syncContainerKeys(api, cnt, as(owner), memoryPins(), () => false);
    state.generation += 1; // removal of someone else: generation 3 has no envelopes
    const second = await syncContainerKeys(api, cnt, as(owner), memoryPins(), () => false);
    expect(second.container.keyGeneration).toBe(4);
    state.members.push(newcomer);
    await syncContainerKeys(api, cnt, as(owner), memoryPins(), () => false);
    const theirs = await syncContainerKeys(api, cnt, as(newcomer), memoryPins(), () => false);
    expect([...theirs.ring.keys()].sort()).toEqual([2, 4]);
  });

  it("stops at a changed colleague key unless the user confirms it", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor");
    const { api } = server([owner, editor]);
    const pins = memoryPins({ [editor.member.userId]: base64(new Uint8Array(32).fill(9)) });
    const refused = await syncContainerKeys(api, cnt, as(owner), pins, () => false);
    expect(refused.plan).toEqual({ kind: "untrusted", members: ["editor"] });
    expect(api.rotate).not.toHaveBeenCalled();
    const confirm = vi.fn(() => true);
    const accepted = await syncContainerKeys(api, cnt, as(owner), pins, confirm);
    expect(confirm).toHaveBeenCalledOnce();
    expect(accepted.minted).toBe(true);
    expect(pins.get()[editor.member.userId]).toBe(editor.public!.publicKey);
  });

  it("re-reads and re-plans once when another steward rotated first", async () => {
    const owner = user("owner", "b", "owner"), admin = user("admin", "c", "admin");
    const { state, api } = server([owner, admin]);
    const rotate = api.rotate;
    let raced = false;
    // The admin's browser mints between the owner's read and the owner's rotation.
    const racing: KeyAPI = { ...api, rotate: async (cid, expected, rows) => {
      if (!raced) { raced = true; await syncContainerKeys(api, cnt, as(admin), memoryPins(), () => false); }
      return rotate(cid, expected, rows);
    } };
    const result = await syncContainerKeys(racing, cnt, as(owner), memoryPins(), () => false);
    expect(result.minted).toBe(false);
    expect(result.container.keyGeneration).toBe(2);
    expect(result.ring.size).toBe(1);
    expect(state.envelopes.filter((row) => row.keyGeneration === 2)).toHaveLength(2); // one key, no split
  });

  it("only reads keys for a member, or a session that may not wrap", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor");
    const { api } = server([owner, editor]);
    await syncContainerKeys(api, cnt, as(editor), memoryPins(), () => false);
    await syncContainerKeys(api, cnt, as(owner, false), memoryPins(), () => false);
    expect(api.stepUp).not.toHaveBeenCalled();
    expect(api.rotate).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run.** `npx vitest run src/keyService.test.ts`. Expected: FAIL (module not found).

- [ ] **Step 3: Implement.** `web/src/keyService.ts`:

```ts
import type { HeldIdentity, PublicIdentity } from "./identity";
import { newContainerKey, openKeyring, planSweep, sealFor, type Envelope, type KeyedContainer, type Keyring, type Member, type MemberKey, type SweepPlan } from "./keyring";
import { comparePins, type PinChange, type Pins } from "./pins";
import { base64 } from "./crypto";

export type KeyAPI = {
  /** The container's current generations; read at the start of every pass, never trusted from a tab's memory. */
  container: (containerID: string) => Promise<KeyedContainer>;
  envelopes: (containerID: string) => Promise<Envelope[]>;
  members: (containerID: string) => Promise<Member[]>;
  userIdentity: (userID: string) => Promise<PublicIdentity | undefined>;
  /** Proves the cached login secret again; envelope writes need a fresh user step-up. */
  stepUp: () => Promise<void>;
  putEnvelopes: (containerID: string, envelopes: Envelope[]) => Promise<void>;
  rotate: (containerID: string, expectedGeneration: number, envelopes: Envelope[]) => Promise<{ keyGeneration: number }>;
};
export type PinStore = { load: () => Promise<Pins>; save: (pins: Pins) => Promise<void> };
export type Me = { userId: string; identity?: HeldIdentity; canWrap: boolean };
/** "untrusted": the user declined a colleague's changed key, so nothing was shared. */
export type KeySync = { container: KeyedContainer; ring: Keyring; plan: SweepPlan | { kind: "untrusted"; members: string[] }; minted: boolean };

const code = (error: unknown) => (error as { code?: string }).code;

/**
 * Loads this browser's keys for a team container. When the caller is an owner or admin
 * whose session may wrap (a local password session with an identity), it then shares
 * keys: the first mint, the re-mint after a removal, and wraps for members missing
 * a generation. A changed colleague key stops everything unless the user confirms it.
 * Another steward winning a race (409 already_exists) is retried once from fresh server state.
 */
export async function syncContainerKeys(api: KeyAPI, containerID: string, me: Me, pins: PinStore, confirmChanged: (changes: PinChange[]) => boolean | Promise<boolean>): Promise<KeySync> {
  for (let attempt = 0; ; attempt += 1) {
    let container = await api.container(containerID);
    const envelopes = await api.envelopes(container.id);
    const ring = openKeyring(container.id, envelopes, me.identity);
    if (!me.identity || !me.canWrap) return { container, ring, plan: { kind: "idle" }, minted: false };
    const members = await api.members(container.id);
    const role = members.find((member) => member.userId === me.userId)?.role;
    if (role !== "owner" && role !== "admin") return { container, ring, plan: { kind: "idle" }, minted: false };
    const own = { deviceId: me.identity.deviceId, publicKey: base64(me.identity.publicKey) };
    const keyed: MemberKey[] = await Promise.all(members.map(async (member) => ({ ...member, identity: member.userId === me.userId ? own : await api.userIdentity(member.userId) })));
    const plan = planSweep({ container, me: me.userId, members: keyed, envelopes, ring });
    if (plan.kind === "idle" || plan.kind === "blocked") return { container, ring, plan, minted: false };
    const saved = await pins.load();
    const others = keyed.filter((member) => member.userId !== me.userId);
    const { fresh, changed } = comparePins(saved, others);
    if (changed.length && !(await confirmChanged(changed))) return { container, ring, plan: { kind: "untrusted", members: changed.map((entry) => entry.member.username) }, minted: false };
    await pins.save({ ...saved, ...Object.fromEntries([...fresh, ...changed.map((entry) => entry.member)].map((member) => [member.userId, member.identity!.publicKey])) });
    try {
      await api.stepUp();
      if (plan.kind === "mint") {
        const key = newContainerKey();
        const next = container.keyGeneration + 1;
        const result = await api.rotate(container.id, container.keyGeneration, plan.recipients.map((member) => sealFor(member, container.id, next, key)));
        container = { ...container, keyGeneration: result.keyGeneration, sharedGeneration: container.sharedGeneration || result.keyGeneration };
      } else {
        await api.putEnvelopes(container.id, plan.grants.map((grant) => sealFor(grant.member, container.id, grant.generation, ring.get(grant.generation)!)));
      }
    } catch (error) {
      // already_exists: another steward rotated or wrapped first. Re-read once; the caller's container may be stale.
      if (code(error) !== "already_exists" || attempt > 0) throw error;
      continue;
    }
    const after = await api.envelopes(container.id);
    return { container, ring: openKeyring(container.id, after, me.identity), plan, minted: plan.kind === "mint" };
  }
}
```

- [ ] **Step 4: `api.ts`.** Apply:

```diff
--- a/web/src/api.ts
+++ b/web/src/api.ts
@@ -1,17 +1,21 @@
 import { confirmSSOAction } from "./reauth";
 import type { IdentityAPI, IdentityRecord, IdentityUpload, PublicIdentity } from "./identity";
+import type { Envelope } from "./keyring";
 export type User = { id: string; role: string; username?: string };
 export type Session = { sso?: boolean; user: User; expiresAt: string; hardExpiresAt: string };
-export type Container = { id: string; kind: string; teamId?: string; metaCiphertext: string; metaVersion: number; changeSeq: number; keyGeneration: number };
+export type Container = { id: string; kind: string; teamId?: string; metaCiphertext: string; metaVersion: number; changeSeq: number; keyGeneration: number; sharedGeneration: number };
 export type Comment = { id: string; authorUserId: string; username: string; bodyCiphertext: string; keyGeneration: number; createdAt: string };
 export type AdminUser = { id: string; username: string; role: string; status: string; quotaBytes: number; createdAt: string };
-export type AdminTeam = { id: string; kind: string; ownerUserId: string; metaCiphertext?: string; metaVersion?: number; changeSeq?: number; keyGeneration?: number };
+export type AdminTeam = { id: string; kind: string; ownerUserId: string; metaCiphertext?: string; metaVersion?: number; changeSeq?: number; keyGeneration?: number; sharedGeneration?: number };
 export type Change = { id: string; kind: string; changeSeq: number; deleted: boolean };
 export type Note = { id: string; title: string; body: string; version: number; updatedAt: string; section?: string; order?: string; level?: 0 | 1 | 2 };
 
 type APIError = { error?: { code?: string; message?: string }; conflictId?: string; currentVersion?: number };
 export class APIRequestError extends Error { code?: string; conflictId?: string; currentVersion?: number; constructor(message: string, detail: APIError) { super(message); this.name = "APIRequestError"; this.code = detail.error?.code; this.conflictId = detail.conflictId; this.currentVersion = detail.currentVersion; } }
 
+/** Marks writes from a bundle that seals shared containers with their container key; the server refuses shared-container writes without it. */
+export const KEY_SCHEME = "shared-v1";
+
 export function csrfToken(): string {
   return document.cookie.split("; ").find((v) => v.startsWith("csrf_token="))?.slice(11) ?? "";
 }
@@ -35,7 +39,10 @@
   const headers = new Headers(init.headers);
   headers.set("Accept", "application/json");
   if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
-  if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) headers.set("X-CSRF-Token", csrfToken());
+  if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
+    headers.set("X-CSRF-Token", csrfToken());
+    headers.set("X-Kynotes-Key-Scheme", KEY_SCHEME);
+  }
   const response = await actionFetch(path, { ...init, headers, credentials: "include" });
   if (!response.ok) {
     let detail: APIError = {};
@@ -131,6 +138,14 @@
 }
 export const putMyIdentity = (input: IdentityUpload) => request<{ deviceId: string; fingerprint: string }>("/api/v1/me/identity", { method: "PUT", body: JSON.stringify(input) });
 export const identityAPI: IdentityAPI = { myIdentity, putMyIdentity, stepUp: async (authSecret) => (await stepUp(authSecret))?.identity };
+export const containerEnvelopes = (containerID: string) => request<Envelope[]>(`/api/v1/containers/${encodeURIComponent(containerID)}/envelopes`);
+export const putEnvelopes = (containerID: string, envelopes: Envelope[]) => request<void>(`/api/v1/containers/${encodeURIComponent(containerID)}/envelopes`, { method: "PUT", body: JSON.stringify({ envelopes }) });
+export const rotateKeys = (containerID: string, expectedGeneration: number, envelopes: Envelope[]) => request<{ keyGeneration: number }>(`/api/v1/containers/${encodeURIComponent(containerID)}/key-rotations`, { method: "POST", body: JSON.stringify({ expectedGeneration, envelopes }) });
+/** A colleague's public identity; undefined when they have none or the server will not show it. */
+export async function userIdentity(userID: string): Promise<PublicIdentity | undefined> {
+  try { return await request<PublicIdentity>(`/api/v1/users/${encodeURIComponent(userID)}/identity`); }
+  catch (error) { if (error instanceof APIRequestError && error.code === "not_found") return undefined; throw error; }
+}
 export const members = (containerID: string) => request<Array<{ userId: string; username: string; role: string }>>(`/api/v1/containers/${encodeURIComponent(containerID)}/members`);
 export const notifications = () => request<Array<{ id: string; objectId: string; authorUserId: string; createdAt: string; kind: string }>>("/api/v1/notifications");
 export const presence = (containerID: string) => request<Array<{ userId: string; state: string }>>(`/api/v1/presence?containerId=${encodeURIComponent(containerID)}`);
@@ -159,7 +174,7 @@
     credentials: "include", headers: { Accept: "application/octet-stream" },
   });
   if (!response.ok) throw new Error(`Unable to read note (${response.status})`);
-  return { bytes: new Uint8Array(await response.arrayBuffer()), version: Number(response.headers.get("X-Kynotes-Version") ?? 0) };
+  return { bytes: new Uint8Array(await response.arrayBuffer()), version: Number(response.headers.get("X-Kynotes-Version") ?? 0), keyGeneration: Number(response.headers.get("X-Kynotes-Key-Generation") ?? 0) };
 }
 
 export async function saveObject(objectID: string, bytes: Uint8Array, baseVersion: number, keyGeneration = 1) {
```

- [ ] **Step 5: Pass.** `npx tsc --noEmit && npx vitest run`. Expected: PASS (the wiring test included).

- [ ] **Step 6: Commit.** `git add -A web/src && git commit -m "web: steward key sync service and team-key API calls"`

### Task 6: Wire `main.tsx`

**Files:** Modify `web/src/main.tsx`. Each replacement below matches exactly once in the Task 2 state; apply them in order. Interfaces used: `readKeysFor(containerID, hint?) → KeyRef[]`, `writeKeyFor(container) → { key, generation } | undefined`, `syncKeys(container) → Promise<Container>` (current generation, ring stored, steward work done), `currentContainer(id)`, `keyWait`, `keyNotice`.

- [ ] **Step 1: Apply the replacements.**

1. **imports: api.** Replace:

```tsx
  conflictCiphertext,
  resolveConflict,
```

with:

```tsx
  conflictCiphertext,
  containerEnvelopes,
  putEnvelopes,
  rotateKeys,
  stepUp,
  userIdentity,
  resolveConflict,
```

2. **imports: identity, keyring, key service, pins.** Replace:

```tsx
import { ensureIdentity, rewrapIdentity, type IdentityRecord } from "./identity";
```

with:

```tsx
import { ensureIdentity, rewrapIdentity, type HeldIdentity, type IdentityRecord } from "./identity";
import { openFirst, openKeyring, readKeys, writeKey, type Keyring } from "./keyring";
import { syncContainerKeys, type KeyAPI, type PinStore } from "./keyService";
import { fingerprint, type PinChange } from "./pins";
```

3. **imports: crypto.** Replace:

```tsx
  fromBase64,
  legacyKeyRef,
```

with:

```tsx
  base64,
  fromBase64,
  legacyKeyRef,
```

4. **imports: storage (pins).** Replace:

```tsx
  getNote,
  clearUpload,
```

with:

```tsx
  getNote,
  getPins,
  clearUpload,
```

5. **imports: storage (types).** Replace:

```tsx
  storeIdentityKey,
} from "./storage";
```

with:

```tsx
  storeIdentityKey,
  storePins,
  type PendingSave,
  type PendingUpload,
} from "./storage";
```

6. **AuthState knows an SSO session.** Replace:

```tsx
type AuthState = {
  username: string;
  authSecret: string;
  user: Session["user"];
};
```

with:

```tsx
type AuthState = {
  username: string;
  authSecret: string;
  user: Session["user"];
  /** A single sign-on session: it cannot prove the password, so it never wraps keys. */
  sso?: boolean;
};
```

7. **session resume records SSO.** Replace:

```tsx
            setAuth({
              username: res.user.username,
              authSecret: cachedKey,
              user: res.user,
            });
```

with:

```tsx
            setAuth({
              username: res.user.username,
              authSecret: cachedKey,
              user: res.user,
              sso: res.sso,
            });
```

8. **password typed into an SSO session stays an SSO session.** Replace:

```tsx
          onLogin({ username: activeName, authSecret, user: sessionUser });
```

with:

```tsx
          onLogin({ username: activeName, authSecret, user: sessionUser, sso: true });
```

9. **PlainAttachment carries its generation.** Replace:

```tsx
type PlainAttachment = { id: string; name: string; type: string; size: number };
```

with:

```tsx
type PlainAttachment = { id: string; name: string; type: string; size: number; keyGeneration?: number };
```

10. **Workspace key state and helpers.** Replace:

```tsx
  // The login-derived content key: legacy rows, personal notebooks, and (until team keys) everything.
  const legacy = useMemo(() => legacyKeyRef(auth.authSecret), [auth.authSecret]);

```

with:

```tsx
  // Team keys. Content in a shared container is sealed with its container key at the
  // current generation; everything else, and every legacy row, uses the login-derived key.
  const legacy = useMemo(() => legacyKeyRef(auth.authSecret), [auth.authSecret]);
  const ringsRef = useRef<Record<string, Keyring>>({});
  const [rings, setRings] = useState(ringsRef.current);
  const putRing = (containerID: string, ring: Keyring) => { ringsRef.current = { ...ringsRef.current, [containerID]: ring }; setRings(ringsRef.current); };
  const noKeys: Keyring = new Map();
  const readKeysFor = (containerID: string, hint?: number) => readKeys(ringsRef.current[containerID] ?? noKeys, legacy, hint);
  const writeKeyFor = (container: Container) => writeKey(container, ringsRef.current[container.id] ?? noKeys, legacy);
  // Read-only until a team owner shares this generation's key.
  const keyWait = Boolean(selected && !writeKey(selected, rings[selected.id] ?? noKeys, legacy));
  const [keyNotice, setKeyNotice] = useState("");
  const identityRef = useRef<HeldIdentity | undefined>(undefined);
  async function heldIdentity() {
    // Created after the first password sign-in, possibly after this workspace mounted.
    if (!identityRef.current) identityRef.current = await getIdentityKey(auth.username, auth.user.id).catch(() => undefined);
    return identityRef.current;
  }
  async function currentContainer(id: string): Promise<Container> {
    const found = (await containers()).find((entry) => entry.id === id);
    if (!found) throw new Error("Notebook not found");
    return found;
  }
  const keyAPI: KeyAPI = {
    container: currentContainer,
    envelopes: containerEnvelopes,
    members,
    userIdentity,
    stepUp: async () => { await stepUp(auth.authSecret); },
    putEnvelopes,
    rotate: rotateKeys,
  };
  const pinStore: PinStore = {
    load: () => getPins(auth.username, auth.user.id).catch(() => ({})),
    save: (pins) => storePins(auth.username, auth.user.id, pins).catch(() => undefined),
  };
  async function confirmChangedKeys(changes: PinChange[]) {
    const lines = await Promise.all(changes.map(async (change) => `${change.member.username}: ${await fingerprint(change.member.identity!.publicKey)}`));
    return confirm(`The encryption key of ${changes.map((change) => change.member.username).join(", ")} changed since you last shared keys with them. A password reset or account recovery does this; so would a server substituting its own key. Compare these fingerprints with the person (Settings shows theirs) before continuing:\n\n${lines.join("\n")}\n\nShare this notebook's keys with the new key?`);
  }
  /** Loads this browser's keys for a team container and, as its owner or admin, shares them. Returns it at its current generation. */
  async function syncKeys(container: Container): Promise<Container> {
    // Personal notebooks keep the login-derived key until personal containers move to shared keys (P5).
    if (container.kind !== "team" && !container.teamId) return container;
    const result = await syncContainerKeys(keyAPI, container.id, { userId: auth.user.id, identity: await heldIdentity(), canWrap: !auth.sso }, pinStore, confirmChangedKeys);
    putRing(container.id, result.ring);
    const next = { ...container, keyGeneration: result.container.keyGeneration, sharedGeneration: result.container.sharedGeneration };
    setItems((value) => value.map((entry) => (entry.id === next.id ? { ...entry, keyGeneration: next.keyGeneration, sharedGeneration: next.sharedGeneration } : entry)));
    if (result.plan.kind === "blocked") setKeyNotice(`This notebook is not end-to-end shared yet: ${result.plan.waitingFor.join(", ")} must first sign in with a password to get an encryption key. Accounts that sign in only through single sign-on cannot hold one yet.`);
    else if (result.plan.kind === "untrusted") setKeyNotice(`Keys were not shared: you did not confirm the new encryption key of ${result.plan.members.join(", ")}.`);
    else setKeyNotice("");
    if (result.minted) await resealName(next);
    return next;
  }
  /** After the first key is minted, the name moves from the creator's legacy key to the container key. */
  async function resealName(container: Container) {
    const write = writeKeyFor(container);
    if (!write || !container.metaCiphertext) return;
    try {
      const { name } = await openFirst(readKeysFor(container.id), (key) => decryptContainerMeta(key, container.id, fromBase64(container.metaCiphertext)));
      const encoded = base64(await encryptContainerMeta(write.key, container.id, name));
      const result = await updateContainer(container.id, encoded, container.metaVersion);
      setItems((value) => value.map((entry) => (entry.id === container.id ? { ...entry, metaCiphertext: encoded, metaVersion: result.metaVersion, changeSeq: result.changeSeq } : entry)));
    } catch { /* Another account's legacy name stays opaque until it is renamed. */ }
  }

```

11. **image previews: trial decryption.** Replace:

```tsx
            const plaintext = await decryptAttachment(legacy, selected?.id ?? "", encrypted);
```

with:

```tsx
            const containerID = selected?.id ?? "";
            const plaintext = await openFirst(readKeysFor(containerID, attachment.keyGeneration), (key) => decryptAttachment(key, containerID, encrypted));
```

12. **image previews: re-run when keys arrive.** Replace:

```tsx
  }, [attachmentsForNote, auth.authSecret, selected?.id]);
```

with:

```tsx
  }, [attachmentsForNote, rings, selected?.id]);
```

13. **notebook names: load shared keyrings, trial decryption.** Replace:

```tsx
      const nextNames: Record<string, string> = {};
      for (const item of loaded) {
        try {
          if (item.metaCiphertext)
            nextNames[item.id] = (
              await decryptContainerMeta(
                legacy,
                item.id,
                fromBase64(item.metaCiphertext),
              )
            ).name;
        } catch {
```

with:

```tsx
      const nextNames: Record<string, string> = {};
      const identity = await heldIdentity();
      for (const item of loaded) {
        try {
          // Names of shared containers need their keys; a steward's sharing waits until the notebook is opened.
          if (item.sharedGeneration > 0) putRing(item.id, openKeyring(item.id, await containerEnvelopes(item.id), identity));
          if (item.metaCiphertext)
            nextNames[item.id] = (await openFirst(readKeysFor(item.id), (key) => decryptContainerMeta(key, item.id, fromBase64(item.metaCiphertext)))).name;
        } catch {
```

14. **objects: trial decryption (server copy or cache).** Replace:

```tsx
          const payload = await decryptObject(legacy, container.id, useCache ? cached!.payload : object.bytes);
```

with:

```tsx
          const payload = await openFirst(readKeysFor(container.id, useCache ? cached!.keyGeneration : object.keyGeneration), (key) => decryptObject(key, container.id, useCache ? cached!.payload : object.bytes));
```

15. **objects: trial decryption (cache fallback).** Replace:

```tsx
              add(change.id, await decryptObject(legacy, container.id, cached.payload), cached.version, cached.updatedAt);
```

with:

```tsx
              add(change.id, await openFirst(readKeysFor(container.id, cached.keyGeneration), (key) => decryptObject(key, container.id, cached.payload)), cached.version, cached.updatedAt);
```

16. **loadContainer: sync keys before reading.** Replace:

```tsx
    loadCarried.current.clear();
    try {
      const objects = await readContainerObjects(container);
```

with:

```tsx
    loadCarried.current.clear();
    setKeyNotice("");
    try {
      // Keys first: an owner may mint or re-mint here, and reads try the current key first.
      const keyed = await syncKeys(container).catch((error) => {
        setError(error instanceof Error ? `Unable to share this notebook's keys: ${error.message}` : "Unable to share this notebook's keys");
        return container;
      });
      if (superseded()) return [];
      setSelected(keyed);
      const objects = await readContainerObjects(keyed);
```

17. **comments: trial decryption.** Replace:

```tsx
          const decrypted = await decryptComment(
            legacy,
            containerID ?? "",
            fromBase64(item.bodyCiphertext),
          );
```

with:

```tsx
          const decrypted = await openFirst(readKeysFor(containerID ?? "", item.keyGeneration), (key) => decryptComment(key, containerID ?? "", fromBase64(item.bodyCiphertext)));
```

18. **attachment metadata: trial decryption, keep the generation.** Replace:

```tsx
          const metadata = await decryptAttachmentMetadata(legacy, containerID ?? "", fromBase64(item.metadataCiphertext));
          decoded.push({ id: item.id, ...metadata });
```

with:

```tsx
          const metadata = await openFirst(readKeysFor(containerID ?? "", item.keyGeneration), (key) => decryptAttachmentMetadata(key, containerID ?? "", fromBase64(item.metadataCiphertext)));
          decoded.push({ id: item.id, ...metadata, keyGeneration: item.keyGeneration });
```

19. **new team workspace: mint before naming.** Replace:

```tsx
      const container = await createContainer("workbook", "", teamContainer.id);
      const encrypted = await encryptContainerMeta(legacy, container.id, name);
```

with:

```tsx
      // Mint the workspace's own key before naming it, so the name is shared too.
      const container = await syncKeys(await createContainer("workbook", "", teamContainer.id));
      const write = writeKeyFor(container);
      if (!write) throw new Error("This team notebook is waiting for keys");
      const encrypted = await encryptContainerMeta(write.key, container.id, name);
```

20. **rename: current write key.** Replace:

```tsx
      const encrypted = await encryptContainerMeta(
        legacy,
        selected.id,
        name,
      );
```

with:

```tsx
      const write = writeKeyFor(selected);
      if (!write) throw new Error("This notebook is waiting for a team owner to share its keys");
      const encrypted = await encryptContainerMeta(write.key, selected.id, name);
```

21. **saveNow: current write key and generation.** Replace:

```tsx
      const payload = notePayload(note);
      const encrypted = await encryptNote(
        legacy,
        selected.id,
        payload,
      );
      const savedAt = new Date().toISOString();
      const containerID = selected.id;
      await cacheWrite(() => putNote({ id: note.id, containerID, version: note.version, payload: encrypted, updatedAt: savedAt }));
      try {
        const result = await saveObject(
          note.id,
          encrypted,
          note.version,
          selected.keyGeneration,
        );
```

with:

```tsx
      const write = writeKeyFor(selected);
      if (!write) throw new Error("This notebook is waiting for a team owner to share its keys; your change was not saved.");
      const encrypted = await encryptNote(write.key, selected.id, notePayload(note));
      const savedAt = new Date().toISOString();
      const containerID = selected.id;
      await cacheWrite(() => putNote({ id: note.id, containerID, version: note.version, payload: encrypted, updatedAt: savedAt, keyGeneration: write.generation }));
      try {
        const result = await saveObject(note.id, encrypted, note.version, write.generation);
```

22. **saveNow: a retired generation re-keys through the queue.** Replace:

```tsx
        } else {
          await queueSave({ id: note.id, containerID: selected.id, version: note.version, payload: encrypted, updatedAt: savedAt, keyGeneration: selected.keyGeneration });
          syncChannel.current?.postMessage({ type: "queued", id: note.id });
          setSyncStatus("local");
          setError("Saved locally; encrypted change queued for the server.");
        }
```

with:

```tsx
        } else {
          await queueSave({ id: note.id, containerID: selected.id, version: note.version, payload: encrypted, updatedAt: savedAt, keyGeneration: write.generation });
          syncChannel.current?.postMessage({ type: "queued", id: note.id });
          setSyncStatus("local");
          // The notebook's key generation moved on: the queue re-encrypts the change for it.
          if (error instanceof APIRequestError && error.code === "already_exists") void drainQueue();
          else setError("Saved locally; encrypted change queued for the server.");
        }
```

23. **drainQueue: re-key a retired generation.** Replace:

```tsx
          } else {
            remaining = true;
          }
```

with:

```tsx
          } else {
            // A retired generation: re-encrypt for the current key; the next drain sends it.
            if (error instanceof APIRequestError && error.code === "already_exists") await rekeyQueued(item).catch(() => undefined);
            remaining = true;
          }
```

24. **rekeyQueued.** Replace:

```tsx
  async function remove(note: Note) {
```

with:

```tsx
  /** Re-seals a queued save for its container's current key; leaves it queued while keys are pending. */
  async function rekeyQueued(item: PendingSave) {
    const container = await syncKeys(await currentContainer(item.containerID));
    const write = writeKeyFor(container);
    if (!write || write.generation === item.keyGeneration) return;
    const payload = await openFirst(readKeysFor(item.containerID, item.keyGeneration), (key) => decryptObject(key, item.containerID, item.payload));
    if (!payload) return;
    await queueSave({ ...item, payload: await encryptNote(write.key, item.containerID, payload), keyGeneration: write.generation });
    if (selectedRef.current?.id === container.id) setSelected(container);
  }
  async function remove(note: Note) {
```

25. **persistDraft: only with a write key.** Replace:

```tsx
    const containerID = selected.id;
    void cacheWrite(async () => putNote({
      id: note.id,
      containerID,
      version: note.version,
      payload: await encryptNote(legacy, containerID, notePayload(note)),
      updatedAt: new Date().toISOString(),
    })).catch(() => {});
```

with:

```tsx
    const containerID = selected.id;
    const write = writeKeyFor(selected);
    if (!write) return;
    void cacheWrite(async () => putNote({
      id: note.id,
      containerID,
      version: note.version,
      payload: await encryptNote(write.key, containerID, notePayload(note)),
      updatedAt: new Date().toISOString(),
      keyGeneration: write.generation,
    })).catch(() => {});
```

26. **writeObject: current write key.** Replace:

```tsx
    if (!selected) return null;
    const encrypted = await encryptNote(legacy, selected.id, payload);
    const updatedAt = new Date().toISOString();
    const containerID = selected.id;
    await cacheWrite(() => putNote({ id, containerID, version, payload: encrypted, updatedAt }));
    try {
      const result = await saveObject(id, encrypted, version, selected.keyGeneration);
```

with:

```tsx
    if (!selected) return null;
    const write = writeKeyFor(selected);
    if (!write) {
      setError("This notebook is waiting for a team owner to share its keys; the change was not saved.");
      return null;
    }
    const encrypted = await encryptNote(write.key, selected.id, payload);
    const updatedAt = new Date().toISOString();
    const containerID = selected.id;
    await cacheWrite(() => putNote({ id, containerID, version, payload: encrypted, updatedAt, keyGeneration: write.generation }));
    try {
      const result = await saveObject(id, encrypted, version, write.generation);
```

27. **writeObject: queue at the sent generation, re-key a retired one.** Replace:

```tsx
        await queueSave({ id, containerID: selected.id, version, payload: encrypted, updatedAt, keyGeneration: selected.keyGeneration });
        syncChannel.current?.postMessage({ type: "queued", id });
        setSyncStatus("local");
```

with:

```tsx
        await queueSave({ id, containerID: selected.id, version, payload: encrypted, updatedAt, keyGeneration: write.generation });
        syncChannel.current?.postMessage({ type: "queued", id });
        setSyncStatus("local");
        if (error instanceof APIRequestError && error.code === "already_exists") void drainQueue();
```

28. **otherTabDraft: trial decryption.** Replace:

```tsx
    const payload = await decryptObject(legacy, selected.id, cached.payload).catch(() => undefined);
```

with:

```tsx
    const containerID = selected.id;
    const payload = await openFirst(readKeysFor(containerID, cached.keyGeneration), (key) => decryptObject(key, containerID, cached.payload)).catch(() => undefined);
```

29. **conflict recovery: server copy.** Replace:

```tsx
      const payload = await decryptObject(legacy, containerID, server.bytes);
```

with:

```tsx
      const payload = await openFirst(readKeysFor(containerID, server.keyGeneration), (key) => decryptObject(key, containerID, server.bytes));
```

30. **conflict recovery: rejected copies.** Replace:

```tsx
          const decrypted = await decryptObject(legacy, containerID, await conflictCiphertext(conflict.id)).catch(() => undefined);
```

with:

```tsx
          const bytes = await conflictCiphertext(conflict.id);
          const decrypted = await openFirst(readKeysFor(containerID), (key) => decryptObject(key, containerID, bytes)).catch(() => undefined);
```

31. **uploads: sealUpload, and re-seal once when the generation moved.** Replace:

```tsx
  async function uploadPending(job: Awaited<ReturnType<typeof pendingUploads>>[number]) {
```

with:

```tsx
  /** Encrypts a file for the container's current key and registers a resumable upload for it. */
  async function sealUpload(container: Container, objectID: string, objectVersion: number, plaintext: Uint8Array, file: { name: string; type: string; size: number }): Promise<PendingUpload> {
    const write = writeKeyFor(container);
    if (!write) throw new Error("This notebook is waiting for a team owner to share its keys");
    const encrypted = await encryptAttachment(write.key, container.id, plaintext);
    const upload = await createUpload(container.id, encrypted.byteLength, await digestSha256Hex(encrypted));
    const metadata = await encryptAttachmentMetadata(write.key, container.id, file);
    const job = { uploadId: upload.uploadId, containerID: container.id, objectID, objectVersion, keyGeneration: write.generation, chunkBytes: upload.chunkBytes, nextChunk: upload.nextChunk, payload: encrypted, metadataCiphertext: base64(metadata), name: file.name, type: file.type, size: file.size };
    await putUpload(job);
    return job;
  }
  async function uploadPending(job: PendingUpload, resealed = false): Promise<string> {
```

32. **uploads: finalize re-seal.** Replace:

```tsx
    const finalized = await finalizeUpload(job.uploadId, job.metadataCiphertext, job.keyGeneration);
    await attachToObject
```

with:

```tsx
    let finalized: Awaited<ReturnType<typeof finalizeUpload>>;
    try {
      finalized = await finalizeUpload(job.uploadId, job.metadataCiphertext, job.keyGeneration);
    } catch (error) {
      if (resealed || !(error instanceof APIRequestError && error.code === "already_exists")) throw error;
      // The key generation moved during the upload: re-seal the file for the current key and send it again.
      const container = await syncKeys(await currentContainer(job.containerID));
      const keys = readKeysFor(job.containerID, job.keyGeneration);
      const plaintext = await openFirst(keys, (key) => decryptAttachment(key, job.containerID, job.payload));
      const file = await openFirst(keys, (key) => decryptAttachmentMetadata(key, job.containerID, fromBase64(job.metadataCiphertext)));
      const next = await sealUpload(container, job.objectID, job.objectVersion, plaintext, file);
      await deleteUpload(job.uploadId).catch(() => undefined);
      await clearUpload(job.uploadId);
      setUploadProgress((value) => { const rest = { ...value }; delete rest[job.uploadId]; return rest; });
      return uploadPending(next, true);
    }
    await attachToObject
```

33. **uploadAttachment: through sealUpload.** Replace:

```tsx
      const encrypted = await encryptAttachment(legacy, selected.id, new Uint8Array(await file.arrayBuffer()));
      const digest = await digestSha256Hex(encrypted);
      const upload = await createUpload(selected.id, encrypted.byteLength, digest);
      const metadata = await encryptAttachmentMetadata(legacy, selected.id, { name: file.name, type: file.type, size: file.size });
      const job = { uploadId: upload.uploadId, containerID: selected.id, objectID: selectedNote.id, objectVersion: selectedNote.version, keyGeneration: selected.keyGeneration, chunkBytes: upload.chunkBytes, nextChunk: upload.nextChunk, payload: encrypted, metadataCiphertext: btoa(String.fromCharCode(...metadata)), name: file.name, type: file.type, size: file.size };
      await putUpload(job);
      const attachmentID = await uploadPending(job);
      return { id: attachmentID, name: file.name, type: file.type, size: file.size };
```

with:

```tsx
      const job = await sealUpload(selected, selectedNote.id, selectedNote.version, new Uint8Array(await file.arrayBuffer()), { name: file.name, type: file.type, size: file.size });
      const attachmentID = await uploadPending(job);
      return { id: attachmentID, name: file.name, type: file.type, size: file.size, keyGeneration: job.keyGeneration };
```

34. **inline files: trial decryption.** Replace:

```tsx
    const encrypted = await downloadAttachment(attachment.id);
    const plaintext = await decryptAttachment(legacy, selected.id, encrypted);
    return URL.createObjectURL
```

with:

```tsx
    const encrypted = await downloadAttachment(attachment.id);
    const containerID = selected.id;
    const plaintext = await openFirst(readKeysFor(containerID, attachment.keyGeneration), (key) => decryptAttachment(key, containerID, encrypted));
    return URL.createObjectURL
```

35. **open attachment: trial decryption.** Replace:

```tsx
      const encrypted = await downloadAttachment(attachment.id);
      const plaintext = await decryptAttachment(legacy, selected.id, encrypted);
      const url
```

with:

```tsx
      const encrypted = await downloadAttachment(attachment.id);
      const containerID = selected.id;
      const plaintext = await openFirst(readKeysFor(containerID, attachment.keyGeneration), (key) => decryptAttachment(key, containerID, encrypted));
      const url
```

36. **comment: current write key; a re-key keeps the text.** Replace:

```tsx
      const encrypted = await encryptComment(
        legacy,
        selected.id,
        commentText.trim(),
        commentSection.trim(),
      );
      await createComment(
        selectedNote.id,
        btoa(String.fromCharCode(...encrypted)),
        selected.keyGeneration,
      );
```

with:

```tsx
      const write = writeKeyFor(selected);
      if (!write) throw new Error("This notebook is waiting for a team owner to share its keys");
      const encrypted = await encryptComment(write.key, selected.id, commentText.trim(), commentSection.trim());
      try {
        await createComment(selectedNote.id, base64(encrypted), write.generation);
      } catch (error) {
        if (!(error instanceof APIRequestError && error.code === "already_exists")) throw error;
        // The notebook was re-keyed meanwhile: pick up the new key; the text stays in the box.
        setSelected(await syncKeys(selected));
        throw new Error("This notebook's keys just changed. Send the comment again.");
      }
```

37. **removal: re-mint now (forward secrecy).** Replace:

```tsx
      await removeMember(selected.id, userID);
      setMembersForTeam(await members(selected.id));
```

with:

```tsx
      await removeMember(selected.id, userID);
      // Forward secrecy: the removal retired every key; mint new ones now rather than at the next open.
      for (const child of items.filter((entry) => entry.teamId === selected.id)) await syncKeys(child);
      setSelected(await syncKeys(selected));
      setMembersForTeam(await members(selected.id));
```

38. **key-wait and notice banners.** Replace:

```tsx
                {queueMode ? <div className="workspace-kind">Open tasks across your personal notebooks</div> : selected && <div className="workspace-kind">{selected.kind === "team" ? "Team notebook" : "Notebook"}</div>}

```

with:

```tsx
                {queueMode ? <div className="workspace-kind">Open tasks across your personal notebooks</div> : selected && <div className="workspace-kind">{selected.kind === "team" ? "Team notebook" : "Notebook"}</div>}
                {!queueMode && keyWait && <div className="workspace-kind" role="status">Waiting for a team owner to share this notebook's keys. It is read-only until then.</div>}
                {!queueMode && keyNotice && <div className="workspace-kind" role="status">{keyNotice}</div>}

```

39. **no new page while waiting for keys.** Replace:

```tsx
                  disabled={!selected || busy || sectionHidden}
                  title={sectionHidden ? "Add a section to this group first" : "New page"}
```

with:

```tsx
                  disabled={!selected || busy || sectionHidden || keyWait}
                  title={sectionHidden ? "Add a section to this group first" : "New page"}
```

40. **title read-only while waiting.** Replace:

```tsx
                  readOnly={recovering === selectedNote.id}
                  value={selectedNote.title}
```

with:

```tsx
                  readOnly={recovering === selectedNote.id || keyWait}
                  value={selectedNote.title}
```

41. **canvas read-only while waiting.** Replace:

```tsx
                      editable={recovering !== selectedNote.id}
```

with:

```tsx
                      editable={recovering !== selectedNote.id && !keyWait}
```

42. **AdminTeams: never rename a shared team with a legacy key.** Replace:

```tsx
    const selected = teams.find((entry) => entry.id === team);
    if (!selected) return;
```

with:

```tsx
    const selected = teams.find((entry) => entry.id === team);
    // A shared team's name is sealed with its container key; a legacy-key name would be unreadable to members.
    if (!selected || selected.sharedGeneration) return;
```

43. **AdminTeams: rename button.** Replace:

```tsx
      <button className="quiet" onClick={() => void renameTeam()} disabled={!team}>
        Rename team
      </button>
```

with:

```tsx
      <button className="quiet" onClick={() => void renameTeam()} disabled={!team || Boolean(teams.find((entry) => entry.id === team)?.sharedGeneration)} title="Shared teams are renamed from the team notebook">
        Rename team
      </button>
```

44. **Settings: own fingerprint state.** Replace:

```tsx
  const [audit, setAudit] = useState<Array<Record<string, string>>>([]);
  useEffect(() => {
    if (admin) {
```

with:

```tsx
  const [audit, setAudit] = useState<Array<Record<string, string>>>([]);
  const [ownFingerprint, setOwnFingerprint] = useState("");
  useEffect(() => {
    // From this browser's own copy of the key, so the server cannot show a different one.
    void getIdentityKey(username, userID)
      .then((identity) => (identity ? fingerprint(base64(identity.publicKey)) : ""))
      .then(setOwnFingerprint, () => setOwnFingerprint(""));
  }, [username, userID]);
  useEffect(() => {
    if (admin) {
```

45. **Settings: show it.** Replace:

```tsx
                This browser holds your local zero-knowledge encryption key to allow instant 1-click SSO login without entering a password.
              </p>
```

with:

```tsx
                This browser holds your local zero-knowledge encryption key to allow instant 1-click SSO login without entering a password.
              </p>
              <p className="config-muted">
                {ownFingerprint
                  ? <>Your encryption key fingerprint: <code>{ownFingerprint}</code>. Team owners see it when your key changes; compare it with them in person.</>
                  : "This browser holds no encryption key for team notebooks. Sign in with your password to create or unlock it."}
              </p>
```

- [ ] **Step 2: Check the wiring.** `cd web && npx tsc --noEmit && npx vitest run`. Expected: PASS. Then:

```bash
grep -nE 'selected\.keyGeneration' src/main.tsx      # nothing: writes use write.generation
grep -c 'legacyKeyRef(' src/main.tsx                  # 2
grep -nE 'auth\.authSecret' src/main.tsx              # only: legacy memo, keyAPI.stepUp, SettingsView prop
```

- [ ] **Step 3: Commit.** `git commit -am "web: team notebooks use shared container keys"`

### Task 7: Embedded bundle, docs and DOX

**Files:** `internal/web/dist/`, `DESIGN.md`, `IMPLEMENTATION_PLAN.md`, `docs/superpowers/specs/2026-10-07-team-keys-design.md`, `AGENTS.md`, `CHANGELOG.md`.

- [ ] **Step 1: Bundle.** `npm run build --prefix web && rm -rf internal/web/dist && cp -r web/dist internal/web/dist && diff -qr web/dist internal/web/dist && go test ./internal/web`.

- [ ] **Step 2: `DESIGN.md` §Encryption.** After the paragraph ending "comment and attachment writes recheck only the gate.", add:

```markdown
The web client seals a team container's content with its container key once
the container is shared, and reads by trial: the row's generation, other held
generations, then the legacy login-derived key. It never writes legacy
ciphertext into a shared container; a member without the current key reads
only. Shared containers refuse content writes that lack the
`X-Kynotes-Key-Scheme: shared-v1` header, so a page loaded before shared keys
cannot write. Owners and admins mint keys only through rotation; envelope
`PUT` may add a member to any shared generation that already has envelopes
(history for newcomers) and never mints one. The first mint waits until every
member has an identity. Browsers pin colleagues' identity keys on first use and
ask before wrapping for a changed one.
```

- [ ] **Step 3: `IMPLEMENTATION_PLAN.md`.** Line 350 (`already_exists` row): append "; a shared container written without `X-Kynotes-Key-Scheme: shared-v1` (`this notebook uses shared keys: reload the page`)". Line 1228 (`GET /api/v1/containers`): append "; each row carries `keyGeneration` and `sharedGeneration`". Line 1241 (envelope `PUT`): replace "`409 already_exists` for a stale generation or an existing recipient envelope" with "legacy containers: the current generation only; shared containers: any generation from `sharedGeneration` to current that already has an envelope (`409 already_exists` otherwise: `key generation changed` outside the range, `key rotation incomplete` for an empty generation); `409` for an existing recipient envelope". In §9 **Write gate** after "Otherwise the writer's own live identity needs one." add "and the request must carry `X-Kynotes-Key-Scheme: shared-v1`". Line 1330 (object `PUT` headers): add "`X-Kynotes-Key-Scheme` (shared containers)".

- [ ] **Step 4: Spec.** In §7 under "**P3a as built.**" (the decomposition added with this plan), record resolved ambiguities 1–6 above as numbered items, and the known limits: steward work runs only when a steward with a local password session opens the notebook (or removes a member); a member added without an identity reads only until P3c; `loadContainers` fetches envelopes per shared container and a steward's open fetches one identity per member (`ponytail:` upgrade path: a batch route); a key-wait queue item re-syncs keys every 15 s drain; admin pages cannot read shared team names. In §6 replace "**SSO users (open question):** …" with a pointer to §8 and P3c.

- [ ] **Step 5: `AGENTS.md`.** After the "Team keys P2" bullet add:

```markdown
- Team keys P3a (web): `web/src/keyring.ts` (pure: envelopes → generation keys, write key, read
  order, steward sweep plan), `web/src/keyService.ts` (one sweep against an injected API: mint via
  rotation, backfill wraps, one retry on 409) and `web/src/pins.ts` (TOFU pins in the vault record,
  local fingerprints). Content crypto takes a `KeyRef`; `main.tsx` reaches the login key only through
  `legacyKeyRef` (two call sites, test-gated) and writes shared containers only with the current
  container key (else read-only "waiting for keys"). Server: containers report `sharedGeneration`;
  shared containers refuse writes without `X-Kynotes-Key-Scheme: shared-v1`; envelope `PUT`
  backfills existing shared generations and never mints (`putGenerationTx`). Verify
  `TestSharedContainerRefusesStaleClientWrites`, `TestStewardBackfillsSharedHistoryOnly`,
  `TestSharedGenerationIsMintedOnlyByRotation`, `TestContainersReportSharedGeneration`,
  `npm test` (keyring, keyService, pins, crypto, storage) and `npm run e2e --prefix web`
  (three browsers against a throwaway server, `web/e2e/server.sh`).
```

Update the `web/` Child DOX Index bullet that says plaintext stays in browser memory to add "team notebooks use shared container keys (`keyring.ts`)".

- [ ] **Step 6: `CHANGELOG.md`.** Under Unreleased, first:

```markdown
- Team keys phase 3a: team notebooks are shared end to end. When an owner or admin opens a team
  notebook whose members all have encryption keys, their browser creates the notebook key and
  shares it; members added later get the notebook's history; removing a member replaces the key
  for new content. A member waiting for a key sees the notebook read-only. Browsers remember
  colleagues' key fingerprints and ask before trusting a changed one (Settings shows your own).
  Single sign-on-only accounts cannot hold keys yet, so a team that includes one stays unshared,
  and the owner sees who is missing. Browser tabs opened before this release must be reloaded to
  write to a shared notebook (`409 already_exists`). `GET /api/v1/containers` reports
  `sharedGeneration`.
```

- [ ] **Step 7: DOX closeout.** Re-read `../AGENTS.md` → `AGENTS.md`. `internal/backup/AGENTS.md` unchanged (no schema change). Note in the PR that `FRONTEND_IMPLEMENTATION_PLAN.md` has no content-key text to update.

- [ ] **Step 8: Commit.** `git add -A && git commit -m "docs: team keys P3a contracts, spec and DOX; embedded bundle"`

### Task 8: Three-browser check (owner, editor, newcomer)

**Files:** Modify `web/package.json` (+ lock), `.gitignore`, `.github/workflows/ci.yml`. Create `web/playwright.config.ts`, `web/e2e/server.sh`, `web/e2e/team-keys.e2e.ts`.

- [ ] **Step 1: Dependency.** `npm install --prefix web --save-dev --save-exact @playwright/test@1.63.0`; add `"e2e": "playwright test"` to `scripts`. Add `web/test-results/` and `web/playwright-report/` to `.gitignore`. The spec file is named `*.e2e.ts` so vitest's default `*.test`/`*.spec` include never collects it; `tsconfig.json` includes only `src`.

- [ ] **Step 2: Config and throwaway server.** `web/playwright.config.ts`:

```ts
import { defineConfig } from "@playwright/test";

// Real-browser checks against a throwaway server (e2e/server.sh). Never point this at real data.
const url = process.env.KYNOTES_E2E_URL ?? "http://127.0.0.1:18080";
export default defineConfig({
  testDir: "e2e",
  testMatch: "*.e2e.ts",
  timeout: 180_000,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  use: { baseURL: url, browserName: "chromium", trace: "retain-on-failure", screenshot: "only-on-failure" },
  webServer: process.env.KYNOTES_E2E_URL ? undefined : { command: "bash e2e/server.sh", url: `${url}/readyz`, timeout: 180_000, reuseExistingServer: false },
});
```

`web/e2e/server.sh` (fresh data per run; `dev_insecure_cookies` is what allows a data dir under `/tmp`, never use it elsewhere):

```bash
#!/usr/bin/env bash
# Throwaway KyNotes server for the browser checks: a fresh data directory per run.
# It serves the embedded bundle, so build and sync internal/web/dist first.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
data=$(mktemp -d)
trap 'rm -rf "$data"' EXIT
cat > "$data/kynotes.yaml" <<YAML
server:
  bind: "127.0.0.1:18080"
  dev_insecure_cookies: true
secrets:
  pairing_secret: "12345678901234567890123456789012"
  server_salt_key: "12345678901234567890123456789012"
data_dir: "$data"
YAML
(cd "$root" && go build -o "$data/kynotes-server" ./cmd/kynotes-server)
"$data/kynotes-server" --config "$data/kynotes.yaml"
```

- [ ] **Step 3: The scenario.** `web/e2e/team-keys.e2e.ts`:

```ts
import { readFileSync } from "node:fs";
import { expect, test, type Browser, type Page } from "@playwright/test";
import { decryptObject, fromBase64, type KeyRef } from "../src/crypto";
import { unwrapEnvelope } from "../src/teamKeys";

// Three people in three isolated browser contexts (cookies and IndexedDB apart).
const TEMPORARY = "temporary horse battery staple";
const OWN = "my own horse battery staple";
const TEAM = "Team Keys E2E";

async function person(browser: Browser): Promise<{ page: Page; answers: string[] }> {
  const page = await (await browser.newContext()).newPage();
  const answers: string[] = [];
  page.on("dialog", (dialog) => void (dialog.type() === "prompt" ? dialog.accept(answers.shift()) : dialog.accept()));
  return { page, answers };
}

async function signIn(page: Page, username: string, password: string) {
  await page.goto("/");
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Unlock KyNotes" }).click();
  await expect(page.getByRole("button", { name: "Settings" })).toBeVisible();
}

/** An administrator-set password blocks the identity; the user's own change creates it. */
async function takeOverPassword(page: Page) {
  await page.getByRole("button", { name: "Settings" }).click();
  await page.getByLabel("Current password").fill(TEMPORARY);
  await page.getByLabel("New password", { exact: true }).fill(OWN);
  await page.getByLabel("Confirm new password").fill(OWN);
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: "Change password" }).click();
  await expect.poll(() => identityOf(page), { timeout: 30_000 }).not.toBeNull();
  await page.getByRole("button", { name: "← Workspace" }).click();
}

/** This browser's identity from the IndexedDB keys vault (P1 stores it unwrapped). Never creates the database. */
function identityOf(page: Page) {
  return page.evaluate(() => new Promise<{ deviceId: string; privateKey: number[] } | null>((resolve) => {
    const open = indexedDB.open("kynotes-web");
    open.onupgradeneeded = () => open.transaction!.abort(); // not created yet: leave it to the app
    open.onerror = () => resolve(null);
    open.onsuccess = () => {
      const db = open.result;
      if (!db.objectStoreNames.contains("keys")) { db.close(); resolve(null); return; }
      const all = db.transaction("keys").objectStore("keys").getAll();
      all.onsuccess = () => {
        db.close();
        const identity = (all.result as Array<{ identity?: { deviceId: string; privateKey: Uint8Array } }>).find((row) => row.identity)?.identity;
        resolve(identity ? { deviceId: identity.deviceId, privateKey: [...identity.privateKey] } : null);
      };
    };
  }));
}

async function openTeam(page: Page) {
  await page.reload();
  await page.getByRole("button", { name: TEAM }).click();
  await expect(page.locator(".workspace-title")).toHaveText(TEAM);
}

const objectSave = (page: Page) => page.waitForResponse((response) => response.request().method() === "PUT" && /\/api\/v1\/objects\/obj_/.test(response.url()) && response.ok());

async function writePage(page: Page, title: string, comment: string) {
  const created = objectSave(page);
  await page.getByRole("button", { name: "New page" }).click();
  await created;
  const titled = objectSave(page);
  await page.locator(".title-input").fill(title);
  await titled;
  await page.getByPlaceholder("Add a comment…").fill(comment);
  await page.getByRole("button", { name: "Comment", exact: true }).click();
  await expect(page.getByText(comment)).toBeVisible();
}

async function readPage(page: Page, title: string, comments: string[]) {
  await page.locator(".note-row", { hasText: title }).click();
  await expect(page.locator(".title-input")).toHaveValue(title);
  for (const comment of comments) await expect(page.getByText(comment)).toBeVisible();
}

async function addToTeam(page: Page, username: string) {
  await page.getByRole("button", { name: "Admin" }).click();
  const team = page.getByRole("combobox", { name: "Team", exact: true });
  await team.selectOption({ index: 1 });
  const person = page.getByRole("combobox", { name: "Person", exact: true });
  await person.selectOption((await person.locator("option", { hasText: username }).first().getAttribute("value"))!);
  await page.getByRole("button", { name: "Add to team" }).click();
  await page.getByRole("button", { name: "← Workspace" }).click();
}

const containerOf = (page: Page) => /#\/(cnt_[0-9a-z]+)/.exec(page.url())![1];

test("team keys: three people share, a removed member loses new content", async ({ browser }) => {
  const owner = await person(browser);
  const editor = await person(browser);
  const newcomer = await person(browser);

  // Owner: first-run setup (its own password, so its identity exists at once), then accounts.
  await owner.page.goto("/");
  await owner.page.getByLabel("Administrator Username").fill("owner");
  await owner.page.getByLabel("Master Password").fill(OWN);
  await owner.page.getByLabel("Confirm Password").fill(OWN);
  await owner.page.getByRole("button", { name: "Initialize KyNotes" }).click();
  await expect.poll(() => identityOf(owner.page), { timeout: 30_000 }).not.toBeNull();
  await owner.page.getByRole("button", { name: "Admin" }).click();
  for (const name of ["editor", "newcomer"]) {
    await owner.page.getByPlaceholder("Username").fill(name);
    await owner.page.getByPlaceholder("Temporary password").fill(TEMPORARY);
    await owner.page.getByRole("button", { name: "Create user" }).click();
    await expect(owner.page.getByText(name, { exact: true }).first()).toBeVisible();
  }
  owner.answers.push(TEAM);
  await owner.page.getByRole("button", { name: "Create team" }).click();
  await owner.page.getByRole("button", { name: "← Workspace" }).click();

  for (const [who, name] of [[editor, "editor"], [newcomer, "newcomer"]] as const) {
    await signIn(who.page, name, TEMPORARY);
    await takeOverPassword(who.page);
  }

  // Owner opens the team with every member keyed: the first key is minted and the name re-sealed.
  await addToTeam(owner.page, "editor");
  await openTeam(owner.page);
  await expect(owner.page.getByText(/not end-to-end shared yet/)).toHaveCount(0);
  await writePage(owner.page, "Owner page", "owner comment");
  await owner.page.locator('input[type="file"]').setInputFiles({ name: "evidence.txt", mimeType: "text/plain", buffer: Buffer.from("shared attachment bytes") });
  await expect(owner.page.getByRole("button", { name: /evidence\.txt/ })).toBeVisible();
  const cid = containerOf(owner.page);

  // Editor reads the owner's page, comment and attachment, and writes back.
  await openTeam(editor.page);
  await readPage(editor.page, "Owner page", ["owner comment"]);
  const download = editor.page.waitForEvent("download");
  await editor.page.getByRole("button", { name: /evidence\.txt/ }).click();
  expect(readFileSync(await (await download).path()).toString()).toBe("shared attachment bytes");
  await writePage(editor.page, "Editor page", "editor comment");

  // Newcomer joins after content exists: the owner's next open wraps every held generation.
  await addToTeam(owner.page, "newcomer");
  await openTeam(owner.page);
  await openTeam(newcomer.page);
  await readPage(newcomer.page, "Owner page", ["owner comment"]);
  await readPage(newcomer.page, "Editor page", ["editor comment"]);
  const held = await identityOf(newcomer.page);
  const rows = await newcomer.page.evaluate(async (id) => (await fetch(`/api/v1/containers/${id}/envelopes`)).json(), cid) as Array<{ deviceId: string; keyGeneration: number; envelope: string }>;
  const keys = new Map<number, KeyRef>(rows.filter((row) => row.deviceId === held!.deviceId)
    .map((row) => [row.keyGeneration, unwrapEnvelope(fromBase64(row.envelope), Uint8Array.from(held!.privateKey), cid, row.keyGeneration, held!.deviceId)]));
  expect(keys.size).toBeGreaterThan(0);

  // Remove the newcomer; the owner's browser re-mints before writing again.
  await owner.page.locator(".member-row", { hasText: "newcomer" }).getByRole("button", { name: "Remove" }).click();
  await expect(owner.page.locator(".member-row", { hasText: "newcomer" })).toHaveCount(0);
  await writePage(owner.page, "After removal", "after comment");
  const objectOf = async (title: string) => {
    const id = await owner.page.locator(".note-row", { hasText: title }).getAttribute("data-page-id");
    return owner.page.evaluate(async (oid) => {
      const response = await fetch(`/api/v1/objects/${oid}`);
      return { generation: Number(response.headers.get("X-Kynotes-Key-Generation")), bytes: [...new Uint8Array(await response.arrayBuffer())] };
    }, id!);
  };
  const before = await objectOf("Owner page");
  const after = await objectOf("After removal");
  // Control: the keys the newcomer held really open content from before the removal.
  await expect(decryptObject(keys.get(before.generation)!, cid, Uint8Array.from(before.bytes))).resolves.toMatchObject({ title: "Owner page" });
  // Forward secrecy: none of them opens content written after it.
  expect(keys.has(after.generation)).toBe(false);
  for (const key of keys.values()) await expect(decryptObject(key, cid, Uint8Array.from(after.bytes))).rejects.toThrow();

  // The newcomer no longer sees the team; the editor reads the new content with the new key.
  await newcomer.page.reload();
  await expect(newcomer.page.getByRole("button", { name: TEAM })).toHaveCount(0);
  await openTeam(editor.page);
  await readPage(editor.page, "After removal", ["after comment"]);
  await readPage(editor.page, "Owner page", ["owner comment"]);
});
```

Selectors follow the current UI (setup form labels, `Unlock KyNotes`, `Create user`, `Create team` prompt, `Team`/`Person` comboboxes, `.note-row`, `.title-input`, `Add a comment…`, `.member-row` Remove). If the UI moved, fix selectors only, never assertions.

- [ ] **Step 4: Run.** `npx --prefix web playwright install chromium` once, then, after Task 7's bundle sync: `npm run e2e --prefix web`. Expected: `1 passed`. The server serves `internal/web/dist`, so a stale bundle fails here first. Each run needs a fresh server (setup runs once per data dir); `--repeat-each` against one server is not meaningful.

- [ ] **Step 5: Visual pass (Playwright MCP, scratch server only).** At 1280×900 and 390×844 in Busnes Light and Dark: the key-wait line and the "not end-to-end shared yet" notice render inside the notebook header without overflow; Settings shows the fingerprint in `<code>` without overflowing its card at 390 px. Save screenshots next to the existing ones and add a "Team keys P3a" section to `UI-VERIFICATION.md` with capture conditions.

- [ ] **Step 6: CI.** In `.github/workflows/ci.yml` job `test`, after `- run: go test -race ./...`, add:

```yaml
      - name: Team keys in three real browsers
        run: |
          cd web
          npx playwright install --with-deps chromium
          npm run e2e
```

(The job already set up Node and Go and verified `internal/web/dist`; `publish` depends on `test`, so a failing browser run blocks publishing, matching `AGENTS.md`.)

- [ ] **Step 7: Commit.** `git add -A && git commit -m "web: three-browser team keys check in CI"`

### Task 9: Final verification

- [ ] **Step 1:** `go build ./... && go vet ./... && test -z "$(gofmt -l .)" && go test -race ./... && govulncheck ./...`
- [ ] **Step 2:** `cd web && npm test && npm run build && node src/ky-ui/check-vendor.mjs && cd .. && diff -qr web/dist internal/web/dist && npm run e2e --prefix web`
- [ ] **Step 3: Mutations.** From a clean tree, apply each alone, run the named test, confirm it fails, revert with `git checkout -- <file>` (rebuild and re-sync the bundle before an e2e mutation). Paste the failures into the PR.

| Mutation | Must fail |
|---|---|
| `teamkeys_routes.go`: `if scheme != keySchemeShared {` → `if false {` | `TestSharedContainerRefusesStaleClientWrites` |
| `putGenerationTx`: `if !held {` → `if false {` | `TestSharedGenerationIsMintedOnlyByRotation` |
| `putGenerationTx`: drop `requested < shared \|\|` | `TestStewardBackfillsSharedHistoryOnly` |
| `putGenerationTx`: `if shared == 0 {` → `if true {` | `TestStewardBackfillsSharedHistoryOnly` |
| `keyring.ts` `writeKey`: `return key && {…}` → `return { key: key ?? legacy, generation: container.keyGeneration }` | `keyring.test.ts` writes … only with the current key |
| `keyring.ts` `planSweep`: never-shared branch always `mint` | `keyring.test.ts` mints the first key only…; `keyService.test.ts` does not share… |
| `keyring.ts` `planSweep`: wrap only `generation === container.keyGeneration` | `keyring.test.ts` wraps every held generation…; `keyService.test.ts` re-mints … history |
| `keyService.ts`: `continue;` → `throw error;` | `keyService.test.ts` re-reads and re-plans once… |
| `keyService.ts`: skip `confirmChanged` | `keyService.test.ts` stops at a changed colleague key… |
| `main.tsx`: one personal-notebook write back to `legacyKeyRef(auth.authSecret)` | `keyring.test.ts` main.tsx key wiring |

Known survivor (record in the PR): removing the two `syncKeys` lines from `removeTeamMember` keeps the e2e green, because the owner's next write meets `409` and `rekeyQueued` re-mints. The immediate re-mint stays for child workspaces and for teams nobody writes to.

- [ ] **Step 4:** Open the PR with the `pull-request` skill, stacked on `feat/team-keys-p2` (PR #38). Body: resolved ambiguities, mutation evidence, the e2e result, docs left unchanged and why.
