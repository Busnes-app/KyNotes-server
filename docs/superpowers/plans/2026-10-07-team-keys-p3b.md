# Team Keys Phase 3b (Invitations, Membership Key Status, P2 Invitation Limits) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** People join team notebooks through a one-time invitation link. An invitation carries the team's current keys when the inviter can see the invitee's identity. Member lists show who holds a key. A member waiting for a key can ask an owner. Settings lists the colleague keys this browser trusts and re-trusts a changed one. The P2 invitation limits are closed on the server.

**Architecture:** The server work is four small route and storage changes in `internal/httpapi` and `internal/storage`:
- Accept reads the invitation inside its own transaction.
- One `admitMemberTx` admits members for both accept and the server-admin add route. It reactivates revoked rows and records `memberships.invited_by` (migration 0023). The removal rule reads that column.
- A per-user token bucket limits invitation creation.
- GC deletes the envelopes of expired invitations.

The web client gets pure helpers, each tested on its own:
- `invitations.ts`: link parse and format, a session-storage stash, and the key-request text.
- `keyring.ts`: `memberKeyStatus`.
- `keyService.ts`: `inviteWithKeys`, and `KeySync` now returns `members` and `envelopes`.
- `pins.ts`: `pinRows`.
- `stuckEdits.ts`: finds and exports unsent edits.
- `loadGate.ts`: lets only the newest notebook load finish.

Two Settings cards (`components/PinnedKeys.tsx` and `components/UnsentEdits.tsx`) use these helpers. `main.tsx` wires them in. The invite-time envelope format, the step-up and the server rules are the ones P2 shipped. Only the client starts using them.

**Tech Stack:** Go 1.26 (`net/http`, SQLite via `modernc`), TypeScript/React (Vite, vitest, fake-indexeddb), `@noble/curves`/`@noble/ciphers` (already pinned), `@playwright/test` 1.63.0 (already a devDependency).

**Spec:** `docs/superpowers/specs/2026-10-07-team-keys-design.md`: §3 (membership flows), §5, §6 (pins), §7 (P2 as built and its known limits, P3a as built and its parked N1, P3b), §8. Conventions follow `docs/superpowers/plans/2026-10-07-team-keys-p3a.md`.

**Evidence status:** this plan was **not** prototyped. The code blocks were written against `feat/team-keys-p3b` at `38a2a2b`, then amended against `9ee0c41` (P3a floors: `KeyFloor`, `guardContainer`, `keysAllowed`, `storePins` returning `PinsStored`); see `.superpowers/sdd/2026-10-07-team-keys-p3b/preflight.md`. None of them has been compiled or run. Each task's own test step is the first proof. If a block does not compile, fix the code and keep the test's assertions.

---

## Global Constraints

| Item | Exact value |
|---|---|
| Migration | `internal/storage/migrations/0023_membership_inviter.sql`: `ALTER TABLE memberships ADD COLUMN invited_by TEXT NOT NULL DEFAULT ''`. No backfill. `storage.migrate` refuses gaps (`migration versions are not contiguous`), so P3c's link-request table moves from `0023` to `0024` (spec edit in Task 11) |
| Accept | One `SELECT` inside the accept transaction: `id`, `token_hash`, `invitee_id = session user`, `status='pending'`, `expires_at > now` (RFC 3339 UTC strings, compared as text, as `GET /users/{id}/identity` already does). Any miss is `404 not_found`. The inviter must still be a live steward (unchanged). A live membership in the team scope is `409 already_exists`. The outer pre-transaction read is removed |
| Admission | `admitMemberTx(tx, cid, userID, role, invitedBy, now)` covers the team and its live child workspaces. It reactivates revoked rows (`role`, `created_at`, `revoked_at=''`, `invited_by`) and inserts any missing rows. Accept passes the inviter; the server-admin add route passes `''` |
| Removal | An owner may remove any non-owner (unchanged). An admin may remove a non-admin non-owner (unchanged), **or an admin whose `invited_by` is the caller** |
| Rate limit | `ratelimit.invitation_per_hour`, default `30`, env `KYNOTES_RATELIMIT_INVITATION_PER_HOUR`. Applies to `POST` on `/api/v1/containers/{id}/invitations` and its `/api/…` alias. Keyed by session user (IP without a session), refilled per hour. Over the limit: `429 rate_limited`, `Retry-After: 60`. `0` disables it, like the other limits |
| GC | Every `storage.RunGC` run executes `DELETE FROM invitation_envelopes WHERE invitation_id IN (SELECT id FROM invitations WHERE status='pending' AND expires_at<=now)`. Invitation rows stay |
| Invite link | `<origin>/#/invite/<inv_ID>/<token>`. The ID matches `inv_[0-9a-hjkmnp-tv-z]{26}`; the token is 43 base64url characters. On page load the link moves to `sessionStorage["kynotes-invitation"]` and leaves the address bar through `history.replaceState` |
| Invite-time keys | Only for a caller with an identity and a password session (`!auth.sso`). Target: the team container the user invited to, only. `kind`/`teamId` never choose which keys leave, so child workspaces get keys from the steward sweep after accept. The target's floor comes from `store.loadKeyState`: if `keysAllowed(team, floor)` is false, no keys are sent (`rollback`). A key is sealed only when `sharedGeneration > 0` and this browser holds the **current** generation. The invitee's identity comes from `GET /users/{id}/identity`. A changed pin is confirmed (decline: no keys). A first-seen pin goes through `store.addFresh` (`storePins`) before the step-up: `{ok:false}` with conflicts sends no keys (`untrusted`), and without conflicts (`pins-unsaved`). The step-up runs before `POST`. On `409 already_exists`, it retries once without keys (`moved`). Each of these outcomes still sends the invitation, without keys. Thrown errors (step-up, network, a malformed identity key) surface, and nothing is sent |
| Member status | `has-key` (identity holds an envelope at the current generation), `waiting`, `no-identity`. Labels: "has key", "waiting for key", "no encryption key yet". A never-shared notebook shows only `no-identity` |
| Pin re-trust | Settings re-trusts only a `changed` row, and only the exact key it displays, through `confirmFingerprintChange` → `storeConfirmedPin` (spec §6). Pins are never deleted here ("Forget this device" clears them all) |
| Unsent edits | Pending saves whose `containerID` is missing from a successful `GET /api/v1/containers`. Export decrypts with the legacy login key only (generation-0 edits). Discard requires a confirm |
| Error codes | No new codes |
| Unchanged (checked) | Envelope byte format v2, `insertInvitationEnvelopeTx`, `moveInvitationEnvelopesTx`, the identity-visibility SQL, `keyring.openKeyring`/`planSweep`/`sealFor`/`guardContainer`/`keysAllowed`, `storage.storePins` (`PinsStored`), `CanvasPage.tsx`, mobile/probe clients |
| Out of scope | Device linking and SSO identities (P3c), legacy-row migration (P4), pending uploads for lost notebooks, in-app key requests, an invite role picker (the UI keeps `editor`) |

## Resolved ambiguities (recorded in the spec in Task 11)

1. **How an invitee finds an invitation.** Today the token only reaches the inviter, in a toast. P3b uses a one-time link, `#/invite/<id>/<token>`, and adds no route. The token travels in the URL fragment, which browsers never send to a server. On load, the app moves the link into `sessionStorage` so it survives a single sign-on round trip, and removes it from the address bar and history. The server already binds the invitation to the invitee's account (`invitee_id`), so a leaked link is useless to anyone else. A list-my-invitations route was rejected: accept still needs the token, which the server stores only as a hash.
2. **"Let a server admin remove an admin it invited."** Server admins can already remove any non-owner through `DELETE /admin/teams/{id}/members/{userID}`. The P2 limit is about the team `admin` role: `collab_routes.go` refuses admin-on-admin removal. Rule: a team admin may remove another admin only when that admin's current membership came from the caller's invitation. The inviter is recorded per membership (`memberships.invited_by`). Rows from before the migration are not backfilled, so they fail closed and only the owner or a server admin removes them. Reading the inviter from the `invitations` table instead was rejected: once reactivation exists, the latest accepted invitation may not be what admitted the current row.
3. **Migration number.** P3b takes `0023` because it merges before P3c, and the runner requires contiguous versions. P3c's `0023_link_requests.sql` becomes `0024_link_requests.sql`.
4. **What re-admission restores.** It restores only what the new grant says: the new role and the new inviter. It restores no keys. The envelopes deleted at removal stay deleted; keys come from invitation envelopes or the steward sweep. Accept and the server-admin add route share `admitMemberTx`, because the `409` on a revoked row had the same root cause in both. Deleted child workspaces stay revoked.
5. **Expiry recheck.** The invitation is read once, inside the transaction, so one check exists and the test pins it. The previous outer read is deleted rather than duplicated.
6. **Expired invitation envelopes.** The hourly GC deletes them. The invitation rows stay as history, and accept already refuses them. Adding an `expired` status write was rejected: nothing reads it.
7. **Rate limit shape.** A config key, like every other limit (`ratelimit.invitation_per_hour`, default 30 per user per hour). The server cannot tell a probing caller from an honest one, so the bucket bounds the liveness signal rather than removing it. The residual limit is recorded.
8. **Invite-time scope.** Only the current generation of the team container the user invited to is sealed, and only when `keysAllowed` passes against this device's floor. Child workspaces are not sealed at invite time: the browser can name them only through the server's `teamId`, and a server that relabelled another notebook as a child would get its key handed to the invitee. Their keys arrive through the steward sweep after accept (`ponytail:`; upgrade path: a parent link the team key authenticates). `invitation_envelopes` accepts only the current generation (P2 rule 8), and the sweep backfills history after accept. The invitee's identity is visible only when the inviter already shares a live container with them (P2 rule 9). Strangers therefore always get a keyless invitation. The prompt says which case applied, and shows the sealed key's fingerprint so the inviter can compare it (TOFU, made visible).
9. **Asking a steward.** No server route. The waiting banner offers "Ask an owner". It copies a request naming the notebook's owners and admins and carrying the member's own fingerprint and the notebook link, for the member to send out of band. Notifications today carry only mentions, and a key-request notification would be a new table and route for a convenience.
10. **Member status is informational.** It is computed in the browser from the envelope list and the identity lookups, both of which come from the server. It never decides trust: `openKeyring` and the pins do.
11. **Colleague names in Settings.** Pins store user IDs only. Settings shows usernames seen in key passes this session, and falls back to the user ID. The vault record format is unchanged.
12. **N1 scope.** Settings lists queued **saves** for notebooks the server no longer lists. It lists nothing when the list cannot be fetched, so an outage never offers sendable work for deletion. Export opens only what the legacy key opens: generation-0 edits and pre-sharing rows. Edits sealed with a shared key this tab no longer holds are counted and left out. Pending uploads for lost notebooks are out of scope (`ponytail:`; upgrade path: the same card over `pendingUploads()`).
13. **Double-load race (root cause).** `loadContainer` decided "superseded" by comparing `loadingContainerID` with the container's ID. Two loads of the **same** notebook (an auto-load plus a click) therefore both believed they were current. The first load's `finally` cleared the flag. The second load then saw itself superseded and returned early, after it had already emptied the page list. Each `selectContainer` call now takes a ticket from `loadGate()`, and only the newest ticket may finish.
14. **Finding user IDs.** Non-admins have no directory, so Settings shows the user's own ID ("Team owners need it to invite you"). The invite prompt still asks for a user ID.
15. **Re-invited members receive history like any newcomer** (controller ruling: re-inviting is an explicit owner decision; withholding would hide team work). The steward sweep wraps every generation it holds for the re-admitted identity, including those minted while the member was away.

## Review Focus (likely failure modes and their pinning tests)

1. **Re-admission restores more than the new grant**: an old role, an old inviter, old envelopes, or a deleted child workspace. A reasonable person expects a fresh membership with the new role and no keys until a steward or the invitation supplies them. Pinned by `TestRemovedMemberIsReadmittedByReactivation`: role and row count, no envelopes, a live member is still `409`, and the server-admin add route behaves the same. Also pinned by `TestTeamAdminRemovesOnlyAdminsItInvited`, last step: the owner's re-invite makes the peer the owner's invitee.
2. **An expired invitation, or another account's, is accepted.** The expected result is `404`, with the invitation still pending and no membership created. Pinned by `TestAcceptChecksExpiryAndInviteeInsideItsTransaction`. Mutations: drop `expires_at>?`; drop `invitee_id=?`.
3. **Invite-time keys reach a substituted or unconfirmed key, or leave before the pin is kept or without a step-up.** Pinned by these `keyService.test.ts` tests:
   - "seals the team's current key for a visible invitee, pinned and stepped up first" (call order).
   - "asks before sealing for a changed invitee key; a decline sends no keys".
   - "never sends keys whose recipient pin this device could not keep".
   - "sends no keys when another pass pinned a different key for the invitee first" (`PinsStored` conflict).
   - "sends no keys for a team this device saw at a later sharing state, or saw shared and now reported personal" (`keysAllowed`).
4. **Clicking the notebook the app is still opening leaves an empty page list.** Pinned by `loadGate.test.ts` "lets only the newest load finish, even for the same notebook" and "decides superseded loads by ticket, never by notebook ID". The e2e step 6 smoke test also covers it.
5. **"Discard unsent edits" offers sendable work**, either while the notebook list is unreachable or for a notebook still listed. Pinned by `stuckEdits.test.ts` "are the queued edits of notebooks the server no longer lists, and none when the list is unknown".

Also check:
- `TestInvitationCreationIsRateLimitedPerCaller`: limited across containers and through the alias; other callers are unaffected; accept is never limited.
- `TestGCDeletesEnvelopesOfExpiredInvitations`.
- e2e step 4: the re-trust goes through `storeConfirmedPin`, so the later sweep opens no fingerprint dialog.

---

## File Map

| File | Change |
|---|---|
| `internal/httpapi/collab_routes.go` | Accept reads inside its transaction and calls `admitMemberTx`; the removal rule reads `invited_by` |
| `internal/httpapi/teamkeys_routes.go` | New `admitMemberTx` |
| `internal/httpapi/admin_routes.go` | `POST /admin/teams/{id}/members` uses `admitMemberTx` |
| `internal/httpapi/ratelimit.go`, `internal/config/config.go`, `kynotes.example.yaml` | `invitation_per_hour` bucket |
| `internal/storage/migrations/0023_membership_inviter.sql` | New |
| `internal/storage/gc.go` | Deletes envelopes of expired invitations |
| `internal/httpapi/teamkeys_p3b_test.go`, `internal/storage/gc_test.go` | New tests |
| `internal/httpapi/teamkeys_test.go` | Re-invite assertion `409` → `204` |
| `internal/httpapi/ratelimit_alias_test.go` | Invitation bucket test |
| `web/src/invitations.ts`, `invitations.test.ts` | New: links, stash, key-request text |
| `web/src/api.ts`, `api.test.ts` | `Invitation`, `inviteMember(…, envelopes)`, `acceptInvitation` |
| `web/src/keyring.ts`, `keyring.test.ts` | `InvitationEnvelope`, `memberKeyStatus` |
| `web/src/keyService.ts`, `keyService.test.ts` | `KeySync.members/envelopes`, `inviteWithKeys` |
| `web/src/pins.ts`, `pins.test.ts` | `pinRows` |
| `web/src/stuckEdits.ts`, `stuckEdits.test.ts` | New |
| `web/src/loadGate.ts`, `loadGate.test.ts` | New |
| `web/src/components/PinnedKeys.tsx`, `UnsentEdits.tsx` | New Settings cards |
| `web/src/main.tsx`, `web/src/styles.css` | Wiring, banner, status, Settings, `.pin-row` |
| `web/e2e/team-keys.e2e.ts` | P3b steps |
| `internal/web/dist/` | Regenerated bundle |
| `DESIGN.md`, `IMPLEMENTATION_PLAN.md` | Changed in the server tasks that change contracts (1–4) |
| The spec, `AGENTS.md`, `CHANGELOG.md`, `UI-VERIFICATION.md` | Tasks 11–12 |

## Interfaces

```go
// internal/httpapi/teamkeys_routes.go
// Task 1: admitMemberTx(tx *sql.Tx, cid, userID, role, now string) error
// Task 2 (final):
func admitMemberTx(tx *sql.Tx, cid, userID, role, invitedBy, now string) error // errMembershipExists when a row in scope is live

// internal/config/config.go
type RateLimit struct { LoginPerMinute, PairingPerHour, UploadPerMinute, InvitationPerHour int } // yaml invitation_per_hour
```

```ts
// api.ts
export type Invitation = { id: string; token: string; expiresAt: string };
export function inviteMember(containerID: string, inviteeID: string, role: string, envelopes?: InvitationEnvelope[]): Promise<Invitation>;
export const acceptInvitation: (id: string, token: string) => Promise<void>;

// invitations.ts
export type InviteLink = { id: string; token: string };
export const inviteLink: (origin: string, invitation: InviteLink) => string;
export function parseInviteLink(hash: string): InviteLink | undefined;
export function stashInviteLink(location: Pick<Location, "hash" | "pathname">, history: Pick<History, "replaceState">, storage: Pick<Storage, "setItem">): boolean;
export function stashedInvite(storage: Pick<Storage, "getItem">): InviteLink | undefined;
export const clearStashedInvite: (storage: Pick<Storage, "removeItem">) => void;
export function keyRequestText(input: { notebook: string; stewards: string[]; fingerprint: string; link: string }): string;

// keyring.ts
export type InvitationEnvelope = Envelope & { containerId: string };
export type MemberKeyStatus = "has-key" | "waiting" | "no-identity";
export function memberKeyStatus(container: KeyedContainer, members: MemberKey[], envelopes: Envelope[]): Record<string, MemberKeyStatus>;

// keyService.ts
export type KeySync = { /* P3a fields */ members: MemberKey[]; envelopes: Envelope[] };
export type InviteAPI = Pick<KeyAPI, "userIdentity" | "stepUp"> & { invite: (containerID: string, inviteeID: string, role: string, envelopes: InvitationEnvelope[]) => Promise<Invitation> };
export type InviteKeys = "sealed" | "cannot-wrap" | "rollback" | "no-keys" | "no-identity" | "untrusted" | "pins-unsaved" | "moved";
export type Invited = { invitation: Invitation; keys: InviteKeys; recipient?: MemberKey };
export type InviteTarget = { container: ReportedContainer; ring: Keyring };
export function inviteWithKeys(api: InviteAPI, target: InviteTarget, invitee: Member, caller: Caller, store: PinStore, confirmChanged: (changes: PinChange[]) => boolean | Promise<boolean>): Promise<Invited>;

// pins.ts
export type PinRow = { userId: string; pinned: string; current?: string; state: "same" | "changed" | "unseen" };
export function pinRows(pins: Pins, current: Record<string, string | undefined>): PinRow[];

// stuckEdits.ts
export function stuckSaves(queued: PendingSave[], live: ReadonlySet<string> | undefined): PendingSave[];
export function exportUnsent(items: PendingSave[], open: (item: PendingSave) => Promise<unknown>): Promise<{ json: string; unreadable: number }>;

// loadGate.ts
export function loadGate(): { begin(): { superseded: () => boolean } };

// components
export function PinnedKeys(props: { username: string; userID: string; names: Record<string, string> }): JSX.Element;
export function UnsentEdits(props: { legacyKey: KeyRef }): JSX.Element | null;
```

---

### Task 1: Server: accept reads the invitation inside its transaction; removed members are re-admitted

**Files:** Modify `internal/httpapi/collab_routes.go`, `internal/httpapi/teamkeys_routes.go`, `internal/httpapi/admin_routes.go`, `internal/httpapi/teamkeys_test.go`, `DESIGN.md`, `IMPLEMENTATION_PLAN.md`. Create `internal/httpapi/teamkeys_p3b_test.go`.

**Interfaces:**
- Consumes: the test helpers `newTeam`, `invite` (role `admin`), `accept`, `status`, `quote` and `pairUser`, and the `member` type.
- Produces: `admitMemberTx(tx *sql.Tx, cid, userID, role, now string) error`. Task 2 adds `invitedBy`.

- [ ] **Step 1: Write the failing tests.** Create `internal/httpapi/teamkeys_p3b_test.go`:

```go
package httpapi

import (
	"net/http"
	"testing"
	"time"
)

// livesOf returns userID's live and total membership rows, and its live role in cid.
func livesOf(t *testing.T, tm team, userID, cid string) (live, rows int, role string) {
	t.Helper()
	if err := tm.owner.db.QueryRow(`SELECT (SELECT COUNT(*) FROM memberships WHERE user_id=?1 AND revoked_at=''),(SELECT COUNT(*) FROM memberships WHERE user_id=?1),COALESCE((SELECT role FROM memberships WHERE user_id=?1 AND container_id=?2 AND revoked_at=''),'')`, userID, cid).Scan(&live, &rows, &role); err != nil {
		t.Fatal(err)
	}
	return
}

func TestAcceptChecksExpiryAndInviteeInsideItsTransaction(t *testing.T) {
	tm := newTeam(t)
	guest, other := tm.owner.addUser(t, "guest"), tm.owner.addUser(t, "other")
	inv, code := invite(t, tm.owner, tm.id, guest.id)
	if code != http.StatusOK {
		t.Fatalf("invite=%d", code)
	}
	if code := accept(t, other.pairClient, inv); code != http.StatusNotFound {
		t.Fatalf("another account accepted the invitation: %d", code)
	}
	if _, err := tm.owner.db.Exec(`UPDATE invitations SET expires_at=? WHERE id=?`, time.Now().UTC().Add(-time.Second).Format(time.RFC3339), inv[0]); err != nil {
		t.Fatal(err)
	}
	if code := accept(t, guest.pairClient, inv); code != http.StatusNotFound {
		t.Fatalf("accepted an expired invitation: %d", code)
	}
	var state string
	if err := tm.owner.db.QueryRow(`SELECT status FROM invitations WHERE id=?`, inv[0]).Scan(&state); err != nil || state != "pending" {
		t.Fatalf("invitation status=%q %v", state, err)
	}
	for _, u := range []member{guest, other} {
		if live, rows, _ := livesOf(t, tm, u.id, tm.id); live != 0 || rows != 0 {
			t.Fatalf("%s: live=%d rows=%d", u.id, live, rows)
		}
	}
}

func TestRemovedMemberIsReadmittedByReactivation(t *testing.T) {
	tm := newTeam(t)
	if code, out := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id+"/members/"+tm.editor.id, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("remove=%d %s", code, out)
	}
	inv, _ := invite(t, tm.owner, tm.id, tm.editor.id) // role admin
	if code := accept(t, tm.editor.pairClient, inv); code != http.StatusNoContent {
		t.Fatalf("re-invited former member=%d", code)
	}
	if live, rows, role := livesOf(t, tm, tm.editor.id, tm.id); live != 2 || rows != 2 || role != "admin" {
		t.Fatalf("live=%d rows=%d role=%q; want team and child live as admin, no new rows", live, rows, role)
	}
	var envelopes int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM key_envelopes WHERE device_id=?`, tm.editorID).Scan(&envelopes); err != nil || envelopes != 0 {
		t.Fatalf("re-admission restored envelopes: %d %v", envelopes, err)
	}
	again, _ := invite(t, tm.owner, tm.id, tm.editor.id)
	if code := accept(t, tm.editor.pairClient, again); code != http.StatusConflict {
		t.Fatalf("live member accepted again: %d", code)
	}
	// The server-admin add route re-admits the same way.
	if code, out := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id+"/members/"+tm.viewer.id, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("remove viewer=%d %s", code, out)
	}
	if _, err := tm.owner.db.Exec(`UPDATE users SET role='admin' WHERE id=?`, pairUser); err != nil {
		t.Fatal(err)
	}
	add := func() int {
		code, _ := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/admin/teams/"+tm.id+"/members", []byte(`{"userId":`+quote(tm.viewer.id)+`,"role":"commenter"}`), true, false))
		return code
	}
	if code := add(); code != http.StatusNoContent {
		t.Fatalf("admin re-add=%d", code)
	}
	if live, rows, role := livesOf(t, tm, tm.viewer.id, tm.id); live != 2 || rows != 2 || role != "commenter" {
		t.Fatalf("admin re-add: live=%d rows=%d role=%q", live, rows, role)
	}
	if code := add(); code != http.StatusConflict {
		t.Fatalf("admin add of a live member=%d", code)
	}
}
```

In `teamkeys_test.go` `TestCollaboratorRemovalRulesAndAcceptOutcomes`, replace the last block:

```go
	again, _ := invite(t, tm.owner, tm.id, tm.viewer.id)
	if code := accept(t, tm.viewer.pairClient, again); code != http.StatusConflict {
		t.Fatalf("re-invited former member=%d", code)
	}
```

with:

```go
	again, _ := invite(t, tm.owner, tm.id, tm.viewer.id)
	if code := accept(t, tm.viewer.pairClient, again); code != http.StatusNoContent {
		t.Fatalf("re-invited former member=%d", code)
	}
```

- [ ] **Step 2: Run them and watch them fail.** Run `go test ./internal/httpapi -run 'TestAcceptChecksExpiryAndInviteeInsideItsTransaction|TestRemovedMemberIsReadmittedByReactivation|TestCollaboratorRemovalRulesAndAcceptOutcomes' -count=1`. Expected: `TestRemovedMemberIsReadmittedByReactivation` fails with `re-invited former member=409`, and the collaborator test fails the same way. The expiry test passes today because of the outer pre-read; Step 3 moves that check into the transaction, and Task 13's mutation proves the new check is the one holding.

- [ ] **Step 3: Add `admitMemberTx`.** In `teamkeys_routes.go`, after `removeMemberTx`:

```go
// admitMemberTx makes userID a member of cid and its live child workspaces with
// role. Rows a removal revoked are reactivated (the unique index keeps one row
// per container and user) and keep no keys; errMembershipExists when any row in
// the team scope is live.
func admitMemberTx(tx *sql.Tx, cid, userID, role, now string) error {
	var live int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM memberships WHERE user_id=?1 AND revoked_at='' AND container_id IN (SELECT id FROM containers WHERE id=?2 OR team_id=?2)`, userID, cid).Scan(&live); err != nil {
		return err
	}
	if live > 0 {
		return errMembershipExists
	}
	const scope = `(SELECT id FROM containers WHERE (id=?2 OR team_id=?2) AND deleted_at='')`
	for _, q := range []string{
		`UPDATE memberships SET role=?3,created_at=?4,revoked_at='' WHERE user_id=?1 AND container_id IN ` + scope,
		`INSERT INTO memberships(id,container_id,user_id,role,created_at) SELECT 'mem_' || lower(hex(randomblob(12))),c.id,?1,?3,?4 FROM containers c WHERE c.id IN ` + scope + ` AND NOT EXISTS(SELECT 1 FROM memberships m WHERE m.container_id=c.id AND m.user_id=?1)`,
	} {
		if _, err := tx.Exec(q, userID, cid, role, now); err != nil {
			return err
		}
	}
	return nil
}
```

- [ ] **Step 4: Accept in one transaction.** In `collab_routes.go` `POST /api/v1/invitations/{id}/accept`, replace everything from `sum := sha256.Sum256([]byte(in.Token))` through the closing `})` of its `dbTx` call with:

```go
		sum := sha256.Sum256([]byte(in.Token))
		id, tokenHash := r.PathValue("id"), hex.EncodeToString(sum[:])
		e := dbTx(db, func(tx *sql.Tx) error {
			now := time.Now().UTC().Format(time.RFC3339)
			// One read, in the transaction that consumes it: invitee, status and expiry cannot change before the update.
			var cid, inviter, role string
			if e := tx.QueryRow(`SELECT container_id,inviter_id,role FROM invitations WHERE id=? AND token_hash=? AND invitee_id=? AND status='pending' AND expires_at>?`, id, tokenHash, s.UserID, now).Scan(&cid, &inviter, &role); e != nil {
				return e
			}
			if _, e := tx.Exec(`UPDATE invitations SET status='accepted',responded_at=? WHERE id=?`, now, id); e != nil {
				return e
			}
			// The inviter must still be a live steward of a live container.
			var steward int
			if e := tx.QueryRow(`SELECT COUNT(*) FROM memberships m JOIN containers c ON c.id=m.container_id AND c.deleted_at='' JOIN users u ON u.id=m.user_id AND u.status='active' WHERE m.container_id=? AND m.user_id=? AND m.revoked_at='' AND m.role IN ('owner','admin')`, cid, inviter).Scan(&steward); e != nil {
				return e
			}
			if steward == 0 {
				return sql.ErrNoRows
			}
			if e := admitMemberTx(tx, cid, s.UserID, role, now); e != nil {
				return e
			}
			return moveInvitationEnvelopesTx(tx, id, s.UserID, now)
		})
```

The `errors.Is(e, errMembershipExists)` → `409` and `writeTeamKeyError` lines after it stay. `sql.ErrNoRows` maps to `404`. The transaction is `BEGIN IMMEDIATE` (`_txlock=immediate`), so the read and the update are serialized.

- [ ] **Step 5: The server-admin add route admits the same way.** In `admin_routes.go` `POST /api/v1/admin/teams/{id}/members`, replace from `membershipID, _ := ids.Mint("mem")` through the closing `}` of `if err := dbTx(...); err != nil { ... }` with:

```go
		cid := r.PathValue("id")
		now := time.Now().UTC().Format(time.RFC3339)
		if err := dbTx(db, func(tx *sql.Tx) error {
			var ok bool
			if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM containers WHERE id=? AND kind='team' AND deleted_at='') AND EXISTS(SELECT 1 FROM users WHERE id=? AND status='active')`, cid, in.UserID).Scan(&ok); err != nil {
				return err
			}
			if !ok {
				return sql.ErrNoRows
			}
			return admitMemberTx(tx, cid, in.UserID, in.Role, now)
		}); err != nil {
			WriteError(w, r, 409, "already_exists", "unable to add member")
			return
		}
```

(Before this change, an unknown team or user returned `204` and inserted nothing. It now returns the route's existing `409`.)

- [ ] **Step 6: Run the tests.** Run `go test ./internal/httpapi -count=1 && go vet ./... && test -z "$(gofmt -l .)"`. Expected: PASS.

- [ ] **Step 7: Contracts.**

In `IMPLEMENTATION_PLAN.md` §9, replace:

```
  envelopes still at their generation and drops the rest. A consumed or void
  invitation is `404`; an existing membership row anywhere in the team scope
  is `409`.
```

with:

```
  envelopes still at their generation and drops the rest. The invitation is
  read inside that transaction: a consumed, expired, void or other account's
  invitation is `404`. A live membership anywhere in the team scope is `409`;
  rows a removal revoked are reactivated with the invitation's role and no keys.
  The server-admin add route admits the same way (`admitMemberTx`).
```

Replace the whole `* **Known limits** (P2): …` paragraph with:

```
* **Known limits** (P2): creating a team invitation to a known user ID reveals
  whether that user is active (invitation creation is not rate-limited);
  invitations may be created without envelopes, and the new member cannot
  write until a steward's sweep supplies them; an admin may invite a peer
  as admin and then cannot remove them; envelopes of expired, never-accepted
  invitations persist until the invitation row is deleted.
```

In the §9 test list, after `- \`TestInvitationsDieWithTheirStewardship\``, add `- \`TestAcceptChecksExpiryAndInviteeInsideItsTransaction\`` and `- \`TestRemovedMemberIsReadmittedByReactivation\``.

In `DESIGN.md` §Teams and revocation limits, after "is still an owner or admin of the live container.", add: "Accepting checks the invitation's invitee and expiry inside that transaction. A member who was removed is admitted again by reactivating their revoked membership, with the new role and no keys."

- [ ] **Step 8: Commit.**

```bash
git add internal/httpapi DESIGN.md IMPLEMENTATION_PLAN.md
git commit -m "httpapi: accept reads its invitation in the transaction; re-admit removed members"
```

### Task 2: Server: `memberships.invited_by` (migration 0023); a team admin removes the admins it invited

**Files:** Create `internal/storage/migrations/0023_membership_inviter.sql`. Modify `internal/httpapi/teamkeys_routes.go`, `collab_routes.go`, `admin_routes.go`, `teamkeys_p3b_test.go`, `DESIGN.md`, `IMPLEMENTATION_PLAN.md`.

**Interfaces:**
- Consumes: `admitMemberTx` from Task 1, and `livesOf`.
- Produces: `admitMemberTx(tx *sql.Tx, cid, userID, role, invitedBy, now string) error`.

- [ ] **Step 1: Write the failing test.** Append to `teamkeys_p3b_test.go`:

```go
func TestTeamAdminRemovesOnlyAdminsItInvited(t *testing.T) {
	tm := newTeam(t)
	peer, other := tm.owner.addUser(t, "peer"), tm.owner.addUser(t, "other")
	remove := func(by *pairClient, target string) int {
		code, _ := status(t, by.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id+"/members/"+target, nil, true, false))
		return code
	}
	join := func(by *pairClient, u member) {
		t.Helper()
		inv, code := invite(t, by, tm.id, u.id) // role admin
		if code != http.StatusOK {
			t.Fatalf("invite %s=%d", u.id, code)
		}
		if code := accept(t, u.pairClient, inv); code != http.StatusNoContent {
			t.Fatalf("accept %s=%d", u.id, code)
		}
	}
	join(tm.admin.pairClient, peer)
	join(tm.owner, other)
	if code := remove(tm.admin.pairClient, other.id); code != http.StatusForbidden {
		t.Fatalf("admin removed the owner's invitee: %d", code)
	}
	if code := remove(peer.pairClient, tm.admin.id); code != http.StatusForbidden {
		t.Fatalf("invited admin removed an admin it did not invite: %d", code)
	}
	if code := remove(tm.admin.pairClient, peer.id); code != http.StatusNoContent {
		t.Fatalf("admin could not remove the admin it invited: %d", code)
	}
	var audits int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='container.member_remove' AND object_id=? AND actor_user_id=?`, peer.id, tm.admin.id).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("audits=%d %v", audits, err)
	}
	// Re-admitted by the owner, the peer is the owner's invitee now.
	join(tm.owner, peer)
	var invitedBy string
	if err := tm.owner.db.QueryRow(`SELECT invited_by FROM memberships WHERE container_id=? AND user_id=?`, tm.id, peer.id).Scan(&invitedBy); err != nil || invitedBy != pairUser {
		t.Fatalf("invited_by=%q %v", invitedBy, err)
	}
	if code := remove(tm.admin.pairClient, peer.id); code != http.StatusForbidden {
		t.Fatalf("admin removed an admin the owner re-invited: %d", code)
	}
}
```

- [ ] **Step 2: Run it and watch it fail.** Run `go test ./internal/httpapi -run TestTeamAdminRemovesOnlyAdminsItInvited -count=1`. Expected: FAIL with `admin could not remove the admin it invited: 403`.

- [ ] **Step 3: Migration.** Create `internal/storage/migrations/0023_membership_inviter.sql`:

```sql
-- The steward whose invitation admitted the current membership; '' for owners,
-- server-admin adds and memberships older than this column (not backfilled: those
-- admins stay removable by owners and server admins only).
ALTER TABLE memberships ADD COLUMN invited_by TEXT NOT NULL DEFAULT '';
```

- [ ] **Step 4: Record the inviter.** Replace `admitMemberTx` in `teamkeys_routes.go` with:

```go
// admitMemberTx makes userID a member of cid and its live child workspaces with
// role, recording invitedBy ('' for a server-admin add). Rows a removal revoked
// are reactivated (the unique index keeps one row per container and user) and
// keep no keys; errMembershipExists when any row in the team scope is live.
func admitMemberTx(tx *sql.Tx, cid, userID, role, invitedBy, now string) error {
	var live int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM memberships WHERE user_id=?1 AND revoked_at='' AND container_id IN (SELECT id FROM containers WHERE id=?2 OR team_id=?2)`, userID, cid).Scan(&live); err != nil {
		return err
	}
	if live > 0 {
		return errMembershipExists
	}
	const scope = `(SELECT id FROM containers WHERE (id=?2 OR team_id=?2) AND deleted_at='')`
	for _, q := range []string{
		`UPDATE memberships SET role=?3,created_at=?4,revoked_at='',invited_by=?5 WHERE user_id=?1 AND container_id IN ` + scope,
		`INSERT INTO memberships(id,container_id,user_id,role,created_at,invited_by) SELECT 'mem_' || lower(hex(randomblob(12))),c.id,?1,?3,?4,?5 FROM containers c WHERE c.id IN ` + scope + ` AND NOT EXISTS(SELECT 1 FROM memberships m WHERE m.container_id=c.id AND m.user_id=?1)`,
	} {
		if _, err := tx.Exec(q, userID, cid, role, now, invitedBy); err != nil {
			return err
		}
	}
	return nil
}
```

In `collab_routes.go` accept, change `admitMemberTx(tx, cid, s.UserID, role, now)` to `admitMemberTx(tx, cid, s.UserID, role, inviter, now)`. In `admin_routes.go`, change `admitMemberTx(tx, cid, in.UserID, in.Role, now)` to `admitMemberTx(tx, cid, in.UserID, in.Role, "", now)`.

- [ ] **Step 5: The removal rule.** In `collab_routes.go` `DELETE /api/v1/containers/{id}/members/{userID}`, replace inside the `dbTx` closure:

```go
			var role, targetRole string
			if tx.QueryRow(`SELECT role FROM memberships WHERE container_id=? AND user_id=? AND revoked_at=''`, cid, s.UserID).Scan(&role) != nil || !isSteward(role) {
				return errInsufficientRole
			}
			if tx.QueryRow(`SELECT role FROM memberships WHERE container_id=? AND user_id=? AND revoked_at=''`, cid, target).Scan(&targetRole) != nil || targetRole == "owner" || (role == "admin" && targetRole == "admin") {
				return errInsufficientRole
			}
```

with:

```go
			var role, targetRole, invitedBy string
			if tx.QueryRow(`SELECT role FROM memberships WHERE container_id=? AND user_id=? AND revoked_at=''`, cid, s.UserID).Scan(&role) != nil || !isSteward(role) {
				return errInsufficientRole
			}
			// An admin removes another admin only when its own invitation admitted that membership.
			if tx.QueryRow(`SELECT role,invited_by FROM memberships WHERE container_id=? AND user_id=? AND revoked_at=''`, cid, target).Scan(&targetRole, &invitedBy) != nil || targetRole == "owner" || (role == "admin" && targetRole == "admin" && invitedBy != s.UserID) {
				return errInsufficientRole
			}
```

- [ ] **Step 6: Run the tests.** Run `go test ./internal/httpapi ./internal/storage -count=1 && go vet ./... && test -z "$(gofmt -l .)"`. Expected: PASS. `TestCollaboratorRemovalRulesAndAcceptOutcomes` still sees `403` for an admin seeded directly (empty `invited_by`).

- [ ] **Step 7: Contracts.**

In `IMPLEMENTATION_PLAN.md` §3, inside the `memberships` SQL block, after `CREATE INDEX idx_memberships_user ON memberships(user_id);`, add `-- Migration 0023 adds invited_by TEXT NOT NULL DEFAULT '': the inviter of the current membership ('' for owners, server-admin adds and older rows).`.

In §9, replace "an admin cannot remove an admin or an owner." with "an admin cannot remove an owner, nor an admin whose current membership it did not invite (`memberships.invited_by`)."

Replace the Known limits (P2) paragraph with:

```
* **Known limits** (P2): creating a team invitation to a known user ID reveals
  whether that user is active (invitation creation is not rate-limited);
  invitations may be created without envelopes, and the new member cannot
  write until a steward's sweep supplies them; envelopes of expired,
  never-accepted invitations persist until the invitation row is deleted.
```

Add `- \`TestTeamAdminRemovesOnlyAdminsItInvited\`` to the §9 test list.

In `DESIGN.md` §Teams and revocation limits, after the sentence Task 1 added, add: "A team admin may remove another admin only when its own invitation admitted that admin's current membership; owners and server administrators may remove any non-owner."

- [ ] **Step 8: Commit.**

```bash
git add internal DESIGN.md IMPLEMENTATION_PLAN.md
git commit -m "httpapi: record who invited a membership; an admin removes the admins it invited"
```

### Task 3: Server: rate-limit invitation creation

**Files:** Modify `internal/config/config.go`, `internal/httpapi/ratelimit.go`, `internal/httpapi/ratelimit_alias_test.go`, `kynotes.example.yaml`, `IMPLEMENTATION_PLAN.md`, `DESIGN.md`.

**Interfaces:**
- Produces: `config.RateLimit.InvitationPerHour int` (yaml `invitation_per_hour`).

- [ ] **Step 1: Write the failing test.** Append to `ratelimit_alias_test.go`:

```go
func TestInvitationCreationIsRateLimitedPerCaller(t *testing.T) {
	cfg := config.Defaults()
	if cfg.RateLimit.InvitationPerHour != 30 {
		t.Fatalf("default invitation_per_hour=%d, want 30", cfg.RateLimit.InvitationPerHour)
	}
	cfg.RateLimit.InvitationPerHour = 2
	h := rateLimitMiddleware(cfg, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	call := func(method, path, ip string) int {
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = ip
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	const team = "/api/v1/containers/cnt_aaaaaaaaaaaaaaaaaaaaaaaaaa/invitations"
	for i := 0; i < 2; i++ {
		if got := call(http.MethodPost, team, "203.0.113.20:1"); got != http.StatusOK {
			t.Fatalf("invitation %d=%d", i, got)
		}
	}
	for _, path := range []string{"/api/v1/containers/cnt_bbbbbbbbbbbbbbbbbbbbbbbbbb/invitations", "/api/containers/cnt_aaaaaaaaaaaaaaaaaaaaaaaaaa/invitations"} {
		if got := call(http.MethodPost, path, "203.0.113.20:1"); got != http.StatusTooManyRequests {
			t.Fatalf("%s after the bucket was spent=%d, want 429", path, got)
		}
	}
	if got := call(http.MethodPost, team, "203.0.113.21:1"); got != http.StatusOK {
		t.Fatalf("another caller=%d", got)
	}
	if got := call(http.MethodPost, "/api/v1/invitations/inv_aaaaaaaaaaaaaaaaaaaaaaaaaa/accept", "203.0.113.20:1"); got != http.StatusOK {
		t.Fatalf("accept was limited: %d", got)
	}
}
```

(`TestRateLimitStillUsesAuthenticatedUserAcrossIPs` already proves that a session keys the bucket by user, for every label other than `login` and `oidc`.)

- [ ] **Step 2: Run it and watch it fail.** Run `go test ./internal/httpapi -run TestInvitationCreationIsRateLimitedPerCaller -count=1`. Expected: a compile failure on `InvitationPerHour`.

- [ ] **Step 3: Config.** In `config.go`:

```go
type RateLimit struct {
	LoginPerMinute    int `yaml:"login_per_minute"`
	PairingPerHour    int `yaml:"pairing_per_hour"`
	UploadPerMinute   int `yaml:"upload_per_minute"`
	InvitationPerHour int `yaml:"invitation_per_hour"`
}
```

In `Defaults()`, change `RateLimit: RateLimit{LoginPerMinute: 10, PairingPerHour: 20, UploadPerMinute: 60}` to `RateLimit: RateLimit{LoginPerMinute: 10, PairingPerHour: 20, UploadPerMinute: 60, InvitationPerHour: 30}`. After the `KYNOTES_RATELIMIT_UPLOAD_PER_MINUTE` block, add:

```go
	if v := os.Getenv("KYNOTES_RATELIMIT_INVITATION_PER_HOUR"); v != "" {
		c.RateLimit.InvitationPerHour, _ = strconv.Atoi(v)
	}
```

- [ ] **Step 4: Middleware.** In `ratelimit.go`, add a case before the upload case:

```go
		case r.Method == http.MethodPost && strings.HasPrefix(path, "/api/v1/containers/") && strings.HasSuffix(path, "/invitations"):
			// Bounds how fast one account can learn whether user IDs are live by inviting them.
			limit, rate, label = cfg.RateLimit.InvitationPerHour, cfg.RateLimit.InvitationPerHour, "invitation"
```

Then change `if label == "pairing" {` to `if label == "pairing" || label == "invitation" {`.

- [ ] **Step 5: Run the tests.** Run `go test ./internal/httpapi ./internal/config -count=1 && go vet ./... && test -z "$(gofmt -l .)"`. Expected: PASS.

- [ ] **Step 6: Contracts.**
  - `kynotes.example.yaml`: after `upload_per_minute: 60`, add `  invitation_per_hour: 30`.
  - `IMPLEMENTATION_PLAN.md`: in the config block, after `  upload_per_minute: 60`, add `  invitation_per_hour: 30`. In §10, replace "uploads `ratelimit.upload_per_minute` per user. Exceeding returns" with "uploads `ratelimit.upload_per_minute` per user, invitation creation `ratelimit.invitation_per_hour` per user. Exceeding returns". Replace the Known limits (P2) paragraph with:

```
* **Known limits** (P2): creating a team invitation to a known user ID reveals
  whether that user is active, at most `ratelimit.invitation_per_hour` times an
  hour per account; invitations may be created without envelopes, and the new
  member cannot write until a steward's sweep supplies them; envelopes of
  expired, never-accepted invitations persist until the invitation row is deleted.
```

  - `IMPLEMENTATION_PLAN.md`: add `- \`TestInvitationCreationIsRateLimitedPerCaller\`` to the §9 test list.
  - `DESIGN.md` §Teams: after Task 2's sentence, add "Invitation creation is rate-limited per account."

- [ ] **Step 7: Commit.**

```bash
git add internal kynotes.example.yaml DESIGN.md IMPLEMENTATION_PLAN.md
git commit -m "httpapi: rate-limit invitation creation per account"
```

### Task 4: Server: GC deletes envelopes of expired invitations

**Files:** Modify `internal/storage/gc.go`, `IMPLEMENTATION_PLAN.md`, `DESIGN.md`. Create `internal/storage/gc_test.go`.

- [ ] **Step 1: Write the failing test.** Create `internal/storage/gc_test.go`:

```go
package storage

import (
	"path/filepath"
	"testing"
	"time"
)

func TestGCDeletesEnvelopesOfExpiredInvitations(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	db := s.DB()
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	stamp := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES('usr_a','a','h','s',100000,'now','now'),('usr_b','b','h','s',100000,'now','now')`)
	exec(`INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at) VALUES('cnt_t','team','usr_a','now','now')`)
	exec(`INSERT INTO devices(id,user_id,public_key,fingerprint,secret_hash,platform,created_at) VALUES('dev_b','usr_b','pk','fp','x','identity','now')`)
	for id, expires := range map[string]string{"inv_old": stamp(-time.Minute), "inv_live": stamp(time.Hour)} {
		exec(`INSERT INTO invitations(id,container_id,inviter_id,invitee_id,token_hash,role,created_at,expires_at) VALUES(?,'cnt_t','usr_a','usr_b',?,'editor','now',?)`, id, "hash-"+id, expires)
		exec(`INSERT INTO invitation_envelopes(invitation_id,container_id,device_id,key_generation,alg,envelope) VALUES(?,'cnt_t','dev_b',1,'x25519-hkdf-sha256-chacha20poly1305',x'01')`, id)
	}
	if _, err := RunGC(db, nil, now, time.Hour, false); err != nil {
		t.Fatal(err)
	}
	var left []string
	rows, err := db.Query(`SELECT invitation_id FROM invitation_envelopes`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		left = append(left, id)
	}
	rows.Close()
	if len(left) != 1 || left[0] != "inv_live" {
		t.Fatalf("envelopes left=%v, want only inv_live", left)
	}
	var invitations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM invitations`).Scan(&invitations); err != nil || invitations != 2 {
		t.Fatalf("GC deleted invitation rows: %d %v", invitations, err)
	}
}
```

- [ ] **Step 2: Run it and watch it fail.** Run `go test ./internal/storage -run TestGCDeletesEnvelopesOfExpiredInvitations -count=1`. Expected: FAIL with `envelopes left=[inv_live inv_old]` (in either order).

- [ ] **Step 3: Implement.** In `gc.go`, after the `idempotency_keys` delete, add:

```go
	// An expired invitation can never be accepted; its envelopes are dead weight.
	_, _ = db.Exec(`DELETE FROM invitation_envelopes WHERE invitation_id IN (SELECT id FROM invitations WHERE status='pending' AND expires_at<=?)`, now.UTC().Format(time.RFC3339))
```

- [ ] **Step 4: Run the tests.** Run `go test ./internal/storage -count=1 && go vet ./... && test -z "$(gofmt -l .)"`. Expected: PASS.

- [ ] **Step 5: Contracts.** In `IMPLEMENTATION_PLAN.md` §9, replace the Known limits (P2) paragraph with the final P3b version:

```
* **Known limits** (P2, narrowed in P3b): creating a team invitation to a known
  user ID reveals whether that user is active, at most
  `ratelimit.invitation_per_hour` times an hour per account; invitations may be
  created without envelopes, and the new member cannot write until a steward's
  sweep supplies them; envelopes of an expired invitation remain until the next
  GC run.
```

Add `- \`TestGCDeletesEnvelopesOfExpiredInvitations\`` to the §9 test list. In `DESIGN.md` §Teams, after Task 3's sentence, add "Envelopes of expired invitations are deleted by the periodic garbage collection."

- [ ] **Step 6: Commit.**

```bash
git add internal/storage DESIGN.md IMPLEMENTATION_PLAN.md
git commit -m "storage: GC deletes envelopes of expired invitations"
```

### Task 5: Web: invitation links and API calls

**Files:** Create `web/src/invitations.ts`, `web/src/invitations.test.ts`. Modify `web/src/api.ts`, `web/src/api.test.ts`, `web/src/keyring.ts`.

**Interfaces:**
- Produces: `Invitation`, `inviteMember(…, envelopes)`, `acceptInvitation`, `InvitationEnvelope`, and the whole of `invitations.ts`, as listed in the Interfaces block.

- [ ] **Step 1: Write the failing tests.** Create `web/src/invitations.test.ts`:

```ts
import { describe, expect, it, vi } from "vitest";
import { clearStashedInvite, inviteLink, keyRequestText, parseInviteLink, stashInviteLink, stashedInvite } from "./invitations";

const id = `inv_${"a".repeat(26)}`;
const token = `${"A-_z".repeat(10)}abc`; // 43 base64url characters
const memory = () => {
  const items = new Map<string, string>();
  return { getItem: (key: string) => items.get(key) ?? null, setItem: (key: string, value: string) => void items.set(key, value), removeItem: (key: string) => void items.delete(key) };
};

describe("invitation links", () => {
  it("round-trips an invitation through its link and rejects anything else", () => {
    const link = inviteLink("https://notes.example", { id, token });
    expect(link).toBe(`https://notes.example/#/invite/${id}/${token}`);
    expect(parseInviteLink(new URL(link).hash)).toEqual({ id, token });
    for (const hash of ["", `#/invite/${id}`, `#/invite/${id}/${token}x`, `#/invite/inv_short/${token}`, `#/invite/${id}/${token.slice(1)}=`, `#/cnt_${"a".repeat(26)}`]) {
      expect(parseInviteLink(hash)).toBeUndefined();
    }
  });

  it("moves a link from the address bar into session storage, and only a link", () => {
    const storage = memory();
    const replaceState = vi.fn();
    expect(stashInviteLink({ hash: `#/cnt_${"a".repeat(26)}`, pathname: "/" }, { replaceState }, storage)).toBe(false);
    expect(replaceState).not.toHaveBeenCalled();
    expect(stashInviteLink({ hash: `#/invite/${id}/${token}`, pathname: "/" }, { replaceState }, storage)).toBe(true);
    expect(replaceState).toHaveBeenCalledWith(null, "", "/");
    expect(stashedInvite(storage)).toEqual({ id, token });
    clearStashedInvite(storage);
    expect(stashedInvite(storage)).toBeUndefined();
  });

  it("ignores a tampered stash", () => {
    const storage = memory();
    storage.setItem("kynotes-invitation", JSON.stringify({ id: "inv_x", token }));
    expect(stashedInvite(storage)).toBeUndefined();
    storage.setItem("kynotes-invitation", "{not json");
    expect(stashedInvite(storage)).toBeUndefined();
  });

  it("writes a key request that names the stewards and carries the fingerprint and link", () => {
    const text = keyRequestText({ notebook: "Plans", stewards: ["alice", "bob"], fingerprint: "abcd ef01", link: "https://notes.example/#/cnt_x" });
    expect(text).toContain("alice or bob");
    expect(text).toContain("abcd ef01");
    expect(text).toContain("https://notes.example/#/cnt_x");
    expect(keyRequestText({ notebook: "Plans", stewards: [], fingerprint: "", link: "l" })).toContain("a team owner");
  });
});
```

In `api.test.ts`, change the import to `import { inviteMember, readObject, serverGeneration } from "./api";` and append:

```ts
describe("inviteMember", () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  it("sends envelopes only when it has some, so a keyless invitation needs no step-up", async () => {
    const sent: unknown[] = [];
    vi.stubGlobal("document", { cookie: "" });
    vi.stubGlobal("fetch", vi.fn(async (_path: string, init?: RequestInit) => {
      sent.push(JSON.parse(String(init?.body)));
      return Response.json({ id: "inv", token: "t", expiresAt: "e" });
    }));
    const cnt = `cnt_${"a".repeat(26)}`, usr = `usr_${"b".repeat(26)}`;
    const envelope = { containerId: cnt, deviceId: `dev_${"c".repeat(26)}`, keyGeneration: 2, alg: "x25519-hkdf-sha256-chacha20poly1305", envelope: "AA==" };
    await inviteMember(cnt, usr, "editor");
    await inviteMember(cnt, usr, "editor", [envelope]);
    expect(sent).toEqual([{ inviteeId: usr, role: "editor" }, { inviteeId: usr, role: "editor", envelopes: [envelope] }]);
  });
});
```

- [ ] **Step 2: Run them and watch them fail.** Run `npm test --prefix web -- invitations api`. Expected: FAIL (`./invitations` is missing, and `inviteMember` sends no envelopes).

- [ ] **Step 3: Implement.** Create `web/src/invitations.ts`:

```ts
import type { Invitation } from "./api";

/** An invitation as its link carries it; the server checks the token and that the session is the invitee. */
export type InviteLink = Pick<Invitation, "id" | "token">;
const LINK = /^#\/invite\/(inv_[0-9a-hjkmnp-tv-z]{26})\/([A-Za-z0-9_-]{43})$/;
const KEY = "kynotes-invitation";

/** The one-time link; the token travels in the fragment, which browsers never send to the server. */
export const inviteLink = (origin: string, invitation: InviteLink) => `${origin}/#/invite/${invitation.id}/${invitation.token}`;

export function parseInviteLink(hash: string): InviteLink | undefined {
  const match = LINK.exec(hash);
  return match ? { id: match[1], token: match[2] } : undefined;
}

/**
 * Moves an invitation link out of the address bar (and history) into this tab's session storage,
 * so it survives a sign-in that leaves the page (single sign-on). True when there was one.
 */
export function stashInviteLink(location: Pick<Location, "hash" | "pathname">, history: Pick<History, "replaceState">, storage: Pick<Storage, "setItem">): boolean {
  const link = parseInviteLink(location.hash);
  if (!link) return false;
  storage.setItem(KEY, JSON.stringify(link));
  history.replaceState(null, "", location.pathname);
  return true;
}

/** The stashed invitation, re-validated: storage is not trusted to hold what was written. */
export function stashedInvite(storage: Pick<Storage, "getItem">): InviteLink | undefined {
  try {
    const value = JSON.parse(storage.getItem(KEY) ?? "null") as Partial<InviteLink> | null;
    return value ? parseInviteLink(`#/invite/${value.id}/${value.token}`) : undefined;
  } catch {
    return undefined;
  }
}

export const clearStashedInvite = (storage: Pick<Storage, "removeItem">) => storage.removeItem(KEY);

/** What a member waiting for keys sends an owner or admin, out of band. */
export function keyRequestText(input: { notebook: string; stewards: string[]; fingerprint: string; link: string }): string {
  const who = input.stewards.length ? input.stewards.join(" or ") : "a team owner";
  const key = input.fingerprint ? ` My encryption key fingerprint is ${input.fingerprint}; please check it matches what your browser shows for me.` : "";
  return `Hi ${who}: please open the team notebook "${input.notebook}" in KyNotes so your browser shares its key with me.${key} ${input.link}`;
}
```

In `keyring.ts`, after the `Envelope` type, add:

```ts
/** An envelope sent with an invitation, for the team or one of its child workspaces. */
export type InvitationEnvelope = Envelope & { containerId: string };
```

In `api.ts`, change `import type { Envelope } from "./keyring";` to `import type { Envelope, InvitationEnvelope } from "./keyring";`, add `export type Invitation = { id: string; token: string; expiresAt: string };` after `Comment`, and replace `inviteMember` with:

```ts
/** Envelopes need a fresh password step-up on the server, so a keyless invitation sends none. */
export function inviteMember(containerID: string, inviteeID: string, role: string, envelopes: InvitationEnvelope[] = []) {
  return request<Invitation>(`/api/v1/containers/${encodeURIComponent(containerID)}/invitations`, { method: "POST", body: JSON.stringify(envelopes.length ? { inviteeId: inviteeID, role, envelopes } : { inviteeId: inviteeID, role }) });
}
export const acceptInvitation = (id: string, token: string) => request<void>(`/api/v1/invitations/${encodeURIComponent(id)}/accept`, { method: "POST", body: JSON.stringify({ token }) });
```

- [ ] **Step 4: Run the tests.** Run `npm test --prefix web && npx --prefix web tsc --noEmit -p web`. Expected: PASS. `main.tsx` still calls `inviteMember(selected.id, userID, "editor")`, which remains valid.

- [ ] **Step 5: Commit.**

```bash
git add web/src/invitations.ts web/src/invitations.test.ts web/src/api.ts web/src/api.test.ts web/src/keyring.ts
git commit -m "web: invitation links, accept and invitation envelopes in the API"
```

### Task 6: Web: member key status, key-sync members, invitation-time wrapping

**Files:** Modify `web/src/keyring.ts`, `web/src/keyring.test.ts`, `web/src/keyService.ts`, `web/src/keyService.test.ts`.

**Interfaces:**
- Consumes: `InvitationEnvelope` (Task 5), `Invitation` (Task 5), and the P3a `sealFor`, `comparePins`, `confirmFingerprintChange`, `keysAllowed`, `ReportedContainer`, `PinStore` (`addFresh` returns `PinsStored`; `loadKeyState` gives the floor), `Caller`.
- Produces: `memberKeyStatus`, `MemberKeyStatus`, `KeySync.members`, `KeySync.envelopes`, `inviteWithKeys`, `InviteAPI`, `InviteKeys`, `InviteTarget`, `Invited`.

- [ ] **Step 1: Write the failing tests.** In `keyring.test.ts`, add `memberKeyStatus` to the `./keyring` import and append:

```ts
describe("memberKeyStatus", () => {
  const owner = person("owner", "b", "owner"), editor = person("editor", "c"), newcomer = person("newcomer", "d");
  const bare: MemberKey = { userId: `usr_${"e".repeat(26)}`, username: "sso", role: "viewer" };
  const row = (member: MemberKey, generation: number): Envelope => ({ deviceId: member.identity!.deviceId, keyGeneration: generation, alg: "x", envelope: "" });

  it("reports has key, waiting and no identity against the current generation only", () => {
    const status = memberKeyStatus({ id: cnt, keyGeneration: 3, sharedGeneration: 2 }, [owner.member, editor.member, newcomer.member, bare], [row(owner.member, 3), row(editor.member, 3), row(newcomer.member, 2)]);
    expect(status).toEqual({ [owner.member.userId]: "has-key", [editor.member.userId]: "has-key", [newcomer.member.userId]: "waiting", [bare.userId]: "no-identity" });
  });

  it("in a never-shared notebook, names only members without an identity", () => {
    expect(memberKeyStatus({ id: cnt, keyGeneration: 1, sharedGeneration: 0 }, [owner.member, bare], [])).toEqual({ [bare.userId]: "no-identity" });
  });
});
```

In `keyService.test.ts`, extend the existing imports; drop none, since the P3a tests still use `beforeEach`, `legacyKeyRef`, `readKeys`, `writeKey`, `fake-indexeddb/auto` and the `./storage` helpers:
- `vitest`: add `type Mock`.
- `./keyring`: add `memberKeyStatus`, `openKeyring`, `type InvitationEnvelope`, `type KeyFloor`, `type Keyring`, `type ReportedContainer`.
- `./keyService`: add `inviteWithKeys`, `type Caller`, `type InviteAPI`, `type InviteKeys`.

Append:

```ts
describe("key status from a sync", () => {
  it("reports members and the envelopes after its own writes", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor"), newcomer = user("newcomer", "d", "editor");
    const { state, api } = server([owner, editor]);
    const ownerStore = memoryStore();
    const minted = await syncContainerKeys(api, cnt, as(owner), ownerStore, never);
    expect(memberKeyStatus(minted.container, minted.members, minted.envelopes)).toEqual({ [owner.member.userId]: "has-key", [editor.member.userId]: "has-key" });
    state.members.push(newcomer);
    const seen = await syncContainerKeys(api, cnt, as(editor), memoryStore(), never);
    expect(memberKeyStatus(seen.container, seen.members, seen.envelopes)[newcomer.member.userId]).toBe("waiting");
    const wrapped = await syncContainerKeys(api, cnt, as(owner), ownerStore, never);
    expect(wrapped.plan.kind).toBe("wrap");
    expect(memberKeyStatus(wrapped.container, wrapped.members, wrapped.envelopes)[newcomer.member.userId]).toBe("has-key");
  });
});

describe("inviteWithKeys", () => {
  const team: ReportedContainer = { id: cnt, kind: "team", keyGeneration: 2, sharedGeneration: 2 };
  const teamKey = newContainerKey();
  const target = { container: team, ring: new Map([[2, teamKey]]) as Keyring };
  const owner = user("owner", "e", "owner"), invitee = user("invitee", "f", "editor");
  const invited: Member = { ...invitee.member, role: "editor" };
  const inviteAPI = (visible = true, refuseKeys = false) => {
    const calls: Array<{ envelopes: InvitationEnvelope[] }> = [];
    const api: InviteAPI = {
      userIdentity: async (id) => (visible && id === invitee.member.userId ? invitee.public : undefined),
      stepUp: vi.fn(async () => {}),
      invite: vi.fn(async (_cid: string, _id: string, _role: string, envelopes: InvitationEnvelope[]) => {
        if (refuseKeys && envelopes.length) throw conflict();
        calls.push({ envelopes });
        return { id: `inv_${"g".repeat(26)}`, token: "t".repeat(43), expiresAt: "2026-10-08T00:00:00Z" };
      }),
    };
    return { api, calls };
  };

  it("seals the team's current key for a visible invitee, pinned and stepped up first", async () => {
    const { api, calls } = inviteAPI();
    const store = memoryStore();
    const result = await inviteWithKeys(api, target, invited, as(owner), store, never);
    expect(result.keys).toBe("sealed");
    expect(result.recipient?.identity?.publicKey).toBe(invitee.public!.publicKey);
    expect(calls[0].envelopes.map((row) => [row.containerId, row.keyGeneration, row.deviceId])).toEqual([[team.id, 2, invitee.held!.deviceId]]);
    expect(store.get()).toEqual({ [invitee.member.userId]: invitee.public!.publicKey });
    const sent = (api.invite as Mock).mock.invocationCallOrder[0];
    expect(store.addFresh.mock.invocationCallOrder[0]).toBeLessThan(sent);
    expect((api.stepUp as Mock).mock.invocationCallOrder[0]).toBeLessThan(sent);
    // The invitee opens the key as one a current steward sent.
    const steward = { ...owner.member, identity: { deviceId: owner.public!.deviceId, publicKey: owner.public!.publicKey } };
    const opened = openKeyring({ containerID: team.id, envelopes: calls[0].envelopes, me: { ...invitee.held!, userId: invitee.member.userId }, members: [steward], pins: {}, known: { mark: 0, digests: {} } });
    expect(opened.ring.get(team.keyGeneration)).toEqual(teamKey);
  });

  it("invites without keys when it cannot see the invitee, cannot wrap, or holds no current key", async () => {
    const cases: Array<[boolean, Caller, typeof target, InviteKeys]> = [
      [false, as(owner), target, "no-identity"],
      [true, as(owner, false), target, "cannot-wrap"],
      [true, { userId: owner.member.userId, canWrap: true }, target, "cannot-wrap"],
      [true, as(owner), { container: team, ring: new Map([[1, teamKey]]) }, "no-keys"],
      [true, as(owner), { container: { ...team, keyGeneration: 1, sharedGeneration: 0 }, ring: new Map([[1, teamKey]]) }, "no-keys"],
    ];
    for (const [visible, caller, given, keys] of cases) {
      const { api, calls } = inviteAPI(visible);
      expect((await inviteWithKeys(api, given, invited, caller, memoryStore(), never)).keys).toBe(keys);
      expect(calls).toEqual([{ envelopes: [] }]);
      expect(api.stepUp).not.toHaveBeenCalled();
    }
  });

  it("sends no keys for a team this device saw at a later sharing state, or saw shared and now reported personal", async () => {
    const cases: Array<[ReportedContainer, KeyFloor]> = [
      [team, { shared: 2, generation: 3 }], // the server rolled the generation back
      [{ ...team, kind: "workbook" }, { shared: 2, generation: 2 }], // relabelled personal, no teamId
    ];
    for (const [container, floor] of cases) {
      const { api, calls } = inviteAPI();
      expect((await inviteWithKeys(api, { container, ring: target.ring }, invited, as(owner), memoryStore({}, { mark: 0, digests: {}, ...floor }), never)).keys).toBe("rollback");
      expect(calls).toEqual([{ envelopes: [] }]);
      expect(api.stepUp).not.toHaveBeenCalled();
    }
  });

  it("asks before sealing for a changed invitee key; a decline sends no keys", async () => {
    const stale = btoa(String.fromCharCode(...new Uint8Array(32).fill(7)));
    const store = memoryStore({ [invitee.member.userId]: stale });
    const declined = inviteAPI();
    const ask = vi.fn(() => false);
    expect((await inviteWithKeys(declined.api, target, invited, as(owner), store, ask)).keys).toBe("untrusted");
    expect(ask).toHaveBeenCalledWith([{ member: expect.objectContaining({ userId: invitee.member.userId }), pinned: stale }]);
    expect(declined.calls).toEqual([{ envelopes: [] }]);
    expect(store.get()[invitee.member.userId]).toBe(stale);
    const confirmed = inviteAPI();
    expect((await inviteWithKeys(confirmed.api, target, invited, as(owner), store, () => true)).keys).toBe("sealed");
    expect(store.confirm).toHaveBeenCalledTimes(1);
    expect(store.get()[invitee.member.userId]).toBe(invitee.public!.publicKey);
    expect(confirmed.calls[0].envelopes).toHaveLength(1);
  });

  it("never sends keys whose recipient pin this device could not keep", async () => {
    const { api, calls } = inviteAPI();
    expect((await inviteWithKeys(api, target, invited, as(owner), memoryStore({}, undefined, false), never)).keys).toBe("pins-unsaved");
    expect(calls).toEqual([{ envelopes: [] }]);
    expect(api.stepUp).not.toHaveBeenCalled();
  });

  it("sends no keys when another pass pinned a different key for the invitee first", async () => {
    const { api, calls } = inviteAPI();
    // storePins compares in its own transaction: the first-seen pin lost to a concurrent pass.
    const store = { ...memoryStore(), addFresh: vi.fn(async (): Promise<PinsStored> => ({ ok: false, conflicts: [invitee.member.userId] })) };
    expect((await inviteWithKeys(api, target, invited, as(owner), store, never)).keys).toBe("untrusted");
    expect(calls).toEqual([{ envelopes: [] }]);
    expect(api.stepUp).not.toHaveBeenCalled();
  });

  it("falls back to an invitation without keys when a generation moved meanwhile", async () => {
    const { api, calls } = inviteAPI(true, true);
    expect((await inviteWithKeys(api, target, invited, as(owner), memoryStore(), never)).keys).toBe("moved");
    expect(calls).toEqual([{ envelopes: [] }]);
  });
});
```

- [ ] **Step 2: Run them and watch them fail.** Run `npm test --prefix web -- keyring keyService`. Expected: FAIL (`memberKeyStatus` and `inviteWithKeys` are not exported, and `members` is undefined).

- [ ] **Step 3: `memberKeyStatus`.** Append to `keyring.ts`:

```ts
export type MemberKeyStatus = "has-key" | "waiting" | "no-identity";

/**
 * What each member holds, for the member list. Shared notebooks: the current generation's key
 * (has-key), an identity waiting for a steward (waiting), or no identity to wrap for. A
 * never-shared notebook lists only members without an identity, who block its first key.
 * Built from server data: it informs and never decides trust.
 */
export function memberKeyStatus(container: KeyedContainer, members: MemberKey[], envelopes: Envelope[]): Record<string, MemberKeyStatus> {
  const held = new Set(envelopes.filter((row) => row.keyGeneration === container.keyGeneration).map((row) => row.deviceId));
  return Object.fromEntries(members.flatMap((member): Array<[string, MemberKeyStatus]> => {
    if (!member.identity) return [[member.userId, "no-identity"]];
    if (container.sharedGeneration === 0) return [];
    return [[member.userId, held.has(member.identity.deviceId) ? "has-key" : "waiting"]];
  }));
}
```

- [ ] **Step 4: `KeySync` reports members and envelopes.** In `keyService.ts`:
  - Change the keyring import to also take `keysAllowed`, `type InvitationEnvelope` and `type ReportedContainer`, and add `import type { Invitation } from "./api";`.
  - In the `KeySync` doc comment, add "members and envelopes: what this pass last saw, including its own writes (memberKeyStatus)." Add the fields `members: MemberKey[]; envelopes: Envelope[];` to the type.
  - In `pass`, after `const envelopes = await api.envelopes(container.id);`, add `let seen: Envelope[] = envelopes;`.
  - The rollback early return builds its `Pass` by hand, so it needs the new fields too. Replace:

```ts
    if (rollback) return { container, changed: [], conflicts: opened.conflicts, known: latest.saved!.known, fresh: [], ring: opened.ring, plan: { kind: "rollback" }, minted: false };
```

  with:

```ts
    if (rollback) return { container, changed: [], conflicts: opened.conflicts, known: latest.saved!.known, fresh: [], ring: opened.ring, plan: { kind: "rollback" }, minted: false, members, envelopes };
```

  - Replace the `result` definition with:

```ts
    const result = (rest: Omit<Pass, "container" | "changed" | "conflicts" | "known" | "fresh" | "members" | "envelopes">, fresh: MemberKey[], last = opened): Pass =>
      ({ container, changed, conflicts: last.conflicts, known: last.known, fresh: uniqueBy([...carried, ...fresh], (member) => member.userId), members, envelopes: seen, ...rest });
```

  - Replace the last three lines of `pass`:

```ts
    if (sweep.kind === "wrap") return result({ ring: opened.ring, plan: sweep, minted: false }, fresh);
    const after = open(pins, await api.envelopes(container.id), opened.ring);
    return result({ ring: after.ring, plan: sweep, minted: true }, fresh, after);
```

  with:

```ts
    if (sweep.kind === "wrap") {
      seen = [...envelopes, ...rows];
      return result({ ring: opened.ring, plan: sweep, minted: false }, fresh);
    }
    seen = await api.envelopes(container.id);
    const after = open(pins, seen, opened.ring);
    return result({ ring: after.ring, plan: sweep, minted: true }, fresh, after);
```

- [ ] **Step 5: `inviteWithKeys`.** Append to `keyService.ts`:

```ts
export type InviteAPI = Pick<KeyAPI, "userIdentity" | "stepUp"> & {
  invite: (containerID: string, inviteeID: string, role: string, envelopes: InvitationEnvelope[]) => Promise<Invitation>;
};
/**
 * sealed: the invitation carries the team's current key. Otherwise it went out without keys, and
 * a steward's sweep shares them after the invitee joins:
 * - cannot-wrap: this browser has no identity, or the session is single sign-on.
 * - rollback: the server reports an older sharing state than this device has seen (keysAllowed).
 * - no-keys: this browser holds no current shared key for the team.
 * - no-identity: the invitee's key is not visible (no identity, or no shared notebook with you).
 * - untrusted: a changed key was not confirmed, or another pass pinned a different key first.
 * - pins-unsaved: the invitee's pin could not be kept.
 * - moved: a generation changed meanwhile.
 */
export type InviteKeys = "sealed" | "cannot-wrap" | "rollback" | "no-keys" | "no-identity" | "untrusted" | "pins-unsaved" | "moved";
export type Invited = { invitation: Invitation; keys: InviteKeys; recipient?: MemberKey };
/** The team the user chose to invite to. Child workspaces are never added here: teamId is a server claim. */
export type InviteTarget = { container: ReportedContainer; ring: Keyring };

/**
 * Invites invitee to the target team. Keys go only when this device's floor allows them, this
 * browser holds the team's current key, and it can see the invitee's identity. The key is sealed
 * for that identity: the pin is checked (a changed key only after confirmation) and a first-seen
 * pin is stored before anything leaves, then a fresh step-up runs. The server installs the
 * envelope at accept while the generation is unchanged. Anything less sends no keys.
 */
export async function inviteWithKeys(api: InviteAPI, target: InviteTarget, invitee: Member, caller: Caller, store: PinStore, confirmChanged: (changes: PinChange[]) => boolean | Promise<boolean>): Promise<Invited> {
  const { container, ring } = target;
  const plain = async (keys: InviteKeys): Promise<Invited> => ({ invitation: await api.invite(container.id, invitee.userId, invitee.role, []), keys });
  if (!caller.identity || !caller.canWrap) return plain("cannot-wrap");
  // This device's floor decides, never the server's sharing state alone.
  if (!keysAllowed(container, await store.loadKeyState(container.id))) return plain("rollback");
  const key = container.sharedGeneration > 0 ? ring.get(container.keyGeneration) : undefined;
  if (!key) return plain("no-keys");
  const identity = await api.userIdentity(invitee.userId);
  if (!identity) return plain("no-identity");
  const member: MemberKey = { ...invitee, identity: { deviceId: identity.deviceId, publicKey: identity.publicKey } };
  let pins = await store.load();
  const { changed } = comparePins(pins, [member]);
  if (changed.length) {
    if ((await confirmChanged(changed)) !== true) return plain("untrusted");
    const confirmation = confirmFingerprintChange(pins, member);
    if (!(await store.confirm(confirmation))) return plain("pins-unsaved");
    pins = confirmation.pins;
  }
  const sealed = sealFor(member, container.id, container.keyGeneration, key, { ...caller.identity, userId: caller.userId }, pins);
  // A first-seen pin is kept before the key leaves; a different pin another pass stored meanwhile wins.
  if (sealed.fresh.length) {
    const stored = await store.addFresh(sealed.pins);
    if (!stored.ok) return plain(stored.conflicts.length ? "untrusted" : "pins-unsaved");
  }
  await api.stepUp();
  try {
    return { invitation: await api.invite(container.id, invitee.userId, invitee.role, [{ ...sealed.envelope, containerId: container.id }]), keys: "sealed", recipient: member };
  } catch (error) {
    // already_exists: a generation moved after this browser read it; the sweep shares the new key after accept.
    if (code(error) !== "already_exists") throw error;
    return plain("moved");
  }
}
```

- [ ] **Step 6: Run the tests.** Run `npm test --prefix web && npx --prefix web tsc --noEmit -p web`. Expected: PASS.

- [ ] **Step 7: Commit.**

```bash
git add web/src/keyring.ts web/src/keyring.test.ts web/src/keyService.ts web/src/keyService.test.ts
git commit -m "web: member key status and invitation-time key wrapping"
```

### Task 7: Web: pin rows and the colleague-keys card

**Files:** Modify `web/src/pins.ts`, `web/src/pins.test.ts`, `web/src/styles.css`. Create `web/src/components/PinnedKeys.tsx`.

**Interfaces:**
- Consumes: `getPins`, `storeConfirmedPin` (storage), `userIdentity` (api), and `confirmFingerprintChange`, `fingerprint`.
- Produces: `pinRows`, `PinRow`, and `PinnedKeys({ username, userID, names })`.

- [ ] **Step 1: Write the failing test.** In `pins.test.ts`, add `pinRows` to the import and append:

```ts
describe("pinRows", () => {
  it("compares each pin with the key the server shows now, sorted by user", () => {
    expect(pinRows({ b: key(2), a: key(1), c: key(3) }, { a: key(1), b: key(9) })).toEqual([
      { userId: "a", pinned: key(1), current: key(1), state: "same" },
      { userId: "b", pinned: key(2), current: key(9), state: "changed" },
      { userId: "c", pinned: key(3), current: undefined, state: "unseen" },
    ]);
  });
});
```

- [ ] **Step 2: Run it and watch it fail.** Run `npm test --prefix web -- pins`. Expected: FAIL (`pinRows` is not exported).

- [ ] **Step 3: Implement.** Append to `pins.ts`:

```ts
export type PinRow = { userId: string; pinned: string; current?: string; state: "same" | "changed" | "unseen" };

/** Settings rows: each pin against the key the server shows now; unseen when it shows none (no shared notebook, or no identity). */
export function pinRows(pins: Pins, current: Record<string, string | undefined>): PinRow[] {
  return Object.entries(pins).sort(([a], [b]) => a.localeCompare(b)).map(([userId, pinned]) => {
    const now = current[userId];
    return { userId, pinned, current: now, state: now === undefined ? "unseen" : sameKey(pinned, now) ? "same" : "changed" };
  });
}
```

Create `web/src/components/PinnedKeys.tsx`:

```tsx
import React, { useEffect, useState } from "react";
import { userIdentity } from "../api";
import type { PublicIdentity } from "../identity";
import { confirmFingerprintChange, fingerprint, pinRows, type PinRow } from "../pins";
import { getPins, storeConfirmedPin } from "../storage";

type Shown = PinRow & { name: string; pinnedPrint: string; currentPrint?: string; identity?: PublicIdentity };
const print = (key: string) => fingerprint(key).catch(() => "unreadable key");

/**
 * Colleagues this browser pinned, with fingerprints computed here from the keys. A changed key is
 * re-trusted only after the user confirms the exact key shown, through confirmFingerprintChange and
 * storeConfirmedPin: the same path as the wrap prompt (spec §6). Pins are never deleted here.
 */
export function PinnedKeys({ username, userID, names }: { username: string; userID: string; names: Record<string, string> }) {
  const [rows, setRows] = useState<Shown[] | undefined>(undefined);
  const [problem, setProblem] = useState("");
  async function load() {
    try {
      const pins = await getPins(username, userID);
      // ponytail: one identity request per pin. Upgrade: a batch identity route.
      const seen: Record<string, PublicIdentity | undefined> = Object.fromEntries(await Promise.all(Object.keys(pins).map(async (id) => [id, await userIdentity(id).catch(() => undefined)] as const)));
      const current = Object.fromEntries(Object.entries(seen).map(([id, identity]) => [id, identity?.publicKey]));
      setRows(await Promise.all(pinRows(pins, current).map(async (row) => ({
        ...row,
        identity: seen[row.userId],
        name: names[row.userId] ?? row.userId,
        pinnedPrint: await print(row.pinned),
        currentPrint: row.current === undefined ? undefined : await print(row.current),
      }))));
    } catch {
      setProblem("This browser could not read the colleague keys it saved.");
    }
  }
  useEffect(() => { void load(); }, [username, userID]);
  async function trust(row: Shown) {
    if (!row.identity) return;
    const accepted = confirm(`Trust ${row.name}'s new encryption key?\n\nNew: ${row.currentPrint}\nWas: ${row.pinnedPrint}\n\nA password reset or account recovery changes it; so would a server substituting its own key. Compare the new fingerprint with ${row.name} in person (their Settings shows it) before trusting it.`);
    if (!accepted) return;
    const confirmation = confirmFingerprintChange(await getPins(username, userID), { userId: row.userId, username: row.name, role: "", identity: { deviceId: row.identity.deviceId, publicKey: row.identity.publicKey } });
    if (!(await storeConfirmedPin(username, userID, confirmation))) {
      setProblem("This browser could not save the new key. Allow site storage and try again.");
      return;
    }
    await load();
  }
  return (
    <section id="colleague-keys" className="config-card">
      <h2>Colleague keys</h2>
      <p className="config-muted">Keys this browser trusts when sharing team notebooks. Fingerprints are computed here, not taken from the server.</p>
      {problem && <p className="config-muted" role="alert">{problem}</p>}
      {rows?.length === 0 && <p className="config-muted">No colleague keys yet. A key is saved the first time you share a team notebook with someone.</p>}
      {rows?.map((row) => (
        <div className="pin-row" key={row.userId}>
          <strong>{row.name}</strong>
          <code>{row.pinnedPrint}</code>
          {row.state === "same" && <span className="config-muted">matches the server</span>}
          {row.state === "unseen" && <span className="config-muted">not visible now (no shared notebook, or no key yet)</span>}
          {row.state === "changed" && (
            <>
              <span className="config-muted">changed to <code>{row.currentPrint}</code></span>
              <button type="button" className="secondary" onClick={() => void trust(row)}>Trust new key</button>
            </>
          )}
        </div>
      ))}
    </section>
  );
}
```

In `styles.css`, after `.member-row .quiet { … }`, add:

```css
.pin-row { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; padding: 8px 0; border-top: 1px solid var(--line); font-size: 12px; }
.pin-row code { overflow-wrap: anywhere; }
```

- [ ] **Step 4: Run the tests.** Run `npm test --prefix web && npx --prefix web tsc --noEmit -p web`. Expected: PASS. The card is not rendered until Task 10.

- [ ] **Step 5: Commit.**

```bash
git add web/src/pins.ts web/src/pins.test.ts web/src/components/PinnedKeys.tsx web/src/styles.css
git commit -m "web: colleague keys card; re-trust a changed key outside the wrap prompt"
```

### Task 8: Web: unsent edits for lost notebooks (N1)

**Files:** Create `web/src/stuckEdits.ts`, `web/src/stuckEdits.test.ts`, `web/src/components/UnsentEdits.tsx`.

**Interfaces:**
- Consumes: `pendingSaves`, `clearQueuedSave`, `deleteNote` and `PendingSave` (storage); `containers` (api); `decryptObject` and `KeyRef` (crypto).
- Produces: `stuckSaves`, `exportUnsent`, and `UnsentEdits({ legacyKey })`.

- [ ] **Step 1: Write the failing test.** Create `web/src/stuckEdits.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { decryptObject, encryptNote, legacyKeyRef } from "./crypto";
import type { PendingSave } from "./storage";
import { exportUnsent, stuckSaves } from "./stuckEdits";

const lost = `cnt_${"a".repeat(26)}`, kept = `cnt_${"b".repeat(26)}`;
const legacy = legacyKeyRef("5a".repeat(32));
const save = async (id: string, containerID: string, title: string, key = legacy): Promise<PendingSave> =>
  ({ id, containerID, version: 1, updatedAt: "2026-10-07T00:00:00Z", keyGeneration: 0, payload: await encryptNote(key, containerID, { type: "page", title, body: "[]" }) });

describe("stuck edits", () => {
  it("are the queued edits of notebooks the server no longer lists, and none when the list is unknown", async () => {
    const queued = [await save(`obj_${"c".repeat(26)}`, lost, "gone"), await save(`obj_${"d".repeat(26)}`, kept, "here")];
    expect(stuckSaves(queued, new Set([kept])).map((item) => item.containerID)).toEqual([lost]);
    expect(stuckSaves(queued, undefined)).toEqual([]);
  });

  it("exports what the key opens and counts the rest", async () => {
    const items = [await save(`obj_${"c".repeat(26)}`, lost, "gone"), await save(`obj_${"e".repeat(26)}`, lost, "sealed elsewhere", legacyKeyRef("6b".repeat(32)))];
    const file = await exportUnsent(items, (item) => decryptObject(legacy, item.containerID, item.payload));
    expect(file.unreadable).toBe(1);
    expect(JSON.parse(file.json)).toEqual([{ id: items[0].id, notebook: lost, updatedAt: "2026-10-07T00:00:00Z", content: expect.objectContaining({ title: "gone" }) }]);
  });
});
```

- [ ] **Step 2: Run it and watch it fail.** Run `npm test --prefix web -- stuckEdits`. Expected: FAIL (`./stuckEdits` is missing).

- [ ] **Step 3: Implement.** Create `web/src/stuckEdits.ts`:

```ts
import type { PendingSave } from "./storage";

/**
 * Queued edits whose notebook the server no longer lists for this account: they can never be
 * sent. An unknown list (offline, server error) yields none, so an outage never offers sendable
 * work for deletion.
 */
export function stuckSaves(queued: PendingSave[], live: ReadonlySet<string> | undefined): PendingSave[] {
  return live ? queued.filter((item) => !live.has(item.containerID)) : [];
}

/** A JSON export of the edits open() reads; the rest are counted, never guessed at. */
export async function exportUnsent(items: PendingSave[], open: (item: PendingSave) => Promise<unknown>): Promise<{ json: string; unreadable: number }> {
  const out: Array<{ id: string; notebook: string; updatedAt: string; content: unknown }> = [];
  let unreadable = 0;
  for (const item of items) {
    const content = await open(item).catch(() => undefined);
    if (content === undefined) unreadable += 1;
    else out.push({ id: item.id, notebook: item.containerID, updatedAt: item.updatedAt, content });
  }
  return { json: JSON.stringify(out, null, 2), unreadable };
}
```

Create `web/src/components/UnsentEdits.tsx`:

```tsx
import React, { useEffect, useState } from "react";
import { containers } from "../api";
import { decryptObject, type KeyRef } from "../crypto";
import { clearQueuedSave, deleteNote, pendingSaves, type PendingSave } from "../storage";
import { exportUnsent, stuckSaves } from "../stuckEdits";

/**
 * Edits queued on this device for notebooks this account can no longer open. They can never be
 * sent. Export opens only what the login-derived key opens (edits made while waiting for keys);
 * discard deletes them after a confirmation. Nothing shows while the notebook list is unavailable.
 */
export function UnsentEdits({ legacyKey }: { legacyKey: KeyRef }) {
  const [stuck, setStuck] = useState<PendingSave[]>([]);
  async function load() {
    const live = await containers().then((list) => new Set(list.map((entry) => entry.id)), () => undefined);
    setStuck(stuckSaves(await pendingSaves().catch(() => []), live));
  }
  useEffect(() => { void load(); }, []);
  if (!stuck.length) return null;
  async function exportAll() {
    const file = await exportUnsent(stuck, (item) => decryptObject(legacyKey, item.containerID, item.payload));
    const url = URL.createObjectURL(new Blob([file.json], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url; link.download = "kynotes-unsent-edits.json"; link.click();
    URL.revokeObjectURL(url);
    if (file.unreadable) alert(`${file.unreadable} edit(s) are sealed with a notebook key this browser no longer holds and were left out.`);
  }
  async function discard() {
    if (!confirm(`Delete ${stuck.length} unsent edit(s) from this browser? They belong to notebooks you can no longer open and cannot be recovered afterwards. Export them first if you need them.`)) return;
    for (const item of stuck) {
      await clearQueuedSave(item.id);
      await deleteNote(item.id);
    }
    await load();
  }
  return (
    <section id="unsent-edits" className="config-card">
      <h2>Unsent edits</h2>
      <p className="config-muted">{stuck.length} edit(s) on this device belong to notebooks you can no longer open, so they can never be saved.</p>
      <button type="button" onClick={() => void exportAll()}>Export unsent edits</button>
      <button type="button" className="secondary danger" onClick={() => void discard()}>Discard unsent edits</button>
    </section>
  );
}
```

- [ ] **Step 4: Run the tests.** Run `npm test --prefix web && npx --prefix web tsc --noEmit -p web`. Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add web/src/stuckEdits.ts web/src/stuckEdits.test.ts web/src/components/UnsentEdits.tsx
git commit -m "web: export or discard edits stranded for a lost notebook (N1)"
```

### Task 9: Web: one load wins (double-load race)

**Files:** Create `web/src/loadGate.ts`, `web/src/loadGate.test.ts`. Modify `web/src/main.tsx`.

**Interfaces:**
- Produces: `loadGate()`; `loadContainer(container, route, superseded)`.

- [ ] **Step 1: Write the failing tests.** Create `web/src/loadGate.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { loadGate } from "./loadGate";

describe("loadGate", () => {
  it("lets only the newest load finish, even for the same notebook", () => {
    const gate = loadGate();
    const first = gate.begin();
    expect(first.superseded()).toBe(false);
    const second = gate.begin();
    expect(first.superseded()).toBe(true);
    expect(second.superseded()).toBe(false);
  });

  it("keeps gates apart", () => {
    const a = loadGate(), b = loadGate();
    const ticket = a.begin();
    b.begin();
    expect(ticket.superseded()).toBe(false);
  });
});

describe("main.tsx load wiring", () => {
  it("decides superseded loads by ticket, never by notebook ID", () => {
    const main = import.meta.glob<string>("./main.tsx", { query: "?raw", import: "default", eager: true })["./main.tsx"];
    expect(main).toMatch(/loads\.begin\(\)/);
    expect(main).not.toMatch(/loadingContainerID\.current !== container\.id/);
    expect(main).not.toMatch(/if \(loadingContainerID\.current === container\.id\)/);
  });
});
```

- [ ] **Step 2: Run them and watch them fail.** Run `npm test --prefix web -- loadGate`. Expected: FAIL (`./loadGate` is missing).

- [ ] **Step 3: Implement.** Create `web/src/loadGate.ts`:

```ts
/**
 * Notebook loads where only the newest may finish. Each begin() supersedes every earlier ticket,
 * a second load of the same notebook included (an automatic load plus a click).
 */
export function loadGate() {
  let latest = 0;
  return {
    begin() {
      const ticket = ++latest;
      return { superseded: () => latest !== ticket };
    },
  };
}
```

In `main.tsx`:
- Add `import { loadGate } from "./loadGate";` next to the `./notes` import.
- After `const loadingContainerID = useRef<string | undefined>(undefined);`, add `const loads = useMemo(loadGate, []);`.
- Replace `selectContainer` and the head of `loadContainer`:

```ts
  /** Null when the open page could not be flushed and stays open. */
  async function selectContainer(container: Container, route?: Route): Promise<Note[] | null> {
    loadingContainerID.current = container.id;
    setLoadingContainer(true);
    try {
      return await loadContainer(container, route);
    } finally {
      // A later switch owns the flag now.
      if (loadingContainerID.current === container.id) {
        loadingContainerID.current = undefined;
        setLoadingContainer(false);
      }
    }
  }
  async function loadContainer(container: Container, route?: Route): Promise<Note[] | null> {
    // Workspace navigation destroys the current editor. Finish its latest
    // encrypted save before replacing the note list so the next load cannot
    // fall back to an older plain document.
    if (!(await flushOpenPage())) return null;
    // Another switch started meanwhile: its results win.
    const superseded = () => loadingContainerID.current !== container.id;
    if (superseded()) return [];
```

  with:

```ts
  /** Null when the open page could not be flushed and stays open. */
  async function selectContainer(container: Container, route?: Route): Promise<Note[] | null> {
    // Every call supersedes the ones before it, a second load of the same notebook included.
    const load = loads.begin();
    loadingContainerID.current = container.id;
    setLoadingContainer(true);
    try {
      return await loadContainer(container, route, load.superseded);
    } finally {
      // A later load owns the flag now.
      if (!load.superseded()) {
        loadingContainerID.current = undefined;
        setLoadingContainer(false);
      }
    }
  }
  async function loadContainer(container: Container, route: Route | undefined, superseded: () => boolean): Promise<Note[] | null> {
    // Workspace navigation destroys the current editor. Finish its latest
    // encrypted save before replacing the note list so the next load cannot
    // fall back to an older plain document.
    if (!(await flushOpenPage())) return null;
    // Another load started meanwhile: its results win.
    if (superseded()) return [];
```

  Confirm `grep -n 'loadContainer(' web/src/main.tsx` shows only the definition and the call in `selectContainer`.
- Add `aria-busy={loadingContainer}` to `<section className="note-list">`. The browser check waits on it.

- [ ] **Step 4: Run the tests.** Run `npm test --prefix web && npx --prefix web tsc --noEmit -p web`. Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add web/src/loadGate.ts web/src/loadGate.test.ts web/src/main.tsx
git commit -m "web: only the newest notebook load finishes"
```

### Task 10: Web: wire `main.tsx`

**Files:** Modify `web/src/main.tsx`.

**Interfaces:**
- Consumes: everything from Tasks 5–9.
- Produces these UI strings, which Task 12 depends on:
  - The invite prompts: `User ID to invite (Settings shows each person's user ID)`, then a prompt containing `Send this link to the person you invited`, with the link as its default value.
  - The banner: `You were invited to a team notebook.`, with the buttons `Join team` and `Not now`. The toast `You joined the team.`
  - The `Ask an owner` button, whose prompt starts `Send this to <stewards>`.
  - The member-row suffixes `has key`, `waiting for key` and `no encryption key yet`.
  - In Settings: `Your user ID: <code>`, `#colleague-keys`, `#unsent-edits`.

- [ ] **Step 1: Imports.**
  - Add `acceptInvitation,` to the `./api` import.
  - Extend the keyring import with `memberKeyStatus, type MemberKeyStatus`.
  - Change the keyService import to `import { inviteWithKeys, syncContainerKeys, type InviteKeys, type KeyAPI, type KeySync, type PinStore } from "./keyService";`.
  - Add `import { clearStashedInvite, inviteLink, keyRequestText, stashInviteLink, stashedInvite } from "./invitations";`, `import { PinnedKeys } from "./components/PinnedKeys";` and `import { UnsentEdits } from "./components/UnsentEdits";`.

- [ ] **Step 2: Module constants and the link stash.** After the `UNVERIFIED_SUBPAGES` constant, add:

```ts
const KEY_STATUS: Record<MemberKeyStatus, string> = { "has-key": "has key", waiting: "waiting for key", "no-identity": "no encryption key yet" };
const INVITE_WITHOUT_KEYS: Record<Exclude<InviteKeys, "sealed">, string> = {
  "cannot-wrap": "The invitation carries no keys: this browser cannot share keys (sign in with your password).",
  rollback: "The invitation carries no keys: the server reports an older sharing state for this team than this browser has seen.",
  "no-keys": "The invitation carries no keys: this browser holds none for this team yet. A team owner's browser shares them after the person joins.",
  "no-identity": "The invitation carries no keys: you cannot see this person's encryption key yet. A team owner's browser shares them after they join.",
  untrusted: "The invitation carries no keys: you did not confirm this person's new encryption key.",
  "pins-unsaved": "The invitation carries no keys: this browser could not save this person's key. Allow site storage.",
  moved: "The invitation carries no keys: this team's key changed meanwhile. A team owner's browser shares the new one after the person joins.",
};
```

Immediately above `createRoot(document.getElementById("root")!).render(`, add:

```ts
// An invitation link opens the app at #/invite/…: keep it in this tab for after sign-in, out of the address bar.
try { stashInviteLink(location, history, sessionStorage); } catch { /* session storage disabled: the link cannot be kept */ }
```

- [ ] **Step 3: State.** After `const [keyNotice, setKeyNotice] = useState("");`, add:

```ts
  // The open notebook's members as its last key pass saw them, and what each holds (informational only).
  const [keyMembers, setKeyMembers] = useState<{ containerID: string; members: MemberKey[]; status: Record<string, MemberKeyStatus> } | undefined>(undefined);
  // Usernames seen in key passes this session, for Settings' colleague keys.
  const colleagueNames = useRef<Record<string, string>>({});
  const [invitation, setInvitation] = useState(() => { try { return stashedInvite(sessionStorage); } catch { return undefined; } });
```

- [ ] **Step 4: Key passes report members.**
  - In `syncKeys`, after `putRing(container.id, result.ring);`, add `for (const member of result.members) colleagueNames.current[member.userId] = member.username;`.
  - Inside its `if ((loadingContainerID.current ?? selectedRef.current?.id) === container.id) {` block, before `setKeyNotice(…)`, add `setKeyMembers({ containerID: container.id, members: result.members, status: result.plan.kind === "rollback" ? {} : memberKeyStatus(result.container, result.members, result.envelopes) });`. A rolled-back server's generations would mislabel every member, and the rollback notice already explains the pause.
  - In `loadContainers`, after `putRing(item.id, pass.ring);`, add `for (const member of pass.members) colleagueNames.current[member.userId] = member.username;`.

- [ ] **Step 5: Invite, join, ask.** Replace `invite()` with:

```ts
  async function invite() {
    const team = selected;
    if (!team) return;
    const userID = prompt("User ID to invite (Settings shows each person's user ID)")?.trim();
    if (!userID) return;
    try {
      // Only the notebook the user chose: kind and teamId never pick which keys leave this browser.
      const target = { container: team, ring: ringsRef.current[team.id] ?? noKeys };
      const invitee = { userId: userID, username: colleagueNames.current[userID] ?? userID, role: "editor" };
      const caller = { userId: auth.user.id, identity: await heldIdentity(), canWrap: !auth.sso };
      const { invitation: made, keys, recipient } = await inviteWithKeys({ userIdentity, stepUp: keyAPI.stepUp, invite: inviteMember }, target, invitee, caller, pinStore, confirmChangedKeys(team.id));
      const carried = keys === "sealed" && recipient?.identity
        ? `The invitation carries this team's keys, sealed for the key with fingerprint ${await fingerprintOf(recipient.identity.publicKey)}; compare it with ${invitee.username} (their Settings shows it).`
        : INVITE_WITHOUT_KEYS[keys as Exclude<InviteKeys, "sealed">];
      prompt(`${carried} Send this link to the person you invited. It works once, only for their account, until ${new Date(made.expiresAt).toLocaleString()}.`, inviteLink(location.origin, made));
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to invite member");
    }
  }
  function dropInvitation() {
    setInvitation(undefined);
    try { clearStashedInvite(sessionStorage); } catch { /* nothing kept */ }
  }
  async function joinTeam() {
    const link = invitation;
    if (!link) return;
    dropInvitation();
    try {
      await acceptInvitation(link.id, link.token);
      setError("You joined the team.");
    } catch (error) {
      const code = error instanceof APIRequestError ? error.code : undefined;
      setError(code === "not_found"
        ? "This invitation is no longer valid: it expired, was already used, is for another account, or its sender can no longer invite."
        : code === "already_exists" ? "You are already a member of this team." : error instanceof Error ? error.message : "Unable to join the team");
    }
    await loadContainers();
  }
  async function askForKeys() {
    const open = selectedRef.current;
    if (!open) return;
    const known = keyMembers?.containerID === open.id ? keyMembers.members : [];
    const stewards = known.filter((member) => (member.role === "owner" || member.role === "admin") && member.userId !== auth.user.id).map((member) => member.username);
    const identity = await heldIdentity();
    const text = keyRequestText({ notebook: nameOf(open), stewards, fingerprint: identity ? await fingerprintOf(base64(identity.publicKey)) : "", link: `${location.origin}/${formatRoute({ container: open.id })}` });
    prompt(`Send this to ${stewards.join(" or ") || "a team owner"}. Their browser shares this notebook's key when they open it.`, text);
  }
```

- [ ] **Step 6: Render.** Replace the key-wait line (P3a shows `ROLLBACK` in it on a rollback; asking an owner cannot fix a rollback, so the button appears only while waiting):

```tsx
                {!queueMode && keyWait && <div className="workspace-kind" role="status">{rollback ? ROLLBACK : "Waiting for a team owner to share this notebook's keys. It is read-only until then."}</div>}
```

with:

```tsx
                {!queueMode && keyWait && <div className="workspace-kind" role="status">{rollback ? ROLLBACK : <>Waiting for a team owner to share this notebook's keys. It is read-only until then. <button className="quiet" onClick={() => void askForKeys()}>Ask an owner</button></>}</div>}
```

After the `keyNotice` line, add:

```tsx
                {invitation && (
                  <div className="conflict-banner" role="status">
                    You were invited to a team notebook.{" "}
                    <button onClick={() => void joinTeam()}>Join team</button>{" "}
                    <button className="quiet" onClick={dropInvitation}>Not now</button>
                  </div>
                )}
```

In the member list, replace:

```tsx
                {membersForTeam.map((member) => (
                  <div className="member-row" key={member.userId}>
                    <span>
                      {member.username} · {member.role}
                    </span>
```

with:

```tsx
                {membersForTeam.map((member) => (
                  <div className="member-row" key={member.userId}>
                    <span>
                      {member.username} · {member.role}
                      {keyMembers?.containerID === selected.id && keyMembers.status[member.userId] && ` · ${KEY_STATUS[keyMembers.status[member.userId]]}`}
                    </span>
```

(The closing `))}` of that map is unchanged.)

- [ ] **Step 7: Settings.**
  - At `<SettingsView`, add the props `legacyKey={legacy}` and `colleagueNames={colleagueNames.current}`.
  - In `SettingsView`, add `legacyKey,` and `colleagueNames,` to the destructuring, and to the props type add:

```ts
  /** The login-derived key, for exporting edits stranded on this device. */
  legacyKey: KeyRef;
  /** Usernames seen in key passes this session, for the colleague keys card. */
  colleagueNames: Record<string, string>;
```

  - In the non-admin `settings-nav`, add `<a href="#colleague-keys">Colleague keys</a>` after the `#device` link.
  - In the `#device` card, before the fingerprint paragraph, add `<p className="config-muted">Your user ID: <code>{userID}</code>. Team owners need it to invite you.</p>`.
  - After that card's closing `</section>`, add:

```tsx
            <PinnedKeys username={username} userID={userID} names={colleagueNames} />
            <UnsentEdits legacyKey={legacyKey} />
```

- [ ] **Step 8: Remove the stale `ponytail:` note.** In `drainQueue`, replace the comment lines:

```ts
            // ponytail: an edit for a notebook this user lost, or sealed under a password changed in
            // another browser, never opens and waits here forever (N1). Upgrade: P3b key-status UI
            // with discard/export for stuck edits.
```

with:

```ts
            // An edit for a notebook this user lost waits here until Settings → Unsent edits exports
            // or discards it. ponytail: one sealed under a password changed in another browser never
            // opens (N3); P5 moves to identity-keyed storage.
```

- [ ] **Step 9: Verify.** Run `npm test --prefix web && npm run build --prefix web`. Expected: PASS, including "main.tsx key wiring": still exactly two `legacyKeyRef(` sites, because Settings receives `legacy` instead of deriving a key.

- [ ] **Step 10: Commit.**

```bash
git add web/src/main.tsx
git commit -m "web: join by link, invite with keys, member key status, colleague keys and unsent edits"
```

### Task 11: Embedded bundle, spec, DOX and changelog

**Files:** `internal/web/dist/`, `docs/superpowers/specs/2026-10-07-team-keys-design.md`, `AGENTS.md`, `CHANGELOG.md`.

- [ ] **Step 1: Bundle.** Run `npm run build --prefix web && rm -rf internal/web/dist && cp -r web/dist internal/web/dist && diff -qr web/dist internal/web/dist && go test ./internal/web`.

- [ ] **Step 2: Spec.**
  - §5 Server, first bullet: after "P2 adds `invitation_envelopes`, `author_user_id` and `containers.shared_generation` as `0022`", add "; P3b adds `memberships.invited_by` as `0023`".
  - §7 P3b bullet: change "(`invitation_envelopes`, team plus child workspaces)" to "(`invitation_envelopes`; as built, the team container only, see P3b ruling 8)", and append "(plan: `docs/superpowers/plans/2026-10-07-team-keys-p3b.md`)".
  - §7 P3c bullet: change `0023_link_requests.sql` to `0024_link_requests.sql`.
  - After the "**P3a as built.**" block, add a "**P3b as built.** Resolved ambiguities:" block. Record resolved ambiguities 1–15 above as numbered one-line items, then a "Known limits:" list:
    - Invitation keys cover only the current generation of the team container. Child workspaces and history arrive with the steward sweep.
    - An invitee with no live notebook in common with the inviter gets a keyless invitation.
    - Member key status and steward names are server data, so they are informational only.
    - Asking for keys is out of band.
    - Expired invitation envelopes last until the next GC run.
    - Admins admitted before migration 0023 have no recorded inviter.
    - Pending uploads for lost notebooks are not listed (`ponytail:`).
  - In the P2 "Known limits left for later phases" sentence, append "P3b resolves all but the first two; the liveness signal is now rate-limited."

- [ ] **Step 3: `AGENTS.md`.** After the "Team keys P3a client trust" bullet, add:

```markdown
- Team keys P3b: invitations and membership keys. Server: `POST /api/v1/invitations/{id}/accept` reads
  the invitation (token, invitee, pending, unexpired) inside its transaction; `admitMemberTx` (accept and
  the server-admin add route) reactivates rows a removal revoked, restores no keys and records
  `memberships.invited_by` (migration `0023_membership_inviter.sql`); a team admin removes another admin
  only when it invited that membership; `ratelimit.invitation_per_hour` limits invitation creation per
  account; `storage.RunGC` deletes envelopes of expired invitations. Web: one-time links
  `#/invite/<id>/<token>` (`web/src/invitations.ts`, kept in session storage across sign-in and removed
  from the address bar); `inviteWithKeys` (`keyService.ts`) seals only the chosen team's current key
  (never children picked by `teamId`), gated by `keysAllowed` against this device's floor, for a
  visible invitee; a changed pin needs confirmation and a first-seen pin goes through `storePins`
  (a conflict sends no keys) before the step-up; anything else sends a keyless invitation;
  re-invited members receive history like any newcomer; `memberKeyStatus` labels member rows (informational); Settings colleague keys
  (`components/PinnedKeys.tsx`, re-trust only via `confirmFingerprintChange` → `storeConfirmedPin`) and
  unsent edits for lost notebooks (`components/UnsentEdits.tsx`, `stuckEdits.ts`); `loadGate.ts` lets only
  the newest notebook load finish. Verify `TestAcceptChecksExpiryAndInviteeInsideItsTransaction`,
  `TestRemovedMemberIsReadmittedByReactivation`, `TestTeamAdminRemovesOnlyAdminsItInvited`,
  `TestInvitationCreationIsRateLimitedPerCaller`, `TestGCDeletesEnvelopesOfExpiredInvitations`, `npm test`
  (keyring, keyService, pins, invitations, stuckEdits, loadGate) and `npm run e2e --prefix web`.
```

In the P3a bullet's known-limit text, if N1 is mentioned, delete it (Settings now covers it).

- [ ] **Step 4: `CHANGELOG.md`.** Under Unreleased, first:

```markdown
- Team keys phase 3b: invitations send a one-time link, and an invitation from someone who can see
  your encryption key carries the team's keys, so you can read at once. Team member lists show who
  has a key, who is waiting and who has none yet; a member waiting for a key can send an owner a
  request. Settings lists the colleague keys your browser trusts, with fingerprints, and re-trusts a
  changed one; it also exports or discards edits stranded for a notebook you lost. A removed member
  can be invited again; a team admin can remove an admin it invited; invitation expiry is checked as
  the invitation is accepted; invitation creation is rate-limited (`ratelimit.invitation_per_hour`,
  default 30); expired invitations' keys are cleaned up. Migration `0023` adds
  `memberships.invited_by`.
```

- [ ] **Step 5: DOX closeout.** Re-read `../AGENTS.md`, then `AGENTS.md`. `internal/backup/AGENTS.md` is unchanged: capsules copy the whole database, so the new column is included and no collection rule changes. `FRONTEND_IMPLEMENTATION_PLAN.md` is unchanged: it has no invitation or key text. Note both in the PR.

- [ ] **Step 6: Commit.**

```bash
git add -A
git commit -m "docs: team keys P3b contracts, spec and DOX; embedded bundle"
```

### Task 12: Browser check: invitations, key status, re-trust, unsent edits

**Files:** Modify `web/e2e/team-keys.e2e.ts`, `UI-VERIFICATION.md`.

**Interfaces:**
- Consumes: the Task 10 UI strings, and `aria-busy` on `.note-list` (Task 9).

- [ ] **Step 1: Helpers.**
  - Change the crypto import to `import { decryptObject, encryptNote, fromBase64, legacyKeyRef, type KeyRef } from "../src/crypto";`.
  - Replace the `Dialog` type and the `page.on("dialog", …)` body in `person`:

```ts
type Dialog = { type: string; text: string | RegExp; answer?: string; seen?: (defaultValue: string, message: string) => void };
```

```ts
  page.on("dialog", (dialog) => {
    const next = who.expected[0];
    const matches = next && dialog.type() === next.type && (typeof next.text === "string" ? dialog.message() === next.text : next.text.test(dialog.message()));
    if (matches) {
      who.expected.shift();
      next.seen?.(dialog.defaultValue(), dialog.message());
      void dialog.accept(next.answer);
      return;
    }
    who.unexpected.push(`${dialog.type()}: ${dialog.message()}`);
    void dialog.dismiss();
  });
```

  - Replace `openTeam` with a version that reloads on an explicit notebook and waits for that load to finish:

```ts
/** Reloads the app on cid (default: the first notebook) and waits until that load has finished. */
async function openTeam(page: Page, name = TEAM, cid?: string) {
  await page.goto("about:blank");
  await page.goto(cid ? `/#/${cid}` : "/");
  await expect(page.locator(".workspace-title")).toHaveText(name);
  await expect(page.locator(".note-list")).toHaveAttribute("aria-busy", "false");
}
```

  - Add after `heldKeys`:

```ts
const SECOND = "Second Team E2E";
const listed = (page: Page) => page.evaluate(async () => ((await (await fetch("/api/v1/containers")).json()) as Array<{ id: string }>).map((entry) => entry.id));

/** This person's own user ID and fingerprint, as their Settings shows them. */
async function ownSettings(page: Page) {
  await page.getByRole("button", { name: "Settings" }).click();
  const code = async (label: RegExp) => (await page.locator("p", { hasText: label }).locator("code").first().textContent())!.trim();
  const values = { userId: await code(/Your user ID/), fingerprint: await code(/Your encryption key fingerprint/) };
  await page.getByRole("button", { name: "← Workspace" }).click();
  return values;
}

/** From the open team, invites userId; returns the link and the message of the link dialog. */
async function inviteFrom(owner: Person, userId: string, carries: RegExp) {
  const shown = { link: "", message: "" };
  owner.expected.push({ type: "prompt", text: /^User ID to invite/, answer: userId });
  await withDialog(owner, { type: "prompt", text: new RegExp(`${carries.source}.*Send this link to the person you invited`, "s"), seen: (value, message) => Object.assign(shown, { link: value, message }) }, () =>
    owner.page.getByRole("button", { name: /Add person/ }).click());
  return shown;
}

/** Opens an invitation link in a fresh load and joins; the token must leave the address bar. */
async function join(who: Person, link: string) {
  await who.page.goto("about:blank");
  await who.page.goto(link);
  await expect(who.page).not.toHaveURL(/invite/);
  await who.page.getByRole("button", { name: "Join team" }).click();
  await expect(who.page.getByText("You joined the team.")).toBeVisible();
}
```

- [ ] **Step 2: The P3b steps.** At the end of `scenario`, add `await p3b(owner, editor, newcomer, cid, senders);`. Then add:

```ts
async function p3b(owner: Person, editor: Person, newcomer: Person, cid: string, senders: Map<string, Uint8Array>) {
  const editorOwn = await ownSettings(editor.page);
  const newcomerOwn = await ownSettings(newcomer.page);
  const ownerDevice = (await vaultOf(owner.page))!.identity!.deviceId;

  // 1. A second team whose invitation carries its key: the editor reads it before any owner reopens it.
  const before = await listed(owner.page);
  await owner.page.getByRole("button", { name: "Admin" }).click();
  await withDialog(owner, { type: "prompt", text: "Team name", answer: SECOND }, () => owner.page.getByRole("button", { name: "Create team" }).click());
  await expect(owner.page.getByRole("combobox", { name: "Team", exact: true })).toContainText(SECOND);
  await owner.page.getByRole("button", { name: "← Workspace" }).click();
  const second = (await listed(owner.page)).find((id) => !before.includes(id))!;
  await openTeam(owner.page, SECOND, second); // the only member: the first key is minted here
  await writePage(owner.page, "Second page", "second comment");
  const sealed = await inviteFrom(owner, editorOwn.userId, /The invitation carries this team's keys, sealed for the key with fingerprint/);
  expect(sealed.message).toContain(editorOwn.fingerprint);
  await owner.page.goto("about:blank"); // no owner tab can sweep meanwhile
  await join(editor, sealed.link);
  await openTeam(editor.page, SECOND, second);
  await expect(editor.page.getByText(WAITING)).toHaveCount(0);
  await readPage(editor.page, "Second page", ["second comment"]);
  const fromInvitation = await editor.page.evaluate(async (id) => (await fetch(`/api/v1/containers/${id}/envelopes`)).json(), second) as Array<{ deviceId: string; envelope: string }>;
  const editorDevice = (await vaultOf(editor.page))!.identity!.deviceId;
  expect(fromInvitation.filter((row) => row.deviceId === editorDevice).map((row) => envelopeSender(fromBase64(row.envelope)))).toEqual([ownerDevice]);
  expect((await heldKeys(editor.page, second, senders)).size).toBe(1);
  await openTeam(owner.page, SECOND, second);
  await expect(owner.page.locator(".member-row", { hasText: "editor" })).toContainText("has key");

  // 2. The removed newcomer is invited back (reactivated, not 409), waits, asks, and gets keys from the sweep.
  await openTeam(owner.page, TEAM, cid);
  const back = await inviteFrom(owner, newcomerOwn.userId, /The invitation carries no keys: you cannot see this person's encryption key yet/);
  await owner.page.goto("about:blank");
  await join(newcomer, back.link);
  await openTeam(newcomer.page, `Notebook ${cid.slice(4, 10)}`, cid);
  await expect(newcomer.page.getByText(WAITING)).toBeVisible();
  let request = "";
  await withDialog(newcomer, { type: "prompt", text: /^Send this to owner\./, seen: (value) => { request = value; } }, () =>
    newcomer.page.getByRole("button", { name: "Ask an owner" }).click());
  expect(request).toContain(newcomerOwn.fingerprint);
  expect(request).toContain(`#/${cid}`);
  await openTeam(editor.page, TEAM, cid);
  await expect(editor.page.locator(".member-row", { hasText: "newcomer" })).toContainText("waiting for key");
  await openTeam(owner.page, TEAM, cid); // the sweep wraps the current key and history
  await expect(owner.page.locator(".member-row", { hasText: "newcomer" })).toContainText("has key");
  await openTeam(newcomer.page, TEAM, cid);
  await readPage(newcomer.page, "After removal", ["after comment"]);

  // 3. A reset deletes the newcomer's identity: members see it has none.
  await owner.page.getByRole("button", { name: "Admin" }).click();
  await owner.page.getByLabel("Confirm your password").fill(OWN);
  await owner.page.getByRole("button", { name: "Authorize user creation and password resets" }).click();
  await expect(owner.page.getByText("Password confirmed for ten minutes.")).toBeVisible();
  owner.expected.push({ type: "prompt", text: "New temporary password for newcomer", answer: TEMPORARY });
  await withDialog(owner, { type: "alert", text: /^Password reset\./ }, () =>
    owner.page.locator(".admin-user", { hasText: "newcomer" }).getByRole("button", { name: "Reset password" }).click());
  await owner.page.goto("about:blank");
  await openTeam(editor.page, TEAM, cid);
  await expect(editor.page.locator(".member-row", { hasText: "newcomer" })).toContainText("no encryption key yet");
  const oldDevice = (await vaultOf(newcomer.page))!.identity!.deviceId;
  await signIn(newcomer.page, "newcomer", TEMPORARY);
  await takeOverPassword(newcomer.page);
  // The vault keeps the old identity until the new one is stored: wait for the new device.
  await expect.poll(async () => (await vaultOf(newcomer.page))?.identity?.deviceId, { timeout: 30_000 }).not.toBe(oldDevice);
  const renewed = await ownSettings(newcomer.page);
  expect(renewed.fingerprint).not.toBe(newcomerOwn.fingerprint);

  // 4. The owner re-trusts the new key in Settings, outside any wrap prompt (opened on the second team, where no wrap targets the newcomer).
  await openTeam(owner.page, SECOND, second);
  await owner.page.getByRole("button", { name: "Settings" }).click();
  const pin = owner.page.locator(".pin-row", { hasText: "newcomer" });
  await expect(pin).toContainText(newcomerOwn.fingerprint);
  await expect(pin).toContainText(renewed.fingerprint);
  await expect(owner.page.locator(".pin-row", { hasText: "editor" })).toContainText(editorOwn.fingerprint);
  await withDialog(owner, { type: "confirm", text: /^Trust newcomer's new encryption key\?/ }, () => pin.getByRole("button", { name: "Trust new key" }).click());
  await expect(pin).toContainText("matches the server");
  // No fingerprint dialog may appear now (unexpected dialogs fail the run): the sweep wraps for the new key.
  await openTeam(owner.page, TEAM, cid);
  await expect(owner.page.locator(".member-row", { hasText: "newcomer" })).toContainText("has key");
  await openTeam(newcomer.page, TEAM, cid);
  await readPage(newcomer.page, "Owner page", ["owner comment"]);

  // 5. An edit stranded on the device for a notebook this account cannot open: exported, then discarded.
  const lost = `cnt_${"z".repeat(26)}`;
  const stranded = await encryptNote(legacyKeyRef((await vaultOf(newcomer.page))!.authSecret), lost, { type: "page", title: "Stranded edit", body: "[]" });
  await newcomer.page.evaluate(({ container, bytes }) => new Promise<void>((resolve, reject) => {
    const open = indexedDB.open("kynotes-web");
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const tx = open.result.transaction("pending", "readwrite");
      tx.objectStore("pending").put({ id: `obj_${"z".repeat(26)}`, containerID: container, version: 1, payload: new Uint8Array(bytes), updatedAt: new Date().toISOString(), keyGeneration: 0 });
      tx.oncomplete = () => { open.result.close(); resolve(); };
      tx.onerror = () => reject(tx.error);
    };
  }), { container: lost, bytes: [...stranded] });
  await newcomer.page.getByRole("button", { name: "Settings" }).click();
  const card = newcomer.page.locator("#unsent-edits");
  await expect(card).toContainText("1 edit(s)");
  const download = newcomer.page.waitForEvent("download");
  await card.getByRole("button", { name: "Export unsent edits" }).click();
  expect(JSON.parse(readFileSync(await (await download).path()).toString())).toEqual([expect.objectContaining({ notebook: lost, content: expect.objectContaining({ title: "Stranded edit" }) })]);
  await withDialog(newcomer, { type: "confirm", text: /^Delete 1 unsent edit/ }, () => card.getByRole("button", { name: "Discard unsent edits" }).click());
  await expect(card).toHaveCount(0);
  await newcomer.page.getByRole("button", { name: "← Workspace" }).click();

  // 6. A click on the notebook the app is still opening on its own leaves it loaded (one load wins).
  await editor.page.goto("about:blank");
  await editor.page.goto(`/#/${cid}`);
  await editor.page.getByRole("button", { name: TEAM, exact: true }).click();
  await expect(editor.page.locator(".note-list")).toHaveAttribute("aria-busy", "false");
  await expect(editor.page.locator(".note-row", { hasText: "Owner page" })).toBeVisible();
}
```

Selectors follow the Task 10 strings and the existing admin UI (`ConfirmPassword`, `.admin-user`, `Reset password`). If the UI moved, fix selectors only, never assertions.

- [ ] **Step 3: Run.** After Task 11's bundle sync, run `npm run e2e --prefix web`. Expected: `1 passed`. Each run needs a fresh server.

- [ ] **Step 4: Visual pass (Playwright MCP, scratch server only).** Check at 1280×900 and 390×844, in Busnes Light and Dark:
  - The join banner, the waiting line with "Ask an owner", and the member-row status suffixes render without overflow.
  - The Settings "Colleague keys" rows (`.pin-row`, both fingerprints, the button) wrap inside their card at 390 px.
  - The "Unsent edits" card fits at 390 px.

  Save the screenshots next to the existing ones, and add a "Team keys P3b" section to `UI-VERIFICATION.md` with the capture conditions, matching the P3a section.

- [ ] **Step 5: Commit.**

```bash
git add web/e2e/team-keys.e2e.ts UI-VERIFICATION.md docs
git commit -m "web: browser check for invitations, key status, re-trust and unsent edits"
```

### Task 13: Final verification

- [ ] **Step 1:** Run `go build ./... && go vet ./... && test -z "$(gofmt -l .)" && go test -race ./... && govulncheck ./...`.
- [ ] **Step 2:** Run `cd web && npm test && npm run build && node src/ky-ui/check-vendor.mjs && cd .. && diff -qr web/dist internal/web/dist && npm run e2e --prefix web`.
- [ ] **Step 3: Mutations.** Start from a clean tree. Apply each mutation alone, run the named test and confirm it fails, then revert with `git checkout -- <file>`. Rebuild and re-sync the bundle before each e2e mutation. Paste the failures into the PR.

| Mutation | Must fail |
|---|---|
| `collab_routes.go` accept: drop ` AND expires_at>?` (and its argument) | `TestAcceptChecksExpiryAndInviteeInsideItsTransaction` |
| `collab_routes.go` accept: drop ` AND invitee_id=?` (and its argument) | `TestAcceptChecksExpiryAndInviteeInsideItsTransaction` |
| `admitMemberTx`: delete the `UPDATE memberships …` statement | `TestRemovedMemberIsReadmittedByReactivation` |
| `admitMemberTx`: live check without `AND revoked_at=''` | `TestRemovedMemberIsReadmittedByReactivation` |
| `admitMemberTx`: `UPDATE` without `,invited_by=?5` | `TestTeamAdminRemovesOnlyAdminsItInvited` |
| removal: `&& invitedBy != s.UserID` → `&& true` | `TestTeamAdminRemovesOnlyAdminsItInvited` |
| removal: `&& invitedBy != s.UserID` → `&& false` | `TestTeamAdminRemovesOnlyAdminsItInvited` |
| `ratelimit.go`: delete the invitation `case` | `TestInvitationCreationIsRateLimitedPerCaller` |
| `gc.go`: delete the `invitation_envelopes` delete | `TestGCDeletesEnvelopesOfExpiredInvitations` |
| `inviteWithKeys`: skip the `changed.length` block | `keyService.test.ts` asks before sealing for a changed invitee key… |
| `inviteWithKeys`: delete `await api.stepUp();` | `keyService.test.ts` seals the team's current key… |
| `inviteWithKeys`: delete `if (!stored.ok) return plain(…);` | `keyService.test.ts` never sends keys whose recipient pin… and …another pass pinned a different key… |
| `inviteWithKeys`: `stored.conflicts.length ? "untrusted" : "pins-unsaved"` → `"pins-unsaved"` | `keyService.test.ts` …another pass pinned a different key… |
| `inviteWithKeys`: `!keysAllowed(…)` → `false` | `keyService.test.ts` sends no keys for a team this device saw at a later sharing state… |
| `inviteWithKeys`: `container.sharedGeneration > 0 ?` → `true ?` | `keyService.test.ts` invites without keys when it… holds no current key |
| `memberKeyStatus`: drop the `row.keyGeneration === container.keyGeneration` filter | `keyring.test.ts` reports has key, waiting… |
| `stuckSaves`: `live ? … : []` → `queued.filter((item) => !live?.has(item.containerID))` | `stuckEdits.test.ts` …none when the list is unknown |
| `loadGate`: `latest !== ticket` → `false` | `loadGate.test.ts` lets only the newest load finish… |
| `PinnedKeys.trust`: `storeConfirmedPin(username, userID, confirmation)` → `storePins(username, userID, confirmation.pins)` | e2e step 4 (row stays changed, or the later open raises an unexpected fingerprint dialog) |
| `main.tsx` `invite()`: call `inviteMember(team.id, userID, "editor")` directly | e2e step 1 (the editor waits for keys) |

Expected survivor (record it in the PR if it survives): reverting the `loadGate` wiring in `main.tsx` may still pass the e2e smoke in step 6, because the race window is timing-dependent. `loadGate.test.ts` "main.tsx load wiring" is the deterministic gate.

- [ ] **Step 4:** Open the PR with the `pull-request` skill, stacked on `feat/team-keys-p3`. In the body include the resolved ambiguities, the mutation evidence, the e2e result, the docs left unchanged and why, and the note that P3c's migration is now `0024`.
