# Sub-project A (Administrator Accounts Apart from Everyday Accounts) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An account is either an administrator account or an everyday account, for good. Administrator sessions reach the admin API and nothing that holds notes or keys. Everyday sessions never reach the admin API. A password someone else set must be replaced before it acts for anyone. Teams an administrator creates belong to an everyday owner, and an administrator never gets a team's keys, not even through an account it controls.

**Architecture:** Migration `0026_account_kinds.sql` adds a fixed `users.account_kind` and `memberships.approved`, turns mixed administrators into everyday accounts that keep their notes, and installs triggers so the database refuses an admin grant on an everyday account and any content row for an administrator. In `internal/auth`, `RequireSession`, `RequireEither` and `RequireDevice` admit only everyday accounts, and `RequireAdmin` admits only admin accounts. The few account routes both kinds need move to a new `RequireAccount`. The same middleware refuses every route but those account routes while a password session's password is administrator-known. A route-inventory test makes every new route take a class. SSO, directory sync and `apply-setup` keep the kinds apart at sign-in and provisioning. The web client routes administrator sessions to a key-free `AdminConsole`, forces the password change before anything else, and lets stewards approve administrator-added members before any key reaches them.

**Tech Stack:** Go 1.26 (`net/http`, SQLite via `modernc`), TypeScript/React (Vite, vitest), `@playwright/test` 1.63.0. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-08-admin-separation-design.md` (every section). Background: `docs/superpowers/specs/2026-10-07-team-keys-design.md` §1 "Admin-created accounts", §3 "Create a team (with sub-project A)", §6 "Admin separation", §9 ruling 11, "P5 as built" rulings 18 and 25; `docs/SSO.md` "Application roles"; `docs/INSTALLER.md` "Identity".

Conventions follow `docs/superpowers/plans/2026-10-08-team-keys-p5.md`.

**Evidence status:** this plan was **not** prototyped. The code blocks were written against `c059649` and re-read against the final P5 head `93b2565` in the pre-flight (`.superpowers/sdd/2026-10-08-admin-separation/preflight.md`, amendments A1–A13). None was compiled or run, so each task's own test step is the first proof. If a block does not compile, fix the code and keep the test's assertions. These facts were checked by reading the tree:
- Content routes use `auth.RequireSession`, `RequireEither`, `RequireDevice` or `RequireUserActionStepUp`, which wraps `RequireSession`. Admin routes use `RequireAdmin`/`RequireStepUp`, and `RequireStepUp` wraps `RequireAdmin`. The routes both kinds need also use `RequireSession` today: `GET /auth/session` (`handleSession`), `POST /auth/logout`, `/auth/logout-all`, `/auth/password` and `/auth/step-up` (`auth_routes.go`), and OIDC step-up `POST`, `GET {id}` and `DELETE {id}` (`sso_routes.go:139-151`).
- `ResolveSession` (`internal/auth/session.go:107`) already joins `users`, so the kind and the change flag cost one more column each.
- `WriteAuthError` maps codes to statuses in one `switch` (`middleware.go:165`). `forbidden` and `step_up_required` are 403, and the default is 401.
- Fixtures that turn a content user into an administrator: `teamkeys_test.go:650`, `teamkeys_p3b_test.go:70,219,241`, `identity_test.go:335,382`, `teamkeys_p3c_test.go:1041`, `teamkeys_p5_test.go:674`, `admin_team_test.go:14`, `sso_stepup_test.go:22`. Fixtures that insert `role='admin'` users: `sso_test.go`, `sso_app_roles_test.go`, `internal/storage/sso_roles_upgrade_test.go`, `internal/backup/service_test.go`, `cmd/kynotes-server/backup_test.go`, `cmd/kynotes-server/backup_socket_test.go`.
- Production paths that create administrators: `auth_routes.go` `/setup`, `internal/app/bootstrap.go`, `cmd/kynotes-server/main.go` `user add --admin`, `admin_routes.go` `POST /admin/users`, `apply_setup.go` `createSSOAdmin`/`grantAdmin`, `sso_directory.go` create and update.
- `POST /admin/teams` inserts the caller's `owner` membership, so the Task 1 triggers break it until Task 1 changes it. That is why the owner change lands in Task 1.
- `planSweep` (`web/src/keyring.ts:217`) wraps for every member with an identity. `MemberKey = Member & {identity?}`, and `Member = {userId, username, role}`.
- `GET /containers/{id}/members` answers `map[string]string` (`collab_routes.go:28-50`), and since P5 `93b2565` adds `keyResetAt` to each row for a steward caller. `web/src/api.ts` `members` returns the rows as `Member[]` with no mapping.
- P5 `763e9cc` `retireKeysTx` (`teamkeys_routes.go`) advances `key_generation` in every keyed container the resetting user is a live member of, at most 3 resets a day (`checkResetLimitTx`).
- The server admin member add (`admin_routes.go:86`) accepts role `admin`, a steward role: a steward may invite, remove, rotate and wrap.
- `logging.Logger` drops every attribute whose key is not in its allowlist (`internal/logging/logger.go:9`); a `remedy` attribute never reaches the log.
- The web `PasswordSettings.submit` calls `rewrapIdentity`, whose first call is `GET /api/v1/me/identity` (`identity.ts:61`); `myIdentity` throws on anything but 200/404.
- `RequireFresh` has no caller.
- The e2e server is shared by every `*.e2e.ts` file in one run (`playwright.config.ts`, `workers: 1`, one `webServer`), and `/setup` can run only once per server.
- Task 1 changes `POST /admin/teams` and the setup insert under the browser, so `npm run e2e` fails from Task 1 until Task 11 adapts it. `go test ./...` and `npm test` pass at the end of every task.
- The probe signs in an everyday account created by `user add` without `--admin` (`.github/workflows/ci.yml:80`). It already treats a `409 password_change_required` at identity create as "take the password over" (`cmd/kynotes-probe/main.go:157`). Its first content call is `GET /me/identity`, and any non-200 answer falls through to that path.

---

## Global Constraints

| Item | Exact value |
|---|---|
| Migration | `internal/storage/migrations/0026_account_kinds.sql`: `users.account_kind TEXT NOT NULL DEFAULT 'user' CHECK(account_kind IN ('user','admin'))`; `memberships.approved INTEGER NOT NULL DEFAULT 1 CHECK(approved IN (0,1))`; the mixed-account step; triggers `users_account_kind_fixed`, `users_admin_role_insert`, `users_admin_role_update`, `memberships_everyday_only`, `memberships_everyday_only_update`, `containers_everyday_owner`, `containers_everyday_owner_update`, `devices_everyday_only`, `devices_everyday_only_update` (the content triggers fail closed: they raise unless an everyday account with that ID exists) |
| Trigger messages | `account_kind_fixed`, `admin_role_needs_admin_account`, `admin_account_holds_no_content` |
| Mixed account | `role='admin'` AND (a `memberships` row for the user, revoked included, OR a `user_identities` row OR a `containers` row with `owner_user_id` = the user) |
| Audit | `account.kind_upgrade` (migration; reason `kind=admin` or `kind=user,admin_dropped=true`), `container.member_approve`, `auth.sso_admin_refused` (reason `admin_account_not_provisioned`, `admin_role_on_everyday_account` or `admin_role_required`) |
| Go constants | `auth.KindEveryday = "user"`, `auth.KindAdmin = "admin"` |
| New error codes | `403 admin_account` ("administrator accounts cannot open notes; sign in with your everyday account"); `403 admin_account_not_provisioned`; `403 admin_role_on_everyday_account`; `403 admin_role_required`; `409 account_kind_mismatch` |
| Broadened code | `409 password_change_required` now answers every content and admin route for a password session while `password_admin_known=1` |
| Account routes (`auth.RequireAccount`) | `GET /api/v1/auth/session`, `GET /api/auth/session`, `POST /api/v1/auth/logout`, `POST /api/auth/logout`, `POST /api/v1/auth/logout-all`, `POST /api/v1/auth/password`, `POST /api/v1/auth/step-up`, `POST /api/v1/auth/oidc/step-up`, `GET /api/v1/auth/oidc/step-up/{id}`, `DELETE /api/v1/auth/oidc/step-up/{id}` |
| Fence-exempt content route (`auth.RequireEveryday`) | `GET /api/v1/me/identity` only: everyday accounts only (`403 admin_account`), but not fenced, because the forced change reads the live identity to re-add a stripped password copy (`rewrapIdentity`). It returns public fields only |
| Session fields | `auth.Session.AccountKind string`, `auth.Session.PasswordChangeRequired bool` (`password_admin_known=1` and `SSOIssuer==""`) |
| Response fields | login and `GET /auth/session`: `user.accountKind`, `passwordChangeRequired`; `GET /admin/users` rows: `accountKind`; `GET /containers/{id}/members` rows: `approved` (bool); `GET /admin/teams` rows: `id`, `ownerUserId`, `ownerUsername`, `memberCount`, `keyed`, `named` (no `metaCiphertext`); directory readback: `accountKind` |
| Changed routes | `POST /api/v1/setup` `{"admin":{"username","authSecret","loginSalt","iterations"},"everyday":{…}}`; `POST /api/v1/admin/users` `{"username","authSecret","loginSalt","iterations","accountKind"}`; `POST /api/v1/admin/teams` `{"ownerUserId"}` + `auth.RequireStepUp`; `POST /api/v1/admin/teams/{id}/members` + `auth.RequireStepUp`, admits with `approved=0`, role `editor`, `commenter` or `viewer` only (`admin` is `400`: an unapproved steward could approve itself, rotate or wrap); `retireKeysTx` (P5 reset) retires only containers where the user's membership is approved |
| New route | `POST /api/v1/containers/{id}/members/{userID}/approve`: everyday session, CSRF, caller an approved owner/admin of team `id` → 204; audit `container.member_approve` |
| Web strings | `ADMIN_ACCOUNT_NOTE = "This is an administrator account. It manages KyNotes and cannot open notes. Sign in with your everyday account to write."`; `CHOOSE_PASSWORD = "An administrator set this account's password. Choose your own before you continue."`; `UNNAMED_TEAM = "An administrator created this team notebook for you. Name it so its members can find it."`; `approvalText(name)`: "<name> was added by an administrator. They get this notebook's keys only after you approve them."; buttons `Name notebook`, `Approve and share keys` |
| Setup form labels | `Administrator username`, `Administrator password`, `Confirm administrator password`, `Everyday username`, `Everyday password`, `Confirm everyday password`; button `Initialize KyNotes` |
| Unchanged (checked) | Envelope v2, pins, `openKeyring`, the save gate, rotation rules other than the approved filter, P5 recovery, D-P5-1/D-P5-2, the SSO step-up scopes, `revokeForRoleChange`, the last-active-admin retention (now admin accounts only) |
| Out of scope | Team ownership transfer; an administrator-visible team label; a UI to split a mixed account; shorter admin sessions; KyIdentity-side enforcement |

## Resolved ambiguities (recorded in the spec §11)

### 1. The kind is a fixed column; the grant stays `role`
An `admin` account without the grant is inert, so revoking the grant never changes the kind.

### 2. Default-deny in the middleware, plus a route inventory
`RequireSession` refuses admin accounts, so a new content route is safe without touching its handler. `TestEveryRouteRefusesTheOtherKind` reads every `"METHOD /path"` literal in `internal/httpapi/*.go` and fails when a route is in the wrong class.

### 3. Triggers back every invariant; handlers answer first
Handlers check first and give clean codes (`404`, `409 account_kind_mismatch`). The triggers turn a handler that forgets into a `500`, never into a stored row.

### 4. The first-sign-in change fences everything but the account routes, for password sessions only

### 5. Admin accounts hold no device credentials
The migration revokes existing ones, a trigger stops new ones, `resolveDevice` skips admin accounts, and registration refuses an admin account's pairing token.

### 6. Administrators never name a team; the owner does on first open

### 7. Administrator-added members wait for a steward's approval

### 8. Team creation and administrator member add need the admin step-up

### 9. `kynotes.admin` on an everyday account refuses sign-in

### 10. Automatic provisioning never creates an admin account, and refuses a token with the role

### 11. Directory creation decides the kind; later events move only the grant

### 12. `apply-setup` reports `conflict` for a subject bound to an everyday account

### 13. Web setup creates both accounts, unflagged, and signs in as the administrator

### 14. Mixed accounts drop the grant even when none remain; `no_active_admin` names the CLI remedy

### 15. Admin browsers keep no IndexedDB record

### 16. `GET /admin/teams` carries no name ciphertext

## Needs Yoshi's decision

The safest option is picked and built for each. Details are in spec §12.

1. Steward approval for administrator-added members (built), against automatic wrapping.
2. Refusing sign-in for an everyday identity carrying `kynotes.admin` (built), against ignoring the claim.
3. No administrator-visible team label (built), against a plaintext label.
4. Mixed accounts drop the grant even when no administrator remains (built), against keeping one mixed administrator.
5. Not built, raised by the pre-flight: an administrator can still take over an approved member that has no identity yet, by resetting its local password (or, holding the SSO settings, by pointing directory sync at its own HMAC secret and linking the unbound local account), and that account's first identity is pinned on first contact, so the sweep wraps for it. The spec §10 residual claimed "it reaches no existing key"; Task 10 corrects it. Options: accept (the person loses their own sign-in, which is visible), or step-up on `POST /admin/sso` and `/admin/sso/pair` plus a steward confirmation for any member's first identity.

## Review Focus (likely failure modes and their pinning tests)

1. **A route added later with the wrong middleware.** It must fail CI, not ship. Pinned by `TestEveryRouteRefusesTheOtherKind` (Task 2), which drives every route literal it finds with both kinds of session.
2. **An administrator signs in through KyIdentity before `apply-setup` ran.** No everyday account may appear for that subject. Pinned by `TestSSOKindsFollowTheToken` case `unprovisioned admin` (Task 6).
3. **The first-run person types the same password for both accounts, or the same username.** Setup must refuse it before anything is created. Pinned by `setup.test.ts` "refuses equal passwords and equal usernames" (Task 7) and `TestSetupCreatesBothAccounts` (`same username`, Task 3).
4. **A temporary-password user reloads the tab mid-change.** The reload must land on the change screen again, not on the workspace. Pinned by the e2e step "a reload keeps the change screen" (Task 11) and `TestPasswordChangeIsForcedAtFirstSignIn` (`GET /auth/session` reports it, Task 2).
5. **A steward removes and re-adds an approved member through the admin route.** Re-admission must reset approval. Pinned by `TestAdminAddedMembersWaitForApproval` (`readmitted`, Task 5).
6. **An administrator adds an account it controls as a team `admin`.** An unapproved steward could approve itself, rotate in a key it knows, or wrap for others. The admin add refuses steward roles (`400`). Pinned by `TestAdminTeamAccessNeedsStepUpAndListsNoNames` (`steward role`, Task 4).
7. **A temporary-password everyday user on the change screen.** The change reads `GET /me/identity` first; a fenced read would strand every administrator-created user on that screen. Pinned by `TestPasswordChangeIsForcedAtFirstSignIn` (`identity read`, Task 2) and e2e step 3.
8. **An unapproved member resets its own key.** P5's `retireKeysTx` would retire the team's key three times a day for an account an administrator controls. Pinned by `TestAdminAddedMembersWaitForApproval` (`unapproved reset`, Task 5).

---

## File Map

| File | Change |
|---|---|
| `internal/storage/migrations/0026_account_kinds.sql` | New (Task 1) |
| `internal/storage/account_kinds_test.go` | New (Task 1) |
| `internal/storage/sso_roles_upgrade_test.go` | `kept` owned by a plain user; re-grant asserted refused (Task 1) |
| `internal/httpapi/admin_routes.go` | Team create owner (Task 1); users/teams API, step-ups, approved=0 (Task 4) |
| `internal/httpapi/admin_team_test.go` | Rewritten (Task 1), extended (Task 4) |
| `internal/httpapi/teamkeys_test.go` | `addAdmin` helper (Task 1) |
| Fixture files listed in the evidence | Separate admin accounts (Task 1) |
| `internal/auth/session.go`, `internal/auth/middleware.go` | Kinds, fence, `RequireAccount` (Task 2) |
| `internal/auth/kinds_test.go` | New (Task 2) |
| `internal/httpapi/auth_routes.go`, `sso_routes.go`, `device_routes.go`, `identity_routes.go` | Account routes on `RequireAccount`; `GET /me/identity` on `RequireEveryday`; register refuses admin tokens (Task 2); setup, login, session fields (Task 3) |
| `internal/httpapi/account_kinds_test.go` | New: inventory, fence, setup (Tasks 2, 3) |
| `internal/app/bootstrap.go`, `internal/app/serve.go`, `cmd/kynotes-server/main.go`, `cmd/kynotes-probe/main.go` | Kinds, `no_active_admin`, probe check (Task 3) |
| `internal/httpapi/teamkeys_routes.go`, `collab_routes.go`, `container_routes.go` | `admitMemberTx(approved)`, approve route, filters, `retireKeysTx` approved scope, `approved` in members, child copies (Task 5) |
| `internal/httpapi/approval_test.go` | New (Task 5) |
| `internal/httpapi/sso_routes.go`, `sso_directory.go`, `apply_setup.go`, `internal/applysetup/decide.go` | Kind rules (Task 6) |
| `internal/httpapi/sso_kinds_test.go`, `internal/applysetup/decide_test.go` | New / extended (Task 6) |
| `web/src/api.ts`, `web/src/setup.ts`, `setup.test.ts`, `web/src/main.tsx` | Types, setup form, `App` routing, `ChoosePassword` (Task 7) |
| `web/src/components/AdminConsole.tsx`, `web/src/adminSeparation.test.ts`, `web/src/observe.ts`, `observe.test.ts`, `keyring.test.ts`, `api.test.ts`, `workspaceWiring.test.ts` | Console extraction (Task 8) |
| `web/src/keyring.ts`, `keyring.test.ts`, `web/src/main.tsx` | Approval in the sweep, banners (Task 9) |
| `IMPLEMENTATION_PLAN.md`, `DESIGN.md` | Frozen contracts, in Tasks 1–6 |
| `docs/SSO.md`, `docs/INSTALLER.md`, the team-keys spec, `AGENTS.md`, `CHANGELOG.md`, `internal/web/dist/` | Task 10 |
| `web/e2e/people.ts`, `web/e2e/admin-separation.e2e.ts`, `web/e2e/team-keys.e2e.ts`, `UI-VERIFICATION.md` | Task 11 |

## Interfaces

```go
// internal/auth
const KindEveryday, KindAdmin = "user", "admin"
type Session struct { /* existing */ AccountKind string; PasswordChangeRequired bool }
func RequireAccount(db *sql.DB, next http.Handler) http.Handler   // any live session, any kind, fence not applied
func RequireEveryday(db *sql.DB, next http.Handler) http.Handler  // everyday kind, fence not applied: GET /me/identity only
func RequireSession(db *sql.DB, next http.Handler) http.Handler   // everyday + fence
func RequireEither(db *sql.DB, next http.Handler) http.Handler    // everyday device, or everyday session + fence
func RequireAdmin(db *sql.DB, next http.Handler) http.Handler     // admin kind + fence + SessionRole=="admin"
func SessionRole(db *sql.DB, s Session) (string, error)           // adds account_kind='admin'

// internal/httpapi
func admitMemberTx(tx *sql.Tx, cid, userID, role, invitedBy string, approved bool, now string) (readmit bool, err error)
func (p *pairClient) addAdmin(t *testing.T, username string) member   // test helper
func seedSSOAdmin(f *logoutFixture, subject string) string            // test helper: admin account bound to subject, returns ID

// internal/applysetup
type Account struct { ID, Username, Role, Status, Kind string }
```

```ts
// web/src/api.ts
export type AccountKind = "user" | "admin";
export type User = { id: string; role: string; username?: string; accountKind: AccountKind };
export type Session = { sso?: boolean; user: User; passwordChangeRequired?: boolean; expiresAt: string; hardExpiresAt: string };
export type AdminUser = { id: string; username: string; role: string; accountKind: AccountKind; status: string; quotaBytes: number; createdAt: string };
export type AdminTeam = { id: string; ownerUserId: string; ownerUsername: string; memberCount: number; keyed: boolean; named: boolean };
export function createAdminTeam(ownerUserId: string): Promise<AdminTeam>;
export function approveMember(containerID: string, userID: string): Promise<void>;
export function setupInit(admin: SetupAccount, everyday: SetupAccount): Promise<{ ok: boolean; user: User; expiresAt: string; hardExpiresAt: string }>;
export type SetupAccount = { username: string; authSecret: string; loginSalt: string; iterations: number };
// web/src/setup.ts
export function setupProblem(input: { admin: string; adminPassword: string; adminConfirm: string; everyday: string; everydayPassword: string; everydayConfirm: string }): string | undefined;
// web/src/keyring.ts
export type Member = { userId: string; username: string; role: string; approved?: boolean };
export type MemberKeyStatus = "has-key" | "waiting" | "no-identity" | "unapproved";
```

---

### Task 1: Schema: account kinds, mixed accounts, content invariants; teams get an everyday owner

**Files:**
- Create: `internal/storage/migrations/0026_account_kinds.sql`, `internal/storage/account_kinds_test.go`
- Modify: `internal/storage/sso_roles_upgrade_test.go`
- Modify: `internal/httpapi/auth_routes.go` (setup insert), `internal/app/bootstrap.go`, `cmd/kynotes-server/main.go` (`user add`), `internal/httpapi/admin_routes.go` (`POST /admin/users` insert, `POST /admin/teams`), `internal/httpapi/apply_setup.go` (`createSSOAdmin`), `internal/httpapi/sso_directory.go` (create)
- Modify: `internal/httpapi/teamkeys_test.go` (`addAdmin`), `internal/httpapi/admin_team_test.go`, and every fixture file in the evidence list
- Modify: `IMPLEMENTATION_PLAN.md` §1.13 migration list and §3.2 schema notes, the `POST /admin/teams` row; `DESIGN.md` "Administrators may manage users…" paragraph

**Interfaces:**
- Consumes: `migrationFS`, `Open` (storage); `newPairClient`, `addUser`, `mint`, `status`, `quote`, `seedContainer` (httpapi tests).
- Produces: the migration and triggers in Global Constraints; `(*pairClient).addAdmin`; `POST /admin/teams {"ownerUserId"}` (step-up comes in Task 4).

- [ ] **Step 1: Write the failing storage tests.** Create `internal/storage/account_kinds_test.go`:

```go
package storage

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func mustFail(t *testing.T, db *sql.DB, want, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("%s: want %q, got %v", q, want, err)
	}
}

func TestAccountKindsHoldTheirInvariants(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "kinds.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	db := st.DB()
	user := `INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,account_kind,created_at,updated_at) VALUES(?,?,'h','s',1,?,?,'now','now')`
	for _, row := range [][]any{{"usr_admin", "admin", "admin", "admin"}, {"usr_plain", "plain", "user", "user"}, {"usr_inert", "inert", "user", "admin"}} {
		if _, err := db.Exec(user, row...); err != nil {
			t.Fatal(err)
		}
	}
	mustFail(t, db, "CHECK", user, "usr_bad", "bad", "user", "root")
	mustFail(t, db, "admin_role_needs_admin_account", user, "usr_mixed", "mixed", "admin", "user")
	mustFail(t, db, "admin_role_needs_admin_account", `UPDATE users SET role='admin' WHERE id='usr_plain'`)
	mustFail(t, db, "account_kind_fixed", `UPDATE users SET account_kind='admin' WHERE id='usr_plain'`)
	mustFail(t, db, "account_kind_fixed", `UPDATE users SET account_kind='user',role='user' WHERE id='usr_admin'`)
	if _, err := db.Exec(`UPDATE users SET role='user' WHERE id='usr_admin'`); err != nil {
		t.Fatal("revoking the grant must stay possible", err)
	}
	if _, err := db.Exec(`UPDATE users SET role='admin' WHERE id='usr_inert'`); err != nil {
		t.Fatal("granting an admin account must stay possible", err)
	}
	if _, err := db.Exec(`INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at) VALUES('cnt_plain','workbook','usr_plain','now','now')`); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"usr_admin", "usr_inert"} {
		mustFail(t, db, "admin_account_holds_no_content", `INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at) VALUES(?,'workbook',?,'now','now')`, "cnt_"+id, id)
		mustFail(t, db, "admin_account_holds_no_content", `INSERT INTO memberships(id,container_id,user_id,role,created_at) VALUES(?,'cnt_plain',?,'viewer','now')`, "mem_"+id, id)
		for _, platform := range []string{"identity", "unknown"} {
			mustFail(t, db, "admin_account_holds_no_content", `INSERT INTO devices(id,user_id,public_key,fingerprint,secret_hash,platform,created_at) VALUES(?,?,'k',?,'h',?,'now')`, "dev_"+id+platform, id, id+platform, platform)
		}
	}
	if _, err := db.Exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at) VALUES('mem_plain','cnt_plain','usr_plain','owner','now')`); err != nil {
		t.Fatal("an everyday member must still be admitted", err)
	}
	if _, err := db.Exec(`INSERT INTO devices(id,user_id,public_key,fingerprint,secret_hash,platform,created_at) VALUES('dev_plain','usr_plain','k','fp','h','unknown','now')`); err != nil {
		t.Fatal(err)
	}
	// A later ownership transfer or re-point must not move content onto an administrator account.
	mustFail(t, db, "admin_account_holds_no_content", `UPDATE containers SET owner_user_id='usr_admin' WHERE id='cnt_plain'`)
	mustFail(t, db, "admin_account_holds_no_content", `UPDATE memberships SET user_id='usr_admin' WHERE id='mem_plain'`)
	mustFail(t, db, "admin_account_holds_no_content", `UPDATE devices SET user_id='usr_admin' WHERE id='dev_plain'`)
	// Fail closed: an unknown account holds nothing either, even where foreign keys are off (openBefore's raw connection).
	mustFail(t, db, "admin_account_holds_no_content", `INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at) VALUES('cnt_ghost','workbook','usr_ghost','now','now')`)
	var approved int
	if err := db.QueryRow(`SELECT approved FROM memberships WHERE id='mem_plain'`).Scan(&approved); err != nil || approved != 1 {
		t.Fatal("memberships default to approved", approved, err)
	}
}

// Migrations before 0026 build a database the way an earlier build left it.
func openBefore(t *testing.T, version int) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "upgrade.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	files, err := migrationFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		var v int
		if _, err := fmt.Sscanf(f.Name(), "%04d_", &v); err != nil {
			t.Fatal(err)
		}
		if v >= version {
			continue
		}
		b, err := migrationFS.ReadFile("migrations/" + f.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(b)); err != nil {
			t.Fatal(f.Name(), err)
		}
		if _, err := db.Exec(`INSERT INTO schema_migrations VALUES(?,'now')`, v); err != nil {
			t.Fatal(err)
		}
	}
	return db, path
}

func TestMixedAdminsKeepTheirNotesAndDropAdmin(t *testing.T) {
	db, path := openBefore(t, 26)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(q, err)
		}
	}
	for _, u := range [][]string{{"member", "admin"}, {"keyholder", "admin"}, {"owner", "admin"}, {"clean", "admin"}, {"plain", "user"}} {
		exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,created_at,updated_at) VALUES(?,?,'h','s',1,?,'now','now')`, u[0], u[0], u[1])
	}
	exec(`INSERT INTO containers(id,kind,owner_user_id,meta_ciphertext,created_at,updated_at) VALUES('team','team','plain',x'01','now','now'),('mine','workbook','owner',x'02','now','now')`)
	exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at,revoked_at) VALUES('m1','team','member','editor','now','gone')`)
	exec(`INSERT INTO devices(id,user_id,public_key,fingerprint,secret_hash,platform,created_at) VALUES('idk','keyholder','k','f1','h','identity','now'),('phone','clean','k','f2','h','unknown','now')`)
	exec(`INSERT INTO user_identities(user_id,device_id,wrapped_private_key,wrap_alg,created_at,updated_at) VALUES('keyholder','idk',x'00','aes-256-gcm','now','now')`)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	want := map[string][2]string{"member": {"user", "user"}, "keyholder": {"user", "user"}, "owner": {"user", "user"}, "clean": {"admin", "admin"}, "plain": {"user", "user"}}
	for id, kr := range want {
		var kind, role string
		if err := st.DB().QueryRow(`SELECT account_kind,role FROM users WHERE id=?`, id).Scan(&kind, &role); err != nil || kind != kr[0] || role != kr[1] {
			t.Fatalf("%s kind=%s role=%s err=%v", id, kind, role, err)
		}
	}
	var meta string
	var rows int
	if err := st.DB().QueryRow(`SELECT hex(meta_ciphertext) FROM containers WHERE id='mine' AND owner_user_id='owner'`).Scan(&meta); err != nil || meta != "02" {
		t.Fatal("a mixed account's notebook changed", meta, err)
	}
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM memberships WHERE id='m1' AND user_id='member'`).Scan(&rows); err != nil || rows != 1 {
		t.Fatal("a mixed account's membership changed", rows, err)
	}
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM user_identities WHERE user_id='keyholder'`).Scan(&rows); err != nil || rows != 1 {
		t.Fatal("a mixed account's identity changed", rows, err)
	}
	var revoked, identityRevoked string
	if err := st.DB().QueryRow(`SELECT revoked_at FROM devices WHERE id='phone'`).Scan(&revoked); err != nil || revoked == "" {
		t.Fatal("an admin account kept a device credential", err)
	}
	if err := st.DB().QueryRow(`SELECT revoked_at FROM devices WHERE id='idk'`).Scan(&identityRevoked); err != nil || identityRevoked != "" {
		t.Fatal("an everyday identity was revoked", err)
	}
	reasons := map[string]string{}
	q, err := st.DB().Query(`SELECT object_id,reason_code FROM audit_events WHERE event='account.kind_upgrade'`)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	for q.Next() {
		var id, reason string
		if err := q.Scan(&id, &reason); err != nil {
			t.Fatal(err)
		}
		reasons[id] = reason
	}
	for _, id := range []string{"member", "keyholder", "owner"} {
		if reasons[id] != "kind=user,admin_dropped=true" {
			t.Fatalf("%s audit %q", id, reasons[id])
		}
	}
	if reasons["clean"] != "kind=admin" || reasons["plain"] != "" {
		t.Fatalf("audits %v", reasons)
	}
}
```

- [ ] **Step 2: Run them and see them fail.** Run: `go test ./internal/storage -run 'TestAccountKinds|TestMixedAdmins' -v`. Expected: FAIL (`no such column: account_kind`).

- [ ] **Step 3: Write the migration.** Create `internal/storage/migrations/0026_account_kinds.sql`:

```sql
-- Sub-project A: an account is an administrator account or an everyday account, for good.
-- users.role stays the administrator grant, allowed only on an administrator account.
ALTER TABLE users ADD COLUMN account_kind TEXT NOT NULL DEFAULT 'user' CHECK(account_kind IN ('user','admin'));
-- Administrator-added members get no key until a steward of the team approves them.
ALTER TABLE memberships ADD COLUMN approved INTEGER NOT NULL DEFAULT 1 CHECK(approved IN (0,1));

-- A mixed account (the grant plus notes) keeps its notes and loses the grant.
INSERT INTO audit_events(id,user_id,actor_user_id,object_id,event,created_at,at,outcome,reason_code)
SELECT 'aud_'||lower(hex(randomblob(16))), u.id, u.id, u.id, 'account.kind_upgrade',
 strftime('%Y-%m-%dT%H:%M:%SZ','now'), strftime('%Y-%m-%dT%H:%M:%SZ','now'), 'success',
 CASE WHEN EXISTS(SELECT 1 FROM memberships m WHERE m.user_id=u.id)
        OR EXISTS(SELECT 1 FROM user_identities i WHERE i.user_id=u.id)
        OR EXISTS(SELECT 1 FROM containers c WHERE c.owner_user_id=u.id)
      THEN 'kind=user,admin_dropped=true' ELSE 'kind=admin' END
FROM users u WHERE u.role='admin';
UPDATE users SET role='user' WHERE role='admin' AND (
 EXISTS(SELECT 1 FROM memberships m WHERE m.user_id=users.id)
 OR EXISTS(SELECT 1 FROM user_identities i WHERE i.user_id=users.id)
 OR EXISTS(SELECT 1 FROM containers c WHERE c.owner_user_id=users.id));
UPDATE users SET account_kind='admin' WHERE role='admin';
UPDATE devices SET revoked_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')
 WHERE revoked_at='' AND user_id IN (SELECT id FROM users WHERE account_kind='admin');

CREATE TRIGGER users_account_kind_fixed BEFORE UPDATE OF account_kind ON users
 WHEN NEW.account_kind<>OLD.account_kind BEGIN SELECT RAISE(ABORT,'account_kind_fixed'); END;
CREATE TRIGGER users_admin_role_insert BEFORE INSERT ON users
 WHEN NEW.role='admin' AND NEW.account_kind<>'admin' BEGIN SELECT RAISE(ABORT,'admin_role_needs_admin_account'); END;
CREATE TRIGGER users_admin_role_update BEFORE UPDATE OF role ON users
 WHEN NEW.role='admin' AND NEW.account_kind<>'admin' BEGIN SELECT RAISE(ABORT,'admin_role_needs_admin_account'); END;
-- Content rows belong to an existing everyday account, on insert and on any later re-point.
CREATE TRIGGER memberships_everyday_only BEFORE INSERT ON memberships
 WHEN NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND account_kind='user') BEGIN SELECT RAISE(ABORT,'admin_account_holds_no_content'); END;
CREATE TRIGGER memberships_everyday_only_update BEFORE UPDATE OF user_id ON memberships
 WHEN NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND account_kind='user') BEGIN SELECT RAISE(ABORT,'admin_account_holds_no_content'); END;
CREATE TRIGGER containers_everyday_owner BEFORE INSERT ON containers
 WHEN NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.owner_user_id AND account_kind='user') BEGIN SELECT RAISE(ABORT,'admin_account_holds_no_content'); END;
CREATE TRIGGER containers_everyday_owner_update BEFORE UPDATE OF owner_user_id ON containers
 WHEN NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.owner_user_id AND account_kind='user') BEGIN SELECT RAISE(ABORT,'admin_account_holds_no_content'); END;
CREATE TRIGGER devices_everyday_only BEFORE INSERT ON devices
 WHEN NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND account_kind='user') BEGIN SELECT RAISE(ABORT,'admin_account_holds_no_content'); END;
CREATE TRIGGER devices_everyday_only_update BEFORE UPDATE OF user_id ON devices
 WHEN NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND account_kind='user') BEGIN SELECT RAISE(ABORT,'admin_account_holds_no_content'); END;
```

  `devices_everyday_only` covers identities too: an identity is a `devices` row with `platform='identity'`, inserted before its `user_identities` row in the same transaction. The audit's `object_id` names the account, so the test reads it there. The `NOT EXISTS` form fails closed: the earlier `(SELECT account_kind …)<>'user'` form is NULL, and silent, for an unknown ID. Before Step 4, `grep -rn "INSERT INTO \(containers\|memberships\|devices\)" internal cmd --include=*_test.go` and give any fixture that inserts for a user ID it never created a real user row.

- [ ] **Step 4: Run the storage tests.** Run: `go test ./internal/storage -v`. Expected: the two new tests PASS. `TestSSOAppRoleUpgradeDoesNotPreserveGlobalAdmin` FAILS, because `linked` owns `kept` and is now mixed, and its re-grant hits the trigger.

- [ ] **Step 5: Fix the 0018 upgrade test.** In `internal/storage/sso_roles_upgrade_test.go`, add `exec(`INSERT INTO users(id,username,role,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES('plain','plain','user','hash','salt',1,'now','now')`)` before the `kept` insert, and change `kept`'s `owner_user_id` from `'linked'` to `'plain'`. Replace the two re-grant lines (`UPDATE users SET role='admin' WHERE id='linked'` and the session `UPDATE`) and the reopen block after them with:

```go
			if withLocal {
				// 0018 demoted it, so 0026 made it an everyday account: the grant can never come back.
				if _, err := db.Exec(`UPDATE users SET role='admin' WHERE id='linked'`); err == nil || !strings.Contains(err.Error(), "admin_role_needs_admin_account") {
					t.Fatal("an everyday account took the admin grant", err)
				}
				return
			}
			exec(`UPDATE sessions SET revoked_at='',sso_app_admin=1 WHERE id='linked'`)
```

  Keep the rest of the reopen block (`st.Close`, `Open`, the `migration repeated` check). Add `"strings"` to the imports. Run `go test ./internal/storage -v`. Expected: PASS.

- [ ] **Step 6: Set the kind on every path that creates an administrator.** Make these exact changes:
  - `internal/httpapi/auth_routes.go` setup insert: column list `…, role, account_kind, status, …` with values `'admin', 'admin', 'active'`. Task 3 replaces this handler.
  - `internal/app/bootstrap.go`: the same addition (`role, account_kind, status, password_admin_known` → `'admin', 'admin', 'active', 1`).
  - `cmd/kynotes-server/main.go` `user add`: wherever `role = "admin"` is set, add `kind = "admin"` (declare `kind := "user"` next to `role`), and add `account_kind` with `kind` to the `INSERT`.
  - `internal/httpapi/admin_routes.go` `POST /admin/users`: add `account_kind` to the `INSERT` with the value `in.Role`. Task 4 replaces the field.
  - `internal/httpapi/apply_setup.go` `createSSOAdmin`: `role, account_kind, status` → `'admin', 'admin', 'active'`.
  - `internal/httpapi/sso_directory.go` create (`INSERT INTO users(… role, status, …)`): add `account_kind` with value `role` (the creation-time role decides the kind, spec §6).

- [ ] **Step 7: Teams get an everyday owner.** Replace the `POST /api/v1/admin/teams` handler body in `admin_routes.go` (keep `auth.RequireAdmin` for now; Task 4 adds the step-up):

```go
	mux.Handle("POST /api/v1/admin/teams", auth.RequireAdmin(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		var in struct {
			OwnerUserID string `json:"ownerUserId"`
		}
		// The team has no name and no key until its owner's browser opens it.
		if json.NewDecoder(r.Body).Decode(&in) != nil || ids.Validate("usr", in.OwnerUserID) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		teamID, _ := ids.Mint("cnt")
		membershipID, _ := ids.Mint("mem")
		now := time.Now().UTC().Format(time.RFC3339)
		err := dbTx(db, func(tx *sql.Tx) error {
			var ok bool
			if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE id=? AND status='active' AND account_kind='user')`, in.OwnerUserID).Scan(&ok); err != nil {
				return err
			}
			if !ok {
				return sql.ErrNoRows
			}
			if _, e := tx.Exec(`INSERT INTO containers(id,kind,owner_user_id,change_seq,meta_ciphertext,meta_version,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`, teamID, "team", in.OwnerUserID, 1, []byte{}, 0, now, now); e != nil {
				return e
			}
			if _, e := tx.Exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at) VALUES(?,?,?,?,?)`, membershipID, teamID, in.OwnerUserID, "owner", now); e != nil {
				return e
			}
			return storage.RecordAuditOutcomeTx(tx, s.UserID, "admin.team.create", teamID, in.OwnerUserID, "success", "", RequestID(r))
		})
		if errors.Is(err, sql.ErrNoRows) {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		writeJSON(w, map[string]any{"id": teamID, "ownerUserId": in.OwnerUserID})
	})))
```

- [ ] **Step 8: The admin fixture helper.** Add to `internal/httpapi/teamkeys_test.go`, after `addUser`:

```go
// addAdmin creates an administrator account (login secret "a"*64) and signs it in. It can hold
// no content: tests that need an administrator and a member use two accounts.
func (p *pairClient) addAdmin(t *testing.T, username string) member {
	t.Helper()
	id := mint(t, "usr")
	hash, _ := auth.HashAuthSecret(strings.Repeat("a", 64))
	if _, err := p.db.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,account_kind,created_at,updated_at) VALUES(?,?,?,?,?,'admin','admin','now','now')`, id, username, hash, base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")), 100000); err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	q := &pairClient{hc: &http.Client{Jar: jar}, db: p.db, url: p.url}
	if code, body := status(t, q.do(t, http.MethodPost, "/api/v1/auth/login", []byte(`{"username":`+quote(username)+`,"authSecret":"`+strings.Repeat("a", 64)+`"}`), false, false)); code != http.StatusOK {
		t.Fatalf("login %s=%d %s", username, code, body)
	}
	return member{q, id}
}
```

- [ ] **Step 9: Rewrite the admin team test.** Replace `internal/httpapi/admin_team_test.go` with:

```go
package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestAdminCreatesATeamForAnEverydayOwner(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	admin := p.addAdmin(t, "server-admin")
	admin.stepUp(t) // Task 4 puts team creation behind the admin step-up
	other := p.addAdmin(t, "other-admin")
	create := func(body string) (int, string) {
		return status(t, admin.do(t, http.MethodPost, "/api/v1/admin/teams", []byte(body), true, false))
	}
	for _, body := range []string{`{}`, `{"ownerUserId":"nope"}`, `{"metaCiphertext":"eA=="}`} {
		if code, out := create(body); code != http.StatusBadRequest {
			t.Fatalf("%s=%d %s", body, code, out)
		}
	}
	disabled := p.addUser(t, "gone")
	if _, err := p.db.Exec(`UPDATE users SET status='disabled' WHERE id=?`, disabled.id); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{other.id, disabled.id, mint(t, "usr")} {
		if code, out := create(`{"ownerUserId":` + quote(id) + `}`); code != http.StatusNotFound {
			t.Fatalf("owner %s=%d %s", id, code, out)
		}
	}
	code, out := create(`{"ownerUserId":` + quote(pairUser) + `}`)
	var team struct {
		ID    string `json:"id"`
		Owner string `json:"ownerUserId"`
	}
	if code != http.StatusOK || json.Unmarshal([]byte(out), &team) != nil || team.Owner != pairUser {
		t.Fatalf("create=%d %s", code, out)
	}
	var owner string
	var adminRows, audits int
	if err := p.db.QueryRow(`SELECT owner_user_id FROM containers WHERE id=?`, team.ID).Scan(&owner); err != nil || owner != pairUser {
		t.Fatal("container owner", owner, err)
	}
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM memberships WHERE container_id=? AND user_id=?`, team.ID, admin.id).Scan(&adminRows); err != nil || adminRows != 0 {
		t.Fatal("the administrator holds a membership", adminRows, err)
	}
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='admin.team.create' AND container_id=? AND object_id=? AND actor_user_id=?`, team.ID, pairUser, admin.id).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("audit", audits, err)
	}
}
```

- [ ] **Step 10: Move every other fixture to a separate administrator.** Run `go test ./... 2>&1 | grep -E 'admin_role_needs_admin_account|admin_account_holds_no_content|FAIL'`. For each failure, apply the rule that fits:
  - A test that runs `UPDATE users SET role='admin' WHERE id=?` on a content user (`pairUser`, a team owner) and then calls an admin route: delete the `UPDATE`, create `admin := <client>.addAdmin(t, "server-admin")` and send the admin request through `admin.do(...)`, with `admin.stepUp(t)` first where the route needs a step-up. This applies to `teamkeys_test.go:650`, `teamkeys_p3b_test.go:70,219,241`, `identity_test.go:335,382`, `teamkeys_p3c_test.go:1041` and `teamkeys_p5_test.go:674`.
  - A test that inserts a user with `role='admin'`: add `account_kind` with `'admin'` to the insert. This applies to `sso_test.go`, `sso_app_roles_test.go`, the `createAdminUser` test helper (`grep -rn 'func createAdminUser' internal`), `internal/backup/service_test.go`, `cmd/kynotes-server/backup_test.go` and `backup_socket_test.go`.
  - An SSO fixture that signs a subject in and then promotes it (`sso_stepup_test.go:22`, `reauthFixture`): seed the subject as an admin account before its first sign-in. Add to `sso_app_roles_test.go`:

```go
// seedSSOAdmin creates the administrator account bound to subject at the fixture's issuer, as
// apply-setup or directory sync would, before the subject first signs in. It returns the ID.
func seedSSOAdmin(f *logoutFixture, subject string) string {
	f.t.Helper()
	id, err := ids.Mint("usr")
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,account_kind,sso_subject,sso_issuer,created_at,updated_at) VALUES(?,?,'unusable','salt',600000,'admin','admin',?,?,'now','now')`, id, subject, subject, f.settings.Load().IssuerURL); err != nil {
		f.t.Fatal(err)
	}
	return id
}
```

    In `reauthFixture`, replace `roleCallback(f, "alice", nil, "")` and the `UPDATE` with `seedSSOAdmin(f, "alice")`. Apply the same replacement wherever a test promotes an SSO subject that the same test never uses for content. Where the test also uses that subject for content, split it into two subjects.
  - A test whose subject is an administrator with content is testing the old mixed behaviour. Split it as above and keep its assertion.

  Re-run until `go test ./...` passes. The kind is not yet enforced by middleware, so only the triggers drive these changes.

- [ ] **Step 11: Frozen contracts.** In `IMPLEMENTATION_PLAN.md`: add `0026_account_kinds.sql` to the §1.13 migration list with one line ("account kinds, mixed-account upgrade, approval flag, content triggers"); replace the `POST /api/v1/admin/teams` row in the §5.1 table with `| POST | /api/v1/admin/teams | session + CSRF, server admin (step-up from Task 4) | {"ownerUserId"} → creates a team owned by that active everyday account, no membership for the caller; 400 malformed, 404 not an active everyday account; audit admin.team.create (object = owner) |`. In `DESIGN.md`, replace "Administrators may manage users, quotas, backups, and audit access, but cannot decrypt user content." with: "Administrators use administrator accounts, which are separate from everyday accounts for good: they manage users, quotas, teams, backups and audit access, hold no membership, identity, key or device, and reach no content route."

- [ ] **Step 12: Commit.**

```bash
git add internal/storage internal/httpapi internal/app internal/backup cmd IMPLEMENTATION_PLAN.md DESIGN.md
git commit -m "storage: account kinds; mixed admins keep their notes; teams get an everyday owner"
```

### Task 2: Middleware: each kind reaches only its routes; a set password is changed first

**Files:**
- Modify: `internal/auth/session.go` (`Session`, `ResolveSession`), `internal/auth/middleware.go`
- Create: `internal/auth/kinds_test.go`, `internal/httpapi/account_kinds_test.go`
- Modify: `internal/httpapi/auth_routes.go`, `internal/httpapi/sso_routes.go` (account routes), `internal/httpapi/device_routes.go` (register)
- Modify: `IMPLEMENTATION_PLAN.md` §1.7 error table, §1.8 route classes, §4.3 middleware semantics

**Interfaces:**
- Consumes: Task 1 schema, `addAdmin`, `addUser`.
- Produces: `auth.KindEveryday`, `auth.KindAdmin`, `auth.RequireAccount`, `Session.AccountKind`, `Session.PasswordChangeRequired`; the codes `admin_account` (403) and `password_change_required` (409) from `WriteAuthError`.

- [ ] **Step 1: Write the failing route tests.** Create `internal/httpapi/account_kinds_test.go`:

```go
package httpapi

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Routes both kinds reach (auth.RequireAccount) and routes with no session at all.
var accountRoutes = map[string]bool{
	"GET /api/v1/auth/session": true, "GET /api/auth/session": true, "POST /api/v1/auth/logout": true, "POST /api/auth/logout": true,
	"POST /api/v1/auth/logout-all": true, "POST /api/v1/auth/password": true, "POST /api/v1/auth/step-up": true,
	"POST /api/v1/auth/oidc/step-up": true, "GET /api/v1/auth/oidc/step-up/{id}": true, "DELETE /api/v1/auth/oidc/step-up/{id}": true,
}
var publicRoutes = map[string]bool{
	"GET /api/v1/theme": true, "GET /api/theme": true, "GET /api/v1/setup": true, "GET /api/setup": true, "POST /api/v1/setup": true, "POST /api/setup": true,
	"POST /api/v1/auth/login-params": true, "POST /api/auth/login-params": true, "POST /api/v1/auth/login": true, "POST /api/auth/login": true,
	"POST /api/v1/auth/recover": true, "GET /api/v1/auth/sso-config": true, "GET /api/auth/sso-config": true,
	"GET /api/v1/auth/oidc/login": true, "GET /api/auth/oidc/login": true, "GET /auth/oidc/login": true,
	"GET /api/v1/auth/oidc/callback": true, "GET /api/auth/oidc/callback": true, "GET /auth/oidc/callback": true,
	"POST /api/v1/auth/oidc/backchannel-logout": true, "POST /api/v1/sync/readback": true, "GET /api/v1/share-links/{token}": true,
	"POST /api/v1/devices/register": true,
}
// Device-credential routes: a session of either kind gets 401.
var deviceRoutes = map[string]bool{"GET /api/v1/sync/pending": true, "POST /api/v1/push/registrations": true}

// routeLiterals finds every "METHOD /path" string literal in the package's non-test sources.
func routeLiterals(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`"((?:GET|POST|PUT|PATCH|DELETE|HEAD) /[^" ]*)"`)
	seen := map[string]bool{}
	var out []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range pattern.FindAllStringSubmatch(string(b), -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				out = append(out, m[1])
			}
		}
	}
	if len(out) < 60 {
		t.Fatalf("found only %d routes; the pattern no longer matches the registrations", len(out))
	}
	return out
}

var pathParam = regexp.MustCompile(`\{[^}]+\}`)

// errorCode(t, body) is teamkeys_p5_test.go's helper; a second definition here would not compile.

// kindsServer is the full router, backup routes included (newPairClient mounts none), with an
// everyday and an administrator account signed in.
func kindsServer(t *testing.T) (everyday, admin *pairClient) {
	t.Helper()
	cfg := config.Defaults()
	cfg.DataDir = t.TempDir()
	cfg.Backup.Dir = t.TempDir()
	cfg.Secrets.ServerSaltKey = strings.Repeat("s", 32)
	cfg.Secrets.PairingSecret = strings.Repeat("p", 32)
	cfg.Server.DevInsecureCookies = true
	st, err := storage.Open(filepath.Join(cfg.DataDir, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	blobs, err := blobstore.New(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewRouter(logging.New(io.Discard, "info", "json"), cfg.Server.MaxRequestBytes, func() bool { return true }, st.DB(), blobs, cfg, backup.New(cfg, st, "test")))
	t.Cleanup(func() { srv.Close(); st.Close() })
	base := &pairClient{db: st.DB(), url: srv.URL}
	return base.addUser(t, "everyday").pairClient, base.addAdmin(t, "server-admin").pairClient
}

// Every route refuses the other kind; a route added with the wrong middleware fails here.
func TestEveryRouteRefusesTheOtherKind(t *testing.T) {
	everyday, admin := kindsServer(t)
	for _, route := range routeLiterals(t) {
		method, path, _ := strings.Cut(route, " ")
		// admin.sock routes (/v1/…) and non-API pages are not on this surface.
		if !strings.HasPrefix(path, "/api/") || publicRoutes[route] || accountRoutes[route] {
			continue
		}
		path = pathParam.ReplaceAllString(path, "x")
		isAdmin := strings.HasPrefix(path, "/api/v1/admin/") || strings.HasPrefix(path, "/api/admin/")
		caller, want, wantCode := admin, http.StatusForbidden, "admin_account"
		switch {
		case isAdmin:
			caller, wantCode = everyday, "forbidden"
		case deviceRoutes[route]:
			want, wantCode = http.StatusUnauthorized, "unauthenticated"
		}
		res := caller.do(t, method, path, nil, true, false)
		code, body := status(t, res)
		if code != want || (method != http.MethodHead && errorCode(t, body) != wantCode) {
			t.Errorf("%s: %d %s, want %d %s (classify it in account_kinds_test.go if it is public or an account route)", route, code, body, want, wantCode)
		}
	}
}

func TestAccountRoutesServeBothKinds(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	admin := p.addAdmin(t, "server-admin")
	for _, c := range []*pairClient{p, admin.pairClient} {
		code, body := status(t, c.do(t, http.MethodGet, "/api/v1/auth/session", nil, false, false))
		if code != http.StatusOK {
			t.Fatalf("session=%d %s", code, body)
		}
		c.stepUp(t)
	}
	if code, body := status(t, admin.do(t, http.MethodGet, "/api/v1/admin/users", nil, false, false)); code != http.StatusOK {
		t.Fatalf("admin users=%d %s", code, body)
	}
	if code, body := status(t, p.do(t, http.MethodGet, "/api/v1/containers", nil, false, false)); code != http.StatusOK {
		t.Fatalf("containers=%d %s", code, body)
	}
}

// Every Handle/HandleFunc whose pattern is not a string literal is invisible to routeLiterals.
// Only these are allowed: their call sites pass literals, or they are HMAC/socket routes.
var dynamicRoutes = map[string]bool{
	"backup_routes.go:path":         true, // mutation("POST /api/v1/admin/backup/…") call sites are literals
	"sso_directory.go:\"POST \"+path": true, // sync/events aliases: HMAC-authenticated, public by design
	"apply_setup.go:\"POST /v1/\"+name": true, // admin Unix socket, not on the network router
}

func TestNoRouteHidesFromTheInventory(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	// A pattern built by concatenation, or held in a variable (checked with grep -P on 93b2565: exactly the three above).
	call := regexp.MustCompile(`\.Handle(?:Func)?\(\s*("[^"]*"\s*\+[^,]*|[^"\s][^,]*),`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range call.FindAllStringSubmatch(string(b), -1) {
			if !dynamicRoutes[f+":"+strings.TrimSpace(m[1])] {
				t.Errorf("%s registers %s: use a \"METHOD /path\" literal so TestEveryRouteRefusesTheOtherKind sees it, or list it here with a reason", f, m[1])
			}
		}
	}
}

func TestPasswordChangeIsForcedAtFirstSignIn(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	admin := p.addAdmin(t, "server-admin")
	for _, id := range []string{pairUser, admin.id} {
		if _, err := p.db.Exec(`UPDATE users SET password_admin_known=1 WHERE id=?`, id); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		c    *pairClient
		path string
	}{{p, "/api/v1/containers"}, {admin.pairClient, "/api/v1/admin/users"}} {
		if code, body := status(t, tc.c.do(t, http.MethodGet, tc.path, nil, false, false)); code != http.StatusConflict || errorCode(t, body) != "password_change_required" {
			t.Fatalf("%s before the change=%d %s", tc.path, code, body)
		}
		// identity read: the change screen reads the live identity first (rewrapIdentity), so it is not fenced.
		want := http.StatusNotFound
		if tc.c == admin.pairClient {
			want = http.StatusForbidden
		}
		if code, body := status(t, tc.c.do(t, http.MethodGet, "/api/v1/me/identity", nil, false, false)); code != want {
			t.Fatalf("identity read before the change=%d %s", code, body)
		}
		code, body := status(t, tc.c.do(t, http.MethodGet, "/api/v1/auth/session", nil, false, false))
		var s struct {
			PasswordChangeRequired bool `json:"passwordChangeRequired"`
		}
		if code != http.StatusOK || json.Unmarshal([]byte(body), &s) != nil || !s.PasswordChangeRequired {
			t.Fatalf("session before the change=%d %s", code, body)
		}
		change := `{"currentAuthSecret":"` + strings.Repeat("a", 64) + `","newAuthSecret":"` + strings.Repeat("b", 64) + `","newLoginSalt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":100000}`
		if code, body := status(t, tc.c.do(t, http.MethodPost, "/api/v1/auth/password", []byte(change), true, false)); code != http.StatusNoContent {
			t.Fatalf("own change=%d %s", code, body)
		}
		if code, body := status(t, tc.c.do(t, http.MethodGet, tc.path, nil, false, false)); code != http.StatusOK {
			t.Fatalf("%s after the change=%d %s", tc.path, code, body)
		}
	}
}

func TestAdminAccountsCannotPairDevices(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	admin := p.addAdmin(t, "server-admin")
	if code, body := status(t, admin.do(t, http.MethodPost, "/api/v1/devices/pairing-token", nil, true, false)); code != http.StatusForbidden || errorCode(t, body) != "admin_account" {
		t.Fatalf("mint=%d %s", code, body)
	}
	token, _, err := auth.MintPairingToken(strings.Repeat("p", 32), admin.id, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, code := p.register(t, token, bytes.Repeat([]byte{9}, 32)); code != http.StatusUnauthorized {
		t.Fatalf("an admin account's pairing token registered a device: %d", code)
	}
}
```

  Imports for that file: `bytes`, `encoding/json`, `io`, `net/http`, `net/http/httptest`, `os`, `path/filepath`, `regexp`, `strings`, `testing`, `time`, and the packages `internal/auth`, `internal/backup`, `internal/blobstore`, `internal/config`, `internal/logging`, `internal/storage`. The dynamic `"POST "+path` registrations (`sync/events` aliases, HMAC-authenticated) do not match the literal pattern. They are public by design and covered by `TestDirectory*`; `TestNoRouteHidesFromTheInventory` fails on any new non-literal registration, so the inventory cannot be bypassed by a variable pattern. `TestEveryRouteRefusesTheOtherKind` sends about 90 requests from one IP: if a route answers `429`, the per-IP bucket is too small for the sweep; raise that bucket in `kindsServer`'s `cfg.RateLimit`, never skip the route.

- [ ] **Step 2: Run them and see them fail.** Run: `go test ./internal/httpapi -run 'TestEveryRoute|TestNoRouteHides|TestAccountRoutes|TestPasswordChangeIsForced|TestAdminAccountsCannotPair' -v`. Expected: FAIL. Admin sessions get 200/400/404 on content routes, there is no `passwordChangeRequired`, and the pairing-token mint answers 200.

- [ ] **Step 3: The session carries kind and fence.** In `internal/auth/session.go`, add to `Session` after `StepUpAt`:

```go
	AccountKind string // KindEveryday or KindAdmin, fixed when the account was created
	// PasswordChangeRequired: a password session on a password someone else set (users.password_admin_known).
	// SSO sessions never carry it: they did not use the password.
	PasswordChangeRequired bool
```

  In `ResolveSession`, extend the query and scan:

```go
	var adminKnown int
	err = db.QueryRow(`SELECT s.id,s.user_id,s.created_at,s.expires_at,s.hard_expires_at,s.revoked_at,s.stepup_at,u.status,s.sso_issuer,s.sso_client_id,s.sso_subject,u.auth_secret_hash,u.account_kind,u.password_admin_known FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?`, hex.EncodeToString(h[:])).Scan(&s.ID, &s.UserID, &created, &expires, &hard, &revoked, &stepup, &status, &s.SSOIssuer, &s.SSOClientID, &s.SSOSubject, &s.passwordHash, &s.AccountKind, &adminKnown)
```

  After the error check, add `s.PasswordChangeRequired = adminKnown != 0 && s.SSOIssuer == ""`.

- [ ] **Step 4: The middleware.** In `internal/auth/middleware.go`:

```go
const (
	KindEveryday = "user"
	KindAdmin    = "admin"
)

// RequireAccount admits a live session of either kind, also one whose password must still change.
// Only the account's own routes use it: session, logout, password change and step-up.
func RequireAccount(db *sql.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := ResolveSession(db, r, time.Now().UTC())
		if err != nil {
			unauthenticated(w)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, s)))
	})
}

// RequireSession admits an everyday session on its own password: every content route.
func RequireSession(db *sql.DB, next http.Handler) http.Handler {
	return RequireAccount(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s, _ := SessionFromContext(r); refuseSession(w, s, KindEveryday) {
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// RequireEveryday admits an everyday session even while its password must change. Only
// GET /api/v1/me/identity uses it: the change screen reads the live identity before the change.
func RequireEveryday(db *sql.DB, next http.Handler) http.Handler {
	return RequireAccount(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s, _ := SessionFromContext(r); refuseSession(w, Session{AccountKind: s.AccountKind}, KindEveryday) {
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// refuseSession answers for a session of the wrong kind, or one whose password someone else set.
func refuseSession(w http.ResponseWriter, s Session, kind string) bool {
	switch {
	case s.AccountKind != kind && kind == KindEveryday:
		WriteAuthError(w, "admin_account", "administrator accounts cannot open notes; sign in with your everyday account")
	case s.AccountKind != kind:
		WriteAuthError(w, "forbidden", "administrator access required")
	case s.PasswordChangeRequired:
		WriteAuthError(w, "password_change_required", "change the password an administrator set first")
	default:
		return false
	}
	return true
}
```

  Replace `RequireAdmin` with:

```go
func RequireAdmin(db *sql.DB, next http.Handler) http.Handler {
	return RequireAccount(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := SessionFromContext(r)
		if refuseSession(w, s, KindAdmin) {
			return
		}
		if role, err := SessionRole(db, s); err != nil || role != "admin" {
			WriteAuthError(w, "forbidden", "administrator access required")
			return
		}
		next.ServeHTTP(w, r)
	}))
}
```

  In `SessionRole`, change the `CASE` to `CASE WHEN u.role='admin' AND u.account_kind='admin' AND (s.sso_issuer='' OR s.sso_app_admin=1) THEN 'admin' ELSE 'user' END`. In `RequireEither`, replace the session branch with:

```go
		if s, e := ResolveSession(db, r, time.Now().UTC()); e == nil {
			if refuseSession(w, s, KindEveryday) {
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, s)))
			return
		}
```

  In `resolveDevice`, add `AND u.account_kind='user'` to the `JOIN users u ON u.id=d.user_id` condition (write it as `JOIN users u ON u.id=d.user_id AND u.account_kind='user'`). In `WriteAuthError`, change the 403 case to `case "forbidden", "step_up_required", "admin_account":` and add `case "password_change_required": status = http.StatusConflict`. Delete `RequireFresh`: it has no caller (checked on `93b2565`).

- [ ] **Step 5: Unit tests for the auth package.** Create `internal/auth/kinds_test.go`:

```go
package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRefuseSessionKeepsKindsApart(t *testing.T) {
	for _, tc := range []struct {
		s    Session
		kind string
		want int
	}{
		{Session{AccountKind: KindEveryday}, KindEveryday, 0},
		{Session{AccountKind: KindAdmin}, KindEveryday, http.StatusForbidden},
		{Session{AccountKind: KindEveryday}, KindAdmin, http.StatusForbidden},
		{Session{AccountKind: ""}, KindEveryday, http.StatusForbidden},
		{Session{AccountKind: KindEveryday, PasswordChangeRequired: true}, KindEveryday, http.StatusConflict},
		{Session{AccountKind: KindAdmin, PasswordChangeRequired: true}, KindAdmin, http.StatusConflict},
	} {
		rec := httptest.NewRecorder()
		refused := refuseSession(rec, tc.s, tc.kind)
		if refused != (tc.want != 0) || (refused && rec.Code != tc.want) {
			t.Errorf("%+v for %s: refused=%v code=%d", tc.s, tc.kind, refused, rec.Code)
		}
	}
}
```

  A session with an empty kind (a code path that forgot to load it) must fail closed. The third case also pins that the kind check runs before the fence.

- [ ] **Step 6: Account routes take `RequireAccount`.** In `internal/httpapi/auth_routes.go`, change `auth.RequireSession` to `auth.RequireAccount` for `handleSession`, `handleLogout`, `POST /api/v1/auth/password`, `POST /api/v1/auth/logout-all` and `POST /api/v1/auth/step-up`. In `handleSession`, add `"accountKind": s.AccountKind` inside the `user` map, and `"passwordChangeRequired": s.PasswordChangeRequired` at the top level. In `internal/httpapi/sso_routes.go`, do the same for the three OIDC step-up routes (lines 139, 140 and 151). In `internal/httpapi/identity_routes.go:126`, change `GET /api/v1/me/identity` from `auth.RequireSession` to `auth.RequireEveryday`: it returns public fields only, and without it `ChoosePassword` (Task 7) fails on every temporary password, because `rewrapIdentity` reads it before the change and `myIdentity` throws on `409`. The identity writes and the recovery-copy routes keep `RequireUserActionStepUp`, so they stay fenced.

- [ ] **Step 7: Registration refuses an admin account's token.** In `device_routes.go`, after `userID = claim.Sub`:

```go
		var everyday bool
		if db.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE id=? AND account_kind='user' AND status='active')`, userID).Scan(&everyday) != nil || !everyday {
			WriteError(w, r, 401, "unauthenticated", "invalid pairing token")
			return
		}
```

- [ ] **Step 8: Run the tests.** Run: `go test ./internal/auth ./internal/httpapi -v -run 'TestRefuseSession|TestEveryRoute|TestNoRouteHides|TestAccountRoutes|TestPasswordChangeIsForced|TestAdminAccountsCannotPair'`. Expected: PASS. If `TestEveryRouteRefusesTheOtherKind` names a route, decide its class from spec §2. A public or account route goes in the test's map, and the reason goes in the commit message. A content or admin route gets fixed middleware. Then run `go test -race ./...`. Every older test that signed in a flagged account (`password_admin_known=1`) and then used a content route now gets 409. For each one, either change the password first, the way `TestPasswordChangeIsForcedAtFirstSignIn` does, or, when the test is about the P5 identity fence itself, assert the 409 instead. Keep its intent. Expected after that: PASS.

- [ ] **Step 9: Frozen contracts.** In `IMPLEMENTATION_PLAN.md` §1.7, add rows: `| admin_account | 403 | an administrator account reached a content route |` and change the `password_change_required` row text to "a password session on a password someone else set reached any route other than session, logout, logout-all, password change, step-up or `GET /me/identity`; P5's identity fence still applies inside identity actions". In §1.8, add a row `| Account (session, logout, logout-all, password, step-up, OIDC step-up) | required, either kind | rejected | — |`, and change the Admin row's Session cell to "required, an admin account with role `admin`". Add a sentence under the table: "Content route classes admit everyday accounts only (`403 admin_account`); admin routes admit admin accounts only." In §4.3, add `RequireAccount` and `RequireEveryday` (only `GET /me/identity`), and update the `RequireSession`, `RequireEither`, `RequireDevice` and `RequireAdmin` bullets to say the same.

- [ ] **Step 10: Commit.**

```bash
git add internal/auth internal/httpapi IMPLEMENTATION_PLAN.md
git commit -m "auth: administrator sessions reach no content, everyday sessions no admin route; a set password is changed first"
```

### Task 3: Setup creates both accounts; login and session report the kind; bootstrap, CLI, start-up, probe

**Files:**
- Modify: `internal/httpapi/auth_routes.go` (`handleSetupInit`, `handleLogin`), `internal/httpapi/setup_test.go`, `internal/httpapi/account_kinds_test.go`
- Modify: `internal/app/bootstrap.go` (comment only; the kind landed in Task 1), the server start-up in `internal/app` (where `EnsureBootstrapAdmin` is called), and its test
- Modify: `cmd/kynotes-server/main.go` (`user add` usage text), `cmd/kynotes-probe/main.go` (`login`)
- Modify: `IMPLEMENTATION_PLAN.md` `POST /setup` and login rows

**Interfaces:**
- Consumes: Task 2 `Session` fields.
- Produces: `POST /api/v1/setup` `{"admin":{…},"everyday":{…}}`; login `{"user":{"id","role","accountKind"},"passwordChangeRequired",…}`; `app.WarnWithoutAdmin(db, log) bool`.

- [ ] **Step 1: Write the failing setup test.** Add to `internal/httpapi/account_kinds_test.go`:

```go
func setupBody(admin, everyday string) []byte {
	account := func(name, fill string) string {
		return `{"username":` + quote(name) + `,"authSecret":"` + strings.Repeat(fill, 64) + `","loginSalt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":100000}`
	}
	return []byte(`{"admin":` + account(admin, "a") + `,"everyday":` + account(everyday, "b") + `}`)
}

func TestSetupCreatesBothAccounts(t *testing.T) {
	db, cfg := setupTestDB(t)
	mux := http.NewServeMux()
	AuthRoutes(mux, db, cfg)
	post := func(body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/v1/setup", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	for name, body := range map[string][]byte{
		"old shape":     []byte(`{"username":"admin","authSecret":"` + strings.Repeat("a", 64) + `"}`),
		"same username": setupBody("owner", "Owner"),
		"no everyday":   []byte(`{"admin":{"username":"admin","authSecret":"` + strings.Repeat("a", 64) + `","loginSalt":"x","iterations":100000}}`),
	} {
		if rec := post(body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s=%d %s", name, rec.Code, rec.Body.String())
		}
	}
	var users int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&users); err != nil || users != 0 {
		t.Fatal("a refused setup created accounts", users, err)
	}
	rec := post(setupBody("admin", "owner"))
	var out struct {
		User struct{ ID, AccountKind string } `json:"user"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.User.AccountKind != "admin" {
		t.Fatalf("setup=%d %s", rec.Code, rec.Body.String())
	}
	for name, want := range map[string]string{"admin": "admin|admin|0", "owner": "user|user|0"} {
		var kind, role string
		var flagged int
		if err := db.QueryRow(`SELECT account_kind,role,password_admin_known FROM users WHERE username=?`, name).Scan(&kind, &role, &flagged); err != nil || kind+"|"+role+"|"+strconv.Itoa(flagged) != want {
			t.Fatalf("%s: %s|%s|%d %v", name, kind, role, flagged, err)
		}
	}
	if rec := post(setupBody("admin2", "owner2")); rec.Code != http.StatusForbidden {
		t.Fatalf("second setup=%d", rec.Code)
	}
}

func TestLoginReportsKindAndChangeFlag(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	admin := p.addAdmin(t, "server-admin")
	if _, err := p.db.Exec(`UPDATE users SET password_admin_known=1 WHERE id=?`, admin.id); err != nil {
		t.Fatal(err)
	}
	res := admin.do(t, http.MethodPost, "/api/v1/auth/login", []byte(`{"username":"server-admin","authSecret":"`+strings.Repeat("a", 64)+`"}`), false, false)
	code, body := status(t, res)
	var out struct {
		User struct{ AccountKind string } `json:"user"`
		PasswordChangeRequired bool        `json:"passwordChangeRequired"`
		Identity               any         `json:"identity"`
	}
	if code != http.StatusOK || json.Unmarshal([]byte(body), &out) != nil || out.User.AccountKind != "admin" || !out.PasswordChangeRequired || out.Identity != nil {
		t.Fatalf("login=%d %s", code, body)
	}
}
```

  Add `"bytes"`, `"net/http/httptest"` and `"strconv"` to the imports. Update `TestSetupFlow` in `setup_test.go` to post `setupBody("admin", "owner")` where it posted `setupPayload`, and to keep its plaintext-password `400` case.

- [ ] **Step 2: Run them and see them fail.** Run: `go test ./internal/httpapi -run 'TestSetup|TestLoginReports' -v`. Expected: FAIL. The new body shape is `400`, and the login response has no `accountKind`.

- [ ] **Step 3: The setup handler.** Replace `handleSetupInit` with:

```go
	type setupAccount struct {
		Username   string `json:"username"`
		AuthSecret string `json:"authSecret"`
		LoginSalt  string `json:"loginSalt"`
		Iterations int    `json:"iterations"`
	}
	valid := func(a *setupAccount) bool {
		a.Username = strings.ToLower(strings.TrimSpace(a.Username))
		return a.Username != "" && len(a.AuthSecret) == 64 && a.LoginSalt != "" && a.Iterations >= 100000 && a.Iterations <= 1000000
	}
	// First-run setup creates the administrator account and the everyday account that writes notes,
	// both with passwords the person at setup chose, and signs this browser in as the administrator.
	handleSetupInit := func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Admin, Everyday *setupAccount }
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if dec.Decode(&in) != nil || in.Admin == nil || in.Everyday == nil || !valid(in.Admin) || !valid(in.Everyday) || in.Admin.Username == in.Everyday.Username {
			WriteError(w, r, 400, "invalid_request", "an administrator and an everyday account with different usernames are required")
			return
		}
		accountIDs := [2]string{}
		for i := range accountIDs {
			id, err := ids.Mint("usr")
			if err != nil {
				WriteError(w, r, 500, "internal", "failed to mint user id")
				return
			}
			accountIDs[i] = id
		}
		now := time.Now().UTC().Format(time.RFC3339)
		err := dbTx(db, func(tx *sql.Tx) error {
			var count int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
				return err
			}
			if count > 0 {
				return errSetupDone
			}
			for i, a := range []*setupAccount{in.Admin, in.Everyday} {
				kind := []string{"admin", "user"}[i]
				hash, err := auth.HashAuthSecret(a.AuthSecret)
				if err != nil {
					return err
				}
				if _, err := tx.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,account_kind,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'active',?,?)`, accountIDs[i], a.Username, hash, a.LoginSalt, a.Iterations, kind, kind, now, now); err != nil {
					return err
				}
			}
			return storage.RecordAuditOutcomeTx(tx, accountIDs[0], "setup.initialized", "", accountIDs[1], "success", "", RequestID(r))
		})
		if errors.Is(err, errSetupDone) {
			WriteError(w, r, http.StatusForbidden, "setup_completed", "setup has already been completed")
			return
		}
		if errors.Is(err, auth.ErrBusy) {
			authBusy(w, r, "setup temporarily unavailable")
			return
		}
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		s, err := auth.MintSession(db, w, accountIDs[0], cfg.Server.DevInsecureCookies, time.Now().UTC())
		if err != nil {
			WriteError(w, r, 500, "internal", "failed to create session")
			return
		}
		writeJSON(w, map[string]any{
			"ok":            true,
			"user":          map[string]string{"id": accountIDs[0], "role": "admin", "accountKind": "admin", "username": in.Admin.Username},
			"everyday":      map[string]string{"id": accountIDs[1], "username": in.Everyday.Username},
			"expiresAt":     s.ExpiresAt.UTC().Format(time.RFC3339),
			"hardExpiresAt": s.HardExpiresAt.UTC().Format(time.RFC3339),
		})
	}
```

  Add `var errSetupDone = errors.New("setup already completed")` at package level in `auth_routes.go`. The count check moves inside the transaction, so two racing setups cannot both create accounts. The synthetic-salt and default-iterations fallbacks go away: the browser always sends both.

- [ ] **Step 4: Login reports the kind.** In `handleLogin`, select `account_kind` and `password_admin_known` with the user row (`SELECT id,auth_secret_hash,status,role,account_kind,password_admin_known FROM users WHERE username=?`, scanning into `kind` and `known int`). Load the identity only for everyday accounts:

```go
		s, err := auth.MintPasswordSession(db, w, id, stored, cfg.Server.DevInsecureCookies, time.Now().UTC(), func(tx *sql.Tx) (err error) {
			if kind != auth.KindEveryday {
				return nil // an administrator account holds no identity
			}
			identity, err = loadIdentity(tx, id, true)
			return err
		})
```

  Then make the response `out := map[string]any{"user": map[string]string{"id": id, "role": role, "accountKind": kind}, "passwordChangeRequired": known != 0, …}`. The dummy-verifier branch leaves `kind` empty, and that branch never reaches the response.

- [ ] **Step 5: No administrator at start-up.** In `internal/app/bootstrap.go`, add:

```go
// WarnWithoutAdmin logs no_active_admin when the database has accounts but no active administrator
// account, which the 0026 upgrade causes when every administrator also held notes. /setup stays
// closed; the CLI creates one.
func WarnWithoutAdmin(db *sql.DB, log *logging.Logger) bool {
	var users, admins int
	if db.QueryRow(`SELECT COUNT(*), COUNT(*) FILTER (WHERE account_kind='admin' AND role='admin' AND status='active') FROM users`).Scan(&users, &admins) != nil || users == 0 || admins > 0 {
		return false
	}
	// The remedy is in the message: the logger drops every attribute key outside its allowlist.
	log.Warn("no_active_admin: no active administrator account; create one with kynotes-server user add --admin --username <name>", "event", "no_active_admin")
	return true
}
```

  Call it in `internal/app/serve.go` right after `EnsureBootstrapAdmin` (line 38); `logging.Logger` embeds `*slog.Logger`, so `log.Warn` exists. The bootstrap-only branch in `cmd/kynotes-server/main.go:101` exits without serving and needs no call. Add `internal/app/bootstrap_test.go` with `TestWarnWithoutAdmin`. It opens a store and inserts one everyday user, expects `true` and a log line (written to a `bytes.Buffer` through `logging.New(&buf, "info", "json")`) that contains `user add --admin`, then inserts an active admin account (`role='admin', account_kind='admin'`) and expects `false`. A fresh store with no users expects `false`.

- [ ] **Step 6: CLI text and probe.** In `cmd/kynotes-server/main.go`, change the `user add` usage to `"usage: user add --username <name> [--password <pass>] [--admin]  (--admin creates an administrator account, which cannot open notes)"`. In `cmd/kynotes-probe/main.go` `login()`, add `AccountKind string \`json:"accountKind"\`` to the decoded `User`. After `p.userID = session.User.ID`, add:

```go
	if session.User.AccountKind != "user" {
		return errors.New("the probe account is an administrator account, which cannot open notes; use an everyday account (user add without --admin)")
	}
```

- [ ] **Step 7: Run everything.** Run: `go test -race ./...`. Expected: PASS.

- [ ] **Step 8: Frozen contracts.** In `IMPLEMENTATION_PLAN.md`, replace the `POST /api/v1/setup` description (in §4.2, or wherever `grep -n '/setup' IMPLEMENTATION_PLAN.md` finds it) with the new body, the `400` for equal or missing usernames, "both accounts unflagged, session for the administrator", and the in-transaction `403 setup_completed`. Add `accountKind` and `passwordChangeRequired` to the login and session response descriptions.

- [ ] **Step 9: Commit.**

```bash
git add internal cmd IMPLEMENTATION_PLAN.md
git commit -m "setup: an administrator and an everyday account; login reports the kind; warn when no administrator remains"
```

### Task 4: Admin API: kinds on users, team list without names, step-up for team access

**Files:**
- Modify: `internal/httpapi/admin_routes.go`, `internal/httpapi/admin_team_test.go`
- Modify: `IMPLEMENTATION_PLAN.md` admin route rows

**Interfaces:**
- Consumes: Task 1 team create; Task 2 `RequireStepUp` on admin kinds; `admitMemberTx` (its signature changes in Task 5, so this task calls today's).
- Produces: `POST /admin/users {"accountKind"}`; `PATCH /admin/users/{id}` `409 account_kind_mismatch`; `GET /admin/users` `accountKind`; `GET /admin/teams` shape; `auth.RequireStepUp` on team create and member add.

- [ ] **Step 1: Write the failing tests.** Add to `internal/httpapi/admin_team_test.go`:

```go
func TestAdminUserRoutesKeepKindsApart(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	admin := p.addAdmin(t, "server-admin")
	admin.stepUp(t)
	create := func(name, kind string) (int, string) {
		body := `{"username":` + quote(name) + `,"authSecret":"` + strings.Repeat("c", 64) + `","loginSalt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":100000,"accountKind":` + quote(kind) + `}`
		return status(t, admin.do(t, http.MethodPost, "/api/v1/admin/users", []byte(body), true, false))
	}
	if code, out := create("x", "root"); code != http.StatusBadRequest {
		t.Fatalf("unknown kind=%d %s", code, out)
	}
	for name, kind := range map[string]string{"alice": "user", "ops": "admin"} {
		if code, out := create(name, kind); code != http.StatusOK {
			t.Fatalf("create %s=%d %s", name, code, out)
		}
		var got, role string
		var flagged int
		if err := p.db.QueryRow(`SELECT account_kind,role,password_admin_known FROM users WHERE username=?`, name).Scan(&got, &role, &flagged); err != nil || got != kind || role != kind || flagged != 1 {
			t.Fatalf("%s: %s %s %d %v", name, got, role, flagged, err)
		}
	}
	var alice string
	if err := p.db.QueryRow(`SELECT id FROM users WHERE username='alice'`).Scan(&alice); err != nil {
		t.Fatal(err)
	}
	patch := func(id, role string) (int, string) {
		return status(t, admin.do(t, http.MethodPatch, "/api/v1/admin/users/"+id, []byte(`{"role":`+quote(role)+`,"status":"active","quotaBytes":0}`), true, false))
	}
	if code, out := patch(alice, "admin"); code != http.StatusConflict || errorCode(t, out) != "account_kind_mismatch" {
		t.Fatalf("promote everyday=%d %s", code, out)
	}
	code, out := status(t, admin.do(t, http.MethodGet, "/api/v1/admin/users", nil, false, false))
	if code != http.StatusOK || !strings.Contains(out, `"accountKind":"admin"`) || !strings.Contains(out, `"accountKind":"user"`) {
		t.Fatalf("list=%d %s", code, out)
	}
}

func TestAdminTeamAccessNeedsStepUpAndListsNoNames(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	admin := p.addAdmin(t, "server-admin")
	other := p.addAdmin(t, "other-admin")
	editor := p.addUser(t, "editor")
	body := []byte(`{"ownerUserId":` + quote(pairUser) + `}`)
	if code, out := status(t, admin.do(t, http.MethodPost, "/api/v1/admin/teams", body, true, false)); code != http.StatusForbidden || errorCode(t, out) != "step_up_required" {
		t.Fatalf("create without step-up=%d %s", code, out)
	}
	admin.stepUp(t)
	code, out := status(t, admin.do(t, http.MethodPost, "/api/v1/admin/teams", body, true, false))
	var team struct{ ID string }
	if code != http.StatusOK || json.Unmarshal([]byte(out), &team) != nil {
		t.Fatalf("create=%d %s", code, out)
	}
	add := func(c *pairClient, user string) (int, string) {
		return status(t, c.do(t, http.MethodPost, "/api/v1/admin/teams/"+team.ID+"/members", []byte(`{"userId":`+quote(user)+`,"role":"editor"}`), true, false))
	}
	if code, out := add(other.pairClient, editor.id); code != http.StatusForbidden || errorCode(t, out) != "step_up_required" {
		t.Fatalf("add without step-up=%d %s", code, out)
	}
	if code, out := add(admin.pairClient, other.id); code != http.StatusNotFound {
		t.Fatalf("add an admin account=%d %s", code, out)
	}
	// steward role: an unapproved team admin could approve itself, rotate in a key it knows, or wrap.
	for _, role := range []string{"admin", "owner"} {
		if code, out := status(t, admin.do(t, http.MethodPost, "/api/v1/admin/teams/"+team.ID+"/members", []byte(`{"userId":`+quote(editor.id)+`,"role":`+quote(role)+`}`), true, false)); code != http.StatusBadRequest {
			t.Fatalf("add as %s=%d %s", role, code, out)
		}
	}
	if code, out := add(admin.pairClient, editor.id); code != http.StatusNoContent {
		t.Fatalf("add=%d %s", code, out)
	}
	code, out = status(t, admin.do(t, http.MethodGet, "/api/v1/admin/teams", nil, false, false))
	var list []map[string]any
	if code != http.StatusOK || json.Unmarshal([]byte(out), &list) != nil || len(list) != 1 {
		t.Fatalf("list=%d %s", code, out)
	}
	row := list[0]
	if _, leaked := row["metaCiphertext"]; leaked || row["ownerUsername"] != "pair" || row["memberCount"] != float64(2) || row["keyed"] != false || row["named"] != false {
		t.Fatalf("row %v", row)
	}
}
```

- [ ] **Step 2: Run them and see them fail.** Run: `go test ./internal/httpapi -run 'TestAdminUserRoutes|TestAdminTeamAccess' -v`. Expected: FAIL.

- [ ] **Step 3: Users.** In `POST /admin/users`, rename the input field to ``AccountKind string `json:"accountKind"` ``, validate `in.AccountKind == "user" || in.AccountKind == "admin"`, and insert `role` and `account_kind` both as `in.AccountKind`. Audit reason `kind=<kind>`. In `PATCH /admin/users/{id}`, before the `UPDATE`:

```go
		var kind string
		if err := db.QueryRow(`SELECT account_kind FROM users WHERE id=?`, id).Scan(&kind); errors.Is(err, sql.ErrNoRows) {
			WriteError(w, r, 404, "not_found", "not found")
			return
		} else if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		if in.Role == "admin" && kind != auth.KindAdmin {
			WriteError(w, r, 409, "account_kind_mismatch", "everyday accounts cannot hold administrator access; create a separate administrator account")
			return
		}
```

  In `GET /admin/users`, select `account_kind` and add `"accountKind": kind` to each row.

- [ ] **Step 4: Teams.** Change `POST /api/v1/admin/teams` and `POST /api/v1/admin/teams/{id}/members` from `auth.RequireAdmin` to `auth.RequireStepUp`. In the member add's existence query, change `AND EXISTS(SELECT 1 FROM users WHERE id=? AND status='active')` to `AND EXISTS(SELECT 1 FROM users WHERE id=? AND status='active' AND account_kind='user')`. In its input check, drop `in.Role != "admin" &&`: the administrator adds `editor`, `commenter` or `viewer` only. A steward role on an unapproved member would let the account approve itself (Task 5), invite, remove members, or rotate in a key it generated, which every member's next write would use. Only a steward's invitation makes a team admin. Replace `GET /api/v1/admin/teams` with:

```go
	mux.Handle("GET /api/v1/admin/teams", auth.RequireAdmin(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Administrator pages hold no team keys, so they get no name ciphertext either.
		rows, err := db.Query(`SELECT c.id,c.owner_user_id,u.username,(SELECT COUNT(*) FROM memberships m WHERE m.container_id=c.id AND m.revoked_at=''),c.shared_generation>0,c.meta_version>0
 FROM containers c JOIN users u ON u.id=c.owner_user_id WHERE c.kind='team' AND c.deleted_at='' ORDER BY c.id`)
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var id, owner, username string
			var members int64
			var keyed, named bool
			if rows.Scan(&id, &owner, &username, &members, &keyed, &named) != nil {
				WriteError(w, r, 500, "internal", "internal server error")
				return
			}
			out = append(out, map[string]any{"id": id, "ownerUserId": owner, "ownerUsername": username, "memberCount": members, "keyed": keyed, "named": named})
		}
		if rows.Err() != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		writeJSON(w, out)
	})))
```

  Drop the `encoding/base64` import if nothing else in the file uses it.

- [ ] **Step 5: Run.** Run: `go test -race ./internal/httpapi`. Expected: PASS. Tests that added members through the admin route without a step-up now get `403 step_up_required`; add `admin.stepUp(t)` before them.

- [ ] **Step 6: Frozen contracts.** Update the `IMPLEMENTATION_PLAN.md` rows for `POST /admin/users`, `PATCH /admin/users/{id}`, `GET /admin/users`, `GET /admin/teams`, `POST /admin/teams` (step-up) and `POST /admin/teams/{id}/members` (step-up, everyday target, role `editor`/`commenter`/`viewer` only, `approved=0` from Task 5).

- [ ] **Step 7: Commit.**

```bash
git add internal/httpapi IMPLEMENTATION_PLAN.md
git commit -m "admin: account kinds on users; team list without names; step-up for team creation and member add"
```

### Task 5: Steward approval: administrator-added members get no key until a steward approves

**Files:**
- Modify: `internal/httpapi/teamkeys_routes.go` (`admitMemberTx`, `insertEnvelopeTx`, `uncoveredIdentitiesSQL`), `internal/httpapi/collab_routes.go` (accept caller, members list, approve route), `internal/httpapi/admin_routes.go` (member add caller)
- Create: `internal/httpapi/approval_test.go`
- Modify: `IMPLEMENTATION_PLAN.md` (§5.1 new route row, §9 membership rules), `DESIGN.md` (membership paragraph)

**Interfaces:**
- Consumes: `newTeam`, `team.rotate`, `envelopesBody`, `envJSON`, `countEnvelopes`, `addAdmin`, `addUser`, `createIdentity`, `stepUp`, `errorCode`.
- Produces: `admitMemberTx(tx, cid, userID, role, invitedBy string, approved bool, now string)`; `POST /api/v1/containers/{id}/members/{userID}/approve`; `"approved"` in member rows.

- [ ] **Step 1: Write the failing test.** Create `internal/httpapi/approval_test.go`:

```go
package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"
)

func approvedOf(t *testing.T, c *pairClient, cid, userID string) (bool, bool) {
	t.Helper()
	code, body := status(t, c.do(t, http.MethodGet, "/api/v1/containers/"+cid+"/members", nil, false, false))
	var rows []struct {
		UserID   string `json:"userId"`
		Approved bool   `json:"approved"`
	}
	if code != http.StatusOK || json.Unmarshal([]byte(body), &rows) != nil {
		t.Fatalf("members=%d %s", code, body)
	}
	for _, row := range rows {
		if row.UserID == userID {
			return row.Approved, true
		}
	}
	return false, false
}

func TestAdminAddedMembersWaitForApproval(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1) // generation 2 is the first key
	srv := tm.owner.addAdmin(t, "server-admin")
	srv.stepUp(t)
	puppet := tm.owner.addUser(t, "puppet")
	puppetID := puppet.createIdentity(t)
	add := func() {
		t.Helper()
		if code, out := status(t, srv.do(t, http.MethodPost, "/api/v1/admin/teams/"+tm.id+"/members", []byte(`{"userId":`+quote(puppet.id)+`,"role":"editor"}`), true, false)); code != http.StatusNoContent {
			t.Fatalf("admin add=%d %s", code, out)
		}
	}
	add()
	// A child workspace created after the add copies the team's rows, approval included.
	code, out := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/containers", []byte(`{"kind":"workbook","teamId":`+quote(tm.id)+`}`), true, false))
	var later struct{ ID string }
	if code != http.StatusOK || json.Unmarshal([]byte(out), &later) != nil {
		t.Fatalf("child=%d %s", code, out)
	}
	for _, cid := range []string{tm.id, tm.child, later.ID} {
		if approved, listed := approvedOf(t, tm.owner, cid, puppet.id); !listed || approved {
			t.Fatalf("%s: listed=%v approved=%v", cid, listed, approved)
		}
	}
	// No steward may wrap for the member yet, and rotation does not wait for it.
	tm.owner.stepUp(t)
	if code, out := status(t, tm.owner.do(t, http.MethodPut, "/api/v1/containers/"+tm.id+"/envelopes", envelopesBody(envJSON(puppetID, 2, 3)), true, false)); code != http.StatusBadRequest {
		t.Fatalf("wrap for an unapproved member=%d %s", code, out)
	}
	tm.rotate(t, tm.id, 2)
	approve := func(c *pairClient, cid string) (int, string) {
		return status(t, c.do(t, http.MethodPost, "/api/v1/containers/"+cid+"/members/"+puppet.id+"/approve", nil, true, false))
	}
	if code, out := approve(tm.editor.pairClient, tm.id); code != http.StatusForbidden {
		t.Fatalf("editor approves=%d %s", code, out)
	}
	if code, out := approve(srv.pairClient, tm.id); code != http.StatusForbidden || errorCode(t, out) != "admin_account" {
		t.Fatalf("server admin approves=%d %s", code, out)
	}
	if code, out := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/containers/"+tm.id+"/members/"+puppet.id+"/approve", nil, false, false)); code != http.StatusForbidden {
		t.Fatalf("approve without CSRF=%d %s", code, out)
	}
	if code, out := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/containers/"+tm.id+"/members/"+mint(t, "usr")+"/approve", nil, true, false)); code != http.StatusNotFound {
		t.Fatalf("approve a non-member=%d %s", code, out)
	}
	if code, out := approve(tm.owner, tm.id); code != http.StatusNoContent {
		t.Fatalf("owner approves=%d %s", code, out)
	}
	for _, cid := range []string{tm.id, tm.child} {
		if approved, _ := approvedOf(t, tm.owner, cid, puppet.id); !approved {
			t.Fatalf("%s still unapproved", cid)
		}
	}
	var audits int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='container.member_approve' AND container_id=? AND object_id=?`, tm.id, puppet.id).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("approve audit", audits, err)
	}
	if code, out := status(t, tm.owner.do(t, http.MethodPut, "/api/v1/containers/"+tm.id+"/envelopes", envelopesBody(envJSON(puppetID, 3, 3)), true, false)); code/100 != 2 {
		t.Fatalf("wrap after approval=%d %s", code, out)
	}
	// Removal and an administrator's re-add start over: approval is not remembered.
	if code, out := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id+"/members/"+puppet.id, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("remove=%d %s", code, out)
	}
	add()
	if approved, listed := approvedOf(t, tm.owner, tm.id, puppet.id); !listed || approved {
		t.Fatal("readmitted member kept its approval")
	}
	// unapproved reset: it never held a key, so its reset retires nothing (P5 retireKeysTx).
	before, _ := generationOf(t, tm.owner, tm.id)
	puppet.stepUp(t)
	if code, out := status(t, puppet.do(t, http.MethodPut, "/api/v1/me/identity", resetBody(bytes.Repeat([]byte{7}, 32), expecting(puppetID)+resetRecovery+b64s(recoveryCopy)+`"}`), true, false)); code != http.StatusOK {
		t.Fatalf("unapproved reset=%d %s", code, out)
	}
	if after, _ := generationOf(t, tm.owner, tm.id); after != before {
		t.Fatalf("an unapproved member's reset retired the team key: %d -> %d", before, after)
	}
}

func TestInvitedMembersAreApproved(t *testing.T) {
	tm := newTeam(t)
	for _, m := range []member{tm.admin, tm.editor, tm.viewer} {
		if approved, listed := approvedOf(t, tm.owner, tm.id, m.id); !listed || !approved {
			t.Fatalf("%s approved=%v", m.id, approved)
		}
	}
	guest := tm.owner.addUser(t, "guest")
	inv, code := invite(t, tm.owner, tm.id, guest.id)
	if code != http.StatusOK {
		t.Fatalf("invite=%d", code)
	}
	if code := accept(t, guest.pairClient, inv); code != http.StatusNoContent {
		t.Fatalf("accept=%d", code)
	}
	if approved, _ := approvedOf(t, tm.owner, tm.id, guest.id); !approved {
		t.Fatal("an invited member waits for approval")
	}
}
```

  `invite(t, p, cid, invitee) ([2]string, int)` and `accept(t, p, inv [2]string) int` are in `teamkeys_test.go:840-853`. `resetBody`, `expecting`, `resetRecovery`, `recoveryCopy`, `b64s` and `generationOf` are the P5 reset helpers in `teamkeys_p5_test.go`; add `"bytes"` to the imports.

- [ ] **Step 2: Run it and see it fail.** Run: `go test ./internal/httpapi -run 'TestAdminAddedMembers|TestInvitedMembers' -v`. Expected: FAIL. The members response has no `approved`, and the approve route answers 405.

- [ ] **Step 3: Admission records approval.** In `teamkeys_routes.go`, change `admitMemberTx` to:

```go
// admitMemberTx admits userID to team cid and its live child workspaces, reactivating rows a removal
// revoked. approved is false only for the server-admin add: no key reaches that member until a
// steward of the team approves it.
func admitMemberTx(tx *sql.Tx, cid, userID, role, invitedBy string, approved bool, now string) (readmit bool, err error) {
	var live int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM memberships WHERE user_id=?1 AND revoked_at='' AND container_id IN (SELECT id FROM containers WHERE id=?2 OR team_id=?2)`, userID, cid).Scan(&live); err != nil {
		return false, err
	}
	if live > 0 {
		return false, errMembershipExists
	}
	const scope = `(SELECT id FROM containers WHERE (id=?2 OR team_id=?2) AND deleted_at='')`
	for i, q := range []string{
		`UPDATE memberships SET role=?3,created_at=?4,revoked_at='',invited_by=?5,approved=?6 WHERE user_id=?1 AND container_id IN ` + scope,
		`INSERT INTO memberships(id,container_id,user_id,role,created_at,invited_by,approved) SELECT 'mem_' || lower(hex(randomblob(12))),c.id,?1,?3,?4,?5,?6 FROM containers c WHERE c.id IN ` + scope + ` AND NOT EXISTS(SELECT 1 FROM memberships m WHERE m.container_id=c.id AND m.user_id=?1)`,
	} {
		res, err := tx.Exec(q, userID, cid, role, now, invitedBy, approved)
		if err != nil {
			return false, err
		}
		if n, _ := res.RowsAffected(); i == 0 && n > 0 {
			readmit = true
		}
	}
	return readmit, nil
}
```

  Update the callers: `collab_routes.go:196` passes `true` (accept), and `admin_routes.go:111` passes `false` (server-admin add). Child workspaces created later copy team memberships in two `INSERT … SELECT`s (`container_routes.go:91`, the creating steward's row, and `:94`, everyone else's): add `approved` to both column lists and both `SELECT`s, beside `invited_by`. Without it an unapproved member is approved in every new child workspace.

- [ ] **Step 4: Keys follow approval.** In `insertEnvelopeTx`, change the recipient join to `JOIN memberships m ON m.user_id=d.user_id AND m.container_id=? AND m.revoked_at='' AND m.approved=1`. In `uncoveredIdentitiesSQL`, add `AND m.approved=1` to its memberships join. An unapproved recipient then gets the existing `errEnvelopeInvalid` (`400 invalid_request`). Invitation envelopes need no change: accept admits with `approved=true`, and `moveInvitationEnvelopesTx` runs only after that admission. In P5's `retireKeysTx`, change the scope to `(SELECT container_id FROM memberships WHERE user_id=?1 AND revoked_at='' AND approved=1)`: an unapproved member never held a key, so its self-service reset retires nothing, and an account an administrator controls cannot hold a team's writes in waiting three times a day.

- [ ] **Step 5: Members report approval; the approve route.** In `collab_routes.go` `GET …/members`, add `m.approved` to the `SELECT` after P5's `keyResetAt` subquery, scan it into `approved int`, and change the rows to `out := []map[string]any{}` with `member := map[string]any{"userId": id, "username": username, "role": memberRole, "approved": approved != 0}`. Keep P5's steward-only `if isSteward(role) && resetAt != "" { member["keyResetAt"] = resetAt }` (`TestStewardsSeeWhoResetTheirKey` pins it). Add after the members `DELETE` route:

```go
	mux.Handle("POST /api/v1/containers/{id}/members/{userID}/approve", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		cid, target := r.PathValue("id"), r.PathValue("userID")
		if ids.Validate("cnt", cid) != nil || ids.Validate("usr", target) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		err := dbTx(db, func(tx *sql.Tx) error {
			var role string
			// An unapproved caller is never a steward (the admin add admits no steward role); approved=1 keeps it so.
			if err := tx.QueryRow(`SELECT m.role FROM memberships m JOIN containers c ON c.id=m.container_id AND c.deleted_at='' AND c.team_id='' WHERE m.container_id=? AND m.user_id=? AND m.revoked_at='' AND m.approved=1`, cid, s.UserID).Scan(&role); err != nil {
				return err
			}
			if !isSteward(role) {
				return errInsufficientRole
			}
			res, err := tx.Exec(`UPDATE memberships SET approved=1 WHERE user_id=? AND revoked_at='' AND container_id IN (SELECT id FROM containers WHERE (id=? OR team_id=?) AND deleted_at='')`, target, cid, cid)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return errNotMember
			}
			return storage.RecordAuditOutcomeTx(tx, s.UserID, "container.member_approve", cid, target, "success", "", RequestID(r))
		})
		if writeTeamKeyError(w, r, err) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))
```

  `c.team_id=''` restricts approval to the team itself; child workspaces follow it. Check that `isSteward` exists in Go (`grep -n 'func isSteward' internal/httpapi`); it is the owner-or-admin test `insertEnvelopeTx` uses. Approving an approved member is a 204 with an audit row. The `UPDATE` matches the row, so `RowsAffected` is 1.

- [ ] **Step 6: Run.** Run: `go test -race ./internal/httpapi`. Expected: PASS. P3b tests that re-add through the server-admin route and then expect keys to flow (`TestRemovedMemberIsReadmittedByReactivation`, `TestAcceptAndAdminAddAreAudited`) now need an owner approval before any envelope step. Add `status(t, tm.owner.do(t, http.MethodPost, "/api/v1/containers/"+tm.id+"/members/"+<id>+"/approve", nil, true, false))` there and keep their assertions.

- [ ] **Step 7: Frozen contracts.** In `IMPLEMENTATION_PLAN.md`, add the approve route to the §5.1 table: `| POST | /api/v1/containers/{id}/members/{userID}/approve | session + CSRF, owner/admin of team id | 204; approves the member on the team and its child workspaces; 404 non-member, 403 non-steward; audit container.member_approve |`. In §9, add: "A member the server administrator added (`approved=0`) receives no envelope and is not required by rotation until a steward approves it; invitations admit approved members." Put the same sentence in the `DESIGN.md` membership paragraph, after "Team roles are owner, admin, editor, commenter, and viewer." In the `PUT /api/v1/me/identity` row, change "the user is a live member of" to "the user is a live, approved member of". Add `approved` (bool) to the `GET /api/v1/containers/{id}/members` row beside `keyResetAt`.

- [ ] **Step 8: Commit.**

```bash
git add internal/httpapi IMPLEMENTATION_PLAN.md DESIGN.md
git commit -m "teams: members an administrator adds get no key until a steward approves them"
```

### Task 6: SSO, directory sync and apply-setup keep the kinds apart

**Files:**
- Modify: `internal/httpapi/sso_routes.go` (callback), `internal/httpapi/sso_directory.go` (`syncSingleUser`, apply audit, readback), `internal/applysetup/decide.go`, `internal/httpapi/apply_setup.go` (`lookupAccount`)
- Create: `internal/httpapi/sso_kinds_test.go`
- Modify: `internal/applysetup/decide_test.go`, `internal/httpapi/apply_setup_test.go`, `internal/httpapi/sso_app_roles_test.go`, `internal/httpapi/sso_directory_test.go`
- Modify: `IMPLEMENTATION_PLAN.md` OIDC callback and directory rows

**Interfaces:**
- Consumes: `newLogoutFixture`, `roleCallback`, `seedSSOAdmin`, `directoryPayload`, `sendDirectory`, `sso.AdminAppRole`.
- Produces: `ssoKindRefusal(kind string, appAdmin bool) string`; `applysetup.Account.Kind`; readback `accountKind`.

- [ ] **Step 1: Write the failing tests.** Create `internal/httpapi/sso_kinds_test.go`:

```go
package httpapi

import (
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/sso"
)

func TestSSOKindsFollowTheToken(t *testing.T) {
	f := newLogoutFixture(t)
	admin := []string{sso.AdminAppRole}
	refused := func(name, subject string, roles []string, code string) {
		t.Helper()
		res := roleCallback(f, subject, roles, "")
		if res.Code != 403 || errorCode(t, res.Body.String()) != code {
			t.Fatalf("%s: %d %s", name, res.Code, res.Body.String())
		}
	}
	refused("unprovisioned admin", "boss", admin, "admin_account_not_provisioned")
	var n int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM users WHERE username='boss'`).Scan(&n); err != nil || n != 0 {
		t.Fatal("a token with the admin role created an account", n, err)
	}
	if res := roleCallback(f, "alice", nil, ""); res.Code != 302 {
		t.Fatalf("everyday sign-in: %d %s", res.Code, res.Body.String())
	}
	refused("everyday with the role", "alice", admin, "admin_role_on_everyday_account")
	seedSSOAdmin(f, "ops")
	refused("admin without the role", "ops", nil, "admin_role_required")
	if res := roleCallback(f, "ops", admin, ""); res.Code != 302 {
		t.Fatalf("admin sign-in: %d %s", res.Code, res.Body.String())
	}
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='auth.sso_admin_refused' AND outcome='denied'`).Scan(&n); err != nil || n != 3 {
		t.Fatal("refusal audits", n, err)
	}
}

func TestDirectoryNeverGrantsAdminToEverydayAccounts(t *testing.T) {
	f := newLogoutFixture(t)
	settings := f.settings.Load()
	settings.HMACSecret = strings.Repeat("s", 32)
	if err := f.settings.Save(settings); err != nil {
		t.Fatal(err)
	}
	send := func(subject string, version int64, roles []any, event string) {
		t.Helper()
		p := directoryPayload(subject, subject, version, true)
		p["roles"] = roles
		if r := sendDirectory(t, f.router, "/sync/events", settings.HMACSecret, subject+"-"+time.Now().String(), event, p); r.Code != 200 {
			t.Fatalf("%s v%d: %d %s", subject, version, r.Code, r.Body.String())
		}
	}
	kind := func(subject string) (string, string) {
		var k, role string
		if err := f.db.QueryRow(`SELECT account_kind,role FROM users WHERE sso_subject=?`, subject).Scan(&k, &role); err != nil {
			t.Fatal(err)
		}
		return k, role
	}
	send("ops", 1, []any{sso.AdminAppRole}, "user.created")
	if k, role := kind("ops"); k != "admin" || role != "admin" {
		t.Fatalf("created administrator identity: %s %s", k, role)
	}
	send("alice", 1, []any{}, "user.created")
	send("alice", 2, []any{sso.AdminAppRole}, "user.updated")
	if k, role := kind("alice"); k != "user" || role != "user" {
		t.Fatalf("everyday account took the grant: %s %s", k, role)
	}
	var reason string
	if err := f.db.QueryRow(`SELECT reason_code FROM audit_events WHERE event='directory.apply' AND object_id='alice' ORDER BY at DESC, rowid DESC LIMIT 1`).Scan(&reason); err != nil || !strings.Contains(reason, "role=user") || !strings.HasSuffix(reason, ",role_refused=everyday_account") {
		t.Fatalf("audit %q %v", reason, err)
	}
	// Another active administrator, so revoking ops's grant is not the last-admin retention case.
	if _, err := f.db.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,account_kind,created_at,updated_at) VALUES('usr_spare','spare','h','s',1,'admin','admin','now','now')`); err != nil {
		t.Fatal(err)
	}
	send("ops", 2, []any{}, "user.updated")
	if k, role := kind("ops"); k != "admin" || role != "user" {
		t.Fatalf("revoked grant: %s %s", k, role)
	}
}
```

  `directoryPayload(id, username, version, active)` and `sendDirectory(t, router, path, secret, eventID, type, payload)` are used here as `TestSSOAppRolesRequireExplicitTokenAndAccountPermission` uses them.

  Add to `TestDecideAdmin` in `internal/applysetup/decide_test.go`: give `admin` and `other` `Kind: "admin"`, give `disabled` `Kind: "user"`, add `inert := &Account{ID: "usr_1", Username: "owner", Role: "user", Status: "active", Kind: "admin"}` and `everyday := &Account{ID: "usr_1", Username: "owner", Role: "user", Status: "active", Kind: "user"}`, and replace the `bound user` case with `{"bound admin without grant", inert, nil, Created, GrantAdmin}` and `{"bound everyday", everyday, nil, Conflict, NoAction}`.

  In `apply_setup_test.go` `TestApplyAdminGrantRevokesCredentials`, insert `usr_b` with `account_kind` `'admin'` (role `'user'`). Add `TestApplyAdminNeverPromotesAnEverydayAccount`: insert `usr_c` (`role='user'`, `account_kind='user'`, bound to `sub-everyday`), call `applyAdmin(db, cfg, setupTestIssuer, applysetup.Admin{Issuer: setupTestIssuer, Subject: "sub-everyday", Username: "x-admin"})`, and expect `res.Status == applysetup.Conflict`, `role` still `user` and zero `admin.user.update` audits.

- [ ] **Step 2: Run them and see them fail.** Run: `go test ./internal/httpapi ./internal/applysetup -run 'TestSSOKinds|TestDirectoryNeverGrants|TestDecideAdmin|TestApplyAdmin' -v`. Expected: FAIL.

- [ ] **Step 3: The callback.** In `sso_routes.go`, add at package level:

```go
// ssoKindRefusal: an identity carrying kynotes.admin is an administrator identity. It signs in only to an
// admin account, and an admin account only with it. Automatic provisioning never makes one. "" admits.
func ssoKindRefusal(kind string, appAdmin bool) string {
	switch {
	case kind == "" && appAdmin:
		return "admin_account_not_provisioned"
	case kind == auth.KindEveryday && appAdmin:
		return "admin_role_on_everyday_account"
	case kind == auth.KindAdmin && !appAdmin:
		return "admin_role_required"
	}
	return ""
}

var ssoKindMessages = map[string]string{
	"admin_account_not_provisioned":  "administrator identities sign in only to an administrator account set up by apply-setup, directory sync or an administrator",
	"admin_role_on_everyday_account": "this identity carries the KyNotes administrator role, but its account is an everyday account; ask your identity administrator to move the role to a separate administrator identity",
	"admin_role_required":            "this administrator account needs the KyNotes administrator role at sign-in",
}
```

  In the callback, change the lookup to `SELECT id, status, account_kind FROM users WHERE sso_subject=? AND sso_issuer=?`, scanning into `userID, userStatus, kind`. Right after the lookup's error check, before automatic provisioning:

```go
		if refused := ssoKindRefusal(kind, claims.AppAdmin); refused != "" {
			recordAuditOutcome(db, userID, "auth.sso_admin_refused", "", claims.Subject, "denied", refused, RequestID(r))
			WriteError(w, r, http.StatusForbidden, refused, ssoKindMessages[refused])
			return
		}
```

  Automatic provisioning then runs only for tokens without the role, and its `INSERT` sets `account_kind` `'user'` explicitly.

- [ ] **Step 4: Directory.** In `syncSingleUser`, add `account_kind` to both `SELECT`s (scanning into `existingKind`) and change the return type to `(note string, err error)`:

```go
const (
	noteRetained = ",admin_retained=true"
	noteRefused  = ",role_refused=everyday_account"
)
```

  After `role := u.localRole()` and the status lines, for an existing account:

```go
	// An everyday account never takes the grant; the subject's sign-in is refused instead (ssoKindRefusal).
	if role == "admin" && existingKind != auth.KindAdmin {
		role, note = "user", noteRefused
	}
```

  Place this after the insert branch, so it applies only to an existing account. Set `note = noteRetained` where `retained = true` was set. Change the revocation condition to `if u.localRole() != existingRole && note != noteRefused`, and return `note, err`. In the creation `INSERT`, `account_kind` is `role` (Task 1). In the caller, replace `var retained bool` with `var note string`, and `retained, err = syncSingleUser(tx, cfg, settings.IssuerURL, &u)` with `note, err = syncSingleUser(tx, cfg, settings.IssuerURL, &u)`. Replace the audit block (from `role, extra := u.localRole(), ""` through its `RecordAuditOutcomeTx` call) with:

```go
		if err == nil {
			role := u.localRole()
			switch note {
			case noteRetained:
				role = "admin"
			case noteRefused:
				role = "user"
			}
			err = storage.RecordAuditOutcomeTx(tx, "", "directory.apply", "", u.ID, "success", fmt.Sprintf("revision=%d,active=%t,role=%s,event=%s", revision, *u.Active, role, event.ID)+note, RequestID(r))
		}
```

  In readback, select `account_kind` beside `status,role` and add `"accountKind": kind` to `observed` (`""` when absent).

- [ ] **Step 5: apply-setup.** In `internal/applysetup/decide.go`, change `Account` to `type Account struct{ ID, Username, Role, Status, Kind string }`. In `DecideAdmin`, add this case after the disabled one:

```go
	case bound != nil && bound.Kind != "admin":
		return Conflict, NoAction, "the account bound to this identity is an everyday account; give the administrator its own identity"
```

  In `apply_setup.go`, both `lookupAccount` queries select `id,username,role,status,account_kind`, and `lookupAccount` scans `&a.Kind`.

- [ ] **Step 6: Adapt the role tests that assumed one account for both jobs.** In `TestSSOAppRolesRequireExplicitTokenAndAccountPermission` (`sso_app_roles_test.go`):
  1. Before the first callback, add `aliceID := seedSSOAdmin(f, "alice")` and `UPDATE users SET role='user' WHERE id=aliceID`: an admin account whose grant directory sync has not given yet.
  2. `legacy := roleCallback(f, "alice", nil, "admin")` now answers `403 admin_role_required`. Assert that, and delete the `admin(legacy…)` and `role persisted` checks.
  3. `tokenOnly` (role claim, grant not given) stays `302` with `admin()` `403`.
  4. `roleCallback(f, "alice", []string{"admin"}, "admin")` now answers `403 admin_role_required`. Assert that code instead of `302`.
  5. After `provision(2, …)`, check only `admin(tokenOnly…) == 401`, since `legacy` has no session.
  6. `user := roleCallback(f, "alice", []string{}, "admin")` now answers `403 admin_role_required`. Assert that, and read the session report from `elevated` instead (`Role == "admin"`, plus `AccountKind == "admin"`).
  7. The local password session's device pairing now answers `403 admin_account`. `f.pairing` calls `t.Fatalf` on anything but 200 (`sso_logout_test.go:213`), so send the request directly: `res := f.send(withCookies(httptest.NewRequest("POST", "/api/v1/devices/pairing-token", nil), cookies))`, and assert `res.Code == 403` and `errorCode(t, res.Body.String()) == "admin_account"`.
  Keep every later assertion (`fail_role_audit` and on).

  Run `go test ./internal/httpapi -run 'TestDirectory|TestSSOAppRoles|TestSSOStepUp' -v`. Some directory tests create a subject without `kynotes.admin` and grant it later. If the test is about the shapes of role data (`TestDirectoryAppRoleShapes`), make the first event for the subject carry `kynotes.admin`: it is an administrator identity. If it is about the everyday account, assert `role_refused=everyday_account`. `TestDirectoryRetainsLastActiveAdminGrant` and `TestDirectoryDeactivationIgnoresRoles` keep their assertions once their subject is created with the role.

- [ ] **Step 7: Run.** Run: `go test -race ./...`. Expected: PASS.

- [ ] **Step 8: Frozen contracts.** In `IMPLEMENTATION_PLAN.md`, add the four new 403 codes to §1.7 with their meanings from spec §5. In the OIDC callback description, add the §5 table in one sentence per row. Add `accountKind` to the directory readback.

- [ ] **Step 9: Commit.**

```bash
git add internal IMPLEMENTATION_PLAN.md
git commit -m "sso: the administrator role signs in only to an administrator account; directory and apply-setup never promote an everyday one"
```

### Task 7: Web: account kinds in the API, two-account setup, routing, the forced password change

**Files:**
- Modify: `web/src/api.ts`, `web/src/api.test.ts`, `web/src/main.tsx` (`AuthState`, `App`, `Login`, `PasswordSettings`, new `ChoosePassword`), `web/src/workspaceWiring.test.ts`
- Create: `web/src/setup.ts`, `web/src/setup.test.ts`

**Interfaces:**
- Consumes: Tasks 2–5 response fields.
- Produces: `AccountKind`, `User.accountKind`, `Session.passwordChangeRequired`, `SetupAccount`, `setupInit(admin, everyday)`, `createAdminTeam(ownerUserId)`, `approveMember`, `createAdminUser({…, accountKind})`, `setupProblem`, `CHOOSE_PASSWORD`, `ChoosePassword`, `PasswordSettings` props `everyday` and `onChanged`.

- [ ] **Step 1: Write the failing tests.** Create `web/src/setup.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { setupProblem } from "./setup";

const good = { admin: "admin", adminPassword: "admin horse battery", adminConfirm: "admin horse battery", everyday: "owner", everydayPassword: "owner horse battery", everydayConfirm: "owner horse battery" };

describe("setupProblem", () => {
  it("accepts two accounts with their own names and passwords", () => {
    expect(setupProblem(good)).toBeUndefined();
  });
  it("refuses equal passwords and equal usernames", () => {
    expect(setupProblem({ ...good, everydayPassword: good.adminPassword, everydayConfirm: good.adminPassword })).toBe("Use a different password for each account.");
    expect(setupProblem({ ...good, everyday: " Admin " })).toBe("Use a different username for each account.");
  });
  it("refuses empty names, unequal confirmations and short passwords", () => {
    expect(setupProblem({ ...good, everyday: "  " })).toBe("Both usernames are required.");
    expect(setupProblem({ ...good, adminConfirm: "x" })).toBe("Passwords do not match.");
    expect(setupProblem({ ...good, everydayPassword: "short", everydayConfirm: "short" })).toBe("Passwords must be at least 8 characters.");
  });
});
```

  In `web/src/api.test.ts`, replace the `createAdminTeam` test body with:

```ts
  it("creates a notebook without a name and an administrator's team for a named owner", async () => {
    const sent = capture();
    await createContainer("workbook", cnt);
    await createAdminTeam("usr_owner");
    expect(sent.map((entry) => entry.body)).toEqual([{ kind: "workbook", teamId: cnt }, { ownerUserId: "usr_owner" }]);
    expect(createContainer.length).toBe(0);
    expect(createAdminTeam.length).toBe(1);
  });
```

  In `workspaceWiring.test.ts`, change the I1 test's two `toContain` strings to the new code from Steps 4 and 5:

```ts
    expect(main).toContain("if (res.user.accountKind === \"admin\" || res.passwordChangeRequired) {");
    expect(main).toContain("if (res.sso) {\n          setAuth({ username: res.user.username, authSecret: await ssoDeviceSecret(res.user.username), user: res.user, sso: true });\n          return;\n        }\n        setSessionUser(res.user);");
    expect(main.indexOf("res.passwordChangeRequired) {")).toBeLessThan(main.indexOf("if (res.sso) {"));
    const submit = block("  async function submit(");
    expect(submit).not.toMatch(/sso: true/);
    expect(submit.match(/catch/g)).toHaveLength(1);
    expect(submit).toContain("const result = await login(activeName, authSecret);");
    // Only an everyday account on its own password keeps a vault record, after the server accepted the password.
    expect(submit).toContain("if (everyday && !result.passwordChangeRequired) {\n        await rememberAfter(async () => result, activeName, authSecret);");
```

  In "never tells an owner to wait for a team owner", delete the two assertions on `ADMIN_PASSWORD_FIRST`/`adminSetPassword` and `settlePasswordIdentity(...) === "admin-password"`, because Step 6 deletes that banner, and add `expect(main).not.toMatch(/adminSetPassword|ADMIN_PASSWORD_FIRST/);`. The first test's `createNamed` count stays at 4 here: `createTeam` leaves `main.tsx` only in Task 8, which changes that count.

- [ ] **Step 2: Run them and see them fail.** Run: `cd web && npx vitest run src/setup.test.ts src/api.test.ts src/workspaceWiring.test.ts`. Expected: FAIL (`./setup` missing, and `createAdminTeam` takes no argument).

- [ ] **Step 3: `setup.ts` and `api.ts`.** Create `web/src/setup.ts`:

```ts
/** Why the first-run form may not be sent yet, or undefined. The server never sees either password, so this is the only place they are compared. */
export function setupProblem(input: { admin: string; adminPassword: string; adminConfirm: string; everyday: string; everydayPassword: string; everydayConfirm: string }): string | undefined {
  const admin = input.admin.trim().toLowerCase();
  const everyday = input.everyday.trim().toLowerCase();
  if (!admin || !everyday) return "Both usernames are required.";
  if (admin === everyday) return "Use a different username for each account.";
  if (input.adminPassword !== input.adminConfirm || input.everydayPassword !== input.everydayConfirm) return "Passwords do not match.";
  if (input.adminPassword.length < 8 || input.everydayPassword.length < 8) return "Passwords must be at least 8 characters.";
  if (input.adminPassword === input.everydayPassword) return "Use a different password for each account.";
  return undefined;
}
```

  In `web/src/api.ts`:

```ts
export type AccountKind = "user" | "admin";
export type User = { id: string; role: string; username?: string; accountKind: AccountKind };
export type Session = { sso?: boolean; user: User; passwordChangeRequired?: boolean; expiresAt: string; hardExpiresAt: string };
export type AdminUser = { id: string; username: string; role: string; accountKind: AccountKind; status: string; quotaBytes: number; createdAt: string };
export type AdminTeam = { id: string; ownerUserId: string; ownerUsername: string; memberCount: number; keyed: boolean; named: boolean };
export type SetupAccount = { username: string; authSecret: string; loginSalt: string; iterations: number };

export function setupInit(admin: SetupAccount, everyday: SetupAccount) {
  return request<{ ok: boolean; user: User; expiresAt: string; hardExpiresAt: string }>("/api/v1/setup", { method: "POST", body: JSON.stringify({ admin, everyday }) });
}
export function createAdminTeam(ownerUserId: string) { return request<AdminTeam>("/api/v1/admin/teams", { method: "POST", body: JSON.stringify({ ownerUserId }) }); }
export function createAdminUser(input: { username: string; authSecret: string; loginSalt: string; iterations: number; accountKind: AccountKind }) { return request<{ id: string }>("/api/v1/admin/users", { method: "POST", body: JSON.stringify(input) }); }
export function approveMember(containerID: string, userID: string) { return request<void>(`/api/v1/containers/${encodeURIComponent(containerID)}/members/${encodeURIComponent(userID)}/approve`, { method: "POST" }); }
```

  These replace the existing `User`, `Session`, `AdminUser`, `AdminTeam`, `setupInit`, `createAdminTeam` and `createAdminUser`. `login` returns `Session & { identity?: IdentityRecord }`. Run `npx tsc --noEmit -p .` and fix each caller it names. `observe.ts` callers go away in Task 8, so for now change `newAdminTeam` to take `(sink, ownerUserId)` and pass it through.

- [ ] **Step 4: `App` routes on the session.** In `main.tsx`, add `passwordChangeRequired?: boolean` to `AuthState`. In `App`'s session effect, insert before `if (res.sso) {`:

```tsx
        // An administrator browser keeps no vault record, and a password someone else set unlocks nothing.
        if (res.user.accountKind === "admin" || res.passwordChangeRequired) {
          setAuth({ username: res.user.username, authSecret: "", user: res.user, sso: res.sso, passwordChangeRequired: res.passwordChangeRequired });
          return;
        }
```

  Replace the `return auth ? (<Workspace …/>) : (<Login …/>);` with:

```tsx
  const signOut = () => {
    void logout().finally(() => {
      clearFloors();
      setAuth(null);
      setSessionUser(null);
    });
  };
  if (auth?.passwordChangeRequired)
    return <ChoosePassword auth={auth} onChanged={(authSecret) => setAuth({ ...auth, authSecret: auth.user.accountKind === "admin" ? "" : authSecret, passwordChangeRequired: false })} onLogout={signOut} />;
  if (auth?.user.accountKind === "admin")
    return <AdminConsole username={auth.username} sso={auth.sso === true} onLogout={signOut} password={<PasswordSettings username={auth.username} userID={auth.user.id} everyday={false} onAuthSecret={() => {}} onIdentityCreated={() => {}} />} />;
  return auth ? (
```

  Then keep the existing `<Workspace … />` / `<Login … />` expression. Route `Workspace`'s `onLogout` to `signOut`. `AdminConsole` comes from Task 8. Until then, add a stub in `web/src/components/AdminConsole.tsx` that exports `AdminConsole` with these props and renders `<main className="settings-layout admin-settings-layout"><h1>Administration</h1>{password}<button onClick={onLogout}>Sign out</button></main>`. Task 8 replaces the body.

- [ ] **Step 5: `Login`.** Replace the body of `submit`'s `try` with:

```tsx
      const activeName = username.trim() || sessionUser?.username || "";
      const params = await loginParams(activeName);
      const keys = await deriveLoginKeys(password, params.loginSalt, params.iterations);
      const authSecret = keys.authSecret;
      // A password the server refuses never lets anyone in.
      const result = await login(activeName, authSecret);
      sessionStorage.setItem("kynotes-last-username", activeName);
      const everyday = result.user.accountKind === "user";
      if (everyday && !result.passwordChangeRequired) {
        await rememberAfter(async () => result, activeName, authSecret);
        await settleIdentity(activeName, result.user.id, keys, result.identity);
      }
      onLogin({ username: activeName, authSecret: everyday ? authSecret : "", user: result.user, passwordChangeRequired: result.passwordChangeRequired });
      setPassword("");
```

  Replace the setup form. State: `adminName` (default `"admin"`), `everydayName`, `password`/`confirmPassword` for the administrator, and `everydayPassword`/`everydayConfirm`. `submitSetup`:

```tsx
  async function submitSetup(event: React.FormEvent) {
    event.preventDefault();
    const problem = setupProblem({ admin: adminName, adminPassword: password, adminConfirm: confirmPassword, everyday: everydayName, everydayPassword, everydayConfirm });
    if (problem) {
      setError(problem);
      return;
    }
    setError("");
    setBusy(true);
    try {
      // Each password stays in this browser; the server sees only each account's authSecret.
      const account = async (name: string, secret: string): Promise<SetupAccount> => {
        const loginSalt = randomLoginSalt();
        return { username: name.trim(), authSecret: (await deriveLoginKeys(secret, loginSalt, 600000)).authSecret, loginSalt, iterations: 600000 };
      };
      const result = await setupInit(await account(adminName, password), await account(everydayName, everydayPassword));
      sessionStorage.setItem("kynotes-last-username", everydayName.trim());
      onLogin({ username: adminName.trim(), authSecret: "", user: result.user });
    } catch (error) {
      setError(error instanceof Error ? error.message : "Setup failed");
    } finally {
      setBusy(false);
    }
  }
```

  The form keeps `<h1>Create Admin Account</h1>` replaced by `<h1>Set up KyNotes</h1>`, with two `<fieldset>`s. The first, `<legend>Administrator login</legend>`, has a hint: "Manages users, teams, sign-on and backups. It cannot open notes." The second, `<legend>Everyday login</legend>`, has "The account you write notes with." Each block has three labelled inputs, with the labels from Global Constraints, `type="password"` and `autoComplete="new-password"` on the password fields. The submit button is `Initialize KyNotes`. Remove `settleIdentity` and `rememberAfter` from setup: the browser is the administrator's.

- [ ] **Step 6: `PasswordSettings` and `ChoosePassword`.** Give `PasswordSettings` two props, `everyday: boolean` and `onChanged?: (authSecret: string) => void`. In `submit`, for `everyday === false`, skip `getIdentityKey`, `rewrapIdentity`, `rememberAfter` and `settleIdentity`, and call `changePassword({ currentAuthSecret: currentKeys.authSecret, newAuthSecret: newKeys.authSecret, newLoginSalt, iterations: 600000 })` directly. After `setStatus("Password changed.")`, call `onChanged?.(newKeys.authSecret)`. The workspace's Settings passes `everyday`. Add after `PasswordSettings`:

```tsx
const CHOOSE_PASSWORD = "An administrator set this account's password. Choose your own before you continue.";

/** Shown before anything else while the server reports passwordChangeRequired; nothing runs before the change. */
function ChoosePassword({ auth, onChanged, onLogout }: { auth: AuthState; onChanged: (authSecret: string) => void; onLogout: () => void }) {
  return (
    <main className="auth-page">
      <section className="auth-card">
        <img src="/app-icon.png" width={56} height={56} alt="KyNotes" />
        <h1>Choose your own password</h1>
        <p role="status">{CHOOSE_PASSWORD}</p>
        <PasswordSettings username={auth.username} userID={auth.user.id} everyday={auth.user.accountKind === "user"} onAuthSecret={() => {}} onIdentityCreated={() => {}} onChanged={onChanged} />
        <button className="quiet" onClick={onLogout}>Sign out</button>
      </section>
    </main>
  );
}
```

  For an everyday account, the existing `settleIdentity` after the change creates the identity under the new password (P1), and `rememberAfter` keeps the new vault record. Delete the `adminSetPassword` set, the `ADMIN_PASSWORD_FIRST` constant and its banner. The `identity.ts` `"admin-password"` mapping stays, since the server still answers that code.

- [ ] **Step 7: Run.** Run: `cd web && npm test && npm run build`. Expected: PASS.

- [ ] **Step 8: Commit.**

```bash
git add web/src
git commit -m "web: two-account setup; administrator and change-required sessions route before the workspace"
```

### Task 8: Web: the administrator console holds no key

**Files:**
- Modify: `web/src/components/AdminConsole.tsx` (the full console), `web/src/main.tsx` (remove the admin view), `web/src/observe.ts`, `web/src/observe.test.ts`, `web/src/keyring.test.ts`
- Create: `web/src/adminSeparation.test.ts`

**Interfaces:**
- Consumes: Task 7 API, `AdminBackup`, `ConfirmPassword`, `deriveAuthSecret`, `randomLoginSalt`.
- Produces: `AdminConsole({ username, sso, onLogout, password })`, `ADMIN_ACCOUNT_NOTE`.

- [ ] **Step 1: Write the failing structure test.** Create `web/src/adminSeparation.test.ts`:

```ts
import { describe, expect, it } from "vitest";

const sources = import.meta.glob<string>(["./main.tsx", "./components/AdminConsole.tsx", "./observe.ts"], { query: "?raw", import: "default", eager: true });
const main = sources["./main.tsx"];
const adminConsole = sources["./components/AdminConsole.tsx"];

describe("administrator accounts (sub-project A)", () => {
  it("the admin console imports no key, vault or content crypto module and seals nothing", () => {
    const imports = [...adminConsole.matchAll(/from "([^"]+)"/g)].map((match) => match[1]);
    expect(imports.filter((path) => /keyring|keyService|teamKeys|observe|storage|floors|pins|identity|recovery|linking|outbound|drain/.test(path))).toEqual([]);
    expect(adminConsole).not.toMatch(/\b(?:encrypt|decrypt|seal|unwrap|wrapEnvelope)\w*\(/);
    expect(adminConsole).toContain("ADMIN_ACCOUNT_NOTE");
  });

  it("routes change-required and administrator sessions before the workspace", () => {
    const app = main.slice(main.indexOf("function App("), main.indexOf("function SharedNote("));
    const change = app.indexOf("if (auth?.passwordChangeRequired)");
    const admin = app.indexOf('if (auth?.user.accountKind === "admin")');
    expect(change).toBeGreaterThan(-1);
    expect(admin).toBeGreaterThan(change);
    expect(app.indexOf("<Workspace")).toBeGreaterThan(admin);
  });

  it("the workspace has no administrator view and never creates an administrator's team", () => {
    expect(main).not.toMatch(/setView\("admin"\)|newAdminTeam|listAdminTeams|function AdminTeams|function AdminSSO|createAdminTeam/);
    expect(sources["./observe.ts"]).not.toMatch(/adminTeams|createAdminTeam/);
  });

  it("teams are created for an everyday owner picked from active everyday users", () => {
    expect(adminConsole).toContain('users.filter((entry) => entry.status === "active" && entry.accountKind === "user")');
    expect(adminConsole).toContain("await createAdminTeam(owner)");
    expect(adminConsole).not.toMatch(/prompt\("Team name"/);
  });
});
```

  In `workspaceWiring.test.ts`'s first test, change `toHaveLength(4)` to `toHaveLength(3)`, the comment to "the definition, a notebook, a team workspace", and the `creations` filter to `/newContainer\(floorSink/` with `toHaveLength(2)`; and delete the `{knownNames[entry.id] ?? "Unnamed team"}` assertion in its second test (`AdminTeams` and `knownNames` leave `main.tsx` here). Delete the "AdminTeams decrypts nothing" test from `keyring.test.ts`; the console test replaces it. In `observe.test.ts` "is the only path to the raw container fetchers", change `raw` to `/\b(containers|createContainer)\b/`. Administrator team rows carry no key state, so they no longer pass the observer.

- [ ] **Step 2: Run it and see it fail.** Run: `cd web && npx vitest run src/adminSeparation.test.ts`. Expected: FAIL (the stub has no note, and `main.tsx` still has `AdminTeams`).

- [ ] **Step 3: Move the administrator pages.** From `main.tsx`, move `AdminCreateUser`, `AdminUserActions` and `AdminSSO` verbatim into `components/AdminConsole.tsx`. Move the `{admin && (…)}` branches of `SettingsView` too: the admin tab nav, server status, `AdminSSO`, `AdminBackup`, users, teams and audit, with the `users`/`audit`/`status` state and the `useEffect` that loads them and `saveUser`. Remove `admin`, `createTeam` and `knownNames` from `SettingsView`'s props and the workspace's `setView("admin")` button. The `view` union becomes `"workspace" | "settings"`. Remove `createTeam` from the workspace. Remove `listAdminTeams`, `newAdminTeam` and their imports from `observe.ts`. Then write the console:

```tsx
import { useEffect, useState, type ReactNode } from "react";
import { addAdminTeamMember, adminAudit, adminTeams, adminUsers, createAdminTeam, serviceStatus, updateAdminUser, type AdminTeam, type AdminUser, type AccountKind } from "../api";
import { deriveAuthSecret, randomLoginSalt } from "../crypto";
import { AdminBackup } from "./AdminBackup";
import { ConfirmPassword } from "./ConfirmPassword";

export const ADMIN_ACCOUNT_NOTE = "This is an administrator account. It manages KyNotes and cannot open notes. Sign in with your everyday account to write.";

/** Everything an administrator account reaches: no key, vault, notebook or content crypto (adminSeparation.test.ts). */
export function AdminConsole({ username, sso, onLogout, password }: { username: string; sso: boolean; onLogout: () => void; password: ReactNode }) {
  // (moved state, effect and saveUser from SettingsView's admin branch)
  return (
    <main className="settings-layout admin-settings-layout">
      <div className="settings-content">
        <div className="section-label">ADMIN</div>
        <h1>Administration</h1>
        <p role="note">{ADMIN_ACCOUNT_NOTE}</p>
        {/* (moved admin tab nav, with "Account" added for the password card) */}
        {/* (moved server, SSO, backups, users, teams, audit sections) */}
        <div id="account">{!sso && password}</div>
        <button className="quiet" onClick={onLogout}>Sign out</button>
      </div>
    </main>
  );
}
```

  The three comment lines mark where the moved JSX goes unchanged. They are moves of existing code, not new code. In the moved users section: the role `<select>` shows only for `user.accountKind === "admin"` (Grant: `admin`, Revoked: `user`), and everyday rows show the text "Everyday". `AdminCreateUser` replaces the role select with `<select aria-label="Account type" value={kind} onChange={(event) => setKind(event.target.value as AccountKind)}><option value="user">Everyday</option><option value="admin">Administrator</option></select>` and sends `accountKind: kind`. SSO administrators change no password here, which is why `{!sso && password}`.

- [ ] **Step 4: Teams for an everyday owner.** Replace `AdminTeams` (now in the console) with:

```tsx
function AdminTeams({ users, username }: { users: AdminUser[]; username: string }) {
  const [teams, setTeams] = useState<AdminTeam[]>([]);
  const [owner, setOwner] = useState("");
  const [team, setTeam] = useState("");
  const [user, setUser] = useState("");
  const [role, setRole] = useState("editor");
  const everyday = users.filter((entry) => entry.status === "active" && entry.accountKind === "user");
  async function reload() {
    try {
      setTeams(await adminTeams());
    } catch {
      /* The admin page remains usable if the list refresh is unavailable. */
    }
  }
  useEffect(() => {
    void reload();
  }, []);
  async function create() {
    if (!owner) return;
    try {
      setTeam((await createAdminTeam(owner)).id);
      await reload();
    } catch (error) {
      alert(error instanceof Error ? error.message : "Unable to create team");
    }
  }
  async function add() {
    if (!team || !user) return;
    try {
      await addAdminTeamMember(team, user, role);
      alert("Person added. They get the team's keys once one of its owners approves them.");
      await reload();
    } catch (error) {
      alert(error instanceof Error ? error.message : "Unable to add person");
    }
  }
  return (
    <section className="config-card">
      <h2>Teams</h2>
      <p className="config-muted">A team belongs to an everyday owner, who names it and shares its keys. Administrators never see its name or its notes.</p>
      <ConfirmPassword username={username} what="Creating teams and adding people" />
      <label className="field">
        <span>Owner</span>
        <select value={owner} onChange={(event) => setOwner(event.target.value)}>
          <option value="">Select owner</option>
          {everyday.map((entry) => <option key={entry.id} value={entry.id}>{entry.username}</option>)}
        </select>
      </label>
      <button disabled={!owner} onClick={() => void create()}>Create team</button>
      <ul className="admin-teams">
        {teams.map((entry) => (
          <li key={entry.id}><code>{entry.id}</code> · owner {entry.ownerUsername} · {entry.memberCount} {entry.memberCount === 1 ? "member" : "members"} · {entry.named ? "named" : "not named yet"} · {entry.keyed ? "keyed" : "waiting for its owner"}</li>
        ))}
      </ul>
      <label className="field">
        <span>Team</span>
        <select value={team} onChange={(event) => setTeam(event.target.value)}>
          <option value="">Select team</option>
          {teams.map((entry) => <option key={entry.id} value={entry.id}>{entry.id} · {entry.ownerUsername}</option>)}
        </select>
      </label>
      <label className="field">
        <span>Person</span>
        <select value={user} onChange={(event) => setUser(event.target.value)}>
          <option value="">Select person</option>
          {everyday.map((entry) => <option key={entry.id} value={entry.id}>{entry.username}</option>)}
        </select>
      </label>
      <label className="field">
        <span>Role</span>
        <select value={role} onChange={(event) => setRole(event.target.value)}>
          <option>editor</option>
          <option>commenter</option>
          <option>viewer</option>
        </select>
      </label>
      <button onClick={() => void add()}>Add to team</button>
    </section>
  );
}
```

  The role list has no `admin`: the server refuses steward roles from an administrator (Task 4), and a team admin comes only from a steward's invitation. The structure test pins `users.filter((entry) => entry.status === "active" && entry.accountKind === "user")`. Keep that exact text: assign it to `everyday` as shown. Update the `AdminUserActions` reset alert so it still matches `workspaceWiring.test.ts` ("Password reset. … keeps its encryption key … recovery code … KySignOn gets no password copy back"). That test reads `main.tsx`, so point it at the console source: in `workspaceWiring.test.ts`, change that assertion's subject from `main` to `import.meta.glob<string>("./components/AdminConsole.tsx", { query: "?raw", import: "default", eager: true })["./components/AdminConsole.tsx"]`.

- [ ] **Step 5: Run.** Run: `cd web && npm test && npm run build`. Expected: PASS. Fix each `tsc` error from the removed props at its call site.

- [ ] **Step 6: Commit.**

```bash
git add web/src
git commit -m "web: the administrator console is its own key-free page; teams are created for an everyday owner"
```

### Task 9: Web: stewards approve administrator-added members and name new teams

**Files:**
- Modify: `web/src/keyring.ts`, `web/src/keyring.test.ts`, `web/src/api.ts` (member parsing), `web/src/main.tsx` (banners, approve action), `web/src/workspaceWiring.test.ts`

**Interfaces:**
- Consumes: `approveMember` (Task 7), the members response `approved` (Task 5), `renameWorkspace`, `teamSteward`, `membersForTeam`, `displayName`.
- Produces: `Member.approved`, `MemberKeyStatus "unapproved"`, `UNNAMED_TEAM`, `approvalText`.

- [ ] **Step 1: Write the failing tests.** Add to `web/src/keyring.test.ts`, inside `describe("planSweep", …)`, which defines `owner`, `editor`, `container`, and uses the file's `person` and `seal` helpers:

```ts
  it("leaves a member an administrator added out of every mint and wrap until a steward approves them", () => {
    const added = { ...person("added", "f").member, approved: false };
    const base = { me: owner.member.userId, recoverable: true };
    expect(planSweep({ ...base, container: container(1, 0), members: [owner.member, added], envelopes: [], ring: new Map() })).toEqual({ kind: "mint", recipients: [owner.member] });
    const k2 = newContainerKey();
    const envelopes = [seal(owner.member, 2, k2, owner.held)];
    expect(planSweep({ ...base, container: container(2, 2), members: [owner.member, added], envelopes, ring: new Map([[2, k2]]) })).toEqual({ kind: "idle" });
    expect(planSweep({ ...base, container: container(2, 2), members: [owner.member, { ...added, approved: true }], envelopes, ring: new Map([[2, k2]]) }).kind).toBe("wrap");
    expect(memberKeyStatus(container(2, 2), [owner.member, added], envelopes)).toMatchObject({ [added.userId]: "unapproved" });
  });
```

  Add to `workspaceWiring.test.ts`:

```ts
  it("asks stewards to approve administrator-added members and to name a team an administrator created", () => {
    expect(main).toContain("const UNNAMED_TEAM = \"An administrator created this team notebook for you. Name it so its members can find it.\";");
    expect(main).toMatch(/approvalText = \(name: string\) => `\$\{name\} was added by an administrator\. They get this notebook's keys only after you approve them\.`/);
    expect(main).toContain("teamSteward && membersForTeam.filter((member) => member.approved === false)");
    expect(main).toContain("await approveMember(");
  });
```

  In `api.test.ts`, add a test that `members` (the fetcher at `api.ts:192`) maps a row without `approved` to `approved: false`, a row with `approved: true` to `true`, and keeps `keyResetAt`.

- [ ] **Step 2: Run them and see them fail.** Run: `cd web && npx vitest run src/keyring.test.ts src/workspaceWiring.test.ts src/api.test.ts`. Expected: FAIL.

- [ ] **Step 3: Implement.** In `keyring.ts`:

```ts
/** keyResetAt: shown to owners and admins only, the member's last own key reset (it retires the notebook's key).
 * approved is false only for a member a server administrator added that no steward approved yet; api.ts sets it, failing closed. */
export type Member = { userId: string; username: string; role: string; keyResetAt?: string; approved?: boolean };
```

  In `api.ts`, replace the `members` fetcher (it returns the rows unmapped since P5):

```ts
export const members = async (containerID: string): Promise<Member[]> =>
  (await request<Array<Omit<Member, "approved"> & { approved?: unknown }>>(`/api/v1/containers/${encodeURIComponent(containerID)}/members`)).map((row) => ({ ...row, approved: row.approved === true }));
```

  In `planSweep`, change `const keyed = members.filter((member) => member.identity);` to `const keyed = members.filter((member) => member.identity && member.approved !== false);`. In `memberKeyStatus`, start the `flatMap` callback with `if (member.approved === false) return [[member.userId, "unapproved"]];`, and add `"unapproved"` to `MemberKeyStatus`. Update the doc comment on `planSweep` with one line: "Members an administrator added wait for a steward's approval (spec A §4)." Every key path goes through `planSweep` (`keyService.ts` mint, wrap and the mint-then-wrap history pass of `4172c1a`) or `inviteWithKeys` (a steward's own choice), so this one filter covers the browser.

  In `main.tsx`, add next to the other copy constants:

```tsx
const UNNAMED_TEAM = "An administrator created this team notebook for you. Name it so its members can find it.";
const approvalText = (name: string) => `${name} was added by an administrator. They get this notebook's keys only after you approve them.`;
```

  In the workspace, where the other notebook banners render (`grep -n 'conflict-banner' web/src/main.tsx`), add:

```tsx
                {selected && teamSteward && selected.metaVersion === 0 && writeKeyFor(selected) && (
                  <div className="conflict-banner" role="status">{UNNAMED_TEAM} <button onClick={() => void renameWorkspace()}>Name notebook</button></div>
                )}
                {teamSteward && membersForTeam.filter((member) => member.approved === false).map((member) => (
                  <div className="conflict-banner" role="status" key={member.userId}>
                    {approvalText(displayName(member.username, member.userId))} <button disabled={busy} onClick={() => void approve(member.userId)}>Approve and share keys</button>
                  </div>
                ))}
```

  Add the action beside `renameWorkspace`. `teamIDOf` is however the workspace already finds the team ID for `membersForTeam`; use that same expression.

```tsx
  async function approve(userID: string) {
    const teamID = teamIDOf(selected);
    if (!teamID) return;
    setBusy(true);
    try {
      await approveMember(teamID, userID);
      // The same reload the member list's Remove runs: it re-reads members and runs the key pass, which now wraps for them.
      await reloadTeamMembers();
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to approve");
    } finally {
      setBusy(false);
    }
  }
```

  `reloadTeamMembers` is the function the Remove button calls after `removeMember` (`grep -n 'removeMember' web/src/main.tsx`). If that code is inline, extract it into `reloadTeamMembers` and call it from both places. The member row's key-status label for `"unapproved"` reads "awaiting approval".

- [ ] **Step 4: Run.** Run: `cd web && npm test && npm run build`. Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add web/src
git commit -m "web: stewards approve members an administrator added before any key reaches them; owners name new teams"
```

### Task 10: Docs, DOX and the embedded bundle

**Files:**
- Modify: `docs/SSO.md`, `docs/INSTALLER.md`, `docs/superpowers/specs/2026-10-07-team-keys-design.md`, `docs/superpowers/specs/2026-10-08-admin-separation-design.md` ("As built" if anything changed), `AGENTS.md`, `CHANGELOG.md`, `README.md` (if it describes first-run setup: `grep -n -i 'setup\|admin' README.md`), `internal/web/dist/`

- [ ] **Step 1: `docs/SSO.md` "Application roles".** Replace "Automatic account creation starts as a local user." with the spec §5 table as prose: "Automatic provisioning creates everyday accounts only. A token carrying `kynotes.admin` signs in only to an administrator account (`403 admin_account_not_provisioned` when none is bound, `403 admin_role_on_everyday_account` when an everyday account is). An administrator account signs in only with it (`403 admin_role_required`)." Replace "Directory provisioning normally sets the local permission; a local administrator can also deliberately edit it…" with: "Directory provisioning creates an administrator account when a subject's first event carries `kynotes.admin`; later events grant or revoke the role on that account only. An everyday account never takes it (`role_refused=everyday_account` in the apply audit)." Add an "Upgrade to 0026" paragraph: mixed accounts become everyday accounts, an SSO-linked one's sign-in is refused until KyIdentity moves `kynotes.admin` to a separate administrator identity, and `no_active_admin` names `user add --admin`. Update the `user add --username <name> --admin` mention: it now creates an administrator account.

- [ ] **Step 2: `docs/INSTALLER.md` "Identity".** Add: "KyIdentity holds two identities for the owner. Only the administrator identity carries `kynotes.admin`, and it must exist in KyNotes (the `admins` bundle entry, or a directory `user.created` carrying the role) before it first signs in. The everyday identity's account is created by the directory connector or at its first sign-in." Add the mirror check: "Sign in as the administrator identity; `GET https://<host>/api/v1/containers` must answer `403 admin_account`." Under apply-setup `admins`, replace "creates or promotes the account bound to issuer+subject" with "creates the administrator account bound to issuer+subject, or re-grants a bound administrator account; a subject bound to an everyday account is a `conflict`".

- [ ] **Step 3: Team-keys spec pointers.** In `docs/superpowers/specs/2026-10-07-team-keys-design.md`: in §1 "Admin-created accounts", replace "Forcing that change at first login belongs to sub-project A." with "Sub-project A forces that change at first sign-in for every route (spec `2026-10-08-admin-separation-design.md` §3)." In §3 "Create a team (with sub-project A)", add after step 3: "Built in sub-project A, with steward approval for administrator-added members (§4 there)." In §5, replace "`POST /admin/teams` takes `ownerUserId` (sub-project A)" with "`POST /admin/teams` takes `ownerUserId` (built in sub-project A)". In §7 P4, replace "Admin-owned team naming moved to `createNamed` in P5." with "Administrator-owned teams are gone: sub-project A gives every team an everyday owner, who names it." In "P5 as built" ruling 18, add "(superseded by sub-project A: administrators no longer create keyed teams)". In §6 "Admin separation", add "(built: sub-project A)".

  In the admin-separation spec: §10's "Residual: local-account takeover" ends "It reaches no existing key …"; replace that sentence with "A member that already has an identity reaches no existing key: the reset removes the password copy, and stewards' pins refuse a replaced identity until a person confirms the new fingerprint. A member with no identity yet does: its first identity is pinned on first contact and the sweep wraps for it. The same holds for an unbound local account that an administrator links to an identity it controls by rewriting the SSO settings (`POST /admin/sso`, no step-up) and sending a directory event. The person loses their own sign-in, which is the visible sign." Add it as §12 decision 5 (not built). §4 gains: "The administrator adds `editor`, `commenter` or `viewer` only; a team admin comes from a steward's invitation." §2's table gains `GET /me/identity` as the one content route exempt from the §3 fence (`RequireEveryday`).

- [ ] **Step 4: `AGENTS.md` (DOX).** Add one Child DOX Index bullet:

  "- Sub-project A (administrator separation): `users.account_kind` (`user`/`admin`, fixed; migration `0026_account_kinds.sql` triggers refuse an admin grant on an everyday account and any membership, container or device for an administrator account). `auth.RequireSession`/`RequireEither`/`RequireDevice` admit everyday accounts only (`403 admin_account`); `RequireAdmin`/`RequireStepUp` admit administrator accounts only; `auth.RequireAccount` serves session, logout, logout-all, password, step-up and OIDC step-up. While `password_admin_known` is set, a password session reaches only those routes and `GET /me/identity` (`auth.RequireEveryday`, read by the change screen) (`409 password_change_required`). The server administrator adds team members as `editor`, `commenter` or `viewer` only. `/setup` creates an administrator and an everyday account. `POST /admin/teams {ownerUserId}` (step-up) gives the team an everyday owner and the administrator no membership. Administrator-added members (`memberships.approved=0`) get no envelope and are not required by rotation until a steward calls `POST /containers/{id}/members/{userID}/approve`. SSO: `kynotes.admin` signs in only to an administrator account and an administrator account only with it; directory sync decides the kind at creation; `apply-setup` never promotes an everyday account. Web: `components/AdminConsole.tsx` (no key, vault or content crypto; `adminSeparation.test.ts`), `ChoosePassword`, `setup.ts`. Spec `docs/superpowers/specs/2026-10-08-admin-separation-design.md`. Verify `TestAccountKindsHoldTheirInvariants`, `TestMixedAdminsKeepTheirNotesAndDropAdmin`, `TestEveryRouteRefusesTheOtherKind`, `TestPasswordChangeIsForcedAtFirstSignIn`, `TestSetupCreatesBothAccounts`, `TestAdminCreatesATeamForAnEverydayOwner`, `TestAdminAddedMembersWaitForApproval`, `TestSSOKindsFollowTheToken`, `TestDirectoryNeverGrantsAdminToEverydayAccounts`, `npm test` (setup, adminSeparation, keyring, workspaceWiring) and `npm run e2e --prefix web`."

  Edit the bullets this change makes stale:
  - The `internal/app` bullet: bootstrap seeds an administrator account (flagged), and `WarnWithoutAdmin` logs `no_active_admin`.
  - The `POST /api/v1/admin/teams` bullet: it now takes `ownerUserId`, the list carries no name ciphertext, and nothing passes `observeContainers`.
  - The P1 bullet: `password_admin_known` now also fences every route (point to the new bullet).
  - The P5 bullet: drop "also for administrator-created teams" and "The 'set by an administrator' banner…"; "every keyed container the user belongs to (`retireKeysTx`" becomes "every keyed container where the user is an approved member (`retireKeysTx`".
  - The OIDC/0018 bullet: "SSO admin needs both that ceiling and local account permission" becomes "…and an administrator account with the grant".
  - The `web/` admin-surface sentence ("the admin surface uses tabbed server, users, teams, and audit sections") becomes "the administrator console (`components/AdminConsole.tsx`) uses tabbed …".
  - The Verification line: `npm run e2e` also runs `web/e2e/admin-separation.e2e.ts`.

- [ ] **Step 5: `CHANGELOG.md`.** Add under Unreleased:

  "- Administrator accounts are now separate from everyday accounts. An administrator account manages users, teams, single sign-on, backups and the audit log, and cannot open notes; an everyday account cannot reach administration. First-run setup creates one of each. A password an administrator set must be changed at first sign-in before anything else. Teams an administrator creates belong to an everyday owner, who names the notebook, and people an administrator adds receive a team's keys only after one of its owners approves them. With single sign-on, the `kynotes.admin` role signs in only to an administrator account. Upgrading turns any administrator that also held notes into an everyday account with its notes intact; if that leaves no administrator, the server logs `no_active_admin` and `kynotes-server user add --admin` creates one."

- [ ] **Step 6: Bundle.** Run `npm run build --prefix web && rm -rf internal/web/dist && cp -r web/dist internal/web/dist && diff -qr web/dist internal/web/dist`. Expected: no output.

- [ ] **Step 7: Commit.**

```bash
git add docs AGENTS.md CHANGELOG.md README.md internal/web/dist
git commit -m "docs: administrator separation in SSO, installer, team-keys spec and DOX; embedded bundle"
```

### Task 11: Browser check: two accounts, the forced change, a key-free console, approval

**Files:**
- Create: `web/e2e/people.ts`, `web/e2e/admin-separation.e2e.ts`
- Modify: `web/e2e/team-keys.e2e.ts`, `UI-VERIFICATION.md`

**Interfaces:**
- Consumes: Task 7–9 strings and labels.
- Produces: `people.ts` exports `Dialog`, `Person`, `person`, `withDialog`, `signIn`, `shoot`, `ADMIN`, `OWNER`, `adminConsole`, `createUser`, `createTeamFor`, `addToTeam`, `approve`.

- [ ] **Step 1: Shared helpers.** Move `Dialog`, `Person`, `person`, `withDialog`, `signIn` and `shoot` from `team-keys.e2e.ts` to `web/e2e/people.ts` and export them. Give `shoot` a first parameter `prefix: string` used in the file name in place of the literal `team-keys`, and pass `"team-keys"` at its existing call sites. Add:

```ts
export const ADMIN = { username: "admin", password: "admin horse battery staple" };
export const OWNER = { username: "owner", password: "my own horse battery staple" };

/** The administrator console in page: first-run setup once per server (every e2e file shares it), else a sign-in. */
export async function adminConsole(page: Page) {
  await page.goto("/");
  const required = await page.evaluate(async () => ((await (await fetch("/api/v1/setup")).json()) as { setupRequired: boolean }).setupRequired);
  if (required) {
    await page.getByLabel("Administrator username").fill(ADMIN.username);
    await page.getByLabel("Administrator password").fill(ADMIN.password);
    await page.getByLabel("Confirm administrator password").fill(ADMIN.password);
    await page.getByLabel("Everyday username").fill(OWNER.username);
    await page.getByLabel("Everyday password").fill(OWNER.password);
    await page.getByLabel("Confirm everyday password").fill(OWNER.password);
    await page.getByRole("button", { name: "Initialize KyNotes" }).click();
  } else {
    await page.getByLabel("Username").fill(ADMIN.username);
    await page.getByLabel("Password", { exact: true }).fill(ADMIN.password);
    await page.getByRole("button", { name: "Unlock KyNotes" }).click();
  }
  await expect(page.getByRole("heading", { name: "Administration" })).toBeVisible();
}

/** On the console: confirms the administrator's password for the step-up routes (team creation, member add, user creation). */
export async function confirmAdmin(page: Page, section: string) {
  const card = page.locator(`#${section}`);
  const field = card.getByLabel("Password", { exact: true });
  if (await field.count()) {
    await field.fill(ADMIN.password);
    await card.getByRole("button", { name: /Confirm/ }).click();
  }
}

export async function createUser(admin: Person, username: string, password: string, kind: "Everyday" | "Administrator" = "Everyday") {
  const { page } = admin;
  await confirmAdmin(page, "users");
  await page.getByPlaceholder("Username").fill(username);
  await page.getByPlaceholder("Temporary password").fill(password);
  await page.getByLabel("Account type").selectOption({ label: kind });
  await page.getByRole("button", { name: "Create user" }).click();
  await expect(page.locator(".admin-user", { hasText: username })).toBeVisible();
}

/** Creates a team owned by ownerName and returns its ID. */
export async function createTeamFor(admin: Person, ownerName: string): Promise<string> {
  const { page } = admin;
  await confirmAdmin(page, "teams");
  const before = await page.locator(".admin-teams li").count();
  const owner = page.getByRole("combobox", { name: "Owner", exact: true });
  await owner.selectOption((await owner.locator("option", { hasText: ownerName }).first().getAttribute("value"))!);
  await page.getByRole("button", { name: "Create team" }).click();
  await expect(page.locator(".admin-teams li")).toHaveCount(before + 1);
  return (await page.getByRole("combobox", { name: "Team", exact: true }).inputValue());
}

export async function addToTeam(admin: Person, username: string, teamID: string) {
  const { page } = admin;
  await confirmAdmin(page, "teams");
  await page.getByRole("combobox", { name: "Team", exact: true }).selectOption(teamID);
  const who = page.getByRole("combobox", { name: "Person", exact: true });
  await who.selectOption((await who.locator("option", { hasText: username }).first().getAttribute("value"))!);
  await withDialog(admin, { type: "alert", text: "Person added. They get the team's keys once one of its owners approves them." }, () => page.getByRole("button", { name: "Add to team" }).click());
}

/** In the owner's open team: approves an administrator-added member and waits for the key pass. */
export async function approve(owner: Person, username: string) {
  const banner = owner.page.locator(".conflict-banner", { hasText: `was added by an administrator` }).filter({ hasText: username });
  await banner.getByRole("button", { name: "Approve and share keys" }).click();
  await expect(banner).toHaveCount(0);
}
```

  `ConfirmPassword` (`components/ConfirmPassword.tsx`) labels its field "Confirm your password" and its button "Authorize <what, lower-cased>", and renders nothing until its `session()` call answers. So `confirmAdmin` waits for the field instead of counting it: `const field = card.getByLabel("Confirm your password"); await expect(field).toBeVisible(); await field.fill(ADMIN.password); await card.getByRole("button", { name: /^Authorize / }).click(); await expect(card.getByText("Password confirmed for ten minutes.")).toBeVisible();`. Replace the sketch above with that. The sections' `id`s come from the console's Task 8 markup (`users`, `teams`). `createTeamFor` relies on `create()` selecting the new team (`setTeam`).

- [ ] **Step 2: The admin-separation check.** Create `web/e2e/admin-separation.e2e.ts`:

```ts
import { expect, test } from "@playwright/test";
import { ADMIN, OWNER, addToTeam, adminConsole, approve, createTeamFor, createUser, person, shoot, signIn, withDialog, type Person } from "./people";

const TEMPORARY = "temporary sep battery staple";
const ALICE_OWN = "alice own sep battery staple";
const OPS_OWN = "ops own sep battery staple";
const TEAM = "Separated Team E2E";
const CHOOSE_PASSWORD = "An administrator set this account's password. Choose your own before you continue.";
const UNNAMED_TEAM = "An administrator created this team notebook for you. Name it so its members can find it.";
const ADMIN_ACCOUNT_NOTE = "This is an administrator account. It manages KyNotes and cannot open notes. Sign in with your everyday account to write.";

const apiStatus = (who: Person, path: string) => who.page.evaluate(async (p) => {
  const response = await fetch(p);
  return { status: response.status, code: ((await response.json().catch(() => ({}))) as { error?: { code?: string } }).error?.code };
}, path);
const vaultRows = (who: Person) => who.page.evaluate(() => new Promise<number>((resolve) => {
  const open = indexedDB.open("kynotes-web");
  open.onupgradeneeded = () => open.transaction!.abort();
  open.onerror = () => resolve(0);
  open.onsuccess = () => {
    const db = open.result;
    if (!db.objectStoreNames.contains("keys")) { db.close(); resolve(0); return; }
    const count = db.transaction("keys").objectStore("keys").count();
    count.onsuccess = () => { db.close(); resolve(count.result); };
  };
}));

async function choosePassword(who: Person, current: string, next: string) {
  await expect(who.page.getByText(CHOOSE_PASSWORD)).toBeVisible();
  await who.page.getByLabel("Current password").fill(current);
  await who.page.getByLabel("New password", { exact: true }).fill(next);
  await who.page.getByLabel("Confirm new password").fill(next);
  await who.page.getByRole("button", { name: "Change password" }).click();
}

test("administrator and everyday accounts stay apart", async ({ browser }) => {
  const admin = await person(browser);
  const owner = await person(browser);
  const alice = await person(browser);
  const ops = await person(browser);
  try {
    // 1. The administrator console: no workspace, no notes, nothing kept in the browser.
    await adminConsole(admin.page);
    await expect(admin.page.getByText(ADMIN_ACCOUNT_NOTE)).toBeVisible();
    await expect(admin.page.getByRole("button", { name: "Settings" })).toHaveCount(0);
    expect(await apiStatus(admin, "/api/v1/containers")).toEqual({ status: 403, code: "admin_account" });
    expect(await vaultRows(admin)).toBe(0);
    await shoot("admin-separation", admin.page, "console", "admin", admin.page.getByRole("heading", { name: "Administration" }));

    // 2. The everyday owner from setup reaches notes and no administration.
    await signIn(owner.page, OWNER.username, OWNER.password);
    expect(await apiStatus(owner, "/api/v1/admin/users")).toEqual({ status: 403, code: "forbidden" });
    await expect(owner.page.getByRole("button", { name: "Admin" })).toHaveCount(0);

    // 3. Accounts an administrator creates change their password before anything else, even after a reload.
    await createUser(admin, "sep-alice", TEMPORARY);
    await createUser(admin, "sep-ops", TEMPORARY, "Administrator");
    await alice.page.goto("/");
    await alice.page.getByLabel("Username").fill("sep-alice");
    await alice.page.getByLabel("Password", { exact: true }).fill(TEMPORARY);
    await alice.page.getByRole("button", { name: "Unlock KyNotes" }).click();
    await expect(alice.page.getByText(CHOOSE_PASSWORD)).toBeVisible();
    expect(await apiStatus(alice, "/api/v1/containers")).toEqual({ status: 409, code: "password_change_required" });
    await shoot("admin-separation", alice.page, "choose-password", "everyday", alice.page.getByText(CHOOSE_PASSWORD));
    await alice.page.reload();
    await choosePassword(alice, TEMPORARY, ALICE_OWN);
    await expect(alice.page.getByRole("button", { name: "Settings" })).toBeVisible();
    expect((await apiStatus(alice, "/api/v1/containers")).status).toBe(200);
    // The identity is created after the change, in the background: wait for it, or the owner's approval wraps for nobody.
    await expect.poll(async () => (await apiStatus(alice, "/api/v1/me/identity")).status, { timeout: 30_000 }).toBe(200);

    // 4. A team for the everyday owner: the owner names it, and approves the person the administrator added.
    const teamID = await createTeamFor(admin, OWNER.username);
    await addToTeam(admin, "sep-alice", teamID);
    await owner.page.goto(`/#/${teamID}`);
    await expect(owner.page.getByText(UNNAMED_TEAM)).toBeVisible();
    await withDialog(owner, { type: "prompt", text: "Notebook name", answer: TEAM }, () => owner.page.getByRole("button", { name: "Name notebook" }).click());
    await expect(owner.page.locator(".workspace-title")).toHaveText(TEAM);
    await alice.page.goto(`/#/${teamID}`);
    await expect(alice.page.getByText("This notebook is read-only until its keys reach this browser.")).toBeVisible();
    await shoot("admin-separation", owner.page, "approve", "owner", owner.page.locator(".conflict-banner", { hasText: "sep-alice" }));
    await approve(owner, "sep-alice");
    await alice.page.reload();
    await expect(alice.page.locator(".workspace-title")).toHaveText(TEAM);
    await expect(alice.page.getByText("This notebook is read-only until its keys reach this browser.")).toHaveCount(0);

    // 5. The administrator sees the team's owner and count, never its name.
    await admin.page.reload();
    await expect(admin.page.locator(".admin-teams li", { hasText: teamID })).toContainText(`owner ${OWNER.username}`);
    await expect(admin.page.getByText(TEAM)).toHaveCount(0);

    // 6. A second administrator account also changes its temporary password first, then gets the console.
    await ops.page.goto("/");
    await ops.page.getByLabel("Username").fill("sep-ops");
    await ops.page.getByLabel("Password", { exact: true }).fill(TEMPORARY);
    await ops.page.getByRole("button", { name: "Unlock KyNotes" }).click();
    await choosePassword(ops, TEMPORARY, OPS_OWN);
    await expect(ops.page.getByRole("heading", { name: "Administration" })).toBeVisible();
    expect(await vaultRows(ops)).toBe(0);
    expect(ADMIN.username).not.toBe(OWNER.username);
  } finally {
    for (const who of [admin, owner, alice, ops]) expect(who.unexpected).toEqual([]);
  }
});
```

  Check the `shoot` arguments against the signature you gave it in Step 1 (`prefix, page, phase, state, focus`), and match the calls.

- [ ] **Step 3: Adapt `team-keys.e2e.ts`.** Import the moved helpers from `./people`. In `scenario`, replace the first-run block (from `await owner.page.goto("/");` to `await owner.page.getByRole("button", { name: "← Workspace" }).click();`) with:

```ts
  // The administrator is its own account and browser; the owner is the everyday account from setup.
  const admin = await another();
  await adminConsole(admin.page);
  for (const name of ["editor", "newcomer"]) await createUser(admin, name, TEMPORARY);
  await signIn(owner.page, OWNER.username, OWNER.password);
  await expect.poll(() => vaultOf(owner.page), { timeout: 30_000 }).toMatchObject({ identity: expect.anything() });
  const teamID = await createTeamFor(admin, OWNER.username);
  await owner.page.goto(`/#/${teamID}`);
  await withDialog(owner, { type: "prompt", text: "Notebook name", answer: TEAM }, () => owner.page.getByRole("button", { name: "Name notebook" }).click());
```

  `OWN` stays the owner's password: `OWNER.password` has the same value. A temporary password now lands on the change screen, not the workspace. Add to `people.ts`:

```ts
export const CHOOSE_PASSWORD = "An administrator set this account's password. Choose your own before you continue.";

/** Signs in on a password an administrator set and replaces it on the change screen; lands in the workspace or console. */
export async function signInAndChoose(page: Page, username: string, temporary: string, own: string) {
  await page.goto("/");
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password", { exact: true }).fill(temporary);
  await page.getByRole("button", { name: "Unlock KyNotes" }).click();
  await expect(page.getByText(CHOOSE_PASSWORD)).toBeVisible();
  await page.getByLabel("Current password").fill(temporary);
  await page.getByLabel("New password", { exact: true }).fill(own);
  await page.getByLabel("Confirm new password").fill(own);
  await page.getByRole("button", { name: "Change password" }).click();
  await expect(page.getByText(CHOOSE_PASSWORD)).toHaveCount(0);
}
```

  Replace each `await signIn(who.page, name, TEMPORARY); await takeOverPassword(who.page);` pair with `await signInAndChoose(who.page, name, TEMPORARY, OWN);` followed by the vault poll `takeOverPassword` ran (`await expect.poll(() => vaultOf(who.page), { timeout: 30_000 }).toMatchObject({ identity: expect.anything() });`). Then delete `takeOverPassword`. In `admin-separation.e2e.ts`, use `signInAndChoose` for steps 3 and 6 in place of the inline sign-in and `choosePassword`, keeping the `409` check and the reload between sign-in and change in step 3 (sign in inline there, reload, then change on the screen). Replace each `addToTeam(owner, name)` with `await addToTeam(admin, name, teamID); await openTeam(owner.page); await approve(owner, name);`. Pass `admin` into `p3b` and `p5`:
  - `p3b`'s second team: `createTeamFor(admin, OWNER.username)`, then the owner names it `SECOND`.
  - `p3b` step 3's reset: `admin.page` and `.admin-user` on the console.
  - `p5` step 4's reset: the same.
  - After each administrator reset, the person's next sign-in lands on the change screen. Change their password there (`RESET_TEMPORARY` → `NEW_OWN`, or as the step already did through Settings) before the step's assertions.
  Every `owner.page.getByRole("button", { name: "Admin" })` goes. A grep for `name: "Admin" }` in `team-keys.e2e.ts` must return nothing.

- [ ] **Step 4: Run.** Build and sync the bundle (Task 10 Step 6), then run `npm run e2e --prefix web`. Expected: both files pass. `admin-separation.e2e.ts` runs first (alphabetical, one worker) and performs setup, and `team-keys.e2e.ts` then signs in through `adminConsole`. Run `KYNOTES_E2E_SHOTS=/tmp/shots npm run e2e --prefix web` once. Copy `admin-separation-*.png` into `docs/` and add an "Administrator separation" section to `UI-VERIFICATION.md` that lists the three states (`console`, `choose-password`, `approve`) in light/dark at desktop and mobile, with the measured `scrollWidth` lines the run prints.

- [ ] **Step 5: Commit.**

```bash
git add web/e2e UI-VERIFICATION.md docs/admin-separation-*.png internal/web/dist
git commit -m "e2e: administrator and everyday accounts stay apart; forced password change; steward approval"
```

### Task 12: Final verification

- [ ] **Step 1:** Run `go build ./... && go vet ./... && test -z "$(gofmt -l .)" && go test -race ./... && govulncheck ./...`.
- [ ] **Step 2:** Run `cd web && npm test && npm run build && node src/ky-ui/check-vendor.mjs && cd .. && diff -qr web/dist internal/web/dist && npm run e2e --prefix web`.
- [ ] **Step 3: Mutations.** Start from a clean tree. Apply each mutation alone, run the named test, confirm it fails, and revert it with `git checkout -- <file>`. Before each e2e mutation, rebuild and re-sync the bundle (Task 10 Step 6). Paste the failures into the PR.

| Mutation | Must fail |
|---|---|
| `0026`: drop `users_admin_role_update` | `TestAccountKindsHoldTheirInvariants` |
| `0026`: drop `users_admin_role_insert` | same |
| `0026`: drop `users_account_kind_fixed` | same |
| `0026`: drop `memberships_everyday_only` | same |
| `0026`: drop `containers_everyday_owner` | same |
| `0026`: drop `devices_everyday_only` | same (both platforms) |
| `0026`: mixed predicate without the `user_identities` clause | `TestMixedAdminsKeepTheirNotesAndDropAdmin` (`keyholder`) |
| `0026`: mixed predicate without the revoked-membership case (`AND m.revoked_at=''`) | same (`member`) |
| `0026`: skip the device revocation | same (`phone`) |
| `0026`: revoke identity devices too (drop the kind filter) | same (`idk`) |
| `refuseSession`: drop the `KindEveryday` case | `TestEveryRouteRefusesTheOtherKind`; `TestRefuseSessionKeepsKindsApart` |
| `refuseSession`: drop the `PasswordChangeRequired` case | `TestPasswordChangeIsForcedAtFirstSignIn`; `TestRefuseSessionKeepsKindsApart` |
| `refuseSession`: check `PasswordChangeRequired` before the kind | `TestRefuseSessionKeepsKindsApart` (third case) |
| `refuseSession`: `s.AccountKind == KindAdmin` instead of `!= kind` for everyday | `TestRefuseSessionKeepsKindsApart` (empty kind) |
| `RequireAdmin`: drop `refuseSession(…, KindAdmin)` | `TestPasswordChangeIsForcedAtFirstSignIn` (a flagged administrator reaches `/admin/users`). Everyday sessions are still refused by `SessionRole` |
| `SessionRole`: drop `u.account_kind='admin'` | survivor: `refuseSession` and the `users_admin_role_*` triggers each refuse an everyday administrator already. Record it as defence in depth |
| `RequireEither`: serve an admin session | `TestEveryRouteRefusesTheOtherKind` (`GET /api/v1/containers`, `GET /api/v1/objects/{id}`) |
| `resolveDevice`: drop `u.account_kind='user'` | survivor (no admin device can exist: `devices_everyday_only`); record |
| `ResolveSession`: `PasswordChangeRequired = adminKnown != 0` (also for SSO) | `TestSSOAccountSetsAndFetches…` and the P3c SSO admin-known tests (an SSO session on a flagged account is refused) |
| `handleSession` on `RequireSession` again | `TestAccountRoutesServeBothKinds`; `TestPasswordChangeIsForcedAtFirstSignIn` |
| `/auth/password` on `RequireSession` again | `TestPasswordChangeIsForcedAtFirstSignIn` (the change itself is refused) |
| `/auth/step-up` on `RequireSession` again | `TestAccountRoutesServeBothKinds` |
| Device register: drop the everyday check | `TestAdminAccountsCannotPairDevices` (500 from the trigger, not 401) |
| `/setup`: allow equal usernames | `TestSetupCreatesBothAccounts` (`same username`) |
| `/setup`: count check outside the transaction | none expected (race); record as a survivor |
| `/setup`: flag the everyday account | `TestSetupCreatesBothAccounts` |
| `/setup`: mint the session for the everyday account | `TestSetupCreatesBothAccounts` (`accountKind`) |
| Login: load the identity for admin accounts | survivor (admin accounts hold none); record |
| `POST /admin/teams`: owner check without `account_kind='user'` | `TestAdminCreatesATeamForAnEverydayOwner` (500 from the trigger, not 404) |
| `POST /admin/teams`: insert the caller's membership too | same (trigger 500) |
| `POST /admin/teams`: back on `RequireAdmin` | `TestAdminTeamAccessNeedsStepUpAndListsNoNames` |
| Admin member add: back on `RequireAdmin` | same |
| Admin member add: no `account_kind='user'` | same (`add an admin account` 500, not 404) |
| Admin member add: `approved=true` | `TestAdminAddedMembersWaitForApproval` |
| Accept: `approved=false` | `TestInvitedMembersAreApproved` |
| `admitMemberTx` reactivation keeps the old `approved` | `TestAdminAddedMembersWaitForApproval` (`readmitted`) |
| `insertEnvelopeTx`: drop `m.approved=1` | `TestAdminAddedMembersWaitForApproval` (wrap before approval) |
| `uncoveredIdentitiesSQL`: drop `m.approved=1` | same (`rotate(2)` refused) |
| Approve: drop `isSteward` | same (editor approves) |
| Approve: drop CSRF | same (approve without CSRF) |
| Approve: drop `c.team_id=''` | none expected with these fixtures (a child workspace ID approves only its own rows); record as a survivor |
| `GET /admin/teams`: return `metaCiphertext` | `TestAdminTeamAccessNeedsStepUpAndListsNoNames` |
| `PATCH /admin/users`: drop the kind check | `TestAdminUserRoutesKeepKindsApart` (500 from the trigger, not 409) |
| `ssoKindRefusal`: drop any one case | `TestSSOKindsFollowTheToken` |
| Callback: run the kind check after automatic provisioning | same (`boss` account created) |
| Directory: drop the everyday refusal | `TestDirectoryNeverGrantsAdminToEverydayAccounts` (trigger 500) |
| Directory create: `account_kind` always `user` | same (`ops` created) |
| `DecideAdmin`: drop the everyday case | `TestDecideAdmin` (`bound everyday`); `TestApplyAdminNeverPromotesAnEverydayAccount` |
| `WarnWithoutAdmin`: always `false` | `TestWarnWithoutAdmin` |
| `setupProblem`: drop the equal-password check | `setup.test.ts` "refuses equal passwords and equal usernames" |
| `setupProblem`: compare usernames without trim/lower-case | same |
| `planSweep`: drop `member.approved !== false` | `keyring.test.ts` "leaves a member an administrator added…" |
| `api.ts` members: `approved: row.approved !== false` | `api.test.ts` (missing field is `false`) |
| `App`: route `accountKind === "admin"` after `<Workspace` | `adminSeparation.test.ts` "routes change-required…" |
| `App`: drop the `passwordChangeRequired` branch in the session effect | `workspaceWiring.test.ts` I1; e2e step 3 (`reload` lands on the workspace) |
| `Login.submit`: `rememberAfter` for admin accounts | `workspaceWiring.test.ts` I1; e2e `vaultRows(admin)` |
| `AdminConsole`: import `../keyring` | `adminSeparation.test.ts` |
| `AdminTeams`: offer administrator accounts as owners | `adminSeparation.test.ts` (the filter string); `TestAdminCreatesATeamForAnEverydayOwner` refuses them server-side |
| Workspace: re-add the "Admin" button | `adminSeparation.test.ts`; e2e step 2 |
| Approval banner: show to non-stewards | e2e none (the server refuses with 403); `workspaceWiring.test.ts` pins `teamSteward &&`; record |
| `0026`: content triggers back to `(SELECT account_kind …)<>'user'` | `TestAccountKindsHoldTheirInvariants` (`cnt_ghost`) |
| `0026`: drop any `_update` content trigger | same (the re-point cases) |
| Admin member add: accept role `admin` again | `TestAdminTeamAccessNeedsStepUpAndListsNoNames` (`steward role`) |
| Approve: drop `m.approved=1` on the caller | survivor (no unapproved steward can exist: the admin add refuses steward roles); record |
| `retireKeysTx`: drop `approved=1` | `TestAdminAddedMembersWaitForApproval` (`unapproved reset`) |
| Child workspace copy: drop `approved` | `TestAdminAddedMembersWaitForApproval` (the later child) |
| Members list: drop P5's `keyResetAt` | `TestStewardsSeeWhoResetTheirKey` |
| `GET /me/identity` back on `RequireSession` | `TestPasswordChangeIsForcedAtFirstSignIn` (`identity read`); e2e step 3 (the change screen fails) |
| `RequireEveryday`: drop the kind check | `TestEveryRouteRefusesTheOtherKind` (`GET /api/v1/me/identity`); `TestPasswordChangeIsForcedAtFirstSignIn` (admin identity read) |
| `WarnWithoutAdmin`: remedy as an attribute again | `TestWarnWithoutAdmin` (the line lacks `user add --admin`) |
| Register a route with a variable pattern | `TestNoRouteHidesFromTheInventory` |

  Record every survivor in the PR with its reason (the triggers and `SessionRole` back each other; the setup race needs fault injection).

- [ ] **Step 4: Hand-off.** Open the PR with the `pull-request` skill, stacked on the team-keys P5 branch. In the body, include:
  - the resolved ambiguities and the four items needing Yoshi's decision;
  - the mutation evidence, with survivors and reasons, and the e2e result;
  - the docs left unchanged, and why;
  - that `TestEveryRouteRefusesTheOtherKind` reads route literals from source, and how to classify a new route.

  Mirror the hand-off to myslop with the `myslop-handoff` skill.
