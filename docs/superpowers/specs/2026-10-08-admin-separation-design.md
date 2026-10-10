# Sub-project A: administrator accounts apart from everyday accounts (design)

Status: draft for Yoshi's review, 2026-10-08. Plan: `docs/superpowers/plans/2026-10-08-admin-separation.md`.
Branch `feat/admin-separation`, stacked on the team-keys P5 branch.

Authority, highest first:

1. The suite preference "Administrator separation" in `busnes.app/AGENTS.md`: administrator identities are for
   administration and recovery only; everyday identities hold no application administrator grant; the separation is
   enforced in identity assignments and in product authorization, API included, not by labels or operator
   discipline; administrator identities cannot use ordinary notes workflows; administration stays available within
   the product's confidentiality contract; existing mixed-use accounts migrate with their content and verified owner
   access intact. The "Installer ownership and handover" preference adds one dedicated administrator login and a
   separate everyday identity, with administrator access verified in every product.
2. Yoshi's earlier scope for A: content routes refuse administrator sessions; mixed accounts keep their notes and
   drop admin; administrators create teams with an everyday owner; a password set by someone else is changed at
   first sign-in. Pending notes it closes: team-keys spec §3 "Create a team (with sub-project A)", §5
   "`POST /admin/teams` takes `ownerUserId` (sub-project A)", §6 "Admin separation", §1 "Forcing that change at
   first login belongs to sub-project A", P4 plan ruling 16 "Administrator-owned teams wait for sub-project A".
3. KyNotes has never been live (team-keys §9): breaking changes are allowed, and no real data needs migrating. The
   mixed-account rule still holds for the code path and for development databases, kept minimal.

## 0. Current state (findings)

- **F1. One account does both jobs.** `/setup`, `BOOTSTRAP_ADMIN_*` and `user add --admin` create one account
  with `role='admin'` that also writes notes. The P5 e2e signs in the first-run administrator and has it own the
  team it creates.
- **F2. The administrator grant is a mutable column on any account.** `PATCH /admin/users/{id}` sets
  `role` to `admin` on any user; `apply-setup` (`DecideAdmin` → `GrantAdmin`) promotes the account bound to a
  subject; directory sync maps `kynotes.admin` onto whichever account the subject is bound to.
- **F3. Content routes do not look at the role.** Every content, identity, key and device route is wrapped in
  `auth.RequireSession`, `RequireEither`, `RequireDevice` or `RequireUserActionStepUp`, none of which reads
  `users.role`. An administrator session reaches all of them.
- **F4. Administrators own and key the teams they create.** `POST /admin/teams` makes the caller the `owner`, and
  P5's `createTeam` in `main.tsx` mints the first key and seals the name in the administrator's browser
  (`createNamed`). The administrator therefore holds every key of every team it creates, against team-keys §3
  ("gives the admin no membership") and §6 ("admins never hold memberships in teams they create").
- **F5. `password_admin_known` fences identity actions only.** A session on a password someone else set reaches
  every other route, administrator routes included.
- **F6. SSO maps one subject to one account for both jobs.** `auth.SessionRole` is `role='admin'` AND (local
  session OR `sso_app_admin=1`); the same session reads notes. Automatic provisioning creates `role='user'` whatever
  the token says.
- **F7. An administrator can obtain team keys through an account it controls.** `POST /admin/teams/{id}/members`
  adds any active user, and the steward sweep (`planSweep`) wraps keys for every member with an identity the next
  time an owner opens the notebook, with no question asked. An administrator who creates an everyday account (it
  knows the temporary password and can take the account over) and adds it to a team receives that team's keys.
- **F8. Administrator accounts pair devices.** Device pairing and device credentials work for any account.

## 1. Account kinds

- `users.account_kind` is `user` (everyday) or `admin`. It is set when the account is created and never changes.
  "Promote" and "demote" between kinds do not exist; a person who needs both has two accounts.
- `users.role` stays as the administrator **grant**. `role='admin'` is allowed only on an `admin` account.
  An `admin` account whose grant is revoked (`role='user'`, for example by directory sync) can sign in but reaches
  nothing beyond its own account routes.
- An `admin` account never holds content: no membership, identity, owned container or device credential.
- The database enforces all of this with triggers in migration `0026_account_kinds.sql`, and every handler checks
  first so callers get a clean error code instead of a failed insert. The triggers are the backstop for any handler
  that forgets.

## 2. What each kind reaches

Every route belongs to exactly one class. A test reads the route registrations from the source and fails on a route
no class lists, so a new route cannot be added unclassified.

| Class | Middleware | Everyday session | Admin session | Device credential |
|---|---|---|---|---|
| Public (setup, login, login-params, recover, theme, sso-config, OIDC login/callback, back-channel logout, `sync/events`, `sync/readback`, `GET /share-links/{token}`, health) | none | yes | yes | n/a |
| Account (`GET /auth/session`, `POST /auth/logout`, `/auth/logout-all`, `/auth/password`, `/auth/step-up`, OIDC step-up start, poll, cancel) | `auth.RequireAccount` | yes | yes | no |
| Content (containers, objects, conflicts, comments, uploads, attachments, share-link create, members, invitations, notifications, presence, devices, envelopes, key rotations, `/me/identity*`, `/me/link-requests*`, `/users/{id}/identity`) | `RequireSession`, `RequireEither`, `RequireDevice`, `RequireUserActionStepUp` | yes | **403 `admin_account`** | everyday accounts only |
| Fence-exempt content (`GET /me/identity` only, read by the change screen) | `auth.RequireEveryday` | yes, not fenced by §3 | **403 `admin_account`** | no |
| Admin (`/api/v1/admin/*`, `/api/admin/*`) | `RequireAdmin`, `RequireStepUp` | **403 `forbidden`** | needs `role='admin'` and, for SSO, the session's `kynotes.admin` ceiling | no |

- The refusal is in the middleware, so it is default-deny: a new content route built on `RequireSession` refuses
  administrators without any change to the handler.
- `admin_account` is a new 403 code: "administrator accounts cannot open notes; sign in with your everyday account".
- `auth.SessionRole` adds `account_kind='admin'` to its condition. Admin routes therefore need the admin kind, the
  grant and, for SSO sessions, the verified ceiling.
- Device credentials resolve only for everyday accounts. Pairing-token minting is a content route.
- The kind cannot change, so the middleware check needs no in-transaction recheck. The existing rechecks
  (`RecheckSessionTx`, `RecheckUserStepUpTx`) stay as they are.

## 3. A password set by someone else is changed at first sign-in

- `password_admin_known=1` (administrator create and reset, `BOOTSTRAP_ADMIN_*`, `user add`) now fences the whole
  account, not only identity actions. A **password** session on such an account reaches only the account routes.
  Every content and admin route answers `409 password_change_required` until the user's own
  `POST /auth/password` (or `/auth/recover`) clears the flag. P5's identity fence stays, as defence in depth.
- SSO sessions are not fenced: they did not use the password. The P3c rule stands: changing an
  administrator-set password on an SSO-linked account needs a KySignOn confirmation, and a local session on such an
  account is refused with `409 sso_sign_in_required`.
- Login and `GET /auth/session` report `passwordChangeRequired` (true only for a fenced password session) and
  `user.accountKind`.
- The browser shows a "Choose your own password" screen before the workspace or the admin console, and does
  nothing else first: no identity settle, no vault record, no key pass. After the change, an everyday account
  creates its identity under the new password through the existing P1 path. P5's "set by an administrator" banner
  and the `adminSetPassword` set go away.
- The change fence comes from `ResolveSession`, which already reads the user row. An administrator reset sets the
  flag and revokes every session in one transaction, so no session sees the flag go from 0 to 1. Only the user's own
  change clears it.

## 4. Teams: an everyday owner, no keys for administrators, steward approval

- `POST /api/v1/admin/teams` takes `{"ownerUserId":"usr_…"}`, needs an admin step-up, and creates the team with that
  everyday user as `owner` (`containers.owner_user_id` and an `owner` membership, approved). The administrator gets
  no membership. The owner must be an active everyday account; anything else is a uniform `404 not_found`, and a
  missing or malformed ID is `400`. Audit `admin.team.create`, object = the owner.
- The administrator never names a team. The server never sees a name, and an administrator has no key to seal one.
  The owner's browser mints the first key on its first open (P5 sweep), and the workspace asks the owner to name the
  notebook (`UNNAMED_TEAM` banner with "Name notebook"). Until then, members see the existing "Notebook <id>"
  fallback.
- `GET /api/v1/admin/teams` returns `id`, `ownerUserId`, `ownerUsername`, `memberCount` (live memberships), `keyed`
  (`shared_generation > 0`) and `named` (`meta_version > 0`). It returns no name ciphertext: administrator pages
  have nothing to open it with (team-keys §9 ruling 11).
- **Steward approval (closes F7).** `memberships.approved` (default 1). The server-admin add route
  (`POST /admin/teams/{id}/members`, now with an admin step-up) admits the member with `approved=0`, on the team and
  its child workspaces, and only for an active everyday account (admin accounts get the uniform `404`). The
  administrator adds `editor`, `commenter` or `viewer` only; a team admin comes from a steward's invitation. Until a
  steward of the team approves:
  - envelope `PUT` refuses the member's identity as a recipient (`400 invalid_request`, the existing
    `errEnvelopeInvalid`);
  - rotation does not require the member's identity (`uncoveredIdentitiesSQL` counts approved members only);
  - the browser's `planSweep` leaves the member out of mints and wraps;
  - the member list reports `"approved": false`, and stewards see "added by an administrator, approve to share this
    notebook's keys" with "Approve and share keys".
- `POST /api/v1/containers/{id}/members/{userID}/approve`: an everyday session, CSRF, a steward (owner or admin role)
  of team `id`, and a live target membership. It sets `approved=1` on the team and its children, audits
  `container.member_approve` and answers 204. A non-member target is `404`, a non-steward caller `403`.
  Invitations and accepted members are approved; a steward chose them.
- The administrator may still remove members (`DELETE /admin/teams/{id}/members/{userID}`, unchanged, forward-only
  rotation). Removing them gives the administrator no key.

## 5. SSO

The suite rule makes `kynotes.admin` the mark of an administrator identity, and an administrator identity never uses
notes. So:

| Account bound to the subject | Token has `kynotes.admin` | Result |
|---|---|---|
| none (automatic provisioning) | no | everyday account created, everyday session (unchanged) |
| none | yes | **403 `admin_account_not_provisioned`**, no account created, audited. Administrator accounts come only from `apply-setup`, directory sync or an administrator |
| everyday | no | everyday session (unchanged) |
| everyday | yes | **403 `admin_role_on_everyday_account`**, no session, audited. The IdP assigned the administrator role to an everyday identity |
| admin | yes | admin session with the ceiling (unchanged) |
| admin | no | **403 `admin_role_required`**, no session |

- So every SSO session's kind agrees with its token. `SessionRole` keeps the ceiling check.
- SSO step-up callbacks (admin or user scope) do not mint sessions. Their existing scope checks stand: an admin
  grant needs the claim, and a user grant is consumable only by user-action routes, which refuse admin accounts.

## 6. Directory sync

- When an active resource is **created** with exact `kynotes.admin`, the new account is an `admin` account with the
  grant. Without it, the account is everyday. Linking an unbound local account by username keeps that account's kind.
- An update that adds `kynotes.admin` to an everyday account changes nothing: the event is applied (revision,
  status, username), the role stays `user`, and the `directory.apply` audit carries `role_refused=everyday_account`.
  The subject's next sign-in is refused by the §5 table, which surfaces the misassignment.
- An update that removes `kynotes.admin` from an admin account revokes the grant (role `user`, sessions revoked,
  cutoff advanced), as today. The last-active-admin retention applies only to admin accounts, which are the only ones
  that can hold the grant.
- Readback adds `accountKind`.

## 7. Creating the two accounts

- **Web first-run setup** (`POST /api/v1/setup`) creates both accounts in one transaction:
  `{"admin":{username, authSecret, loginSalt, iterations}, "everyday":{…same…}}`. The usernames must differ (`400`).
  Neither account is flagged, because the person at setup chose both passwords. The browser refuses identical
  passwords before sending (the server cannot compare them). The response signs the browser in as the
  **administrator**; the admin console then says which everyday account writes notes. The old body (`username`,
  `authSecret`) is `400`.
- **`BOOTSTRAP_ADMIN_*`**: creates the admin account only (flagged). The administrator creates everyday accounts in
  the console.
- **`user add`**: `--admin` creates an admin account, otherwise an everyday one. Both are flagged, as today.
- **Admin console**: "Create user" has an account type, Everyday or Administrator (`POST /admin/users`
  `{"accountKind":"user"|"admin", …}` replaces `role`). The new account is flagged. `PATCH /admin/users/{id}` may set
  `role='admin'` only on an admin account (`409 account_kind_mismatch` otherwise) and returns `accountKind` in the
  list. An administrator still cannot demote or disable itself.
- **`apply-setup` `admins`**: creates an admin account bound to issuer+subject, or reports `present` for a bound
  admin account. It grants the role again to a bound admin account whose grant was revoked (`GrantAdmin`). A subject
  bound to an **everyday** account is a `conflict` ("bound to an everyday account; give the administrator its own
  identity") and nothing changes. No new bundle section: the everyday account comes from KyIdentity's directory
  connector (`user.created` without the role) or from the owner's first sign-in (automatic provisioning), always as
  everyday.
- **Installer** (`docs/INSTALLER.md`): KyIdentity holds two identities for the owner; only the administrator identity
  carries `kynotes.admin`. Verification gains its mirror: the administrator identity's
  `GET /api/v1/containers` answers `403 admin_account`, and the everyday identity's
  `GET /api/v1/admin/backup/status` answers `403`. The handover is unchanged: `adminUsernames`, plus the everyday
  identity from KyIdentity's handover.

## 8. Mixed accounts (migration 0026)

A mixed account is an account with `role='admin'` that holds a membership row (live or revoked), an identity, or an
owned container. The migration:

1. adds `users.account_kind` (`CHECK IN ('user','admin')`, default `user`) and `memberships.approved` (default 1);
2. audits every mixed account (`account.kind_upgrade`, `admin_dropped=true`) and sets its `role` to `user`: it keeps
   every note, membership, identity and key, and becomes an everyday account;
3. sets `account_kind='admin'` on every remaining `role='admin'` account, audited `kind=admin`;
4. revokes the device credentials (not identities) of admin accounts;
5. creates the triggers in §1.

If no active admin account remains, the server logs `no_active_admin` at every start with the remedy
(`kynotes-server user add --admin --username <name>`, which works on a stopped server). `/setup` does not reopen:
anyone who reached it first would become the administrator. For an SSO-linked mixed account, the IdP keeps
sending `kynotes.admin`, so its next sign-in is refused (§5) until KyIdentity moves the role to a separate
administrator identity. `docs/SSO.md` says so.

## 9. Web

- `App` routes on the session: `passwordChangeRequired` → `ChoosePassword`; `accountKind==="admin"` →
  `AdminConsole`; otherwise the workspace, as today.
- `components/AdminConsole.tsx` holds the administrator pages moved out of `main.tsx` (server, users, teams, audit,
  SSO, backups). It imports nothing from `keyring`, `keyService`, `teamKeys`, `crypto` content functions, `observe` or
  the vault (`storage.ts`) apart from the theme. An admin browser keeps no vault record: `Login` skips
  `rememberAfter`'s device key and the identity settle for admin accounts.
- The workspace loses the "Admin" button, the `admin` view and `createTeam`. `observe.ts` loses
  `listAdminTeams`/`newAdminTeam` (administrator pages hold no keys and raise no floors). `api.ts` gains
  `approveMember`, and `createAdminTeam(ownerUserId)` takes the owner.
- The setup form has two blocks, "Administrator login" and "Everyday login" (notes). A pure `setupProblem()` in
  `web/src/setup.ts` refuses an empty name, equal usernames, unequal confirmations, short passwords and equal
  passwords.
- The workspace shows the unnamed-team banner to stewards (§4) and the approval banner per unapproved member.

## 10. Threat notes and residuals

- **Closed:** an administrator session reads or writes no content (§2); an administrator never holds a membership,
  identity or key (§1, §4); an administrator cannot get a team's keys by adding an account it controls without a
  steward's approval (§4); a password someone else set acts for nobody until its user replaces it (§3); an IdP
  assignment of `kynotes.admin` never yields a notes session (§5).
- **Residual: steward approval is a human check.** A steward who approves an account the administrator controls gives
  it the keys. The banner names the account by `displayName` (ID first) and says an administrator added it.
- **Residual: local-account takeover (P3c, unchanged).** An administrator can reset an everyday account's password and
  sign in as it. A member that already has an identity reaches no existing key: the reset removes the password copy,
  and stewards' pins refuse a replaced identity until a person confirms the new fingerprint. A member with no
  identity yet does: its first identity is pinned on first contact and the sweep wraps for it. The same holds for an
  unbound local account that an administrator links to an identity it controls by rewriting the SSO settings
  (`POST /admin/sso`, no step-up) and sending a directory event. The person loses their own sign-in, which is the
  visible sign.
- **Residual: whoever operates KyIdentity** can create an administrator identity or sign in as an everyday one (P3c
  decision 4, unchanged).
- **Residual: a disabled sole owner.** A team whose only steward is disabled has nobody to mint or approve. The
  administrator can add a member, which waits for approval that nobody can give. Ownership transfer is out of scope
  (§13).
- **Residual: the server operator** (database access) can edit `account_kind` past the triggers. That is the existing
  server-trust boundary; content stays end-to-end encrypted.

## 11. Resolved ambiguities

1. **Kind is a fixed column, the grant stays `role`.** Reusing `role` as the kind would make grant revocation a kind
   change. An `admin` account without the grant is inert.
2. **Default-deny in the middleware, plus a route-inventory test.** One check in `RequireSession`/`RequireEither`/
   `RequireDevice` covers every content route; the account routes move to a new `RequireAccount`.
3. **Database triggers back every invariant.** Handlers check first for clean codes. The triggers stop a handler that
   forgets.
4. **The first-sign-in change fences every route except the account ones,** for both kinds, password sessions only.
5. **An `admin` account never holds devices.** The migration revokes existing ones, and a trigger stops new ones.
6. **Administrators never name teams.** The owner names the notebook on first open; no plaintext label exists.
7. **Administrator-added members wait for a steward's approval** before any key reaches them (closes F7).
8. **Team creation and administrator member add need the admin step-up.** Both choose who may receive a team's keys.
9. **`kynotes.admin` on an everyday-bound subject refuses sign-in** rather than being ignored (§5): the token says
   the identity is an administrator identity, and those never use notes.
10. **Automatic provisioning never creates an admin account,** and refuses a token carrying the role, so an
    administrator identity that signs in before `apply-setup` is not silently turned into an everyday account.
11. **Directory creation decides the kind from the roles at creation.** Later role changes move only the grant.
12. **`apply-setup` never promotes an everyday account:** `conflict`, unchanged.
13. **Web setup creates both accounts and signs in as the administrator,** with unflagged passwords the person chose.
14. **Mixed accounts become everyday accounts, even when that leaves no administrator.** The `no_active_admin`
    start-up log names the CLI remedy; `/setup` stays closed.
15. **Admin browsers keep no IndexedDB record.** There is nothing to unlock.
16. **`GET /admin/teams` drops the name ciphertext.**

## 12. Needs Yoshi's decision

Each item has the safest option picked and built. Changing one is a small follow-up.

1. **Steward approval for administrator-added members (§4, ruling 7).** Picked: approval required. It adds a click
   for owners of administrator-built teams. The alternative is the P3 behaviour, where the sweep wraps automatically
   and an administrator can get a team's keys through an account it controls (F7).
2. **Refuse sign-in when an everyday identity carries `kynotes.admin` (§5, ruling 9).** Picked: refuse. The
   alternative ignores the claim and lets the person keep writing notes, which tolerates a misassigned IdP role
   silently.
3. **No administrator-visible team label (ruling 6).** Picked: the console shows ID, owner, member count and
   keyed/named state, never a name. The alternative, a plaintext administrator label, would put team names on the
   server in the clear.
4. **Mixed accounts drop the grant even when none remain (ruling 14).** Picked: drop, with the CLI remedy. The
   alternative keeps a mixed administrator until another exists, which violates the separation for the life of that
   account. KyNotes was never live, so this affects development databases only.
5. **Takeover of an approved member with no identity yet (§10, not built).** An administrator can reset such a
   member's local password, or link an unbound local account to an identity it controls through the SSO settings,
   and the member's first identity is then pinned on first contact and wrapped for. Options: accept it (the person
   loses their own sign-in, which is visible), or require a step-up on `POST /admin/sso` and `/admin/sso/pair` plus a
   steward confirmation for any member's first identity.

## 13. Out of scope

- Transferring a team's ownership, and a recovery path for a team whose only steward is gone.
- An administrator-visible team label (decision 3).
- Splitting an existing mixed account into two from the UI. The migration keeps the notes; the operator creates the
  new administrator.
- Short-lived administrator sessions, and step-up on every admin mutation. Only team creation and member add gain
  one.
- KyIdentity-side enforcement. The installer check verifies it; this design refuses it at sign-in.

## 14. Verification

`go test -race ./...`, `go vet ./...`, `gofmt -l .`, `npm test`, `npm run build`, the bundle diff, and
`npm run e2e --prefix web` (`web/e2e/admin-separation.e2e.ts` and the adapted `team-keys.e2e.ts`). Each authorization
rule has a test that fails when the rule is removed. The plan's final task lists the mutations, each with the test
that must fail.
