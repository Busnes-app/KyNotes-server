# Sub-project T: shared team keys (design draft)

Status: approved direction 2026-10-07 (C → B → T → A list); delivered in phases P1–P5, one PR each. Source of truth read: origin/master at 1410db2.

## 0. Current state and findings

- **Every content key comes from `authSecret`.** `web/src/crypto.ts` `deriveObjectKeyBytes(authSecret, containerID, info)` (HKDF, salt = container ID) keys the container meta (`kynotes/container-meta/v1`), objects and pages (`kynotes/object/v1`), attachment bytes (also `kynotes/object/v1`), attachment metadata (`kynotes/attachment-meta/v1`) and comments (`kynotes/comment/v1`). Sealed share links already use a random per-link key (`encryptSharePayload`), so they are fine.
- **Finding F1 (security). The server sees `authSecret`.** It is the login verifier. `POST /auth/login`, `/auth/step-up`, `/setup` and `/admin/users` all send it, and `admin_routes.go` `POST /admin/users` has the admin's browser derive it from a password the admin picked. So a malicious server, or the admin who created an account, can derive every content key today. The new key hierarchy must not hang off `authSecret`.
- **Finding F2. Changing a password orphans all content.** `POST /auth/password` and recovery replace the salt, so every derived key changes. The UI says "Existing encrypted notes may require the device re-key flow", but no such flow exists.
- **The envelope routes exist but the web client never calls them.** They are `GET`/`PUT /containers/{id}/envelopes` in `internal/httpapi/device_routes.go`. `PUT` is limited to owner/admin, checks freshness with `session.CreatedAt < 5 min` (not `StepUpAt`), and uses `INSERT OR REPLACE`. Rows are keyed per **device** (`key_envelopes.device_id` is a foreign key to `devices`). The web browser is not a device.
- **The save gate.** `object_routes.go`, `upload_routes.go` and the comment route refuse writes when any non-revoked device of any member lacks an envelope at the current generation. Web users have no device rows, so the gate passes trivially today. A single paired phone that never received an envelope would block every save in that container. The gate also ignores `device_containers` selection.
- **Membership changes move no keys.** Member removal (`collab_routes.go`) bumps `key_generation` on the team and its child workspaces and deletes the removed user's envelopes. Admin member removal (`admin_routes.go`) does neither. Invitations and accepts move no keys. Child workspaces copy team memberships when created and when an invitation is accepted.
- **Admins own the teams they create.** `POST /admin/teams` makes the admin the `owner`. The admin's browser encrypts the team name under the admin's own derived key, which is why the UI says "Metadata encrypted by another account remains opaque".
- **Frozen contracts that matter.** Device public keys are X25519, raw 32 bytes, standard base64. The algorithm allowlist is `x25519-hkdf-sha256-chacha20poly1305`. Envelopes are capped at 4096 bytes. `key_generation` lives on containers and on every ciphertext row. Envelope writes require a session (device credentials are rejected), CSRF, and fresh authentication.

## 1. Key hierarchy

```
password ──PBKDF2(loginSalt, iters)──► stretched (32B, never leaves browser)
   ├─HKDF info "kynotes/auth/v1"      ► authSecret   (verifier; server sees it)   [frozen, unchanged]
   └─HKDF info "kynotes/user-kek/v1"  ► userKEK      (NEW; never sent anywhere)
userKEK ──AES-256-GCM, AAD="kynotes/identity/v1"|userID──► wrapped identity private key (server-stored)
identity keypair (X25519, per user)  ◄── envelopes ──  container content key CK[container, generation] (random 32B)
CK ──HKDF(salt=containerID, info=<existing purpose labels>)──► per-purpose AES-256-GCM subkeys
paired phones: own X25519 device key ◄── envelopes ── CK  (unchanged frozen device model)
```

**The user identity keypair**
- On the first login after this ships (and at `/setup` and at `/admin/users` creation, see below), the browser generates an X25519 keypair. It wraps the private key under `userKEK` and uploads the wrapped key plus the public key.
- Any of the user's browsers recovers the private key after a password login (it derives `userKEK` from `stretched`) or from the IndexedDB keys vault.
- `userKEK` uses a new HKDF label off the same PBKDF2 output. The server never sees it, which fixes F1 for all new content.

**Admin-created accounts.** The admin's browser must not generate the user's keypair, because the admin knows the initial password. The identity is created on the user's own first login. Until then the user has no public key and appears as "awaiting first sign-in" in team UIs. An identity wrapped under that password stays readable by the admin, because a later password change only re-wraps it. So the server flags every password someone other than the user set (`users.password_admin_known`: admin create and reset, `BOOTSTRAP_ADMIN_*`, `user add`), refuses `PUT /me/identity` with 409 `password_change_required` while it is set, and the user's own password change (or recovery) clears it; the browser then creates the identity under the new password. Forcing that change at first login belongs to sub-project A. Accounts created before the flag existed are not flagged.

**How this fits the frozen per-device envelope contract (minimal change).** Each user identity is represented as a `devices` row with `platform = 'identity'`:
- `public_key` is the identity public key and the fingerprint is computed by the server as usual.
- `secret_hash` is set to an unusable random value. No secret is ever returned, so the row can never authenticate as a device.

Because of this, `key_envelopes`, its foreign key, the uniqueness rule, the algorithm string, the 4096-byte cap and `GET`/`PUT` semantics all stay as they are. A session `GET` returns all envelopes, and the client picks the one for its identity row.

The server changes for identity rows:
- Exclude them from `GET /devices` and from `DELETE /devices/{id}`.
- Never accept them in the device-auth middleware.
- Exempt them from recovery's "revoke all devices" step. Recovery instead deletes the wrapped private key and the identity's envelopes, because without the old password the key is unrecoverable anyway (see Phase 5).

**Phones** keep their own X25519 device keys. When a phone selects a container, the user's browser (which holds `CK` through the identity key) wraps `CK` for that phone, which needs a session, fresh authentication and step-up.

**Envelope byte format** (new, client-only; the server never parses it). These details are not frozen, so they need DESIGN.md and plan text only:

```
envelope = 0x01 | ephPub(32) | nonce(12) | ChaCha20-Poly1305(key, nonce, CK(32), aad)   // 93 bytes
key      = HKDF-SHA256(ikm = X25519(ephPriv, recipientPub), salt = ephPub || recipientPub,
                       info = "kynotes/envelope/v1", L = 32)
aad      = "kynotes/envelope/v1" | containerID | u32be(keyGeneration) | recipientDeviceID
```

`containerID`, `recipientDeviceID` and `userID` (identity AAD, §1) are exact 30-byte ASCII IDs matching `^(cnt|dev|usr)_[0-9a-hjkmnp-tv-z]{26}$`, validated before the AAD is built. The fixed length is what makes the unprefixed concatenation unambiguous; every client must reject any other length.

The AAD binding stops a malicious server from replaying an envelope into a different container, generation or recipient.

**Crypto library.** WebCrypto has no ChaCha20-Poly1305, X25519 support varies across browsers, and LAN `http://` deployments already rely on `fallbackCrypto.ts`. Recommendation: add `@noble/curves` (x25519) and `@noble/ciphers` (chacha20poly1305). Both are audited, have no dependencies and work in every context. Do not hand-roll these primitives.

**Password change and reset.** `POST /auth/password` gains `wrappedIdentityKey`, which is the same private key re-wrapped under the new `userKEK` and committed in the same transaction. This fixes F2 for shared-key content. An admin password reset cannot re-wrap the key, so the user's identity is reset. Team owners re-grant access automatically through the key steward sweep (§3). Personal containers are lost unless Phase 5 recovery wrapping exists. The admin reset UI must say this explicitly.

## 2. Container content keys

- `CK[container, generation]` is 32 random bytes, minted per container per generation. The purpose subkeys keep the current derivation with only the input key changed: `HKDF(ikm = CK, salt = containerID, info = <existing label>)`. Ciphertext layout (`iv || ct+tag`) and labels stay as they are, so `encryptNote`, `decryptObject`, `encryptAttachment` and the other helpers keep their shape. Their first argument becomes a `KeyRef` (a CK, or a legacy `authSecret`) instead of a string.
- **Covered by CK:** container meta, objects and pages (including CanvasPage bodies, which reach the server only through `encryptNote` in `main.tsx`), conflict copies (normal object saves), comments, attachment bytes, attachment metadata and previews, local IndexedDB caches and pending saves, and `X-Kynotes-Routing-Ciphertext`.
- **Share links:** keep the dedicated random per-link key. Content is decrypted with CK and re-sealed under a fresh key, so links never reveal CK.
- **Choosing a key on read:** the client takes the row's `keyGeneration`. If its keyring has `CK[g]`, it uses that. Otherwise it tries the legacy derived key from its own `authSecret`. AES-GCM authentication makes this trial safe. Generations that have envelopes are "shared". Generations without any are legacy. This needs no schema flag.
- **Scope: personal workbooks too (recommended), in a later phase.** Using one code path everywhere fixes F2, enables phone pairing (the frozen design intends per-device envelopes for every container), and removes the dependency on `authSecret`. Teams ship first because that is the user-visible bug. Personal workbooks follow once identity recovery is proven.

## 3. Membership flows

**Create a team (with sub-project A).**
1. An admin calls `POST /admin/teams {ownerUserId}`. The server creates the container with empty meta, makes the named user the `owner`, and gives the admin **no membership**. Without a membership the admin can never be wrapped for.
2. The admin UI shows the team ID, owner and member count only.
3. When the owner opens the team for the first time with a fresh step-up, the browser mints `CK` through the rotate route (below), sets the encrypted name, and wraps for every member that has an identity.

The fallback rule ("unnamed until the owner opens it") is shown in the UI.

**Key steward sweep.** Whenever an owner or admin member opens a container, the client compares members against envelopes at the current generation:
- For each member that has an identity key but no envelope, it wraps `CK` and calls `PUT` (step-up prompted if needed).
- If the current generation has no envelopes at all (after a rotation or a removal), it mints a new `CK` for that generation.

This single routine covers admin-added members, invitees, members whose identity was reset, and interrupted rotations.

**Add a member.** Two paths:
- **Invitation from an owner or admin member:** the inviter's browser fetches the invitee's identity public key (new `GET /users/{id}/identity`, which returns key and fingerprint) and wraps `CK` for the team and each child workspace. The wrapped keys are stored with the invitation in a new `invitation_envelopes` table. On accept, the server moves them into `key_envelopes` in the same transaction that creates the memberships, but only if the generation still matches. If it does not, they are dropped and the steward sweep fills the gap.
- **Admin add (admin holds no key) or invitee without an identity yet:** the membership is created without keys and the steward sweep wraps later. The member's UI shows "Waiting for a team owner to share keys".

**Remove a member: forward-only rotation, no bulk re-encryption.**
- Keep the frozen behaviour: bump the generation on the team and its children and delete the removed user's envelopes. `admin_routes.go` member removal must do the same (currently a bug).
- The removing client, or later any steward, mints a new `CK` for the new generation and wraps it for the remaining members.
- Old generations keep their envelopes for remaining members so history stays readable.
- The removed member keeps old keys and may hold old ciphertext. That is the documented "best-effort revocation".
- Re-encrypting old content does not improve security against a member who already held plaintext, so it is out of scope.

**Team workspaces** have their own `CK` per child container, matching DESIGN's "each container has a randomly generated key". Their memberships already mirror the team. Every wrap or rotate step iterates over the team plus its children, and the steward sweep runs per container. Deriving child keys from the team key was rejected because it couples rotations across containers.

**New route: `POST /api/v1/containers/{id}/key-rotations`.**
- Body: `{expectedGeneration, envelopes[]}`. Requires session, CSRF, step-up, and an owner or admin role.
- In one transaction: checks that the generation equals `expectedGeneration`, increments it, and inserts the full envelope set. The set must cover every active member's identity, otherwise the call returns 400.
- Used for the first mint, for migration, and for manual rotation. This makes rotation atomic instead of "bump, then hope someone calls PUT".

## 4. Migration of existing data

The migration is lazy, idempotent and never destructive.

1. **Enabling shared keys on a container.** The first steward to open it calls `key-rotations` (generation g → g+1, a new `CK`). Every existing row remains at generation ≤ g and is treated as legacy.
2. **Re-encrypting on open.** Every member's browser runs a background pass when opening a container with shared keys. For each legacy row it can decrypt with its own derived key:
   - **Object:** re-save the current version at the current generation with `baseVersion = current`. This is a normal new version. Older versions keep their legacy ciphertext and history stays readable only to their author, which is documented.
   - **Comment (author only):** new route `PUT /comments/{id}` with `{bodyCiphertext, keyGeneration}`, restricted to the author.
   - **Attachment:** re-encrypt the bytes and metadata and upload them as a new attachment. The object payload's references are updated in the same save. The old blob is released to GC.
   - **Container meta:** a `PATCH` by whoever can decrypt it.
   - **Pending queue and caches:** decrypt with the key that works and re-encrypt at the current generation before retrying. Today a queued legacy save would loop on `409 key rotation incomplete`.
3. **Idempotence.** A row whose current version is already at a shared generation is skipped. Version conflicts use the existing `version_conflict` path. Re-running the pass is a no-op.
4. **Content that no current member can decrypt** (written by another member under their own derived key) can only be migrated by its author, through the same pass on their next open.
   - Add `object_versions.author_user_id` (new migration, default `''`, filled on new writes) so the UI can show "Encrypted by <username>, waiting for them to open this workspace" and so the pass can be targeted. Comments already carry `author_user_id`.
   - If the author has been removed or deleted, the content stays opaque. Owners may delete it, but nothing is deleted automatically.
5. **Personal workbooks** (later phase): the owner is the only author, so the pass migrates everything in the background on login. Migration is complete when no row is left at a legacy generation.
6. **Teams created by an admin (admin owns them today).** That admin account is the only one that can decrypt the existing team name. Sub-project A should run the migration once from the admin's browser (mint, wrap, re-encrypt meta) and then transfer ownership. The alternative is to let the new owner rename the team and accept the opaque old name.

## 5. Changes required

**Server**
- Migration `0021_identity_keys.sql` (P1: `user_identities`, `users.password_admin_known`); P2 adds `invitation_envelopes`, `author_user_id` and `containers.shared_generation` as `0022`:
  - `user_identities(user_id PK, device_id UNIQUE → devices, wrapped_private_key BLOB, wrap_alg, created_at, updated_at)`.
  - `invitation_envelopes(invitation_id, container_id, device_id, key_generation, alg, envelope)`, one per container.
  - `object_versions.author_user_id`.
  - A `devices.platform = 'identity'` convention.
- Routes:
  - `PUT /me/identity`: create the identity; session, CSRF and a local-password step-up (SSO sessions are refused). Create-only in P1: a second create returns 409 `identity_exists`. Replacement (which would delete the user's identity envelopes) is deferred. While `password_admin_known` is set it returns 409 `password_change_required` and creates nothing.
  - `GET /me/identity`: public key, fingerprint and device ID only. It never returns the wrapped private key.
  - The wrapped private key is delivered only in responses that just verified the password: the local `POST /auth/login` and `POST /auth/step-up` success bodies carry `identity` (with `wrapAlg` and `wrappedPrivateKey`, `no-store`) when one exists. A session cookie alone must not yield an offline-guessing target. SSO sessions never receive it.
  - `GET /users/{id}/identity`: device ID, public key and fingerprint of an active user, for the user, a co-member of a live container, and a team or project owner or admin holding a pending invitation they issued to the user; a uniform 404 otherwise.
  - `POST /containers/{id}/key-rotations`.
  - `PUT /comments/{id}`.
  - Invitation create and accept accept and move envelopes.
  - `POST /auth/password` takes `wrappedIdentityKey` and `identityDeviceId` (both or neither). The re-wrap updates only that identity in the password's transaction; a missing, stale or mismatched identity returns 409 `identity_rewrap_required` and changes nothing. It sets `password_admin_known=0`, clears every session's step-up window (an old-password proof must not authorize a wrap under the new one) and shares the step-up lockout.
  - Recovery and admin password reset delete the identity (and, by cascade, its envelopes), audited as `identity.delete`.
- Rule changes:
  - Envelope `PUT` freshness uses `RequireStepUp` (`StepUpAt`) instead of session age.
  - Owner or admin may write for any member. **Any member may write envelopes for their own devices and identity**, so a viewer can pair a phone.
  - `INSERT OR REPLACE` becomes a plain insert at an existing generation. Writing for a recipient that already has an envelope at that generation returns 409, except for the user's own identity. This stops two stewards from splitting a generation across different keys.
  - **The save gate becomes "the writer's own identity has an envelope at the current generation".** The current "every device of every member" rule blocks a whole team while one new member waits for keys, and it ignores device selection.
  - Admin member removal performs the rotation bump. `POST /admin/teams` takes `ownerUserId` (sub-project A).
- **Frozen-contract changes** (DESIGN.md §Encryption and §Teams, plus IMPLEMENTATION_PLAN §5 and §13, updated in the same change):
  - The user identity key is represented as a device row.
  - The save-gate wording changes.
  - The member-self envelope write rule.
  - Insert-only envelopes per generation.
  - The new `userKEK` label `kynotes/user-kek/v1`. This is additive; `kynotes/auth/v1` is unchanged.
  - The algorithm string, wire shape, table schema and size cap are all unchanged.

**Client**
- `crypto.ts`: X25519 keypair generation; `wrapEnvelope` and `unwrapEnvelope`; `deriveUserKEK` (shares the PBKDF2 pass with `deriveAuthSecret` and returns both); identity wrap and unwrap; helpers keyed by `KeyRef`.
- New `keyring.ts`: per-container map from generation to CK, a loader (envelopes, then unwrap), the steward sweep and the migration pass.
- `api.ts`: the new routes plus `containerEnvelopes`.
- `storage.ts`: the keys-vault record gains `identityPrivateKey` alongside `authSecret` (still needed for legacy decryption). A new `ck` store is optional. Prefer re-unwrapping per session so "Forget this device" stays a single delete.
- `main.tsx`: replace about 30 `auth.authSecret` call sites with `keyFor(containerID, generation)`; add the key-wait and opaque-author states; add the steward prompts; admin teams UI.
- `CanvasPage.tsx` is untouched because it never imports crypto.
- Mobile clients are unaffected apart from receiving real envelopes.

## 6. Threat model notes

- **Plaintext keys:** the server stores wrapped identity keys and envelopes only. `userKEK` and CK never leave browsers. This closes F1 for migrated content. Legacy content remains derivable from `authSecret` until it is re-encrypted.
- **Public-key substitution by a malicious server:** it could return its own key from `GET /users/{id}/identity` and receive the next CK.
  - Mitigation now: the client pins (trust on first use) each colleague's identity fingerprint in IndexedDB the first time it wraps for them. It warns and blocks wrapping when a pinned fingerprint changes, unless the user confirms. Each user can see their own fingerprint in Settings and compare it out of band.
  - Mitigation later: a signed membership log (out of scope).
- **Envelope replay or swapping** is blocked by the AAD binding (container, generation, recipient).
- **Removed members** keep the keys for generations before their removal and any plaintext they already downloaded. Rotation is forward-only, which is the documented limit.
- **Insider owner or admin** can wrap a wrong or different key for some members. The insert-only rule plus a client-side check that the key decrypts current meta catches accidental splits. A malicious insider is out of scope.
- **Minting** (rotation, wrapping for others) requires session, CSRF and step-up. Device credentials are never accepted.
- **Admin separation:** admins never hold memberships in teams they create. Account bootstrap must force a password change before the identity exists (§1).
- **Offline guessing:** the wrapped identity key is guessable offline against the password, so it is released only in password-proving responses (local login and step-up), never to a bare session cookie or a device credential.
- **Identities created before `password_admin_known` existed** may be wrapped under a password an administrator once knew. The user's own password change re-wraps rather than replaces them. Replacing the keypair needs the P5 replacement path, so P2 leaves this residual risk for pre-flag accounts.
- **SSO users (open question):** SSO sessions cannot create or receive an identity in P1, because their step-up proves the IdP, not the password the wrap depends on. How SSO-only users get an identity is unresolved.
- **At-rest browser cache:** the identity private key in IndexedDB is equivalent to the cached `authSecret` today, with the same "Forget this device" control.

## 7. Phases

Each phase can ship on its own.

**P1. Crypto primitives and identity (no behaviour change).** Add noble, envelope and identity functions, `userKEK`, migration 0021, `/me/identity`, the identity device row filtered from device lists, and the password-change re-wrap. Identities are created silently on login.
- Tests:
  - RFC 7748 and RFC 8439 vectors.
  - `testdata/protocol/envelope_vectors.json` generated by a Go helper using `x/crypto` and checked in vitest, for cross-implementation agreement.
  - Go tests showing identity rows cannot authenticate and are not listed or revoked.
  - Recovery of the identity from a second browser profile.

**P1 as built.** Resolved ambiguities:
  1. The save gate skips identity rows (one shared constant).
  2. `PUT /me/identity` needs a local-session user step-up; SSO sessions are refused.
  3. `/devices/register` refuses `platform = "identity"` and never re-pairs onto an identity row.
  4. `/setup` no longer sends or accepts the plaintext password (400 without `authSecret`).
  5. Migration 0021 holds `user_identities` and `users.password_admin_known`; P2 tables go in 0022.
  6. `PUT /me/identity` is create-only (409 `identity_exists`); replacement waits for its first caller (P5).
  7. The wrapped key is delivered only in local login and step-up bodies; `GET /me/identity` is public-only; the browser caches it in the IndexedDB vault (cleared by "Forget this device", kept on logout).
  8. Password change must carry `identityDeviceId` and `wrappedIdentityKey` when an identity exists (409 `identity_rewrap_required`); recovery and admin reset delete the identity with an audit row. A silent step-up after login also opens the admin step-up window.
  9. No identity is created while an admin or the server knows the password (see "Admin-created accounts").
  10. Directory deactivation and SSO role changes revoke sessions and paired devices, never the identity row.
  11. Stopgap: content keys still derive from the password, so the password-change form warns that existing notes become unreadable and requires an explicit acknowledgement.

**P2. Server rule changes.** Rotate route, insert-only envelopes, member-self writes, step-up freshness, the new save gate, the admin removal bump, `author_user_id`, invitation envelopes, `PUT /comments/{id}`, DESIGN.md and plan updates.
- Tests:
  - Named Go tests for each rule.
  - Update `TestNewContentRefusedUntilRotationEnvelopesExist` to the new gate.
  - Concurrent-rotate race test.
  - Update the `TestNoUserDataRouteIsRegistered` whitelist.
  - Extend the probe so it installs a real envelope.

**P2 as built.** Resolved ambiguities:
  1. `containers.shared_generation` (0022) is set by the first rotation. While it is 0, the original device gate applies unchanged.
  2. The writer is the session user. Content writes are session-only.
  3. The gate also requires a live membership and is rechecked inside the write transaction (object save, comment create and rewrite, attachment finalize); the object save also rechecks the writer's role there. A refused save leaves its finalized blob on disk without a `blobs` row (`ponytail:`; upgrade path: an age-gated sweep).
  4. Envelope writes and rotations use `RequireUserStepUp` plus `RecheckUserStepUpTx`. SSO sessions are refused.
  5. No new error codes. A stale generation, an existing envelope, a moved generation and an incomplete rotation all share 409 `already_exists` with distinct messages; a non-steward writing for others is 403. P1's `identity_exists`, `password_change_required` and `identity_rewrap_required` are added to the plan's error table and `error_envelopes.json` (additive).
  6. The rotation set covers the caller and every active member's live identity. Members without an identity and disabled users are wrapped later by the sweep.
  7. Own-identity envelope writes are re-wrap only: a member may replace its own identity envelope at a generation but never write it first, so a steward or an accepted invitation supplies it. P3 must self-wrap only a key it unwrapped at that generation. Recipients must be live devices or identities of active members.
  8. `invitation_envelopes` has `device_id` (foreign-key cascade) and one row per container. Removal and rotation delete invitation envelopes below the current generation.
  9. Identity lookup is limited to the user, live co-members and a team or project steward holding a pending invitation they issued; everyone else gets the same 404. A steward therefore cannot wrap at invite time for a stranger: the invitation goes out without envelopes and the sweep fills them after accept. Integrity comes from TOFU pins.
  10. Owner/admin and server-admin removal share one transaction: child-workspace memberships revoked, generations bumped, envelopes and selections deleted, the removed user's pending invitations deleted, audit row written. The owner/admin route re-reads both roles in the transaction (an admin cannot remove an admin or owner). A non-member is 404.
  11. Accept rechecks, in its transaction, that the inviter is still an owner or admin of the live container (404 otherwise); consumed or void invitations are 404 and an existing membership row in the team scope is 409.
  12. `author_user_id` is write-only until P4.
  13. The identity is not rotated on the first password change the user makes themselves; see §6.
  14. The web client needs no change: no container becomes shared until P3 calls the rotation route.

  Known limits left for later phases: creating a team invitation to a known user ID reveals whether the user is active (rate-limit invitation creation); invitations without envelopes leave the new member unable to write until the sweep runs, and no route adds envelopes to an existing invitation; a removed member keeps a revoked membership row, so re-inviting them ends in 409; an admin may invite a peer as admin and then cannot remove them; invitation expiry is not rechecked inside the accept transaction; envelopes of expired, never-accepted invitations persist until the invitation row is deleted.

**P3. Team keys in the web client.** Keyring, `KeyRef` refactor, steward sweep, invitation wrapping, key-wait UI, TOFU pins. New team content is shared. Legacy content is still read by trial decryption.
- Tests:
  - Unit tests for keyring selection.
  - Playwright run with three real browser contexts (owner, editor, newcomer): create, invite, read each other's pages, comments and attachments; remove one member and confirm they cannot read new content while remaining members can read all of it.

**P4. Lazy team migration and admin separation hook.** Re-encryption pass, opaque-author UI, admin-owned team migration (with sub-project A).
- Tests:
  - Fixture database with legacy rows from two authors.
  - Running the pass twice gives an identical state.
  - Per-row checks that the owner keeps access.
  - Pending-queue re-encryption.

**P5. Personal workbooks and recovery.** Mint CK for personal containers and migrate them. Optionally wrap the identity under a client-side recovery code so recovery preserves data. Phone pairing UI.
- Tests:
  - Content survives a password change.
  - Admin reset produces the documented loss path.
  - Cross-browser recovery.

**Risks**
- Mixed-version clients during P3 and P4. Old clients write legacy ciphertext at a shared generation and get a 409 from the new gate, which is acceptable.
- Attachment re-upload cost for large containers. Throttle the pass and make it resumable.
- Members who never log in again leave content opaque indefinitely.
- An X25519 fallback performance regression on low-end devices. noble is about 1 ms per operation, which is acceptable.
- Missing a single `authSecret` call site in `main.tsx`. Grep-gate this in CI.

### Critical Files for Implementation
- /home/yoshi/git/busnes.app/kynotes-server-subpages/web/src/crypto.ts
- /home/yoshi/git/busnes.app/kynotes-server-subpages/web/src/main.tsx
- /home/yoshi/git/busnes.app/kynotes-server-subpages/internal/httpapi/device_routes.go
- /home/yoshi/git/busnes.app/kynotes-server-subpages/internal/httpapi/collab_routes.go
- /home/yoshi/git/busnes.app/kynotes-server-subpages/IMPLEMENTATION_PLAN.md (plus DESIGN.md, `internal/httpapi/admin_routes.go`, `internal/httpapi/object_routes.go`, `web/src/storage.ts`)
## 8. Decision 2026-10-07: identities for SSO-only users and new browsers (owner-approved)

Users who sign in only through KyIdentity have no KyNotes password. Every user, including password users, also gets device linking:

1. **First browser.** After sign-in the browser creates the identity keypair. It shows a one-time **recovery code**, which wraps a copy stored on the server. This is the last-resort backup; the server and KyIdentity cannot unwrap it.
2. **Every trusted browser** keeps the identity private key wrapped under its own **non-extractable WebCrypto key** in IndexedDB. Reloads need no secret.
3. **Linking a new browser or phone.**
   - The newcomer creates a one-time X25519 key and shows a short code or QR.
   - An already-trusted browser or device approves it and wraps the identity key to that one-time public key. The KyNotes server only relays ciphertext.
   - Both screens show the same short check code derived from both public keys, so a server that swaps keys is detected.
4. **KyIdentity is authentication only.** It decides who may request and approve linking. It never holds key material, so KyNotes stays zero-knowledge toward whoever operates KyIdentity.
5. **Loss.** With no trusted device left, the recovery code restores the identity. With neither, the identity is reset, team owners re-share team keys automatically through the steward sweep, and only that user's personal notebooks are lost.

Phasing: device linking ships with P3, before any SSO user needs team keys. The recovery code ships with P5, together with personal notebooks. Password users keep the password unwrap path from P1 and can also link devices.
