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

**Envelope byte format v2** (client-only; the server never parses it). These details are not frozen, so they need DESIGN.md and plan text only. v1 (anonymous sender) never carried content and is gone: no client seals or opens it.

```
envelope = 0x02 | senderDeviceID(30) | ephPub(32) | nonce(12) | ChaCha20-Poly1305(key, nonce, CK(32), aad)   // 123 bytes
key      = HKDF-SHA256(ikm  = X25519(ephPriv, recipientPub) || X25519(senderIdentityPriv, recipientPub),
                       salt = ephPub || recipientPub || senderPub,
                       info = "kynotes/envelope/v2", L = 32)
aad      = "kynotes/envelope/v2" | containerID | u32be(keyGeneration) | recipientDeviceID | senderDeviceID
```

`containerID`, `recipientDeviceID`, `senderDeviceID` and `userID` (identity AAD, §1) are exact 30-byte ASCII IDs matching `^(cnt|dev|usr)_[0-9a-hjkmnp-tv-z]{26}$`, validated before the AAD is built. The fixed length is what makes the unprefixed concatenation unambiguous; every client must reject any other length. Both X25519 agreements must be non-zero (low-order points are refused).

The AAD binding stops a malicious server from replaying an envelope into a different container, generation or recipient. The static sender agreement authenticates the sender: only the holder of the sender's identity private key (or the recipient itself) can seal an envelope that opens under that sender's public key. `internal/teamkeys` is the Go reference and generates `testdata/protocol/envelope_vectors.json`; the web client must match it byte for byte.

**Accepting an envelope.** The recipient reads `senderDeviceID` from the bytes and resolves it against the container's current member list. It opens the envelope only if the sender is its own identity, a current owner or admin whose identity key matches the local pin, or (for generations below this device's own high-water mark) an identity already pinned on this device (§6). An unpinned sender is first contact: the key is pinned once the envelope opens and the UI shows a "new key holder" notice. A pin mismatch is refused and surfaced; it is accepted only after the user confirms the new fingerprint. Envelopes that fail any check are ignored and never used to read or write.

**Crypto library.** WebCrypto has no ChaCha20-Poly1305, X25519 support varies across browsers, and LAN `http://` deployments already rely on `fallbackCrypto.ts`. Recommendation: add `@noble/curves` (x25519) and `@noble/ciphers` (chacha20poly1305). Both are audited, have no dependencies and work in every context. Do not hand-roll these primitives.

**Password change and reset.** `POST /auth/password` gains `wrappedIdentityKey`, which is the same private key re-wrapped under the new `userKEK` and committed in the same transaction. This fixes F2 for shared-key content. An admin password reset cannot re-wrap the key, so the user's identity is reset. Team owners re-grant access automatically through the key steward sweep (§3). Personal containers are lost unless Phase 5 recovery wrapping exists. The admin reset UI must say this explicitly.

## 2. Container content keys

- `CK[container, generation]` is 32 random bytes, minted per container per generation. The purpose subkeys keep the current derivation with only the input key changed: `HKDF(ikm = CK, salt = containerID, info = <existing label>)`. Ciphertext layout (`iv || ct+tag`) and labels stay as they are, so `encryptNote`, `decryptObject`, `encryptAttachment` and the other helpers keep their shape. Their first argument becomes a `KeyRef` (a CK, or a legacy `authSecret`) instead of a string.
- **Covered by CK:** container meta, objects and pages (including CanvasPage bodies, which reach the server only through `encryptNote` in `main.tsx`), conflict copies (normal object saves), comments, attachment bytes, attachment metadata and previews, local IndexedDB caches and pending saves, and `X-Kynotes-Routing-Ciphertext`.
- **Share links:** keep the dedicated random per-link key. Content is decrypted with CK and re-sealed under a fresh key, so links never reveal CK.
- **Choosing a key on read:** the client takes the row's `keyGeneration` (required; a row without one is unreadable) and the container's `sharedGeneration`. A row at or above a non-zero `sharedGeneration` opens only with `CK[keyGeneration]`; if the keyring lacks it, the row waits for keys. A row below `sharedGeneration`, or any row of a never-shared container (`sharedGeneration = 0`), opens only with the legacy key derived from the reader's own `authSecret`. No other generation's CK is ever tried, so a row labelled at or above `sharedGeneration` cannot be downgraded to the legacy key, and a removed member's older CK cannot stand in for a newer generation. A row labelled below `sharedGeneration` still opens with the legacy key, which the server can derive (§6, read downgrade).
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
- **Invitation from an owner or admin member:** an invitation to someone the inviter does not already share a live container with goes out without envelopes: `GET /users/{id}/identity` answers only co-members and a steward holding a pending invitation they issued, and no route adds envelopes to an existing invitation. The steward sweep wraps `CK` after accept. When the invitee is already a co-member, the inviter's browser may fetch their identity key and wrap `CK` for the team and each child workspace; creating an invitation with envelopes needs the same local-password step-up as an envelope `PUT` (SSO sessions are refused), rechecked in the insert transaction; those envelopes are stored in `invitation_envelopes` and moved into `key_envelopes` in the accept transaction, only if the generation still matches. Otherwise they are dropped and the sweep fills the gap.
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
  - Invitation create and accept accept and move envelopes. Create with envelopes needs local-password step-up, rechecked in its transaction; create without envelopes stays session-only. Accept needs no step-up: it only moves envelopes the steward authorized at insertion.
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
  - Mitigation now: the client pins (trust on first use) each colleague's identity public key in IndexedDB the first time it wraps for them or accepts an envelope from them, comparing decoded 32-byte keys. Wrapping for a changed key throws until the user explicitly confirms the new fingerprint; wrapping for oneself only ever targets the browser's own identity. Each user can see their own fingerprint in Settings and compare it out of band. When pins cannot be stored (no IndexedDB vault record), the UI must say so.
  - Pins are lost with "Forget this device", and first contact is blind: a key the server substitutes before the first pin is trusted.
  - Mitigation later: a signed membership log (out of scope).
- **Envelope replay or swapping** is blocked by the AAD binding (container, generation, recipient, sender).
- **Forged envelopes:** without sender authentication a server could seal its own CK to every member and read what they write. Envelope v2 binds the sender's identity key, and recipients accept an envelope only when its sender is (a) themselves, (b) a current owner or admin of the container whose key matches the pin (first contact pins it), or (c) an identity already pinned on this device, and only for a generation below this device's high-water mark. The mark is the highest generation this device itself accepted from its own identity or a current steward, kept per container in the vault record; it only rises, is never taken from the server (a server could inflate `keyGeneration`), and when absent rule (c) is off. Rule (c) keeps history readable after the steward who wrapped it is removed or demoted. A changed steward key is refused and surfaced. The first key accepted for a (container, generation) wins: the device stores a SHA-256 digest of every accepted key beside the mark (add-only), so a different key for that generation, in the same response, later in the session or after a reload, is reported as a conflict and never used.
- **Pins never expire and are never rewritten from server data.** They are added only on first contact (wrap or accepted envelope) and replaced only after the user confirms a changed fingerprint (`storeConfirmedPin` accepts only a `PinConfirmation` that `confirmFingerprintChange` registered, checked by `isPinConfirmation`); storing pins merges and never overwrites an existing entry, and compares in the same IndexedDB transaction: a proposal that names a member already pinned to a different key (a concurrent pass won) writes nothing and reports the member, and that pass stops before any envelope is uploaded; the next pass goes through the changed-key confirmation. A removed member's pin stays, which is what rule (c) relies on.
- **Sharing-state rollback:** a server could report a shared notebook as never shared, or report an older `keyGeneration`, so that writers fall back to the login key it can derive, or seal under a generation a removed member still holds. Each device persists, per container and add-only beside the key mark, the highest `sharedGeneration` and `keyGeneration` it has seen, before using them. Every key choice uses `max(server, stored)` for `sharedGeneration` (`guardContainer`), and a server report lower than either stored value pauses all writes for that container with a notice; the legacy key is never selected and nothing is written below the stored generation. Forget-this-device clears this memory with the pins.
- **Read downgrade (residual until P4):** rows at or above `sharedGeneration` open only with their own generation's CK (§2), so relabelling cannot move them to the legacy key or an older CK. Rows below it still open with the legacy key, and the server can derive that key from `authSecret` (F1). A malicious server can therefore forge a page, comment, attachment or conflict version in a shared container by sealing it under the reader's legacy key and labelling it below `sharedGeneration`. Before sharing, team rows were readable only by their author, so such a row is either the reader's own pre-sharing content or a forgery, and the client cannot tell which. P3a labels these rows "written before this notebook was shared; not end-to-end verified", using the same decision that picks the legacy key (generation 0 included; an honest server never stores 0, because every write must name the current generation, which starts at 1). It re-seals one under the CK only when the user edits or moves that row: never on open, autosave, a renumber caused by another move, a block move that carries a labelled subpage (refused), or a conflict copy. The notebook name read before the first mint is the one exception: the minting steward's browser re-seals it under the first CK and says so ("Shared this notebook's name with members"), since that name was as forgeable as any personal notebook's. P4 closes this by migrating legacy rows to the CK and then refusing legacy reads in shared containers.
- **Residual: fake members.** A malicious server can add an invented member with an owner role and its own identity key; that member's envelopes are first-contact and are pinned. The attack is visible as a new member and a "new key holder" notice with a new fingerprint, not silent. Full prevention needs a signed membership log (future).
- **Removed members** keep the keys for generations before their removal and any plaintext they already downloaded. Rotation is forward-only, which is the documented limit.
- **Insider owner or admin** can wrap a wrong or different key for some members. The insert-only rule plus a client-side check that the key decrypts current meta catches accidental splits. A malicious insider is out of scope.
- **Minting** (rotation, wrapping for others) requires session, CSRF and step-up. Device credentials are never accepted.
- **Admin separation:** admins never hold memberships in teams they create. Account bootstrap must force a password change before the identity exists (§1).
- **Offline guessing:** the wrapped identity key is guessable offline against the password, so it is released only in password-proving responses (local login and step-up), never to a bare session cookie or a device credential.
- **Identities created before `password_admin_known` existed** may be wrapped under a password an administrator once knew. The user's own password change re-wraps rather than replaces them. Replacing the keypair needs the P5 replacement path, so P2 leaves this residual risk for pre-flag accounts.
- **SSO users:** SSO sessions cannot create or receive an identity in P1, because their step-up proves the IdP, not the password the wrap depends on. §8 and P3c resolve this.
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

**P3. Team keys in the web client.** Keyring, `KeyRef` refactor, steward sweep, invitation wrapping, key-wait UI, TOFU pins. New team content is shared. Legacy content is read with the legacy key, shared content with its own generation's key.
- Tests:
  - Unit tests for keyring selection.
  - Playwright run with three real browser contexts (owner, editor, newcomer): create, invite, read each other's pages, comments and attachments; remove one member and confirm they cannot read new content while remaining members can read all of it.

**P3 decomposition (2026-10-07).** P3 ships as three stacked PRs, each usable on its own. The order keeps SSO-only users from ever being locked out: no container is shared while any member lacks an identity, and identities for SSO users (P3c) arrive before anything relaxes that.

- **P3a. Shared team keys for password users** (plan: `docs/superpowers/plans/2026-10-07-team-keys-p3a.md`). `KeyRef` refactor of `crypto.ts`; `keyring.ts` (envelopes to generation keys, write key, exact-generation read key, steward sweep plan); `keyService.ts` (mint through rotation, history backfill, one retry on a lost race); TOFU pins with local fingerprints in the vault record; all `main.tsx` content call sites; read-only "waiting for keys" state; re-keying of queued saves, uploads and comments after a rotation; immediate re-mint after a removal. Server: containers report `sharedGeneration`; shared containers refuse writes without `X-Kynotes-Key-Scheme: shared-v1` (stale tabs); envelope `PUT` may backfill any shared generation that already has envelopes and never mints one. Resolves the P2-carried limits: stale legacy tabs (header plus client re-key), identity-less members (first mint blocked with a named explanation; later additions read only), removal (empty generation re-minted by rotation only). Depends on P2. Personal notebooks stay legacy.
- **P3b. Invitations, membership key status and P2 invitation limits.** The web client gets an invitation accept flow (there is none today) and wraps at invite time for invitees whose identity it can see (`invitation_envelopes`, team plus child workspaces), falling back to the sweep. Team member rows show key status (has key, waiting, no identity), and waiting members can ask a steward. Pin management in Settings lists pinned colleagues with fingerprints and re-trusts a changed key outside the wrap prompt. Server: rate-limit invitation creation, recheck expiry inside accept, let a removed member be re-invited (reactivate the revoked membership row instead of 409), delete envelopes of expired invitations, and let a server admin remove an admin it invited. Depends on P3a (keyring, sweep, pins).
- **P3c. Device linking and identities for SSO users (§8).** Every trusted browser re-wraps its identity under a non-extractable WebCrypto AES-GCM key kept in IndexedDB (secure contexts; plain `http://` LAN origins keep today's raw vault copy and Settings says so). A new browser or phone creates a one-time X25519 key and shows a short code; a trusted browser of the same user approves it and seals the identity private key to that key; both screens show a check code derived from both public keys. Server relay (migration `0023_link_requests.sql`, session-only, CSRF, ciphertext only, audited): `POST /api/v1/me/link-requests` (newcomer posts its one-time public key; 10-minute TTL, at most three pending per user), `GET /api/v1/me/link-requests` (trusted session lists pending requests), `POST /api/v1/me/link-requests/{id}/approve` (step-up; stores the sealed bundle once), `GET /api/v1/me/link-requests/{id}` (newcomer collects the bundle once, then the row is deleted), `DELETE /api/v1/me/link-requests/{id}`. The sealed bundle reuses the envelope construction with label `kynotes/link/v1` and AAD binding user ID and request ID. SSO-only users create their first identity from an SSO session after an action-bound SSO step-up, with no server-wrapped copy until P5's recovery code (`wrap_alg` marks it); envelope writes and rotations then accept the SSO action-bound step-up so SSO stewards can share keys. With that, the P3a "blocked" explanation points users to linking instead of password sign-in. Device envelopes may be self-authored by the same user's identity (members wrap for their own devices), so a device recipient accepts its own user's identity as a sender in addition to the §6 rules. Depends on P3a; P5 adds the recovery code. QR codes need a renderer dependency and are deferred; the short code carries the same information.

**P3a as built.** Resolved ambiguities:
  1. Reads are not trial decryption. A row at or above `sharedGeneration` opens only with its own generation's container key; rows below it, and personal containers, use the legacy key. A missing or malformed generation gets no key and fails closed.
  2. Envelopes are v2 and sender-authenticated. A browser accepts a key only from its own identity, from a current owner or admin that matches its pin, or from a pinned identity for a generation below the device's high-water mark. The first key per generation wins; an accepted key's SHA-256 is stored add-only on the device, and a different key for that generation is a refused conflict.
  3. Pins are trust-on-first-use and add-only. Replacing a pin requires an explicit confirmation showing both fingerprints; a decline is remembered for the session, per member and key.
  4. Container meta `PATCH` carries `keyGeneration`. On a shared container the server refuses a missing, zero, old or future generation with `409 already_exists`, inside the transaction. This amends a frozen route; DESIGN.md and IMPLEMENTATION_PLAN.md changed with it.
  5. `GET /api/v1/objects/{id}/conflicts` returns `keyGeneration` for each conflict copy, so a client opens it with the right key.
  6. Edits made while keys are missing wait in the local encrypted queue at generation 0. They are never uploaded at generation 0 and are resealed under the current key when keys arrive.
  7. Notebook names load through the same read-only key pass, which never prompts or wraps.
  8. Stale legacy tabs are refused by `X-Kynotes-Key-Scheme: shared-v1` on shared containers; envelope `PUT` backfills existing shared generations and never mints one.

  Known limits and parked items:
  - Steward work (mint, backfill, re-mint) runs only when a steward with a local password session opens the notebook or removes a member. A member added without an identity reads only until P3c.
  - `loadContainers` fetches envelopes per shared container, and a steward's open fetches one identity per member. `ponytail:` upgrade path: a batch route.
  - N1: queued generation-0 edits for a notebook the user lost access to stay on the device with no export or discard. `ponytail:` a discard/export control in P3b.
  - N2: a key pass runs on every 15 s drain while edits wait for keys.
  - N3: generation-0 edits become unreadable after a password change made before keys arrive. P5 moves to identity-keyed storage.
  - Admin pages cannot read shared team names.
  - A malicious server can add a fake member; it shows as a new member with a new fingerprint. Preventing it needs a signed membership log.
  - A server that reports an inflated `sharedGeneration` or `keyGeneration` has it stored as this device's floor for good; that notebook then waits for keys until "Forget this device". Denial of service only: the floor never selects a wrong or older key.
  - A first-contact steward can raise the device high-water mark (TOFU), widening the pinned-history exception.
  - Pins never expire.

**P4. Lazy team migration and admin separation hook.** Re-encryption pass, then refusal of legacy-key reads in shared containers (closes the §6 read-downgrade residual), opaque-author UI, admin-owned team migration (with sub-project A).
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
