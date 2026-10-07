# KyNotes Web Frontend MVP — Implementation Plan

This plan builds a responsive, installable web client for the existing KyNotes
Server. The web client is a local-first encrypted application. The server
continues to receive only ciphertext and the protocol metadata defined by
`IMPLEMENTATION_PLAN.md`.

The frontend is a separate application. It does not change the server's frozen
Phase 0 contracts unless a client requirement exposes a genuine protocol bug;
such a change must update `DESIGN.md` and the server plan in the same change.

## 1. MVP outcome

An authenticated user can:

1. Open KyNotes in a desktop or mobile browser.
2. Log in without sending a plaintext password to the server.
3. Enroll the browser as a device.
4. Create and edit encrypted notes.
5. Close and reload the browser, then recover the local notes.
6. Synchronize changes with the server.
7. Work during a temporary offline period and sync later.
8. Upload and download encrypted attachments.
9. Inspect note versions and recover from a basic save conflict.
10. Manage the current browser session and enrolled devices.

The MVP does not include rich collaboration, presence, graph navigation, push
notifications, server-side search, server-side Markdown parsing, publishing,
or a native mobile application.

## 2. Product shape

The default screen is a calm three-pane workspace:

```text
┌──────────────┬──────────────────────────────┬─────────────────┐
│ Containers   │ Note title                   │ Sync confirmed  │
│ Notes        │                              │ Versions        │
│              │ Encrypted note editor        │ Attachments     │
│ + New note   │                              │ Devices         │
└──────────────┴──────────────────────────────┴─────────────────┘
```

The editor is the primary workflow. Sync, encryption, version, and device
states are visible but quiet. A future constellation view may augment the
sidebar; it must not replace ordinary note navigation.

The responsive MVP also includes encrypted, user-defined workspace names, a
KyPost-inspired settings layout, browser-local theme selection with the full
15-theme palette, and an admin-only server status panel. Workspace names remain
ciphertext metadata; the server never receives their plaintext. The admin
surface exposes the persisted default theme and metadata-only administration;
other host-level configuration remains host-managed.

The current client additionally groups personal and team workspaces, supports
manual section and page ordering, edits versioned canvas pages (positioned BlockNote boxes plus ink), autosaves and
supports manual saves, and displays encrypted comments. Admins can set the
server default theme, manage account role/status, and inspect metadata-only
audit records.

The next product slice adds an encrypted local retry queue, deterministic
client-side search, contextual resurfacing, document link graph edges,
encrypted section anchors for comments, a canvas page editor,
commit receipts, and ciphertext-only share links whose decryption material is
kept in the URL fragment. KyBackup owns backup and restore. Cross-server
workspace migration is intentionally deferred to v2.

Browser-sealed links are opened at `/share/<token>#<key>`; the server returns
only the opaque ciphertext and the browser performs decryption. The link key
is never sent in an HTTP request.

## 3. Technology and repository layout

Use React, TypeScript, and Vite for the web application. Use native Web Crypto
and IndexedDB first; add a dependency only when it removes meaningful code.

```text
web/
  index.html
  src/
    app/                 routing, providers, error boundaries
    components/          reusable visual components
    features/
      auth/
      containers/
      notes/
      attachments/
      conflicts/
      devices/
    crypto/              Web Crypto adapters and key lifecycle
    api/                 typed KyNotes HTTP client
    storage/             IndexedDB schema and repositories
    sync/                pull, push, queue, retry, cursor state
    models/              client protocol types
    styles/              design tokens and responsive layout
  public/
packages/
  protocol/               shared JSON types and validation
  crypto/                 platform-neutral crypto interfaces
  sync/                   platform-neutral sync state machine
```

The first implementation may keep `packages/` inside `web/src` while the
interfaces stabilize. Extract shared packages before starting a mobile app.

The production deployment uses one origin. The Docker build runs the frontend
build and embeds `web/dist` into the Go binary, so the existing server serves
the application at `/`:

```text
/       → embedded frontend
/api/   → KyNotes Server
```

This avoids CORS as an MVP concern. HTTPS remains mandatory outside local
development.

## 4. Frozen client contracts

### Authentication

- Use `POST /api/v1/auth/login-params` and `POST /api/v1/auth/login`.
- Derive the authentication secret in the browser using the exact server
  fixture and KDF contract.
- Never send or store the plaintext password.
- Treat session cookies as opaque. Do not copy them into IndexedDB or logs.
- Handle session expiry by preserving encrypted local work and requiring a
  fresh login.

### Device and keys

- Generate the browser device key pair in the browser.
- Keep private key material in a non-exportable Web Crypto key where supported.
- Complete pairing and envelope installation through the existing device API.
- Store only encrypted local vault material and public/device metadata in
  IndexedDB.
- A local key loss is a recoverable user-facing state, not an attempt to bypass
  server authorization.
- Device revocation must immediately stop new sync writes and remove local
  access to the affected container keys.

### Ciphertext

- The editor works on plaintext only in browser memory after successful local
  decryption.
- Object bodies, metadata, comments, and attachments are encrypted before
  leaving the browser.
- Do not put plaintext in URLs, query parameters, analytics, logs, error
  messages, browser titles, or server-visible routing fields.
- Server routing ciphertext remains opaque to the frontend protocol layer.

### Local storage

IndexedDB stores:

- encrypted object payloads;
- encrypted attachment payloads or encrypted cache entries;
- container and object IDs;
- versions, cursors, and sync states;
- public device metadata;
- encrypted key material or non-exportable key references where supported.

IndexedDB must not store plaintext note bodies, passwords, session tokens,
pairing tokens, recovery codes, or device secrets.

## 5. Sync state machine

Every local mutation has an explicit state:

```text
draft
  → encrypted
  → queued
  → uploading
  → server-confirmed
       └→ conflict
             → resolved locally
             → queued again
```

The sync engine must:

- persist the queue before reporting a local save as durable;
- persist the cursor after a successful pull;
- retry only idempotent or safely resumable operations;
- use the server's expected version and conflict response;
- preserve both local and server ciphertext on conflict;
- never silently overwrite a newer local version;
- pause writes when the session or device is revoked;
- recover after browser restart;
- coordinate multiple tabs with a Web Lock or a single-tab fallback;
- expose `offline`, `queued`, `syncing`, `confirmed`, and `attention-needed`
  states to the UI.

## 6. Implementation phases

### Phase A — Frontend foundation

- Scaffold `web/` with TypeScript, React, Vite, and strict checks.
- Add the existing IBM Plex Mono and Space Grotesk assets.
- Add routing, responsive layout, error boundary, and accessible primitives.
- Add typed API request/response helpers for the existing error envelope.
- Configure local development and same-origin production builds.

Exit gate: the app loads on desktop and narrow mobile viewports, handles an
API error envelope, and has no plaintext telemetry or third-party analytics.

### Phase B — Browser crypto and local vault

- Implement the auth-secret derivation fixture.
- Implement the exact object/container encryption adapters.
- Generate and persist a browser device identity.
- Create the IndexedDB schema and versioned migrations.
- Add lock, unlock, logout, and local-wipe flows.
- Add memory-only plaintext boundaries around editor state.

Exit gate: a test can encrypt, close the app, reopen it, unlock locally, and
decrypt the same note without contacting the server for its plaintext.

### Phase C — Authentication and device enrollment

- Build login, session restoration, logout, and expired-session screens.
- Build pairing-token entry or QR handoff.
- Register the browser device and install its envelope.
- Show device name, fingerprint, last-seen time, and revoke action.
- Handle disabled users, revoked devices, CSRF failures, and rate limits.

Exit gate: a clean browser profile can login, enroll, read an authorized
container, and fail closed after device revocation.

### Phase D — Notes workspace

- Build container and object navigation.
- Build note creation and folder navigation.
- Build a deliberately small plaintext editor first: textarea or plain
  structured blocks, not a rich-text framework.
- Encrypt on save and decrypt on read.
- Add drafts and autosave with visible local durability state.
- Add keyboard navigation and mobile single-column layout.

Exit gate: create, edit, reload, and delete a note from both desktop and
mobile-width browsers.

### Phase E — Synchronization and offline use

- Implement change pull and cursor persistence.
- Implement encrypted save queue and retry policy.
- Add browser restart recovery.
- Add online/offline detection without trusting it as the source of truth.
- Add multi-tab coordination.
- Add a sync status panel and attention-needed queue.

Exit gate: disconnect the browser, make edits, close it, reconnect it, and
verify that changes arrive exactly once without losing a local version.

### Phase F — Attachments

- Add encrypted attachment selection and size validation.
- Implement resumable chunk uploads using the server contract.
- Persist upload progress in IndexedDB.
- Add pause, retry, cancel, and resume after reload.
- Add encrypted lazy download and preview handling.

Exit gate: interrupt a multi-chunk upload, reload the browser, resume it, and
download the exact original bytes.

### Phase G — Version history and conflicts

- Display version metadata and sync checkpoints.
- Fetch selected encrypted versions only when requested.
- Decrypt selected versions locally.
- Add side-by-side comparison.
- Add choose-local, choose-server, and save-as-new resolution paths.
- Preserve unresolved conflict data until the user resolves it.

Exit gate: two clients create a stale-save conflict; one client can inspect
both versions locally and resolve it without plaintext reaching the server.

### Phase H — Security, accessibility, and release

- Add CSP and secure production headers.
- Audit XSS, clipboard, downloads, object URLs, and error rendering.
- Verify no plaintext enters logs, URLs, IndexedDB, or network payloads.
- Add keyboard navigation, focus management, reduced motion, and screen-reader
  labels.
- Add build artifact checks and static hosting configuration.
- Document backup, upgrade, and frontend/server version compatibility.

Exit gate: security, accessibility, offline, multi-tab, and end-to-end suites
pass against the Dockerized server.

## 7. Required test matrix

### Unit tests

- Auth-secret derivation matches `testdata/protocol/auth_vectors.json`.
- IDs, error envelopes, request retries, and cursor handling.
- Encryption round trips and wrong-key failures.
- IndexedDB migrations and repository transactions.
- Sync state transitions and retry backoff.
- Conflict resolution never drops either input.

### Browser tests

- Login and session expiry.
- Pairing and device revocation.
- Create/read/edit/delete note.
- Browser reload with local encrypted data.
- Offline edit and reconnect.
- Multi-tab edit coordination.
- Resumable attachment upload.
- Version compare and conflict recovery.
- Mobile-width navigation and keyboard accessibility.

### Privacy tests

Assert that a fixed plaintext marker, password, auth secret, session token,
pairing token, device secret, and recovery code appear in none of:

- network requests;
- URL or document title;
- console or application logs;
- IndexedDB plaintext records;
- generated error messages;
- frontend analytics, which are disabled for the MVP.

## 8. Mobile path

Do not start mobile implementation until Phases B–G pass in the browser.

The mobile app can then reuse:

- `protocol` types;
- API client;
- crypto interfaces and test vectors;
- sync state machine;
- conflict model;
- attachment state machine.

Only platform adapters should differ:

- secure key storage;
- local database;
- background sync;
- file picker and downloads;
- notification integration.

The mobile project should use Expo/React Native only after the shared client
interfaces are extracted and tested. The web app is the reference client for
protocol behavior, not the source of mobile-specific UI assumptions.

## 9. Definition of done

The frontend MVP is complete when:

- the vertical slice works: login → enroll → create encrypted note → reload →
  decrypt;
- all MVP capabilities in §1 work against the current server;
- no plaintext or secret material appears in the privacy test surfaces;
- the app works at desktop and mobile widths;
- offline edits survive reload and synchronize safely;
- a conflict can be inspected and resolved locally;
- attachments resume after interruption;
- `go test -race ./...` remains green for the server;
- frontend typecheck, lint, unit, browser, and production-build checks pass;
- the Docker deployment serves the frontend and proxies `/api/` through HTTPS.

## 10. Explicit non-goals

Do not add the following to the MVP:

- server-side note search or indexing;
- server-side Markdown/YAML/task parsing;
- rich-text collaboration;
- public sharing or publishing;
- telemetry or advertising;
- account self-registration;
- native mobile code before the shared client core is proven;
- a graph-first navigation model;
- a custom editor before the encrypted save/read vertical slice works.
