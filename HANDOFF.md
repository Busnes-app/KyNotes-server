# KyNotes Server Handoff

## Current state

Latest committed code: `1d51444` (`add project handoff`). The frontend editor is BlockNote, embedded into the Go server image from `web/dist`. This product has never gone live, so no production notes were damaged by the formatting bug.

Note bodies use encrypted `NotePayload` values. The body is a `kynotes.blocknote.v1` JSON envelope. Plaintext stays in browser memory; note bodies and attachment payloads are encrypted before IndexedDB/server storage.

## Editor history and current behavior

- `3267e70`: Tiptap document editor
- `466e178`: BlockNote replacement
- `acd30d7`: ignore mount-time editor changes
- `0454f17`: serialize saves
- `51a73eb`: flush drafts when a browser tab is hidden
- `c155445`: convert legacy Tiptap documents to BlockNote blocks
- `6a51b2d`: preserve unsaved edits when navigating away
- `2e003ae`: preserve structured bodies in search/context projections
- `b440bd2`: apply sorting to search results

Workspace navigation flushes the dirty note before clearing the editor. Settings/Admin navigation keeps the editor mounted and hides it instead of remounting it.

The Work queue loads open checklist items across personal workspaces; task parsing remains client-only. Inbox folders still require the planned folder-object client path. Successful server saves show a `Last Committed Ns ago` toast for at most 15 seconds.

## Formatting loss on reopen: root cause and fix

The user reported: create formatted content, confirm it saves, leave the note, return, and find the text present but the formatting gone. Fixed in `2e003ae`. The user confirmed the fix.

The root cause was never in the save, hydration, or legacy-format paths. `main.tsx` built its search index by replacing each note body with flattened plain text:

```ts
notes.map((note) => ({ ...note, body: documentText(note.body) }))
```

The note list and the resurfacing links rendered those objects, and their click handlers passed them to `selectNote`. Reopening a note from the list therefore loaded a plain-text body. `isStructuredNoteBody` returned false, the editor took the `legacyMarkdown` fallback, and every heading, mark, and list was dropped. Any subsequent edit then saved the flattened body over the structured one.

Two facts hid this bug:

- The projection spread the whole note, so `{...note, body: string}` was still structurally a `Note`. TypeScript accepted it.
- Saving always worked correctly. Only reopening corrupted the document, so every earlier fix to the save, autosave, and lifecycle paths addressed healthy code.

`3267e70` introduced both the structured body format and the projection. Before it, the list searched the real notes with `searchNotes(orderedNotes, query)`. That commit routed the list through the flattened projection instead, so the list stopped holding real notes and `orderedNotes` became orphaned. The formatting loss and the dead sort control entered in the same change.

The fix makes the mistake unrepresentable. `indexNotes` in `web/src/knowledge.ts` returns `IndexedNote<T> = NoteProjection & { note: T }`, so a projection carries the note it was flattened from, and the list unwraps `.note` before calling `selectNote`. `IndexedNote` has no `version` field, so passing a projection where a `Note` is required is now a compile error (`TS2741`).

`b440bd2` fixes the second half of `3267e70`: `orderedNotes` was computed but never used, so the Recent/Title sort control and pinning had no effect on the list. The index now reads `orderedNotes`, and `searchNotes` filters, so the order survives. `noUnusedLocals` is enabled to fail the build on the next unused value; it also found presence polling that fetched every 30 seconds into state that nothing rendered, which is now removed. `updatePresence` still publishes this client's presence.

Verified by the frontend test suite, by `tsc`, and by the user against the Docker image. Closed.

## Verification

```bash
cd web
npm test
npm run build
cd ..
go test ./internal/web
go vet ./...
gofmt -l .
git diff --check
go test -race ./...
```

## Docker deployment

`docker-compose.local.yml` exposes `8081:8080` on loopback; set `KYNOTES_LOCAL_BIND=0.0.0.0`
in `.env` for LAN access. From the repository root:

```bash
docker compose -f docker-compose.yml -f docker-compose.local.yml build --no-cache
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d
git rev-parse --short HEAD
docker compose ps
curl http://127.0.0.1:8081/healthz
```

From another machine, use the Docker host address, for example `http://192.168.1.91:8081/`.

## If formatting loss reappears

Reproduce first: format a note, save it, click another note in the list, then click the first note again. Also try it through a resurfacing link and after a workspace switch. Check whether the reopened body is still a `kynotes.blocknote.v1` envelope before instrumenting anything else, because that single check separates a selection-path bug from an editor bug.

The boundary comparison below did not find the `2e003ae` bug, since steps 1 through 4 were all correct and the flattening happened between the note list and step 5. Keep it for a genuinely new failure.

Capture metadata only; never log plaintext note content. Compare these boundaries:

1. BlockNote `current.document` after formatting.
2. The `kynotes.blocknote.v1` body passed to `editBody`.
3. The encrypted payload written by `putNote`.
4. The decrypted payload selected by `selectContainer` after returning.
5. The `initialContent` passed to `BlockNoteEditor`.

If styles exist at step 2 but not step 4, inspect server version/cache selection. If styles exist at step 4 but the screen is plain, inspect BlockNote hydration/CSS. If step 2 is plain, inspect the BlockNote `onChange` callback.

## Open items

- `internal/web/dist/assets` holds superseded bundles. Only the files that `internal/web/dist/index.html` references are needed. Pruning is a deletion and needs explicit approval.

## Important files

- `web/src/BlockNoteEditor.tsx`: lazy editor wrapper and hydration gate.
- `web/src/document.ts`: BlockNote envelope, legacy conversion, and text projection.
- `web/src/knowledge.ts`: search/context index and client-side open-task projection. `indexNotes` flattens bodies for search while retaining the structured source body.
- `web/src/commitToast.ts`: short server-commit toast timing and label.
- `web/src/main.tsx`: loading, workspace navigation, save queue, autosave, attachments, and editor integration.
- `web/src/storage.ts`: encrypted IndexedDB notes and retry queues.
- `web/src/crypto.ts`: browser encryption/decryption.
- `internal/web`: embedded production bundle.
- `Dockerfile`: frontend build and server embedding.
