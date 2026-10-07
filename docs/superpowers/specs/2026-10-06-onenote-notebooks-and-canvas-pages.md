# OneNote-style notebooks and canvas pages

Status: proposed 2026-10-06. Implemented by two plans:
`docs/superpowers/plans/2026-10-06-onenote-navigation.md` (A, ships first) and
`docs/superpowers/plans/2026-10-06-canvas-pages.md` (B, depends on A).

## Goal

KyNotes must feel like OneNote: notebooks hold colored section tabs, sections hold an
ordered page list, and every page is a free-form surface with positioned rich-text
boxes and pen ink. Zero-knowledge stays intact: the server sees no titles, structure,
order, text or ink.

## Decisions

- **Notebook** = an existing container (personal workbook or team workspace). UI copy
  says "notebook"; the API and storage keep `workbook`.
- **Section** = an object created with the existing frozen kind `folder`. Its encrypted
  payload is `{type:"section", title, color, order}`. No server change.
- **Page** = an object of kind `note`. Its encrypted payload gains `type:"page"`,
  `section` (a section object ID) and `order`. Legacy payloads `{title, body}` stay valid.
- **Each object owns its own placement.** There is no notebook manifest. A page records
  its section and order key, and the client merges them at read time. Concurrent edits to
  two pages never touch the same object.
- **Order** uses fractional string keys (`order.ts`, alphabet `0-9a-z`, at most 512
  characters). Ties sort by object ID, so two devices that insert at the same spot never
  hide a page.
- **Quick Notes** is a virtual section, not an object. It holds pages without a section
  and pages whose section was deleted. Deleting a section never deletes pages; they
  reappear in Quick Notes.
- **Every page is a canvas** (`kynotes.canvas.v1`). Existing BlockNote, Tiptap and Markdown
  bodies open as one text box at the origin, converted on read. A page is rewritten only
  when the user edits it.
- **Ink** uses `perfect-freehand` (MIT, no dependencies) to render pressure strokes as SVG.
  Excalidraw and tldraw are not used: Excalidraw text is not rich text, and tldraw is not
  open source.
- **Deep links** use the hash `#/<container>/<section|quick>/<page>`. Hashes never reach
  the server.

## Limits

- Server object limit: 10 MiB of ciphertext. The client refuses new ink once the
  serialized page body exceeds 9 MiB and says so.
- Canvas coordinates are clamped to `0..100000`. A stroke has at most 10,000 points; a page
  has at most 5,000 strokes and 500 boxes. Larger decoded input is truncated at parse.

## Non-goals (v1)

Subpages, section groups, zoom, lasso selection, ink-to-text, page templates, ink in
shared links (they show text only), and native mobile clients. None of these exist yet.

## Removed

The "Recent/Title" sort and the device-local pins. Manual order replaces both. Pins were
stored only in this browser's localStorage, so nothing server-side is lost.
