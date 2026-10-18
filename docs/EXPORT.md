# Notebook export

"Export notebook" in the web client downloads the open notebook as one zip. The browser
decrypts every page and attachment and builds the zip itself. The export reads the notebook
the same way opening it does and sends nothing to the server.

**The zip is not encrypted.** Anyone who gets the file can read the notes. The browser says
so and asks before it starts.

## Layout (`kynotes.export.v1`)

```
<Notebook>/
  manifest.json
  <Group>/<Sub-group>/<Section>/001 <Page title>.md
  <Group>/<Section>/002 <Canvas page>.md
  <Group>/<Section>/002 <Canvas page>.canvas.json
  Quick Notes/001 <Page title>.md
  attachments/<attachment id>/<file name>
```

- **Folders:** groups and sections become folders. Pages with no section go in `Quick Notes`.
- **Page order:** pages are numbered in notebook order. Subpage nesting is in the manifest, not in
  the folders.
- **Page files:** each page is Markdown. It starts with `# <title>`, followed by BlockNote's own
  Markdown output (`blocksToMarkdownLossy`), which loses some formatting.
- **Canvas pages** get two files:
  - a `.md` file with the text boxes in reading order (top to bottom, then left to right);
  - a `.canvas.json` file holding the stored `kynotes.canvas.v1` body unchanged.
- **Attachments:** inline images link to their exported file. Every attachment is also listed
  under `## Attachments` at the end of its page. An attachment shared by several pages is
  stored once.
- **File and folder names:** characters invalid on Windows, macOS or Linux become `_`,
  as do control and bidirectional-override characters. Leading and trailing dots and spaces
  are removed. Names are capped at 100 characters. A name reserved on Windows gets a `_`
  prefix. A name that clashes with another in the same folder gets ` (2)`, ` (3)` and so on.
  No path can lead outside the notebook folder.
- **Zip format:** entries are stored uncompressed, with UTF-8 names. One zip holds at most
  65 535 files and 4 GiB.

## `kynotes.canvas.v1`

```json
{
  "format": "kynotes.canvas.v1",
  "boxes": [{ "id": "…", "x": 0, "y": 0, "width": 640, "blocks": [ /* BlockNote blocks */ ] }],
  "strokes": [{ "id": "…", "tool": "pen", "color": "ink", "size": 4, "points": [x, y, pressure, …] }]
}
```

- **Coordinates:** page pixels from the top-left corner, from 0 to 100 000.
- **Boxes:** `width` is 160–2 000. `blocks` are BlockNote `PartialBlock`s.
- **Strokes:**
  - `tool` is `pen` or `highlighter`.
  - `color` is one of `ink`, `blue`, `red`, `green`, `orange`, `yellow`.
  - `size` is 1–64.
  - `points` is a flat list of `x, y, pressure` triples, where pressure is 0–1.
  - The web client draws each stroke with `perfect-freehand` (`web/src/ink.ts`).
- **Limits:** at most 500 boxes, 5 000 strokes and 10 000 points per stroke. Ids match
  `[A-Za-z0-9-]{1,64}`.

## `manifest.json`

| Field | Meaning |
|---|---|
| `format` | `"kynotes.export.v1"` |
| `notebook` | The notebook name |
| `exportedAt` | The time of the export, in RFC 3339 |
| `groups[]` | `id`, `title`, `color`, `parent` (group id or `null`), `path` |
| `sections[]` | `id`, `title`, `color`, `group` (group id or `null`), `path` |
| `pages[]` | `id`, `title`, `section` (section id or `null` for Quick Notes), `level` (0–2 subpage depth), `path`, `canvas` (canvas pages only), `attachments[]` with `id`, `name`, `type`, `path` |
| `unreadable` | How many notebook objects (pages, sections, groups) and attachments this browser could not decrypt or fetch. These are not in the zip. |

Every `path` is relative to the notebook folder.
