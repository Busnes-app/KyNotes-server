# Subpages and section groups

Status: approved in conversation 2026-10-07; this spec awaits written review.
Builds on `2026-10-06-onenote-notebooks-and-canvas-pages.md` (notebooks, sections, ordered pages).

## Goal

OneNote organisation inside a notebook:

- **Subpages.** A page can be indented up to two levels below the page above it.
- **Section groups.** Groups hold sections and other groups, presented as tabs in OneNote style.

The zero-knowledge and per-object placement rules stay as they are. Every structural field lives inside the object's own ciphertext, and changing one item never rewrites a shared list.

## Data model

### Subpages: a level on each page

- `PagePayload` gains `level?: 0 | 1 | 2`. A missing, invalid or out-of-range value reads as 0, so existing pages are never rewritten.
- A page's parent is the nearest earlier page in the same section, in display order, with a lower level.
- **Normalisation.** In display order, the first page is level 0, and each page is at most one level deeper than the page before it. Normalisation happens at read time for display and is never written back unless the user acts on the page.
- **Indent and outdent** write one page, its own `level`.

### Section groups

- **New payload.** A group is an encrypted object of kind `folder` with payload `{type:"group", title, color, order?, group?}`. The server sees only the `folder` kind, as it does for sections today.
- **Membership.** `SectionPayload` and the group payload gain an optional `group` field holding the parent group's object ID.
- **Missing parents.** If the parent group is missing or deleted, the item shows at the notebook root.
- **Safety caps.** Group depth is capped at 4: anything deeper shows at the root. Cycles are broken at read time by rendering the item at the root, and nothing is written.
- **Quick Notes** stays a virtual section at the notebook root.

### Validation (`parseObjectPayload`)

- `level` must be the integer 0, 1 or 2; anything else is dropped.
- `group` must be an object ID; anything else is dropped.
- A group payload follows the section rules: the title must be a string with a fallback, the colour must be from the palette, and `order` must be a valid order key.
- Decrypted payloads stay untrusted, and invalid fields never throw.

## UI

### Page list

- **Display.** Rows are indented 16px per level.
- **Collapse.** A page with subpages shows a ▸/▾ toggle. Collapsed parent IDs are stored per notebook in browser localStorage under `kynotes-collapsed-<userId>-<containerId>`. Only page IDs are stored there, never content.
- **Indent and outdent.** With a row focused, Tab indents and Shift+Tab outdents. A row menu ("Indent page", "Outdent page") does the same on touch. Indenting is refused at level 2, or when the page would sit more than one level deeper than the page above it.
- **Moving a parent.** Dragging a parent, Alt+Arrow, dropping it on a section tab, or the "Move to section" select carries its block: the parent plus every following page with a deeper level. Relative levels inside the block are kept. The block is clamped so its first page fits its new position.
- **Moving a subpage alone.** A subpage moved by itself has its level clamped to fit its new position.
- **Deleting a parent.** Deleting a page deletes only that page. Its subpages stay and are normalised for display.
- **Search.** Search stays flat across the notebook. Opening a page that is hidden under a collapsed parent expands its ancestors.

### Section tabs and groups

- **Tab strip contents.** The current group's sections come first, then its child groups as folder tabs (📁 name), then ＋. The ＋ button offers "New section" and "New section group". At the notebook root, Quick Notes stays last among the sections.
- **Breadcrumb.** Inside a group, a breadcrumb above the tabs ("Notebook › Group › Subgroup") links to every level.
- **Group tab menu (⋯).** It offers Rename, Color, Move left/right, Move into group…, and Delete group. Deleting a group moves its sections and groups up one level, and the confirmation dialog says so. Nothing else is deleted.
- **Moving sections into groups.** A section can be moved into a group by dropping its tab on a group tab, or through its ⋯ "Move into group…".
- **Deep links.** They keep the form `#/<container>/<section|quick>/<page>`. The visible group path is derived from the section.

## Behaviour on edge cases

- **Another device deletes a group.** Its contents appear one level up on the next load.
- **Concurrent edits to a block.** A block move writes each page through the existing serialized move chain. Concurrent edits on another device surface through the existing conflict-copy recovery.
- **Hostile input.** Hostile structural data, such as cycles, depth over 4, or levels out of range, renders safely and never loops.

## Implementation notes

- **Pure helpers in `web/src/pages.ts`, unit-tested:**
  - level clamping and normalisation;
  - visible rows with collapse;
  - parent-block extraction;
  - block reorder with level clamping;
  - group tree resolution with cycle and depth guards;
  - breadcrumb path;
  - the children of a group.
- **No server or migration changes.**
- **Saving.** Writes reuse the existing save machinery: `placePage`, `writeObject`, `updateSection`, the move chain, reconciliation, and the flush before leaving a page. Groups get an `updateGroup` equivalent built on the same chain, or `updateSection` generalised to cover them.

## Non-goals (v1)

Dragging a page sideways to change its level, keyboard navigation between groups, showing groups in the work-queue view, and syncing collapse state across devices.

## Verification

- **Unit tests.** Vitest covers the pure helpers, including hostile inputs such as cycles, excess depth and invalid levels.
- **Real browser.** A Playwright pass on a localhost scratch server with throwaway data covers indent and outdent (Tab, Shift+Tab, menu), collapse persistence, moving a parent with its block, a lone subpage move, deleting a parent, nested groups with the breadcrumb, deleting a group, moving a section into a group, deep links into a grouped section, and phone width. Screenshots are taken in light and dark themes.
- **Existing checks.** CI runs `npm test` and `npm run build`, compares the embedded bundle, and runs the Go suite.
