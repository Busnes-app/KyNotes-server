# Shared UI verification

## Change

Keep Save and Lock reachable on mobile, use visible keyboard focus, and verify the regenerated embedded bundle in CI. Shared assets are pinned to ky-ui 0.2.0 with content hashes. Product layouts, saved theme keys and named presets remain local.

## Capture conditions

Captured 2026-09-25 from this branch, using the application UI (not a design mockup). Real scratch server, encrypted preview workspace and a synthetic note opened in the lazy-loaded BlockNote editor.

OS-following Busnes Light and Dark were captured at 1280×900 and 390×844 CSS pixels. Browser device scaling may make PNG dimensions larger. Document width stayed within the viewport in these captured states; local navigation/table scrolling is intentional. Screenshots show the selected-page accent, not a complete accessibility audit.

No complete end-to-end product workflow or exhaustive named-theme audit is claimed.

## Checks

26 frontend tests, production build, go test ./internal/web and embedded-bundle comparison passed. Central ky-ui sync --check verified all ten consumers. Screenshot coverage is Busnes Light/Dark; existing named choices are retained, but not every named palette/page combination was visually exercised.

## Screenshots

| Light | Dark |
| --- | --- |
| ![Desktop light](docs/ky-ui-light-desktop.png) | ![Desktop dark](docs/ky-ui-dark-desktop.png) |
| ![Mobile light](docs/ky-ui-light-mobile.png) | ![Mobile dark](docs/ky-ui-dark-mobile.png) |

## Reproduce

Run npm ci, npm test (where configured), and npm run build in web/, then start the product with isolated local preview data following its README. Use System theme, emulate OS light/dark, and inspect both viewport sizes. Do not point preview instances at production data. For KyVault, use a configured development KyIdentity or explicitly labeled read-only browser fixtures; never bypass backend authentication.

## OneNote navigation (2026-10-06)

### Capture conditions

Scratch server on 127.0.0.1 with throwaway data (notebooks "Project Atlas" and "Home"), embedded bundle, Playwright Chromium. OS-following Busnes Light and Dark at 1280×900 and 390×844. The initial run found accent-filled section tabs, a stale page list row after editing, and an unthemed move select; they were fixed in 726a354 and re-verified on the new bundle.

### Results

| Check | Result |
| --- | --- |
| Create notebooks, sections, colors, pages; persist on reload | Pass |
| Reorder pages by drag and Alt+↑/↓; move by dropping on a tab and by the "Move page to section" select; order and placement persist after reload | Pass |
| Edit a page, switch pages within 1 s, reload: edit survives | Pass |
| Offline edit, switch page, drag to another section, back online, reload: edit present in the target section | Pass |
| Delete a section: its pages appear under Quick Notes, also after reload | Pass |
| Deep links in a new tab, Back/Forward one step each, garbage hash opens the first notebook with one changes request | Pass |
| Section ⋯ menu opens at the button, closes after actions and on Esc | Pass (light and dark, re-verified) |
| Search lists a page from another section with its section label | Pass |
| 390px: tab list scrolls horizontally, document width 375 px | Pass |
| Dark theme: selected tab distinguishable from unselected, ⋯ and ＋ transparent | Pass after fix (initial run: fail) |
| Open page's list row title and preview update without reload | Pass after fix (initial run: fail) |

Not run: none of the listed checks were skipped.

### Save path

Hard reload at the start, none between edit and move. Moves ran Planning to Research in round 1 and the reverse in round 2.

| Check | Result |
| --- | --- |
| Online edit, then move: row shows new title/body at once, no conflict text, persists after reload | Pass (both rounds) |
| Offline edit, reconnect, then move: saved after 20 s, no conflict text, persists | Pass (both rounds) |
| Move during autosave (move 0.2 s after typing): typed text persists in the new section | Pass (both rounds) |
| Rapid notebook switching Atlas, Home, Atlas, Home (150 ms): never shows Atlas pages under Home | Pass (both rounds) |
| Alt+↓ twice: focus stays on the moved row, order 1st to 3rd | Pass (both rounds) |
| Typing 200 characters with no delay: body exactly 200 characters after reload | Pass |
| Search, then open the result: editor shows the matching title and body | Pass |
| "Delete section" menu item is red | Pass |

### Conflict recovery

Two tabs: tab 2 offline (per-tab, via CDP) edits a page, tab 1 moves it to another section, tab 2 reconnects. The first save-path round found tab 2's edit lost. The conflict recovery runs found duplicate copies (three identical copies from one click, two from a double-click) and tab 2 staying on the old section. Fixed in b3c23d9..b39d823 and re-verified in round 2 after cleaning up the leftover copies.

| Check | Result |
| --- | --- |
| Banner "Another device saved this page first..." with a "Keep the other version as a copy" button | Pass |
| One click after several retries: one "(conflicting copy)" page directly after the original, in the original's section; original shows the server body; same after reloading both tabs | Pass after fix (initial run: fail) |
| Double-click (20 ms): exactly one copy | Pass after fix (initial run: fail) |
| Editor read-only during recovery (title readOnly, body not editable, keystrokes ignored), editable again afterwards | Pass |
| Tab 2 switches to the original's section after recovery | Pass after fix |

### Open items

- CSP `style-src 'self'` blocks inline styles from the app and BlockNote bundles, producing console errors and a BlockNote placeholder-CSS `insertRule` warning during editing. Not introduced by this branch; whether it predates it was not checked.
- Mobile layout is cramped: sidebar plus tabs take about 500 px and the page list and editor sit in nested scrollers below the fold. Pre-existing and unchanged.

No complete end-to-end product workflow or accessibility audit is claimed.

### Screenshots

| Light | Dark |
| --- | --- |
| ![Desktop light](docs/onenote-nav-light-desktop.png) | ![Desktop dark](docs/onenote-nav-dark-desktop.png) |
| ![Mobile light](docs/onenote-nav-light-mobile.png) | ![Mobile dark](docs/onenote-nav-dark-mobile.png) |
| ![Section menu](docs/onenote-nav-section-menu.png) | ![Conflict banner](docs/onenote-nav-conflict.png) |
| ![Conflict copy](docs/onenote-nav-conflict-copy.png) | |

## Canvas pages (2026-10-07)

Scratch server on copied preview data (never production), Playwright MCP, Chromium, 1280x900 in Busnes Light and Dark unless noted. Fixes landed in 3fc6b41..b43135f and the right-edge box fix in 18690ce.

| Check | Result |
| --- | --- |
| Legacy page opens as one box, no `PUT` on close | Pass. Caveat: copied legacy pages are plain paragraphs, so heading/list formatting is untested |
| Typing, two boxes, same positions after reload; empty box pruned | Pass. One empty box remained and was saved; since the final-review fixes an empty box is saved only by its first edit (not re-run in a browser) |
| Box drag, resize, arrow keys (Shift for larger steps) persist | Pass |
| Ink: colors, sizes, highlighter, undo/redo, eraser, persistence; undo history per page | Pass after fix (3fc6b41..b43135f: invisible toolbar pressed state and swatches, undo keys dead after mouse drawing) |
| Dark theme ink strokes are light | Pass |
| Image drop renders and survives reload | Pass after fix (20a5791: CSP `img-src` allows `blob:`) |
| Work queue lists a checklist item from a second box; only Work queue is selected in the sidebar | Pass (selection fixed in b43135f) |
| Touch 1024x768: Type-mode scroll creates no box, Pen-mode one finger draws | Pass |
| Phone 390x844: boxes stack in reading order, ink tools hidden, ink notice, "Add text" works | Pass |
| Editing a legacy page saves and keeps formatting | Pass (caveat as above) |
| Quick strokes are not truncated (10 back to back) | Pass; two early strokes truncated once, not reproduced |
| Legacy box narrowed to the canvas for display without a `PUT` | Pass |
| New box at the right edge stays inside the canvas | Fixed after verification (18690ce); not re-run in a browser |
| Undo keys ignored inside the step-up `<dialog>` | Fixed after verification (18690ce); not re-run in a browser |
| Ink and click-to-add reach below a long note (surface sized from measured box heights) | Fixed after verification (final-review fixes); not re-run in a browser |
| Editing on a phone keeps desktop box widths | Fixed after verification (final-review fixes); not re-run in a browser |
| Right-edge placement while scrolled horizontally lands at the click | Fixed after verification (final-review fixes, `fitBox` unit-tested); not re-run in a browser |
| Undo keys on non-Latin layouts (`KeyZ`) | Fixed after verification (final-review fixes); not re-run in a browser |
| Page full: body near 9 MiB shows "page is full", no `PUT` | Not run in a browser; `pageFits` is unit-tested |
| Real stylus pressure | Unproven: no pen device |

### Open items

- BlockNote/Mantine inline styles still raise CSP `style-src 'self'` console errors on page load. Not introduced by this branch.
- Already-saved canvas boxes wider than the visible canvas are not narrowed; only legacy boxes are.

### Screenshots

| Light | Dark |
| --- | --- |
| ![Desktop light](docs/canvas-light-desktop.png) | ![Desktop dark](docs/canvas-dark-desktop.png) |
| ![Mobile light](docs/canvas-light-mobile.png) | ![Mobile dark](docs/canvas-dark-mobile.png) |
| ![Pen toolbar light](docs/canvas-pen-toolbar.png) | ![Pen toolbar dark](docs/canvas-pen-toolbar-dark.png) |
