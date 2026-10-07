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

### Open items

- CSP `style-src 'self'` blocks inline styles from the app and BlockNote bundles, producing console errors and a BlockNote placeholder-CSS `insertRule` warning during editing. Not introduced by this branch; whether it predates it was not checked.
- These results predate the page-list reconciliation and notebook-load isolation commits that follow 6f7e6f6; those are covered by `notes.test.ts` and have not been re-run in a browser.
- Mobile layout is cramped: sidebar plus tabs take about 500 px and the page list and editor sit in nested scrollers below the fold. Pre-existing and unchanged.

No complete end-to-end product workflow or accessibility audit is claimed.

### Screenshots

| Light | Dark |
| --- | --- |
| ![Desktop light](docs/onenote-nav-light-desktop.png) | ![Desktop dark](docs/onenote-nav-dark-desktop.png) |
| ![Mobile light](docs/onenote-nav-light-mobile.png) | ![Mobile dark](docs/onenote-nav-dark-mobile.png) |
| ![Section menu](docs/onenote-nav-section-menu.png) | |
