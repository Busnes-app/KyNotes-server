# KyNotes Web UI — Stage 04 Council Review (`argon-round3`, Gemini 4 Argon)

## Executive Verdict

- **Reviewer**: `argon` (Gemini 4 Argon, Round 3 independent audit + three-reviewer council reconciliation)
- **Target**: `8.0/10` visual quality across KyNotes web (`desktop 1280×900` and `mobile 390×844`, Busnes Light and Busnes Dark)
- **Notes cohort (`n = 8` unique captures)**: **8.1 / 10** (range `8.0–8.2`, unweighted mean `8.05`, zero views below `8.0`; `ky_fit` mean **8.5 / 10**)
- **Settings cohort (`n = 4` unique captures)**: **8.4 / 10** (range `8.3–8.5`, unweighted mean `8.40`, zero views below `8.0`; `ky_fit` mean **8.8 / 10**)
- **All unique Stage-04 captures (`n = 12`)**: **8.2 / 10** (unweighted mean `8.17`; `ky_fit` mean **8.6 / 10**)
- **Progression gate**: **`satisfied: true`** for the `8/10` target (`accept_9: false`). All six Round 2 blockers/regressions were verified resolved in the Stage-04 captures and live DOM (`http://127.0.0.1:18101`), and all three council reviewers (`argon-round3` `8.1`, `opus-round3` `8.1`, `sol-round3` `8.2` Notes; `8.4` Settings across all three) independently clear the `8.0` bar.

---

## 1. Inventory & Deduplication Gate (`inventory-v3.json`)

All 64 PNGs in `docs/ui-notes-eight/screenshots/` were inventoried in `inventory-v3.json`:

- **48 prior-stage captures** (`kynotes-02-before-*`, `kynotes-02-after-*`, `kynotes-03-after-*`): listed in `unscored` as prior-stage baseline/comparison artifacts (`not CURRENT input`).
- **16 current Stage-04 captures** (`kynotes-04-after-*`):
  - **12 unique scored views**:
    - `notes` cohort (`n = 8`): `editor-desktop-light`, `editor-desktop-dark`, `editor-mobile-light`, `editor-mobile-dark`, `pages-mobile-light`, `pages-mobile-dark`, `navigation-mobile-light`, `navigation-mobile-dark`
    - `settings` cohort (`n = 4`): `appearance-desktop-light`, `appearance-desktop-dark`, `appearance-mobile-light`, `appearance-mobile-dark`
  - **4 near-duplicates excluded from cohort counts and means** (`ui-council.e2e.ts` captures `workspace-*` immediately after `editor-*` on the same open page without state changes; only sub-pixel AA differs by `12–15` pixels, `pixel_fraction <= 0.000046`, `max_channel_delta = 4`):
    - `kynotes-04-after-workspace-desktop-light.png` → near-duplicate of `kynotes-04-after-editor-desktop-light.png` (`12` px)
    - `kynotes-04-after-workspace-desktop-dark.png` → near-duplicate of `kynotes-04-after-editor-desktop-dark.png` (`15` px)
    - `kynotes-04-after-workspace-mobile-light.png` → near-duplicate of `kynotes-04-after-editor-mobile-light.png` (`12` px)
    - `kynotes-04-after-workspace-mobile-dark.png` → near-duplicate of `kynotes-04-after-editor-mobile-dark.png` (`15` px)

---

## 2. Blind Per-Image Scores (`argon-round3`)

All 12 unique Stage-04 captures were scored blind before reading `opus-round2`, `sol-round2`, `opus-round3`, or `sol-round3`.

| File (`screenshots/kynotes-04-after-...`) | Cohort | Theme | Viewport | H (0.25) | T (0.15) | D (0.20) | C (0.15) | A (0.15) | Co (0.10) | Weighted | **Total** | **Ky Fit** |
| :--- | :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `editor-desktop-light.png` | `notes` | light | `1280×900` | 8 | 8 | 8 | 9 | 8 | 7 | `8.05` | **8.0** | **8.5** |
| `editor-desktop-dark.png` | `notes` | dark | `1280×900` | 8 | 8 | 8 | 9 | 8 | 7 | `8.05` | **8.0** | **8.5** |
| `editor-mobile-light.png` | `notes` | light | `390×844` | 8 | 8 | 7 | 9 | 8 | 8 | `7.95` | **8.0** | **8.5** |
| `editor-mobile-dark.png` | `notes` | dark | `390×844` | 8 | 8 | 7 | 9 | 8 | 8 | `7.95` | **8.0** | **8.5** |
| `pages-mobile-light.png` | `notes` | light | `390×844` | 8 | 8 | 8 | 9 | 8 | 8 | `8.15` | **8.2** | **8.5** |
| `pages-mobile-dark.png` | `notes` | dark | `390×844` | 8 | 8 | 8 | 9 | 8 | 8 | `8.15` | **8.2** | **8.5** |
| `navigation-mobile-light.png` | `notes` | light | `390×844` | 8 | 8 | 7 | 9 | 8 | 8 | `7.95` | **8.0** | **8.3** |
| `navigation-mobile-dark.png` | `notes` | dark | `390×844` | 8 | 8 | 7 | 9 | 8 | 8 | `7.95` | **8.0** | **8.3** |
| `appearance-desktop-light.png` | `settings` | light | `1280×900` | 8 | 9 | 8 | 9 | 9 | 9 | `8.55` | **8.5** | **8.8** |
| `appearance-desktop-dark.png` | `settings` | dark | `1280×900` | 8 | 9 | 8 | 9 | 9 | 9 | `8.55` | **8.5** | **8.8** |
| `appearance-mobile-light.png` | `settings` | light | `390×844` | 8 | 9 | 8 | 9 | 8 | 8 | `8.30` | **8.3** | **8.8** |
| `appearance-mobile-dark.png` | `settings` | dark | `390×844` | 8 | 9 | 8 | 9 | 8 | 8 | `8.30` | **8.3** | **8.8** |

### Per-Surface Observations

1. **Desktop Editor (`editor-desktop-light.png` `8.0`, `editor-desktop-dark.png` `8.0`)**:
   - **What Stage 04 fixed**:
     - Recovery key warning collapsed into `<details class="recovery-notice">` (`37px` single-line summary bar vs `110px` 3-part card in Stage 03), moving the first page row (`Project Atlas overview`) up by `73px` (`y=273` vs `y=346`).
     - Duplicate green status eliminated: `.editor-meta` (`Version 2 · Saved 6:51:04 PM`) now uses `color: var(--muted)` (`#566366` / `#b0bbb9`), leaving `.status-banner` (`Saved Launch checklist.`) as the single semantic green confirmation (`#2b6e44` / `#5bc985`).
     - Selected section tab (`Quick Notes`) no longer draws a `1px` box outline around its `2px` bottom indicator (`border: 0; border-bottom: 2px solid var(--accent)`).
     - Footer section `<select>` (`Quick Notes`) now inherits `var(--ky-font-sans)` (`Space`) and uses `1px solid var(--ky-field-border)`.
     - Sidebar account badge uses username initial `O` (`owner`) instead of the random UUID tail (`9C` / `28`).
   - **What holds Desktop Editor at `8.0` (not `9.0`)**:
     - **Missing `3px` orange left rail on desktop `.sidebar .nav-item.selected`**: `styles.css:497` placed `.workspace > .sidebar .nav-item[aria-current="page"] { box-shadow: inset 3px 0 0 var(--accent); }` inside `@media (max-width: 800px)`. On desktop (`1280×900`), `Project Atlas` in the left rail only receives `--accent-soft` fill (`#fbf0ec` / `#2b2622`) without the `3px` orange left rail that `.note-item.selected` (`Launch checklist`) and mobile `.nav-item[aria-current="page"]` display.
     - **Invisible `.avatar` chip in Busnes Light**: `.avatar` (`styles.css:474`) sets `background: var(--panel-hover)` (`#f2efe7`, `rgb(242,239,231)`), which is identical to the light sidebar background (`--sidebar-start: #f2efe7`). In light mode, `O` floats with zero chip boundary; in dark mode (`#2b383a` on `#1f2b2e`), the `25×25` rounded chip is visible.
     - **Competing `24px` titles**: `h2.workspace-title` (`Project Atlas` in the `252px` list column) renders at `500 24px/28.8px Space`, competing with the active page title `.title-input` (`Launch checklist`, `600 24px Space`).
     - **Fixed `150px` search input on desktop**: `.note-search` (`styles.css:189`) is fixed at `width: 150px` inside the `219px` `.list-actions` row (`150 + 8 + 40 = 198px`), leaving `21px` of dead space on the right instead of `flex: 1`.
     - **Secondary button border contrast**: While `input, select, textarea` now use `--ky-field-border` (`#72797a`, `4.54:1` light / `#879191`, `5.32:1` dark), `.secondary` buttons (`Save` in topbar, `+` New page button) still use `var(--line-strong)` (`rgba(24,35,38,0.38)` = `2.30:1` light; `rgba(242,239,232,0.38)` = `2.32:1` dark).

2. **Mobile Editor (`editor-mobile-light.png` `8.0`, `editor-mobile-dark.png` `8.0`)**:
   - **What Stage 04 fixed**:
     - `.notebook-navigation-toggle` and `.page-navigation-toggle` now render custom `16×16` stroke `ChevronIcon` disclosures (`strokeWidth="1.75"`, rotating `180deg` when open) instead of literal `+` / `−` characters that collided with creation actions (`+ New notebook`, `+` New page).
     - Mobile `.editor` padding tightened from `24px` to `16px` (`styles.css:458`), aligning the note canvas (`x=16..374`, `358px` wide) with the `16px` outer shell margin and giving `Launch checklist` a `326px` prose measure (`y=316..754`).
     - Footer section `<select>` renders in `Space` with `--ky-field-border`.
   - **What holds Mobile Editor at `8.0`**:
     - At `390×844`, `.editor-actions` (`y=766..887`) wraps its four controls (`Quick Notes` select `135×40`, `Indent page` `106×40`, `Outdent page` `118×40`, `Delete` `71×40`) into two rows, and the second row (`y=831..871`) is clipped horizontally by the bottom edge of the `844px` viewport.

3. **Mobile Pages Chooser (`pages-mobile-light.png` `8.2`, `pages-mobile-dark.png` `8.2`)**:
   - **What Stage 04 fixed**:
     - Largest single-surface jump (`+1.4` vs Opus Round 2 `6.8`, `+0.4` vs Sol Round 2 `7.8`): when `.workspace.show-page-navigation` is active on mobile, `styles.css:435-445` hides the redundant `.workspace-title`, `.notebook-kind`, and `.notes-heading`, collapses the outer `.note-list` box border/padding, stretches `.note-search` to `flex: 1`, and hides `.editor` below the open chooser.
     - First page row (`Project Atlas overview`) moves from `y≈590` in Stage 03 up to `y=354`, so all four page rows (`Project Atlas overview`, `Launch checklist`, `Weekly review`, `Research notes`) fit cleanly above the fold (`y=354..660`) with `166px` of breathing room below.
   - **What holds Mobile Pages Chooser at `8.2`**:
     - `<details class="recovery-notice">` (`y=194..232`) uses the browser's default `display: list-item` filled triangle marker (`▸`) directly below two custom stroke `ChevronIcon` disclosure buttons (`y=82..170`).

4. **Mobile Navigation (`navigation-mobile-light.png` `8.0`, `navigation-mobile-dark.png` `8.0`)**:
   - **What Stage 04 fixed**:
     - `.avatar` displays username initial `O` (`owner`) instead of the random user-ID suffix (`9C` / `28`).
     - Both disclosure bars use stroke `ChevronIcon`s (up-chevron on the expanded `Notebooks and account` bar, down-chevron on `Pages in Project Atlas · Research notes`).
     - Selected `Project Atlas` row has both `--accent-soft` fill and the `3px` inset orange rail (`box-shadow: inset 3px 0 0 var(--accent)`).
   - **What holds Mobile Navigation at `8.0`**:
     - In light mode (`navigation-mobile-light.png`), `.avatar` background (`var(--panel-hover)`) matches the sidebar background (`#f2efe7`), making the `25×25` avatar badge invisible.
     - Expanding `.sidebar` (`y=138..561`) pushes `.editor` (`Research notes`) down to `y=637..844` instead of hiding `.editor` like `.show-page-navigation` does.

5. **Settings > Appearance (`appearance-desktop-light/dark.png` `8.5`, `appearance-mobile-light/dark.png` `8.3`)**:
   - **What Stage 04 fixed**:
     - Mobile `.preferences-layout` (`styles.css:416-428`) now uses CSS Grid (`grid-template-areas: "heading" "nav" "content"`) with `display: contents` on `.settings-sidebar` and `.settings-main`, placing `h1` `Settings` (`y=84..113`) and its subtitle (`y=121..166`) *above* `.settings-nav` (`y=182..388`) instead of burying the page title at `y≈316` below six navigation links.
     - Shared `<ky-appearance>` shadow DOM renders a crisp 5-column desktop grid (`171×116` cards) and 2-column mobile grid (`173×116` cards) with contract-exact typography (`24px` title, `17px` section, `15px` body, `13px` labels) and strict orange accent discipline on `Appearance` nav and `Match system`.
   - **What holds Settings below `9.0`**:
     - On mobile (`appearance-mobile-light/dark.png`), the 3-row wrapped `.settings-nav` block (`y=182..388`, `206px` tall) plus section prose still pushes the first theme card row to `y=566`, and `h1` (`x=16`), `← Workspace` text (`x=26`), and `.settings-nav a` text (`x=30`) create three slightly different left text edges.
     - Unselected radio dots inside `<ky-appearance>` dark mode use a filled dark-gray circle rather than a hollow ring matching the border contrast of light mode.

---

## 3. Council Reconciliation (`argon-round3` vs `opus-round3` vs `sol-round3`)

After locking our blind scores above, we inspected `opus-round2.json`, `sol-round2.json`, `opus-round3.json`, and `sol-round3.json` to audit every score delta and every inter-reviewer disagreement.

### 3.1 Score Comparison Across All Three Reviewers

| Capture (`kynotes-04-after-...`) | `argon-round3` | `opus-round3` | `sol-round3` | Spread | Council Consensus / Audit |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `editor-desktop-light` | **8.0** | **8.0** | **8.3** | `0.3` | All `>= 8.0`. Opus & Argon `Co=7` (invisible light `.avatar` chip + missing desktop `3px` notebook rail); Sol `T=9, Co=8`. |
| `editor-desktop-dark` | **8.0** | **8.2** | **8.3** | `0.3` | All `>= 8.0`. Dark `.avatar` chip is visible (`#2b383a` on `#1f2b2e`); Argon keeps `Co=7` because desktop `.nav-item.selected` still lacks the `3px` orange rail. |
| `editor-mobile-light` | **8.0** | **8.2** | **8.2** | `0.2` | All `>= 8.0`. Argon `D=7` because 2-row `.editor-actions` (`y=766..887`) clips row 2 at `y=844`; Opus & Sol `D=8`. |
| `editor-mobile-dark` | **8.0** | **8.2** | **8.2** | `0.2` | All `>= 8.0`. Same mobile footer wrap geometry as light. |
| `pages-mobile-light` | **8.2** | **8.0** | **8.2** | `0.2` | All `>= 8.0`. Argon & Sol `8.2` (`Co=8`); Opus `8.0` (`Co=7` due to UA `<details>` triangle vs stroked `ChevronIcon`). |
| `pages-mobile-dark` | **8.2** | **8.0** | **8.2** | `0.2` | All `>= 8.0`. Same as light. |
| `navigation-mobile-light` | **8.0** | **8.0** | **8.2** | `0.2` | All `>= 8.0`. Opus `Co=7` (invisible light `.avatar` chip); Argon `D=7` (editor pushed to `y=637`). |
| `navigation-mobile-dark` | **8.0** | **8.2** | **8.2** | `0.2` | All `>= 8.0`. Dark `.avatar` chip visible (`#2b383a` on `#1f2b2e`). |
| **Notes Cohort Mean (`n = 8`)** | **8.1** (`8.05`) | **8.1** (`8.10`) | **8.2** (`8.23`) | **`0.1`** | **Unanimous `>= 8.0` pass (`8.1–8.2`)** |
| `appearance-desktop-light` | **8.5** | **8.8** | **8.7** | `0.3` | All three score `D=8, C=9, A=9, Co=9`; differ only by `1` pt on `H` (`8` vs `9`) or `T` (`8` vs `9`). |
| `appearance-desktop-dark` | **8.5** | **8.7** | **8.7** | `0.2` | All `8.5–8.7`. Opus `A=8` for dark unselected radio disc fill. |
| `appearance-mobile-light` | **8.3** | **8.0** | **8.1** | `0.3` | All `8.0–8.3`. Opus & Sol `D=7` (`y=566` first card row + `x=16/26/30` left edges). |
| `appearance-mobile-dark` | **8.3** | **8.0** | **8.1** | `0.3` | All `8.0–8.3`. Same as light. |
| **Settings Cohort Mean (`n = 4`)** | **8.4** (`8.40`) | **8.4** (`8.38`) | **8.4** (`8.40`) | **`0.0`** | **Exact 3-way tie at `8.4 / 10`** |

### 3.2 Audit of Reviewer Disagreements & Evidence Verification

1. **Light `.avatar` chip invisibility (`opus-round3` `Co=7` on light vs `8` on dark; `sol-round3` `Co=8` on both)**:
   - **Verdict**: **Opus is right on the pixel & CSS evidence.** Live DOM inspection (`getComputedStyle`) and pixel sampling confirm that in Busnes Light, `.sidebar` has `background: rgb(242, 239, 231)` (`--sidebar-start: #f2efe7`) and `.avatar` (`styles.css:474`) has `background: var(--panel-hover)` (`#f2efe7`, `rgb(242, 239, 231)`) with `border: 0`. The `25×25` `.avatar` chip has `0` contrast against the sidebar in light mode, making `O` look like an uncontained character, whereas in dark mode (`#2b383a` on `#1f2b2e`) the chip is clearly visible.
2. **Desktop `.sidebar .nav-item.selected` missing `3px` orange left rail (`argon-round3` finding; missed by `opus-round3` and `sol-round3`)**:
   - **Verdict**: **Verified in live DOM and `styles.css:497`.** `opus-round3` assumed desktop `Project Atlas` had a "notebook rail", but `styles.css:497` scoped `.workspace > .sidebar .nav-item[aria-current="page"] { box-shadow: inset 3px 0 0 var(--accent); }` inside `@media (max-width: 800px)`. On desktop (`1280×900`), `Project Atlas` has `boxShadow: "none"` (only `--accent-soft` fill), whereas `.note-item.selected` (`Launch checklist`) and mobile `.nav-item[aria-current="page"]` have the `3px` inset orange rail. Lifting that rule outside the mobile media query fixes desktop/mobile and sidebar/page-list parity in one line.
3. **Recovery `<details>` disclosure marker on `pages-mobile` (`opus-round3` `Co=7` vs `sol-round3` & `argon-round3` `Co=8`)**:
   - **Verdict**: **Non-blocking P3 polish (`Co=8` stands on `pages-mobile`, `8.0–8.2` across reviewers).** Both observations are factually true: collapsing the recovery notice into `<details>` solved the P1 mobile page-list displacement (`y≈590` → `y=354`) and preserved native keyboard expand/collapse (`ui-council.e2e.ts`), while its default `list-item` filled triangle (`▸`) sits alongside stroked `ChevronIcon`s. Hiding `summary::-webkit-details-marker` / `list-style: none` and rendering the shared `ChevronIcon` resolves the glyph mismatch cleanly.
4. **Desktop Settings `appearance-desktop` score shift (`opus-round2` `7.8` → `opus-round3` `8.8/8.7`; `sol-round2` `8.7` → `sol-round3` `8.7`; `argon-round3` `8.5`)**:
   - **Verdict**: **Converged (`8.5–8.8`, `D=8` unanimous).** Between Stage 03 and Stage 04, `appearance-desktop-light/dark.png` shifted vertically by ~6px (`13.8%` pixels changed) with no layout change. In Round 2, Opus penalized `appearance-desktop` (`D=7`, total `7.8`) for cross-screen shell differences and input border contrast on other screens; in Round 3, Opus self-corrected to `8.8/8.7` (`D=8`) and Sol revised `D` from `9` to `8` (`8.7`), aligning with Argon's `8.5` (`D=8`).

---

## 4. Prioritized Remaining Polish (Path from `8.1` toward `9.0`, Non-Blocking for Stage 04)

1. **[P2 · Theme Token / Coherence] Give `.avatar` a visible surface or border in Busnes Light (`web/src/styles.css:474`)**
   - **Evidence**: `.avatar` uses `background: var(--panel-hover)` (`#f2efe7`), which equals `--sidebar-start` (`#f2efe7`) in light mode (`0:1` contrast).
   - **Fix**: Set `.avatar { background: var(--panel); border: 1px solid var(--line-strong); }` (or `box-shadow: inset 0 0 0 1px var(--ky-field-border)`) so the `25×25` `O` badge is legible in both themes.
2. **[P2 · Shell Coherence] Apply the `3px` orange left selection rail to desktop `.sidebar .nav-item[aria-current="page"]` (`web/src/styles.css:497`)**
   - **Evidence**: `.workspace > .sidebar .nav-item[aria-current="page"] { box-shadow: inset 3px 0 0 var(--accent); }` is currently inside `@media (max-width: 800px)`, leaving desktop `Project Atlas` without its left accent rail (`boxShadow: "none"`).
   - **Fix**: Move that rule to the base `.nav-item.selected, .nav-item[aria-current="page"]` selector (`styles.css:120`).
3. **[P2 · Contrast / Affordances] Route `.secondary` button borders to `var(--ky-field-border)` (`web/src/styles.css:464`)**
   - **Evidence**: `input, select, textarea` use `--ky-field-border` (`4.54:1` light / `5.32:1` dark), but `.secondary` buttons (`Save`, `+` New page) use `var(--line-strong)` (`2.30:1` light / `2.32:1` dark).
   - **Fix**: Change `.secondary` (`styles.css:464`) from `border: 1px solid var(--line-strong)` to `border: 1px solid var(--ky-field-border)`.
4. **[P3 · Desktop List Column Hierarchy & Geometry] Step down `h2.workspace-title` and flex `.note-search` (`web/src/styles.css:93, 189`)**
   - **Evidence**: `h2.workspace-title` (`Project Atlas`, `24px`) competes with `.title-input` (`Launch checklist`, `24px`), and `.note-search` (`width: 150px`) leaves `21px` of dead space in `.list-actions` on desktop.
   - **Fix**: Set `.workspace-title { font-size: var(--ky-text-section); }` (`17px`) and `.list-actions .note-search { flex: 1; min-width: 0; width: auto; }` on all viewports.
5. **[P3 · Mobile Editor & Settings Density] Compact `.editor-actions` on mobile and align `.settings-nav` left edge (`web/src/styles.css:256, 326, 416`)**
   - **Evidence**: Mobile `.editor-actions` wraps to two rows (`y=766..887`), clipping row 2 at `y=844`; mobile Settings has three left text edges (`x=16`, `x=26`, `x=30`) and `206px` of vertical nav links before content.
   - **Fix**: Tighten mobile `.editor-actions` button padding/labels so actions fit a single row or compact 2×2 grid above the fold, and remove left padding offset on mobile `.settings-sidebar .back-link` / `.settings-nav a` so they share the `16px` left edge.
