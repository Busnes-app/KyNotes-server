# KyNotes Round 10 (`13-after`) — Gemini 4 Argon Advisory Review

- **Reviewer**: Gemini 4 Argon (`gemini-4-argon-high`, advisory role; non-veto concurrence after both primary reviewers satisfied both covered visual cohorts)
- **Reviewed at (UTC)**: `2026-10-27T03:28:00Z`
- **Worktree / Branch / HEAD**: `/home/yoshi/git/busnes.app/kynotes-server/.claude/worktrees/ui-notes-eight` · `ui/notes-eight` · `1ab04e64de747f409d88b98f02682e85862defe1`
- **Manifest**: `docs/ui-notes-eight/screenshots/13-after-manifest.json` (`sha256: 8438859170ff9907d7dd91ef0fa409740de25e5f6165e1a052599581a02c5044`, `stage: 13-after`, `councilRound: 10`, `gitHead: ad52fda1ad5f06c0b4f71ef55deb50cfad9b5b10`)
- **Inventory**: `docs/ui-notes-eight/screenshots/inventory-v13.json` (`sha256: 0066dbe759e3cc0090994f71d24e2c125a3aa32deafb68dedc1de8bd5da0c2aa`, 262 historical PNGs, 198 exact SHA-256 groups, 148 normalized representatives, 114 direct `duplicate_of` links)
- **Rubric**: `/home/yoshi/.codex-cpa/skills/ky-suite-ui/references/rubric.md` (`sha256: eb4ba8da8ed53c07c92a46dc0ab8c237897b3290e53512b5134e4430037277c3`)
- **Weights (`ky-suite-v2`)**: `hierarchy: 0.20`, `typography: 0.15`, `density_layout: 0.20`, `color: 0.15`, `visible_affordances: 0.15`, `coherence: 0.15` (sum `1.00`, integer `0–10` dimensions, `Decimal` `ROUND_HALF_UP` to `0.1`)

---

## 1. Executive Verdict & Separate Cohort Means

| Visual Cohort | Unique Scored Captures | Excluded Aliases | Exact Sum | Unrounded Mean | Reported Mean (`ROUND_HALF_UP`) | Min / Max File Score | Satisfied (`>= 8.0`) | Separate Ky Fit Mean |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Notes** (4 empty, 4 editor, 4 management, 2 phone page chooser) | 14 | 4 (`workspace-*`) | `112.4` | `8.0285714...` | **`8.0`** | `8.0` / `8.2` | **Yes (`true`)** | `8.0` (`suite_cohesion`: N/A) |
| **Settings / Appearance** (2 desktop, 2 mobile) | 4 | 0 | `32.4` | `8.1000000` | **`8.1`** | `8.0` / `8.2` | **Yes (`true`)** | `8.0` (`suite_cohesion`: N/A) |

- **Advisory Verdict**: **Satisfied (`true`)** for both the **Notes** (`8.0 / 10`) and **Settings / Appearance** (`8.1 / 10`) cohorts, with every unique stage-13 capture scoring `>= 8.0`.
- **Scope**: Scoped visual progression review of the 18 unique stage-13 captures only. Cohort means are kept strictly separate (no cross-cohort pooling). This advisory concurrence does not certify full behavior, keyboard/focus acceptance, WCAG contrast-matrix completion, or 9/10 suite acceptance.

---

## 2. Provenance, Harness Disclosure & Audit Corrections

1. **Source & Bundle Pinning**:
   - `git diff ad52fda1ad5f06c0b4f71ef55deb50cfad9b5b10 -- web/src` is exactly `971` bytes (`sha256: d436a73301bf2782306535bd0404180b043caabdaf40c49fe61d9f341608b583`), adding three responsive CSS rules under `@media (max-width: 800px)` in `web/src/styles.css` for `.settings-header p`, `.preferences-layout .settings-nav`, and `.preferences-layout .settings-nav a`.
   - All 9 `sourceFiles` in `13-after-manifest.json` match `web/` on disk byte-for-byte.
   - `web/dist/index.html` and `internal/web/dist/index.html` match `servedIndexSha256` (`764681485d4035a7b5b95e6253a418dcab1ff0315676588d8349fe0b166e4810`).
2. **Stage-12 to Stage-13 Pixel Delta**:
   - **8 byte-identical captures** vs. stage 12 (`empty` x4, `appearance-desktop` x2, `pages-mobile` x2): retained in current cohort coverage with zero product-improvement credit.
   - **8 timestamp-only captures** vs. stage 12 (`editor` x4, `navigation` x4, plus their 4 `workspace` aliases): only the save-timestamp pill pixels changed.
   - **2 substantively changed captures** vs. stage 12 (`kynotes-13-after-appearance-mobile-light.png` and `kynotes-13-after-appearance-mobile-dark.png`): `114,724` px (light) and `114,685` px (dark) changed from `y=130` downward as the subtitle balanced onto two lines, the 6 Settings section links snapped into a 3x2 grid, and the Appearance card shifted up by `44px` (`y=527` vs. `y=571`).
3. **Harness Disclosure**:
   - In this Antigravity ACP harness, `view_file` / `client_view_file` return raw binary PNG bytes as text replacement characters rather than a multimodal image attachment. All 22 stage-13 PNGs were verified on disk by SHA-256, byte size, and PNG `IHDR` dimensions (`1280x900` desktop, `390x844` mobile), while visual rendering and DOM/CSS geometry were inspected directly via T3 Computer Use (`preview_open`, `preview_snapshot`, `preview_evaluate`) on the live fixture `http://127.0.0.1:18114`.
4. **Corrections of Prior Gemini Round 3 Audit Findings (`G1–G10`)**:
   - Uses exact `ky-suite-v2` weights (`0.20 / 0.15 / 0.20 / 0.15 / 0.15 / 0.15`) and identical `Decimal` `ROUND_HALF_UP` arithmetic in both JSON and Markdown.
   - Confirms the desktop selected row rail exists (`box-shadow: rgb(191, 63, 24) 3px 0px 0px 0px inset` on `.ky-nav-item[aria-current="page"]`).
   - Confirms mobile editor footer controls are not clipped (scrollable within `scrollHeight = 1130`).
   - Confirms native DOM elements (`23` native `<input type="radio">` inside `fieldset.ky-appearance` and `.sync-dot.sync-saved` status indicator; no invented custom elements or Shadow DOM).

---

## 3. Live Computer Use Verification (`http://127.0.0.1:18114`)

- **Session Discipline**: Checked `preview_status`, opened our own dedicated incognito tab (`tab_1p_2e419d46-7b07-427f-bf30-1831131b4cba`) via `preview_open(reuseExistingTab: false, profileId: "incognito")`, passed `tabId` on every tool call, signed in as synthetic `owner`, mutated zero content/theme state (`checkedRadio: "system"`), and closed our tab via `t3_preview_close` when finished.
- **Environment Distinction**: Live T3 browser runs Chromium `154.0.0.0` at `devicePixelRatio: 2`; used strictly to supplement (never replace) the Chromium `156.0.8078.4` scale-1 scored captures.
- **Measured Live Geometry**:
  - **Desktop (`1280x900`, light & dark)**: `scrollWidth == clientWidth == 1280` (`0px` horizontal overflow). Single `240px` left navigation region (`button.notebook-navigation-toggle` `240x48` at `x=0, y=72` over `section.note-list` `240x780` at `x=0, y=120`) beside `section.editor` (`1040x828` at `x=240, y=72`). Active item carries `box-shadow: rgb(191, 63, 24) 3px 0px 0px 0px inset`. Desktop Settings nav renders 6 vertical links (`203x40` at `x=18, y=160..380`, step `44px`) with hrefs `#appearance`, `#reminders`, `#password`, `#device`, `#link-devices`, `#colleague-keys`, and `23` native radio inputs (`1` follow-OS + `22` palettes).
  - **Tablet Breakpoint (`800x900`)**: `scrollWidth == clientWidth == 800` (`0px` horizontal overflow). `.preferences-layout .settings-nav` renders all 6 links in a single horizontal row (`y=223.1, h=40`, six `124px` tracks across `764px`).
  - **Phone (`390x844`, light & dark)**: `scrollWidth == clientWidth == 390` (`0px` horizontal overflow). `.settings-header p` (`358x40` at `x=16, y=126.1`) computes `text-wrap: balance` and `max-width: none`. `.preferences-layout .settings-nav` (`354x84` at `x=18, y=243.1`) computes `grid-template-columns: 115.328px 115.336px 115.336px`, placing `Appearance`, `Reminders`, `Password` on row 1 (`y=243.1, h=40`) and `Trusted Device`, `Link a browser`, `Colleague keys` on row 2 (`y=287.1, h=40`). `#appearance` card top sits at `y=368.1` (`44px` higher than stage 12).

---

## 4. Per-Image Score Table (All 22 Stage-13 Files; 18 Unique Scored)

| File (`screenshots/...`) | SHA-256 Prefix | Cohort | Included in Mean | H (`.20`) | T (`.15`) | D (`.20`) | C (`.15`) | A (`.15`) | Co (`.15`) | Weighted Total | Ky Fit (4-dim mean) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `kynotes-13-after-empty-desktop-light.png` | `70340422c86d` | `notes` | Yes | 8 | 8 | 8 | 8 | 8 | 8 | **`8.0`** | `8.0` |
| `kynotes-13-after-empty-mobile-light.png` | `5dc4060a4fbf` | `notes` | Yes | 8 | 8 | 8 | 8 | 8 | 8 | **`8.0`** | `8.0` |
| `kynotes-13-after-empty-desktop-dark.png` | `6bb7c1e9f1bb` | `notes` | Yes | 8 | 8 | 8 | 8 | 8 | 8 | **`8.0`** | `8.0` |
| `kynotes-13-after-empty-mobile-dark.png` | `438ee621fc82` | `notes` | Yes | 8 | 8 | 8 | 8 | 8 | 8 | **`8.0`** | `8.0` |
| `kynotes-13-after-workspace-desktop-light.png` | `092436455f30` | `notes` | No (`duplicate_of` editor-desktop-light) | 8 | 8 | 8 | 8 | 9 | 8 | `8.2` | `8.0` |
| `kynotes-13-after-editor-desktop-light.png` | `ff94b5e57447` | `notes` | Yes | 8 | 8 | 8 | 8 | 9 | 8 | **`8.2`** | `8.0` |
| `kynotes-13-after-navigation-desktop-light.png` | `0d7bd1d24016` | `notes` | Yes | 8 | 8 | 8 | 8 | 8 | 8 | **`8.0`** | `8.0` |
| `kynotes-13-after-appearance-desktop-light.png` | `1e65157f29c0` | `settings` | Yes | 8 | 8 | 8 | 8 | 9 | 8 | **`8.2`** | `8.0` |
| `kynotes-13-after-workspace-mobile-light.png` | `fac0ca1bed8a` | `notes` | No (`duplicate_of` editor-mobile-light) | 8 | 8 | 8 | 8 | 8 | 8 | `8.0` | `8.0` |
| `kynotes-13-after-editor-mobile-light.png` | `992939e77969` | `notes` | Yes | 8 | 8 | 8 | 8 | 8 | 8 | **`8.0`** | `8.0` |
| `kynotes-13-after-pages-mobile-light.png` | `0afe486402d1` | `notes` | Yes | 8 | 8 | 8 | 8 | 8 | 8 | **`8.0`** | `8.0` |
| `kynotes-13-after-navigation-mobile-light.png` | `134934efa19f` | `notes` | Yes | 8 | 8 | 8 | 8 | 8 | 8 | **`8.0`** | `8.0` |
| `kynotes-13-after-appearance-mobile-light.png` | `43accf28ed40` | `settings` | Yes | 8 | 8 | 8 | 8 | 8 | 8 | **`8.0`** | `8.0` |
| `kynotes-13-after-workspace-desktop-dark.png` | `aa2d4ff1bf00` | `notes` | No (`duplicate_of` editor-desktop-dark) | 8 | 8 | 8 | 8 | 9 | 8 | `8.2` | `8.0` |
| `kynotes-13-after-editor-desktop-dark.png` | `e1585cc65bdb` | `notes` | Yes | 8 | 8 | 8 | 8 | 9 | 8 | **`8.2`** | `8.0` |
| `kynotes-13-after-navigation-desktop-dark.png` | `a75b5d14d72c` | `notes` | Yes | 8 | 8 | 8 | 8 | 8 | 8 | **`8.0`** | `8.0` |
| `kynotes-13-after-appearance-desktop-dark.png` | `c75e0f370c7b` | `settings` | Yes | 8 | 8 | 8 | 8 | 9 | 8 | **`8.2`** | `8.0` |
| `kynotes-13-after-workspace-mobile-dark.png` | `3d0e83693140` | `notes` | No (`duplicate_of` editor-mobile-dark) | 8 | 8 | 8 | 8 | 8 | 8 | `8.0` | `8.0` |
| `kynotes-13-after-editor-mobile-dark.png` | `2fb0e5a699ff` | `notes` | Yes | 8 | 8 | 8 | 8 | 8 | 8 | **`8.0`** | `8.0` |
| `kynotes-13-after-pages-mobile-dark.png` | `c8e90f157707` | `notes` | Yes | 8 | 8 | 8 | 8 | 8 | 8 | **`8.0`** | `8.0` |
| `kynotes-13-after-navigation-mobile-dark.png` | `330ad34a5ab0` | `notes` | Yes | 8 | 8 | 8 | 8 | 8 | 8 | **`8.0`** | `8.0` |
| `kynotes-13-after-appearance-mobile-dark.png` | `f77379a3fcef` | `settings` | Yes | 8 | 8 | 8 | 8 | 8 | 8 | **`8.0`** | `8.0` |

---

## 5. Audited Findings & Residual Polish

1. **`A10-1` (Resolved Blocker — Settings Mobile Layout)**:
   - **Evidence**: `kynotes-13-after-appearance-mobile-light.png` (`43accf28...`), `kynotes-13-after-appearance-mobile-dark.png` (`f77379a3...`), and live `390x844` inspection.
   - **Effect**: The 3 CSS rules under `@media (max-width: 800px)` in `web/src/styles.css` replace stage 12's uneven `3 + 2 + 1` flex wrap and single-word subtitle orphan (`"security."`) with a balanced two-line subtitle (`"Your browser preferences / and account security."`) and an even `3x2` CSS grid (`115.3x40px` cells), shifting the Appearance card up by `44px` (`y=527` vs. `y=571`).
2. **`A10-2` (Non-Blocking Polish — Settings Mobile Alignment & Casing)**:
   - **Evidence**: `kynotes-13-after-appearance-mobile-light/dark.png` and desktop Settings nav.
   - **Effect**: On phone (`390x844`), the `<- Workspace` back link remains left-aligned above the centered `3x2` section-link grid, and `Trusted Device` uses Title Case alongside sentence-case siblings (`Link a browser`, `Colleague keys`). Neither affects scannability or `40px` touch target sizing.
3. **`A10-3` (Non-Blocking Carried Observations — Unchanged Notes Pixels)**:
   - **Evidence**: Stage-13 Notes captures (unchanged from stage 12 apart from save-timestamp text).
   - **Effect**: (a) Empty state topbar shows green `Saved to server` before any notebook exists; (b) desktop BlockNote body text starts at `x=303` vs. note title at `x=278` (`25px` internal gutter); (c) phone page chooser recovery disclosure sits `44px` below the top bar; (d) notebook management commands share `.ky-nav-item` row styling with notebook destinations. All are non-blocking at the `8.0` bar.
