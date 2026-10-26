# KyNotes UI council: Opus round 2 (stage 03)

Reviewer: Claude Opus 5.5, acting as the review sub-agent. This was a read-only review; the only writes are this file and `opus-round2.json`.
Input: the 16 `screenshots/kynotes-03-after-*.png` files and `03-after-manifest.json`. They were captured at head `34849c4` with served index `f3f08683ea19…` in Chromium 156.0.8078.4, using the synthetic Project Atlas fixture.
Rubric: `ky-suite-v2`. Weights are .20/.15/.20/.15/.15/.15, and totals are rounded half-up by `Decimal` in a script.

## Verdict

**Notes: 7.4/10 (mean 7.38, n=8). Settings: 7.7 (mean 7.65, n=4). Not satisfied.**

The visible fixes from round 1 hold up in the captures:

- The phone Pages picker shows rows.
- The orange "Saved" footer button is gone, and the footer is one aligned 40px row.
- Navigation icons are one SVG set.
- All navigation rows are 14px.
- The empty "Team notebooks" gap is gone.
- The Settings nav marks the current item and wraps on phone without clipping.

Notes still falls short of 8 because of four visible defects:

- The phone Pages picker spends about 430px on chrome before its first row.
- The footer notebook select renders in the browser's default font.
- Phone disclosures use +/− instead of chevrons.
- Two smaller desktop defects compete for attention.

The contrast gate fails separately: Settings and comment inputs still use the 1.6:1 `--line` border.

## Inventory

- 16 CURRENT files. I recomputed SHA-256, bytes, dimensions and pixel diffs with Pillow, and all of them match `inventory-v2.json` and the manifest.
- Each of the 4 workspace captures is a near duplicate of its editor counterpart: 12–15 px differ (≤0.0046%), with a max channel delta of 4, at the caret box. Each pair is scored once, on the editor file.
- That leaves **12 unique CURRENT images**: 8 `notes` and 4 `settings`.
- The other 32 files in inventory-v2 belong to earlier stages and are not scored. Stage 02 was used only for the drift comparison, after blind scoring.

## Per-image scores (CURRENT, unique, scored blind)

| File | hier | type | dens | color | afford | coher | **total** | ky_fit (4-dim) |
|---|---|---|---|---|---|---|---|---|
| editor-desktop-light | 7 | 8 | 7 | 8 | 8 | 7 | **7.5** | 7.5 (8/7/7/8) |
| editor-desktop-dark | 7 | 8 | 7 | 8 | 8 | 7 | **7.5** | 7.5 |
| editor-mobile-light | 8 | 8 | 7 | 8 | 7 | 7 | **7.5** | 7.8 (8/7/7/9) |
| editor-mobile-dark | 8 | 8 | 7 | 8 | 7 | 7 | **7.5** | 7.8 |
| pages-mobile-light | 6 | 7 | 6 | 8 | 7 | 7 | **6.8** | 7.3 (8/7/6/8) |
| pages-mobile-dark | 6 | 7 | 6 | 8 | 7 | 7 | **6.8** | 7.3 |
| navigation-mobile-light | 8 | 8 | 8 | 8 | 7 | 7 | **7.7** | 8.0 (8/8/7/9) |
| navigation-mobile-dark | 8 | 8 | 8 | 8 | 7 | 7 | **7.7** | 8.0 |
| appearance-desktop-light | 8 | 8 | 7 | 8 | 8 | 8 | **7.8** | 8.0 (8/8/7/9) |
| appearance-desktop-dark | 8 | 8 | 7 | 8 | 8 | 8 | **7.8** | 8.0 |
| appearance-mobile-light | 7 | 8 | 7 | 8 | 8 | 7 | **7.5** | 8.0 (8/8/7/9) |
| appearance-mobile-dark | 7 | 8 | 7 | 8 | 8 | 7 | **7.5** | 8.0 |

- The ky_fit columns are palette_tokens/type_geometry/shell/accent_discipline. `suite_cohesion` is N/A because only KyNotes was inspected, and ky_fit is never added to the total.
- All rows are high confidence. Light and dark get identical scores because no theme-specific defect is visible: dark keeps the same hierarchy, and its status and danger hues read clearly.
- The JSON has one observation per dimension for every file.

### Key visible facts

**Editor, desktop**

- "Launch checklist" leads the page. The page-list column competes with it in three ways:
  - "Project Atlas" is a 24px title.
  - A 170px boxed recovery notice sits under it.
  - "Quick Notes" appears three times: as the tab, the section label and the footer select.
- Save state is shown twice in green: "● Saved to server" in the header and "Saved on server 7:17:50 PM" in the meta line.
- The section tab combines a grey rounded top outline with an orange underline.
- There is an empty band of about 150px under the list. The canvas text sits 33px in from the title, which is stored geometry and out of scope.

**Editor, phone**

- The page leads the screen.
- The "+" disclosure glyphs read as "add", not "expand".
- The footer select is in the browser's default font, and the footer is cut by the fold.

**Pages, phone**

- The first row starts at y≈590. Before it come:
  - the section tab
  - "Project Atlas" again (the disclosure already says "Pages in Project Atlas")
  - "Notebook"
  - the recovery notice
  - a "Quick Notes" label under the "Quick Notes" tab
- 3 full rows plus the 4th title are visible.
- Left edges step through 12, 16, 20 and 30px.

**Navigation, phone**

- Rhythm is clean and even.
- The avatar shows `auth.user.id.slice(-2)` → "hm" in Mono next to "owner" (`web/src/main.tsx:2866`).

**Appearance**

- The current item is marked. On phone the wrapped nav (≈225px) pushes the "Settings" h1 to fourth in reading order.
- The current-item treatment is an underline on phone but a rail on desktop.

## Source checks behind visible defects

- **Select font.** `web/src/styles.css:6` reads `button, input, textarea { font: inherit; }` and leaves out `select`. That explains the browser-default font in the footer select at both widths.
- **Field-border coverage.** `--ky-field-border` is consumed only by `.title-input`, `.personal-create`, `.editor-actions select` and `.note-search` (styles.css:127, 405, 423). These selectors still use `var(--line)`:
  - Settings/auth `form input` (79)
  - `.field select` (103)
  - `.comment-compose input` (146)
  - `.check-code-input` (381)

  Alpha-blended from the Busnes tokens, `--line` is **1.57:1** on the light panel and **2.06:1** on the dark one. The field border computes to 4.54 and 5.32:1. These ratios come from source, not from browser measurement. The round's brief says low-contrast field borders now consume the token; that is true only for the four selectors above.

## Gates (separate from scores)

| Gate | Status | Evidence |
|---|---|---|
| keyboard | untested by me (claimed pass) | `web/e2e/ui-council.e2e.ts:94-137` asserts that the first row is `toBeInViewport(0.9)`, that Page title is focused and fully in view after same-id and different-id picks, and that "● Unsaved changes" shows during a held PUT. I did not re-run it. |
| focus | untested | No focus captures in either theme. |
| contrast | **fail** (source-computed) | Settings, comment and check-code inputs still use `--line` at 1.57:1 (light) and 2.06:1 (dark). The status primitives are claimed measured in ky-ui tests, which I did not re-run. |
| states | untested | No empty, loading or error captures. |
| responsive | partial | The manifest shows overflow 0 at 390 and 1280 for all 16 captures. Target sizes were not measured. |

I did not inspect the live app and mutated no content. Full product coverage across all themes, focus, empty, error, loading and WebKit remains unproven.

## Drift and comparison (opened only after blind scoring)

Stage 02 and stage 03 are different images, so every delta below is product change, not rubric drift.

| Surface | Opus r1 | Opus r2 | Δ | Sol r1 | Cause |
|---|---|---|---|---|---|
| editor desktop | 6.7 | 7.5 | +0.8 | 8.3 | The filled clean "Saved" button is gone, the footer is realigned, icons are SVG, the "Team notebooks" gap and row gutter are gone, and the field border is stronger. |
| editor phone | 7.1 | 7.5 | +0.4 | 8.3 | Disclosures are unified. The browser-default select font and +/− glyphs hold affordances and coherence at 7. |
| pages phone | 5.2 | 6.8 | +1.6 | 6.6 | 0 rows became 3.5 rows. About 430px of chrome still comes first. |
| navigation phone | 6.7 | 7.7 | +1.0 | 8.0 | Mixed action sizes and glyph icons are fixed, and the gap is gone. |
| appearance desktop | 7.4 | 7.8 | +0.4 | 8.2 | The current-item marker was added (affordances 6 → 8). |
| appearance phone | 7.2 | 7.5 | +0.3 | 7.6 | The nav wraps unclipped with the current item marked (affordances 5 → 8). |

Mean Ky delta is +0.75. Every delta follows a visible change I can name, so it reflects the product, not reviewer softening.

**Re-inspected dimensions where Opus r1 and Sol r1 differed by 2 or more:**

| Dimension | Opus r1 | Sol r1 | Opus r2 | Why |
|---|---|---|---|---|
| Editor typography | 7 | 9 | 8 | The browser-default select font is a visible stray. |
| Editor color | 7 | 9 | 8 | The duplicate green save status and four simultaneous selection markers are not "nothing to remove". |
| Editor coherence | 6 | 8 | 7 | Tab outline plus underline, the boxed notice, and the select font. |
| Appearance affordances | 6 / 5 | 8 / 7 | 8 / 8 | The product fixed it. |
| Pages color | 7 | 9 | 8 | Three rails stack in one short viewport. |
| Navigation typography | 6 | 8 | 8 | The product fixed it. |

No dimension was averaged. Each one moved because of a visible product change, or stayed where it was because of a named visible fact.

## Remaining blockers (all within scope)

1. **Phone Pages picker.** Inside the picker:
   - Drop the repeated "Project Atlas"/"Notebook" header.
   - Drop the "Quick Notes" label under the "Quick Notes" tab.
   - Compact the recovery notice to one line plus a link. Keep the nudge.
   - Align left edges to 16px.

   The target is 6 or more rows above the fold.
2. **Select font.** Add `select` to `styles.css:6` `font: inherit`.
3. **Phone disclosures.** Use chevrons, as the contract asks for section expanders. This also stops them colliding with the new-page "+".
4. **Avatar.** Show the username initial instead of the id tail "hm", or drop the avatar (`main.tsx:2866`).
5. **Desktop save status.** Use one voice. For example, mute the meta timestamp to ink-muted and keep the header status green.
6. **Section tab.** Use one selection treatment: drop either the grey rounded top outline or the underline.
7. **Contrast gate (not the visual score).** Move these borders to `--ky-field-border`: `form input`, `.field select`, `.comment-compose input` and `.check-code-input`.

## What could reach 8

This is a projection with the same anchors, not a promise:

- Fix 1 brings Pages to 8/8/8/8/8/8, a total of **8.0**.
- Fixes 2–4 bring editor phone to **7.8** and navigation to **8.0**.
- A compact desktop notice plus fixes 5–6 bring editor desktop to **8.0**.

The Notes mean would then be 7.95, which rounds half-up to **8.0**. There is no margin: every fix is needed. Editor-phone density stays at 7 because the canvas inset is stored coordinates, which are out of scope.
