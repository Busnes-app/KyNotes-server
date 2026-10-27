# KyNotes council round 7 — Claude Opus 5.5

**Verdict: Notes 7.8 (7.843, n14, min 7.7). Settings 7.9 (n4, min 7.8). Not satisfied for the scoped 8.**
Brand fit 7.9 (separate; `suite_cohesion` N/A). This is not a full-9, competitor or whole-suite claim.

Rubric `ky-suite-v2`, weights .20/.15/.20/.15/.15/.15, integer scores, Decimal half-up. Machine-readable
results are in `opus-round7.json`.

## Provenance verified

- `inventory-v9.json`: all 196 rows match on SHA-256, bytes and PNG dimensions. That is 154 unique hashes, or 140 after near-duplicates. The PNG set on disk equals the inventory.
- `screenshots/10-after-manifest.json`: 22 captures, all matching on hash, bytes and viewport. 18 are unique; the 4 `workspace-*` captures are near-duplicates of `editor-*` (12–15 px, max delta 4). They inherit scores and are excluded from the means.
- Sources: all 8 manifest source hashes match. `sourceDiffSha256 b687b128…` reproduces as `git -C web diff c8b00d8 5ec748e -- src`, and the working tree equals HEAD `5ec748e`.
- Served bundle: `index.html` `6d043056…` is the same in the embedded dist and on the live fixture. The live `index-CF8u7W7X.js` and `index-KWPtcTv_.css` are byte-identical to dist. The embedded CSS contains all three round-7 rules.
- No current capture is pixel-equal to a historical file. Every stage-10 unique differs from stage 09, at minimum in the header Settings/Lock text, which is now 14px.

## Method

- I froze all 18 vectors at 01:51:21Z (`/tmp/opus-r7-frozen.json`, sha `7872aeae…`) before opening any prior report, README, COUNCIL file or the spreadsheet. The reported scores are those frozen vectors, unchanged.
- I inspected each image at full resolution, with 2–3× crops of the pane, header, comment row and cards.
- Contrast figures come from extreme glyph and edge pixels, using WCAG relative luminance.
- Live check: my own new tab on 18110. I opened the existing Launch checklist and switched the emulated scheme to dark and back. I typed nothing and created no content, then closed the tab.

## Scores (unique files)

| File | H | T | D | C | A | Co | Total | Δ vs Opus6 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| empty-desktop-light | 8 | 8 | 8 | 8 | 8 | 8 | 8.0 | 0 |
| empty-desktop-dark | 8 | 8 | 8 | 8 | 8 | 8 | 8.0 | 0 |
| empty-mobile-light | 8 | 8 | 7 | 8 | 8 | 8 | 7.8 | −0.2 |
| empty-mobile-dark | 8 | 8 | 7 | 8 | 8 | 8 | 7.8 | −0.2 |
| editor-desktop-light | 8 | 8 | 8 | 8 | 7 | 8 | 7.9 | +0.5 |
| editor-desktop-dark | 8 | 8 | 8 | 7 | 7 | 8 | 7.7 | +0.3 |
| navigation-desktop-light | 8 | 8 | 8 | 8 | 7 | 8 | 7.9 | +0.3 |
| navigation-desktop-dark | 8 | 8 | 8 | 7 | 7 | 8 | 7.7 | +0.1 |
| editor-mobile-light | 8 | 8 | 7 | 8 | 8 | 8 | 7.8 | 0 |
| editor-mobile-dark | 8 | 8 | 7 | 8 | 8 | 8 | 7.8 | 0 |
| pages-mobile-light | 8 | 8 | 8 | 8 | 7 | 8 | 7.9 | +0.4 |
| pages-mobile-dark | 8 | 8 | 8 | 7 | 7 | 8 | 7.7 | +0.2 |
| navigation-mobile-light | 8 | 8 | 8 | 8 | 7 | 8 | 7.9 | −0.1 |
| navigation-mobile-dark | 8 | 8 | 8 | 8 | 7 | 8 | 7.9 | −0.1 |
| **Notes** (sum 109.8 / 14) | | | | | | | **7.8** | +0.1 (7.757→7.843) |
| appearance-desktop-light | 8 | 8 | 8 | 8 | 8 | 8 | 8.0 | 0 |
| appearance-desktop-dark | 8 | 8 | 8 | 8 | 8 | 8 | 8.0 | 0 |
| appearance-mobile-light | 8 | 8 | 7 | 8 | 8 | 8 | 7.8 | +0.3 |
| appearance-mobile-dark | 8 | 8 | 7 | 8 | 8 | 8 | 7.8 | +0.3 |
| **Settings** (sum 31.6 / 4) | | | | | | | **7.9** | +0.1 |

Notes split by state: empty 7.9 (n4), populated 7.8 (n10). Each dimension's observation, plus the confidence and caveat for every file, is in the JSON.
Confidence is high throughout. The caveats are that these are still images at scale 1 with a fold, and that the fixture's page previews all show identical text.

## What changed and what it earns

All three accepted O6-1 fixes are visible and measured, so **O6-1 is resolved**:

- **Secondary border.** Save, Comment, Search and + now share the field-border edge 114,119,119. That measures 4.54:1 on white, 3.96:1 on the cream pane and 5.32:1 in dark.
- **Control scale.** Search, the comment controls and header Save are 14px with an 8px radius.
- **Pane inset.** The toggle, notebook heading, recovery row, tabs and search all align at x16.

I credited only dimensions whose cited defect lies inside the measured changed-pixel box. That gives +0.50 to each editor-desktop file (typography, density, coherence) and +0.30 to each navigation-desktop file (typography, coherence). Together that is +1.60 weighted, or **+0.114 on the Notes mean from product**.

Rater drift on unchanged pixels, disclosed rather than credited:

- **Notes: −0.35 weighted (−0.025 mean).**
  - Dark placeholder correction (−0.15 × 3).
  - Work queue checkmark correction on phone navigation.
  - Phone-empty status-row spacing, now weighted.
  - Phone pages: round 6 counted the owner-specified omission of repeated headings as a hierarchy defect.
- **Settings: +0.70 weighted (+0.175 mean). Settings 7.8 → 7.9 is rater drift, not product.** Only the header text pixels changed.

Spread against Sol6: the largest gap on any dimension is 1, so no re-inspection was forced.

## Blockers for the scoped 8 (bounded)

- **B7-1: dark placeholders are not themed.** In editor-desktop-dark, navigation-desktop-dark and pages-mobile-dark, the placeholders "Search", "Section (optional)" and "Add a comment…" use the UA grey `rgb(117,117,117)`.
  - It measures 3.16:1 on `rgb(31,43,46)`. Light is 4.61:1.
  - I confirmed it live: computed `::placeholder` is the same value under `color-scheme: dark`.
  - Fix: one `::placeholder` rule using a token that measures ≥4.5:1 in every shipped theme.
- **B7-2: affordance slips in the populated workspace.**
  1. The ink toolbar draws modes (Type/Pen/Highlighter/Eraser, `aria-pressed`) and commands (Undo ink/Redo ink/Add text) identically in one row. Separate the command group.
  2. The add-section "+" is a faint 32×34 glyph next to the bordered 40px add-page "+". Give it the shared icon-button treatment or a label.
  3. The Work queue checkmark icon reads as a checked state. Use a neutral queue icon.

Fixing both would lift about 8 affordance scores and 3 dark colour scores by one point each. That projects to roughly 7.96, which rounds to 8.0. **That is a projection, not an achieved score**; it needs a fresh capture and a fresh blind review.

Non-blocking (O7-3), not preventing the scoped 8:

- The document body is inset 24px (desktop) or 16px (phone) from the title.
- The phone status row sits about 20px above the empty title.
- The empty view shows "Saved to server" before anything exists.
- Header Settings has no current-page state.
- "Trusted Device" breaks sentence case.
- The phone Settings links wrap 3/2/1, with an orphaned subtitle line (owner-deferred).
- Dark unselected radios are UA grey.

## Behaviour residual, kept separate

The phone first-open BODY focus (Sol6) was traced by the parent; I did not re-test it.

- **Impact:** a keyboard or screen-reader user who opens the first page from the no-open-note phone state lands on BODY and has to Tab back in. Later chooser picks focus the title. Nothing points to a content or save risk.
- **Verdict:** it does not lower any visual score and does not block the scoped visual 8. It does block any keyboard or focus acceptance claim.

## Gates (evidence only)

| Gate | Result |
|---|---|
| Keyboard | Untested by me. The parent reports 12/12 on the browser suite; I did not re-run it. Plus the residual above. |
| Focus | Untested. Plus the residual above. |
| Contrast | **Fail (scoped):** dark placeholders at 3.16:1. The four measured control borders pass in both default themes. Other themes are untested. |
| States | Partial: empty first run and populated only. |
| Responsive | Partial pass at 390 and 1280; manifest overflow is 0 on all 22 captures. |

Single left navigation region: pass on every captured desktop state, with one 240px pane.

## Limits

These remain unproven: WebKit; full theme, state, role, focus and contrast coverage; soft-keyboard behaviour; dense-team content; phone management and Settings density. The verdict is scoped to KyNotes. Gemini stays deferred, because both primaries are not satisfied. Nothing here authorises a merge or deploy.
