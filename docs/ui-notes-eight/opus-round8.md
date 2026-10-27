# KyNotes Council, round 8: Claude Opus 5.5

**Verdict: Notes 7.9/10 (7.914), not satisfied. Settings 7.9 (separate). Brand fit 7.9 (separate; suite_cohesion N/A).**

Scope: KyNotes editor, one left navigation region, phone navigation and Appearance, as captured in stage 11 (councilRound 8). This makes no full-9, competitor, whole-suite or accessibility claim.

## Evidence verified

- `inventory-v10.json`: I checked SHA-256, bytes and PNG dimensions for all 218 rows; there are 0 mismatches, 168 unique hashes and 68 `duplicate_of` rows.
- `screenshots/11-after-manifest.json`: I checked all 22 images (hash, bytes, dimensions); overflow is 0 on all of them.
- There are 18 unique current captures:
  - 4 workspace aliases are near-duplicates of their editor captures: 12–15 px differ, max channel delta 4, bbox `[278,197,329,235]` desktop and `[16,293,67,331]` phone. They inherit the editor scores and are excluded from means.
  - The 4 empty and 4 Appearance captures are byte-identical to stage 10. They are still current coverage and are scored here.
- Source pins: all 9 manifest `sourceFiles` match HEAD `07abcc5` and the working tree, including `src/CanvasPage.tsx`.
- Source diff: `git diff f32660c 07abcc5 -- web/src` hashes to `456ee4d1…`, matching the manifest.
- Embed vs live:
  - `internal/web/dist/index.html` matches `servedIndexSha256` `8ef267ad…` and the live 18111 index.
  - The index JS/CSS, CanvasPage and blocknote assets are byte-equal between live and embed.
  - The embedded CSS contains `::placeholder{color:var(--ink);opacity:1}` and `.canvas-tool-divider`. The JS contains the inbox path.
- Not re-run by me (read-only role): production build, unit/browser suites, Go, Docker, probe and repeatable binaries. These are parent-reported.

## Live check (own incognito tab, 1280×800, synthetic owner)

I opened the existing Launch checklist and waited for `.canvas-tool-divider` before measuring.

| Control | Light | Dark |
|---|---|---|
| Placeholders: Search, Section (optional), Add a comment | rgb(86,100,97) on white, opacity 1: **6.1926:1** | rgb(179,188,184) on rgb(31,43,46): **7.4845:1** |
| Section-add `+` | 40×40, **radius 12px**, NavIcon glyph in muted ink, 6.19:1 | 7.48:1 |
| Page-add `+` | 40×40, **radius 8px**, fullwidth `＋` in strong ink, 16.06:1 | 12.67:1 |
| Divider | 1×24, aria-hidden, not focusable | |

- Toolbar order is: Type, Pen, Highlighter, Eraser, `|`, Undo ink, Redo ink, Add text.
- Work queue renders one inbox path.
- I opened the section popover; it showed "New section" and "New section group". Escape closed it, and focus returned to "New section or group". The sections are still `["Quick Notes"]`, so nothing was created.
- The page now shows Version 5 (the capture showed Version 3). My tab sent no PUT; it sent only login and presence POSTs, so another session caused that bump.

## Scores of record (ky-suite-v2, .20/.15/.20/.15/.15/.15, Decimal half-up)

Vector order: hierarchy, typography, density_layout, color, visible_affordances, coherence.

| Unique file (stage 11) | Vector | Total | Round 7 | Changed pixels vs stage 10 |
|---|---|---:|---:|---|
| editor-desktop-light | 8,8,8,8,8,7 | 7.9 | 7.9 | bbox [26,100,1222,873] |
| editor-desktop-dark | 8,8,8,8,8,7 | 7.9 | 7.7 | same |
| editor-mobile-light | 8,8,7,8,8,8 | 7.8 | 7.8 | bbox [79,196,354,324] (divider, time) |
| editor-mobile-dark | 8,8,7,8,8,8 | 7.8 | 7.8 | same |
| navigation-desktop-light | 8,8,8,8,8,8 | 8.0 | 7.9 | bbox [28,100,1222,873] |
| navigation-desktop-dark | 8,8,8,8,8,8 | 8.0 | 7.7 | same |
| navigation-mobile-light | 8,8,8,8,8,8 | 8.0 | 7.9 | bbox [28,180,354,754] |
| navigation-mobile-dark | 8,8,8,8,8,8 | 8.0 | 7.9 | same |
| pages-mobile-light | 8,8,8,8,8,7 | 7.9 | 7.9 | bbox [26,249,184,324] |
| pages-mobile-dark | 8,8,8,8,8,7 | 7.9 | 7.7 | same |
| empty-desktop-light | 8,8,8,8,8,8 | 8.0 | 8.0 | byte-identical |
| empty-desktop-dark | 8,8,8,8,8,8 | 8.0 | 8.0 | byte-identical |
| empty-mobile-light | 8,8,7,8,8,8 | 7.8 | 7.8 | byte-identical |
| empty-mobile-dark | 8,8,7,8,8,8 | 7.8 | 7.8 | byte-identical |
| appearance-desktop-light / dark | 8,8,8,8,8,8 | 8.0 / 8.0 | 8.0 / 8.0 | byte-identical |
| appearance-mobile-light / dark | 8,8,7,8,8,8 | 7.8 / 7.8 | 7.8 / 7.8 | byte-identical |

- **Notes (n=14):** sum 110.8, mean 7.914 → **7.9**. Empty 7.9 (n=4); populated/sparse 7.9 (n=10); minimum 7.8.
- **Settings (n=4):** sum 31.6, mean **7.9**.
- **Brand fit:** the mean over 18 files is 7.944 → 7.9. Type geometry is 7 on editor-desktop and pages-mobile because of the 12px section-add radius; every other dimension is 8; suite_cohesion is N/A.

Per-dimension observations are in `opus-round8.json`.

## Blind pass and drift

I froze all 18 vectors before opening any prior score, README, COUNCIL, spreadsheet or `build-report.py`. The frozen file is `/tmp/opus-r8/frozen-vectors.json` (sha256 `9296152c…`, 02:20:15Z), and each file row keeps them as `blind_scores`.

The blind Notes mean was **8.000**. I did not adopt it:

- **Byte-identical empty-mobile.** The blind pass gave hierarchy 9 and density 8 (+0.4 per file). On re-inspection, the status row's ink sits 17px above the empty title but 28px below the rule, so it still reads as the title's caption. Round 7 read this correctly, so there is no valid drift cause (anchor/cohort/correction/artifact).
- **Phone editor.** The blind pass gave density 8 (+0.2 per file). The changed pixels are only the divider and timestamp. The body still starts at x33 against the title at x17, after about 135px of toolbar chrome.

Together these account for +0.8 of the Notes sum from re-scoring unchanged pixels. Counting it would credit rater drift as product improvement, so the score of record keeps the round-7 reading.

**Product-attributable changes:**
- Affordances +1 on editor-desktop, navigation and pages: placeholders, divider, bordered section-add, inbox icon.
- Dark color +1: placeholder contrast.
- Coherence −1 on editor-desktop and pages-mobile: the new plus mismatch (B8-1).

No file moves by 0.5 or more. Settings vectors equal round 7.

**Spread:** Sol's round 8 is not visible to me. Against Sol's round 7, no dimension differs by 2 or more on any file.

## Findings

**B7-1, resolved.** Theme-ink placeholders are visible in the dark captures and measure 6.19:1 light and 7.48:1 dark.

**B7-2, partly resolved.** The divider separates modes from commands. The Work queue inbox no longer reads as checked. Section-add is now a bordered 40px button. But it is not the same control as page-add (B8-1).

**B8-1, blocker; a regression from the B7-2 fix.** Section-add and page-add are near-miss copies of one control, 20px apart:
- **Radius:** section-add gets 12px from the `.icon-button` squircle rule (`web/src/styles.css:186`), which `.section-tabs .section-add` (`:481`) never overrides. Page-add gets the 8px `--ky-control-radius` (`:506`).
- **Glyph:** section-add uses NavIcon under `.nav-icon{color:var(--ink)}` (`:488`), so it renders lighter and thinner than page-add's strong-ink `＋`.
- **Where:** visible at 1× in editor-desktop (light and dark) and pages-mobile (light and dark).
- **Fix (CSS only):** give `.section-tabs .section-add` `border-radius: var(--ky-control-radius)` and strong-ink glyph color, or render page-add with the same NavIcon. No handler, order or label change.

**B8-2, blocker. This corrects my round 7.** In round 7 I called B7-1/B7-2 the blockers and marked these two items O7-3 non-blocking. But my own round-7 vectors with B7-1/B7-2 fully fixed give 7.943, which rounds to 7.9, not 8. The density 7s that keep the score down are:
- **Phone editor:** a 16px body inset from the title edge, after about 135px of toolbar chrome.
- **Phone empty:** the status row hugs the title.

**What reaches 8:** B8-1 alone gives 7.943 (7.9). B8-1 plus one B8-2 item gives 7.971 (8.0). Both give 8.000.

**O8-3, non-blocking:**
- The empty desktop header says "Saved to server" before anything exists.
- Header Settings has no current-page state.
- "Trusted Device" breaks sentence case.
- The phone Settings link band wraps 3/2/1 and leaves an orphan subtitle (owner-deferred).
- Dark unselected radios are UA grey discs.
- Notebook commands share the quiet nav-row style.

**First-open phone focus (behavior residual).** I did not re-test this. On phone, opening the first page from the no-open-note list can leave focus on BODY. A keyboard or screen-reader user must then Tab back into the page; later chooser picks focus the title. There is no content or save risk. It blocks any keyboard/focus acceptance claim and does not change these visual scores.

## Gates (scoped)

| Gate | Result |
|---|---|
| Keyboard | Untested by me; known focus residual. |
| Focus | Untested; known focus residual. |
| Contrast | Partial: placeholders and section-add glyph pass in the default light and dark themes; named themes untested. |
| States | Partial: empty and populated only. |
| Responsive | Partial pass: 390 and 1280, overflow 0 on all 22 captures. |

Still unproven: WebKit, named themes, loading/error states, dense teams, soft keyboard and tablet.

## Result

- **score:** 7.9 (Notes 7.914; Settings 7.9 separate)
- **satisfied:** false
- **blockers:**
  - B8-1: section-add radius and glyph ink do not match page-add.
  - B8-2: phone editor body inset, or phone empty status-row spacing (at least one).
- Gemini stays deferred: it runs only after both primaries are satisfied.
