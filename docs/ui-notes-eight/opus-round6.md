# KyNotes council, round 6 (stage 09): Claude Opus 5.5

Read-only review of frozen product HEAD `c8b00d8`. The capture manifest head is `022d5e2` plus the recorded `web/src` diff (councilRound 6). Rubric `ky-suite-v2`, weights .20/.15/.20/.15/.15/.15, integer dimensions, Decimal half-up. Machine-readable file: `opus-round6.json`.

## Verdict

| Cohort | Mean | n | Min | Max |
| --- | ---: | ---: | ---: | ---: |
| Notes (all current unique) | **7.8** | 14 | 7.4 | 8.0 |
| Notes, empty first run | 8.0 | 4 | 8.0 | 8.0 |
| Notes, populated/management | 7.7 | 10 | 7.4 | 8.0 |
| Settings (Appearance) | **7.8** | 4 | 7.5 | 8.0 |

- **Satisfied: no.** Notes is at 7.8, below the scoped 8.
- **Ky brand fit** is reported separately: 7.7 overall, Notes 7.7, Settings 7.7. `suite_cohesion` is N/A because only KyNotes is captured.
- **Round-5 blocker O5-1 is resolved.** All five accepted corrections are visible in the stage-09 pixels.
  - `Comment` is secondary.
  - The comments separator is square (computed radius 0).
  - The avatar has a field border in both themes.
  - The no-notebook pane reads "No notebooks yet" at section size. It omits search, `+` and the inner rule, and keeps the recovery disclosure and the direct `New notebook`.
  - The recovery summary and the section select use the shared chevron.
  - The search and `+` borders are equal.
- **Empty first run now reaches 8.0** in all four views. On a phone, `New notebook` sits wholly above the fold (y442–489).
- **One left navigation region:** pass for every captured desktop state, with a single 240px pane.
- **What keeps Notes below 8** is control polish on the populated editor views. It predates this round, and round 5 missed part of it (O6-1 below). It is not a regression, and no layout restart is needed.

## Inventory and provenance (all re-verified)

- **`inventory-v8.json`:** 174/174 entries match on sha256, bytes and IHDR dimensions. There are 174 PNGs on disk, none unlisted, and 122 unique.
- **Stage-09 manifest:**
  - 22/22 file hashes equal the inventory.
  - 8/8 `sourceFiles` hashes match the worktree.
  - `sha256(git diff 022d5e2 -- web/src)` equals the recorded `sourceDiffSha256` (`65a8f5b6…`).
- **Served bundle:** the embedded `internal/web/dist/index.html`, live `127.0.0.1:18109` and live `:18108` all hash to `72df2d95…`, the manifest's `servedIndexSha256`.
- **Test-only change:** `web/e2e/team-keys.e2e.ts` now expects "No notebooks yet". It sits outside the source-diff hash.
- **Current set:** 22 captures, 18 unique.
  - Notes, 14: 4 empty, 4 editor, 2 desktop management, 2 phone chooser, 2 phone page lists.
  - Settings, 4.
- **Aliases, excluded from means:** the 4 `workspace-*` captures inherit the editor scores (12–15 px, max channel delta 4).
  - The diff box is the selected **Type tool button** (desktop x278–328, y197–234), not a caret.
  - The inventory label "caret rasterization" is imprecise, but the near-duplicate rule holds.
- **Byte-identical Settings:** the 4 Appearance images are exact-SHA equal to stage 04. They are scored once as current inputs and get no product credit.
- **Unscored:** 152 historical files, listed in the JSON.
- **Pixel diff against stage 08:** all 14 Notes images carry product pixels, in the regions listed in the JSON `changed_vs_stage08` field, plus save times. Settings show 0 changed pixels.

## Per-file scores (H, T, D, C, A, Co)

All captures: Chromium 156.0.8078.4, scale 1, 1280×900 or 390×844, emulated OS light/dark, synthetic Project Atlas fixture. Confidence is high for every file. Light and dark scored the same everywhere; the JSON has a row for each theme.

| View (×light, dark) | Cohort | State | H | T | D | C | A | Co | Total | ky_fit |
| --- | --- | --- | --: | --: | --: | --: | --: | --: | --: | --: |
| empty-desktop | notes | empty | 8 | 8 | 8 | 8 | 8 | 8 | 8.0 | 7.8 |
| empty-mobile | notes | empty | 8 | 8 | 8 | 8 | 8 | 8 | 8.0 | 8.0 |
| editor-desktop | notes | sparse | 8 | 7 | 7 | 8 | 7 | 7 | 7.4 | 7.5 |
| editor-mobile | notes | sparse | 8 | 8 | 7 | 8 | 8 | 8 | 7.8 | 7.5 |
| navigation-desktop | notes | sparse | 8 | 7 | 8 | 8 | 7 | 7 | 7.6 | 7.8 |
| navigation-mobile | notes | sparse | 8 | 8 | 8 | 8 | 8 | 8 | 8.0 | 8.0 |
| pages-mobile | notes | sparse | 7 | 8 | 7 | 8 | 7 | 8 | 7.5 | 7.5 |
| appearance-desktop | settings | populated | 8 | 8 | 8 | 8 | 8 | 8 | 8.0 | 8.0 |
| appearance-mobile | settings | populated | 7 | 8 | 7 | 8 | 7 | 8 | 7.5 | 7.3 |

### Key observations (full per-dimension text in the JSON)

- **Empty, desktop.**
  - The only accent fill is `New notebook`, under "Your private desk.".
  - The pane names the state correctly.
  - Both disclosures use the same chevron, and no unusable controls remain.
  - Slip: the pane toggle sits at x17 with its chevron at 218, while the content sits at x21 with its chevron at 214, a 4px offset.
- **Empty, phone.** The section-size pane heading no longer outranks the empty title. There is a single rule. Edges and chevrons align at x16 and x366.
- **Editor, desktop (7.4).** No accent fill competes, and the title leads. Three slips remain:
  - **T7: three control-text sizes in one view.** The cap height is 12–13px for Search, Section, the comment input, `Comment` and header `Save` (16px inherited). That is larger than the 15px body (cap 11) and the 14px editor actions (cap 10).
  - **A7 / Co7: mismatched borders.** The secondary `Comment` and `Save` borders sample at 167,171,172, which is **2.32:1** on white. The fields beside them sample at 114,119,119 (4.54:1). The `Comment` row therefore mixes two border weights, two text sizes and two radii (12px squircle against the 8px select). The add-section `+` is also faint.
  - **D7: misaligned edges.** In the pane, the toggle sits at x17, content at x20–21 and rows at x30. The document body is inset 25px from the title edge.
- **Editor, phone.** The select now shows the shared chevron. The body is inset 17px from the title, and there is a gap of about 60px between blocks.
- **Management, desktop.** The pane is even, with Account pinned at the bottom per the contract. The editor half keeps the control-text and border mix.
- **Chooser, phone.** Judged as the captured expanded state, it is clean: 40px rows on aligned edges. The bordered avatar is now visible in light.
- **Pages, phone.** A band of about 44px sits above the recovery row, and the recovery nudge leads the list. The add-section `+` is faint, and header `Save` shows with no editor in view.
- **Appearance.**
  - Desktop: a consistent card grid, with the header `Settings` link showing no current state.
  - Phone: a three-row cloud of borderless section links before the section, plus an orphan "security.".
  - Dark: unselected radios use the UA neutral grey (59,59,59), which is off-token.

## Arithmetic (scripted, exact Decimal)

```
total = sum(Decimal(w)*score).quantize(0.1, ROUND_HALF_UP)
editor-desktop 1.6+1.05+1.4+1.2+1.05+1.05 = 7.35 -> 7.4
nav-desktop    1.6+1.05+1.6+1.2+1.05+1.05 = 7.55 -> 7.6
pages-mobile   1.4+1.2+1.4+1.2+1.05+1.2   = 7.45 -> 7.5
Notes    sum 108.6 / 14 = 7.757142… -> 7.8   (empty 32.0/4 = 8.0; populated 76.6/10 = 7.66 -> 7.7)
Settings sum  31.0 /  4 = 7.75      -> 7.8
```

- Means are taken over the rounded per-file totals.
- I replayed `build-report.py`'s per-row and weight checks read-only on `opus-round6.json`: 22 rows conform, the weights conform, and the score is 7.8. I did not run the script itself, because it rewrites common artifacts.

## Order and prior exposure

1. **Before freezing**, I had seen:
   - the brief, which names prior findings but gives no numbers;
   - the `build-report.py` source, which hardcodes Gemini raw 8.1, Opus handoff 6.7 and owner 6;
   - the **key structure only** of `opus-round5.json`, printed with its values suppressed.
2. **Freeze.** I scored all 18 images at original resolution and persisted the vectors at 2026-10-27T01:30:54Z, as sha256 `63723f14…` covering the quality and ky_fit vectors.
3. **After freezing**, I opened `opus-round5.md`, `sol-round5.md` and `round5-findings-audit.json`. I did not open README, COUNCIL.md, the workbook or `sol-round6.*`, which appeared mid-review.

**Re-inspection after exposure.** Four changes, all upward and all on Settings. The frozen values are in the JSON `reinspection` field.

- **appearance-desktop-dark, A 7→8.** The frozen 7 treated the grey unselected radios as possibly checked. The pixels show the UA grey fill, while the selected card has an accent ring, an accent dot and an accent border, so the selection is unambiguous. I moved this to a palette note.
- **appearance-mobile-dark, A 6→7.** The same radio correction.
- **appearance-mobile-light and -dark, Co 7→8.** These were triggered by the 2-point spread against Sol. My frozen 7 compared the phone selection treatment with the desktop rail, which is a comparison across viewports. On this screen, the links, cards and radios are each consistent.

## Drift against my round 5 (stage-08 counterparts)

| View | R5 → R6 | Δ | Cause |
| --- | --- | ---: | --- |
| empty desktop | 7.5 → 8.0 | +0.5 | Product: state heading; unusable search, `+` and rule gone; chevron disclosure |
| empty phone | 7.0 → 8.0 | +1.0 | Product: heading no longer outranks the title; doubled rule removed |
| editor desktop | 7.3 → 7.4 | +0.1 | Product: H +1, `Comment` no longer the accent fill. Offset by a correction, T 8→7: round 5 missed the 16px control text |
| editor phone | 7.5 → 7.8 | +0.3 | Product: select chevron (A and Co 7→8) |
| management desktop | 7.3 → 7.6 | +0.3 | Product: H +1. Correction D 7→8: the pinned Account is the contract. Correction T 8→7 |
| chooser phone | 7.3 → 8.0 | +0.7 | Product: A and Co, from the bordered avatar. **Calibration: H and D 7→8 (+0.4 of the +0.7) is reviewer drift, not product** |
| pages phone | 7.5 → 7.5 | 0.0 | Product: Co +1 from the chevron. Correction: D −1 for the 44px band, present since stage 05 |
| Appearance desktop | 8.0 → 8.0 | 0.0 | Byte-identical |
| Appearance phone | 7.7 → 7.5 | −0.2 | Calibration on byte-identical pixels: H −1, T +1, A −1 |

- **Byte-identical images:** −0.1 mean, so this session is not more lenient.
- **Product-changed images:** +0.41 mean. Calibration-only moves inside them net about +0.01.
- **Notes product delta:** 7.3 → 7.8, from sum 102.8 to 108.6.
- **Not credited:** save times, initials and alias pixels.
- **Inter-session noise:** about ±0.5, as in round 5. Two round-5 corrections (the 16px control text and the light `.secondary` border) mean my round-5 typography was too generous. I am disclosing that here rather than hiding it.

## Spread against Sol round 5

Sol has not been read for round 6. These are its stage-08 counterparts, whose pixels differ by the round-6 change.

- **Totals:** mine run 0.0–0.9 lower than Sol's.
- **Gaps of 2 or more were re-inspected, not averaged:**
  - Editor and management desktop, **T 9 vs 7: kept.** Measured cap heights show three control-text sizes, with the inputs at 16px above the 15px body.
  - Appearance phone, **A 9 vs 7: kept.** Unselected section links have no visible boundary.
  - Appearance phone, **Co 9 vs 7: corrected to 8**, as described above.
- **Color:** a 1-point gap everywhere, with Sol at 9 and me at 8.

## Blocker to a scoped 8 (O6-1): populated editor control polish

This uses existing tokens only. No feature, layout or behavior change is involved.

1. **`.secondary` border.** It uses `--line-strong`, which samples at 2.32:1 in light and 3.48:1 in dark (`styles.css:476`). That border sits beside `--ky-field-border` inputs at 4.54:1 and 5.32:1, on `Comment` and on header `Save`. Switch it to `--ky-field-border`. This also meets the contract's ≥3:1 control-border rule.
2. **One control-text scale.** `.note-search`, `.comment-compose input` and `button`, and header `Save` inherit 16px. Set them to `--ky-type-nav` (14px) or the body size (15px) so they do not exceed the body or the 14px editor actions.
3. **Desktop pane inset.** Align the toggle (x17, chevron 218) with the pane content (x21, chevron 214).

Items 1–2 drive the editor views' T, A and Co scores of 7; item 3 drives D. Whether these reach 8 or above after recapture is **unproven**. All three were present in stage 08, and round 5 named only the search/`+` mismatch. These are late corrections, not moved goalposts or regressions.

## Non-blocking

- The add-section `+` is a faint glyph below the 40px control size.
- The phone pages view has a band of about 44px above the recovery row.
- The document body is inset 25px on desktop and 17px on phone.
- Empty desktop shows "Saved to server" before anything exists.
- The header `Settings` link has no current state.
- The phone Settings link cloud and orphan subtitle remain (owner-deferred).
- Dark radios use the UA grey, which is off-token.

## Gates (screenshots alone cannot pass a gate)

| Gate | Status | Evidence |
| --- | --- | --- |
| single left region | pass, captured desktop states | 240px pane at x0–239. Supplemental native 960×900 light check: pages w240, editor x240 w720, overflow 0 (not scored) |
| keyboard | untested by me | Parent reports 12/12 fresh browser tests and the stage-09 regressions; not re-run |
| focus | untested | No focus captures |
| contrast | **fail** on `.secondary` borders in light (2.32:1, sampled) | Other pairs untested |
| states | partial | Empty first run and populated only |
| responsive | partial | Overflow 0 at 390 and 1280 per the manifest |

I did not use Computer Use or the live preview, to rule out any fixture mutation. The live hash was checked with a GET only.

## Limits

- **Scope:** this is a scoped 8/10 progression decision only. I make no full-9, competitor or whole-suite claim.
- **Unproven:** WebKit; the full state, role, theme, focus and contrast matrix; the soft keyboard; dense teams and groups; tablet acceptance.
- **Not assessed:** the BlockNote 603 kB chunk warning and the CSP/style advice.
- **Gemini** stays advisory until both primaries are satisfied.
- **Writes:** only `opus-round6.md` and `opus-round6.json` were written.
