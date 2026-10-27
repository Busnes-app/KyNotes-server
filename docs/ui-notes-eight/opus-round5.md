# KyNotes council, round 5 (stage 08): Claude Opus 5.5

Read-only review of frozen product HEAD `ffd3471` (capture manifest head `5dbf6df` plus the recorded source diff; councilRound 5). Rubric `ky-suite-v2`, weights .20/.15/.20/.15/.15/.15, integer dimensions, Decimal half-up. Machine-readable file: `opus-round5.json`.

## Verdict

| Cohort | Mean | n | Min | Max |
| --- | ---: | ---: | ---: | ---: |
| Notes (all current unique) | **7.3** | 14 | 7.0 | 7.5 |
| Notes, empty first run | 7.3 | 4 | 7.0 | 7.5 |
| Notes, populated/management | 7.4 | 10 | 7.3 | 7.5 |
| Settings (Appearance) | **7.9** | 4 | 7.7 | 8.0 |

- Ky brand fit, reported separately: 7.9 overall (Notes 7.8, Settings 8.2). `suite_cohesion` is N/A because only KyNotes is in scope.
- **Satisfied: no.** My evidence does not support a scoped 8/10 for Notes.
- **My round-4 blocker B1 is resolved.** All four empty views show `New notebook` as the single accent-filled action, with first-run copy ("Start with a notebook…"). At 390px the button sits wholly above the fold (y542–589) in both themes. The source change is minimal: `main.tsx` empty editor calls the existing `newWorkspace()`. Key and setup notices stay in place.
- **One left navigation region:** pass (scripted). Every stage-08 desktop capture (empty, editor, management, Appearance; light and dark) has only the x239/240 full-height edge.
- **What keeps Notes below 8:** visual polish that was already in stage 07, not the new change. See the blocker below.

## Inventory and provenance

- **`inventory-v7.json`:** all 152 entries match on sha256, bytes and PNG IHDR dimensions. There are 152 PNGs on disk and none are unlisted.
- **Stage-08 manifest:** 22/22 file hashes match. All 8 `sourceFiles` hashes match the `ffd3471` tree. The served `internal/web/dist/index.html` matches `servedIndexSha256` (`00dcf80d…`).
- **Current set:** 22 captures, 18 unique (Notes 14: 4 empty, 2 desktop management, 2 phone chooser, 4 editor, 2 phone page lists; Settings 4).
- **Current aliases, excluded from means:** the 4 `workspace-*` captures equal the stage-08 editor except for caret rasterization (12–15 px, max channel delta 4). They inherit the editor scores.
- **Equal pixels across stages, still counted:** 4 Appearance captures are exact-SHA equal to stage 04, and 2 `pages-mobile` captures to stage 05. Both appear in history as duplicates, but they are current unique captures for this cohort and are scored and counted.
- **Changes against stage 07:**
  - Empty: 11–15k changed pixels (the new action and copy).
  - Editor and navigation: 240–304 px in the save-time/initials text only (desktop x1182–1221, y100–109).
  - Pages and Appearance: byte-identical.
- **Unscored:** the 130 prior-stage files, which are history rather than current input. They are listed in the JSON.

## Per-file scores (H, T, D, C, A, Co = hierarchy, typography, density/layout, color, visible affordances, coherence)

All captures: Chromium 156.0.8078.4, scale 1, desktop 1280×900 or phone 390×844, emulated OS light/dark, synthetic Project Atlas fixture. Confidence is high for every file (clear full-resolution view, no overlays).

| File (kynotes-08-after-) | Cohort | State | H | T | D | C | A | Co | Total | ky_fit | Equal pixels in history | Δpx vs 07 |
| --- | --- | --- | --: | --: | --: | --: | --: | --: | --: | --: | --- | --: |
| empty-desktop-light | notes | empty | 8 | 8 | 7 | 8 | 7 | 7 | 7.5 | 8.3 | — | 15002 |
| empty-desktop-dark | notes | empty | 8 | 8 | 7 | 8 | 7 | 7 | 7.5 | 8.3 | — | 15004 |
| empty-mobile-light | notes | empty | 7 | 7 | 6 | 8 | 7 | 7 | 7.0 | 8.3 | — | 11315 |
| empty-mobile-dark | notes | empty | 7 | 7 | 6 | 8 | 7 | 7 | 7.0 | 8.3 | — | 11333 |
| editor-desktop-light | notes | sparse | 7 | 8 | 7 | 8 | 7 | 7 | 7.3 | 7.5 | — | 304 |
| editor-desktop-dark | notes | sparse | 7 | 8 | 7 | 8 | 7 | 7 | 7.3 | 7.5 | — | 240 |
| editor-mobile-light | notes | sparse | 8 | 8 | 7 | 8 | 7 | 7 | 7.5 | 7.5 | — | 245 |
| editor-mobile-dark | notes | sparse | 8 | 8 | 7 | 8 | 7 | 7 | 7.5 | 7.5 | — | 240 |
| navigation-desktop-light | notes | sparse | 7 | 8 | 7 | 8 | 7 | 7 | 7.3 | 7.5 | — | 304 |
| navigation-desktop-dark | notes | sparse | 7 | 8 | 7 | 8 | 7 | 7 | 7.3 | 7.5 | — | 240 |
| navigation-mobile-light | notes | sparse | 7 | 8 | 7 | 8 | 7 | 7 | 7.3 | 7.5 | — | 245 |
| navigation-mobile-dark | notes | sparse | 7 | 8 | 7 | 8 | 7 | 7 | 7.3 | 7.5 | — | 240 |
| pages-mobile-light | notes | sparse | 7 | 8 | 8 | 8 | 7 | 7 | 7.5 | 8.0 | 05 (exact) | 0 |
| pages-mobile-dark | notes | sparse | 7 | 8 | 8 | 8 | 7 | 7 | 7.5 | 8.0 | 05 (exact) | 0 |
| appearance-desktop-light | settings | populated | 8 | 8 | 8 | 8 | 8 | 8 | 8.0 | 8.3 | 04 (exact) | 0 |
| appearance-desktop-dark | settings | populated | 8 | 8 | 8 | 8 | 8 | 8 | 8.0 | 8.3 | 04 (exact) | 0 |
| appearance-mobile-light | settings | populated | 8 | 7 | 7 | 8 | 8 | 8 | 7.7 | 8.0 | 04 (exact) | 0 |
| appearance-mobile-dark | settings | populated | 8 | 7 | 7 | 8 | 8 | 8 | 7.7 | 8.0 | 04 (exact) | 0 |

### Observations, one per dimension (full text per file in the JSON)

- **Empty, desktop**
  - H8: `New notebook` is the only accent fill, centred under "Your private desk.". The pane's "Select a notebook" asks for a selection that cannot exist yet.
  - T8: Space type with clean steps.
  - D7: a single 240px region; the pane below the search row is a rule and about 590px of blank.
  - C8: accent appears only on the action.
  - A7: the disabled 40px `+` has no explanation, and the recovery disclosure uses the UA filled triangle.
  - Co7: the UA triangle sits beside stroked chevrons, and the header shows "● Saved to server" before anything exists.
- **Empty, phone**
  - H7: the "Select a notebook" heading (~24px) outranks the empty-state title (~20px).
  - T7: two competing heading sizes in one column.
  - D6: doubled rules at y303 and y328, and the status row sits about 20px above the title.
  - C8: token surfaces and one accent fill.
  - A7: same issues as desktop.
  - Co7: mixed disclosure vocabulary.
- **Editor, desktop**
  - H7: the only accent-filled control is `Comment` (sampled rgb 191,63,24 light, 245,134,95 dark), while header Save is outlined, so the accent marks a secondary task.
  - T8: 15/22.5 Space body in strong ink.
  - D7: comments start at y790 with the compose row pinned to the fold.
  - C8: tokens only, with a slim selection rail.
  - A7: ink tools are borderless text, and the section mover is a native `<select>`.
  - Co7: `.comments` combines `border-top` with a 16px radius (`styles.css:142,190`), drawing curved corner stubs at y790.
- **Editor, phone**
  - H8: title first, and no accent competes above the fold.
  - T8: clean steps.
  - D7: two 48px disclosure bars and a meta row precede the title.
  - C8.
  - A7: the native select.
  - Co7: the native select beside ky controls.
- **Management, desktop**
  - H7: the pane is well grouped, but the main area still carries the accent `Comment`.
  - T8.
  - D7: Account is pinned after a ~380px gap.
  - C8.
  - A7: in light, the avatar chip fill equals the pane (both 242,239,231) and reads as a bare "0 owner"; it is visible in dark.
  - Co7: as in the editor.
- **Chooser, phone**
  - H7: management (y120–549) pushes the title to y685, and Save stays in the header.
  - T8.
  - D7: about 430px precede content.
  - C8.
  - A7: the light avatar chip is invisible.
  - Co7: the chip treatment differs by theme.
- **Pages, phone**
  - H7: there is no in-content title, the recovery nudge is the first row, and header Save shows with no editor visible.
  - T8.
  - D8: an even ~71px row rhythm that scales.
  - C8.
  - A7: the search field border (light 114,119,119; dark 155,157,154) does not match the adjacent `+` (light 167,171,172; dark 120,125,123).
  - Co7: UA triangle beside chevrons.
- **Appearance, desktop**
  - All dimensions 8: one card vocabulary and an unambiguous selection.
  - Swatch hues are theme previews (data).
  - The header `Settings` link has no current-page state.
  - The last card row is cut by the capture fold.
- **Appearance, phone**
  - H8.
  - T7: orphan "security.".
  - D7: section links wrap to three rows, pushing the cards to y570.
  - C8.
  - A8: the radio cards are unambiguous.
  - Co8.

## Arithmetic (scripted, exact Decimal)

```
total = (0.20*H + 0.15*T + 0.20*D + 0.15*C + 0.15*A + 0.15*Co).quantize(0.1, ROUND_HALF_UP)  # exact Decimal sum
7.5 = 1.6+1.2+1.4+1.2+1.05+1.05   6.95 -> 7.0   7.30 -> 7.3   7.65 -> 7.7   8.00
Notes:    sum 102.8 / 14 = 7.342857… -> 7.3   min 7.0
  empty   sum  29.0 /  4 = 7.25      -> 7.3   min 7.0
  rest    sum  73.8 / 10 = 7.38      -> 7.4   min 7.3
Settings: sum  31.4 /  4 = 7.85      -> 7.9   min 7.7
```

- 6.95 is computed as an exact Decimal; the float path also gives 6.95, so it rounds to 7.0.
- Means are taken over the rounded per-file totals.
- I also replayed `build-report.py`'s per-row check read-only on this JSON: 22 rows conform, and the weights match.

## Order and prior exposure

1. I scored all 18 current unique images at original resolution and froze the vectors at 2026-10-26T21:09:07-04:00 (sha256 `912b06c3…`) before opening any prior numeric report.
2. After freezing:
   - A `grep` of `build-report.py` showed the strings "Gemini raw 8.1" and "Handoff 6.7".
   - I loaded `opus-round4.json` and `sol-round4.json` for drift and spread.
   - I assigned the stage-07 empty matched-calibration vectors. They are therefore post-exposure, and disclosed as such.
3. From the brief, I knew that Sol round 4 was satisfied and that Opus round 4 had blocked, but I saw no numbers.

**Re-inspection, one change.** Appearance phone `visible_affordances` went from 7 to 8. Sol's score differed by 2. The bare-text section links are the same items I scored 8 on desktop, and the radio cards are unambiguous. This was a correction for consistency, not averaging. The frozen values are kept in the JSON `reinspection` field.

## Drift against my round 4 (stage-07 counterparts)

| View | Round 4 → round 5 | Δ | Cause |
| --- | --- | ---: | --- |
| empty desktop | 6.5 → 7.5 | +1.0 | Product change: New notebook and first-run copy |
| empty phone | 6.9 → 7.0 | +0.1 | Product change offset by stricter heading/rule reading |
| editor desktop | 8.2 → 7.3 | −0.9 | Correction: round 4 missed the accent `Comment` and the `.comments` radius stubs; timestamp-only pixels |
| editor phone | 8.0 → 7.5 | −0.5 | Correction: native select, duplicated disclosure bars; timestamp-only |
| management desktop | 8.0/8.2 → 7.3 | −0.7/−0.9 | Correction: as editor, plus the light avatar fill equals the pane; timestamp-only |
| chooser phone | 7.6/7.8 → 7.3 | −0.3/−0.5 | Correction: light avatar; timestamp-only |
| pages phone | 8.2 → 7.5 | −0.7 | Correction: search/`+` outline mismatch, header Save without an editor; byte-identical |
| Appearance desktop | 8.3 → 8.0 | −0.3 | Calibration: color 9 was not earned; byte-identical |
| Appearance phone | 8.0 → 7.7 | −0.3 | Calibration: wrapped section links and orphan text; byte-identical |

- **Mean drift:** −0.6 on images that are unchanged or differ only by timestamp; +0.6 on the changed empty views; −0.3 overall.
- **Direction:** drift is downward, so it cannot inflate the result. It is still a reviewer-variance signal: the same model scored byte-identical images 0.3–0.9 higher in round 4.
- **What this means:** treat about ±0.5 as the inter-session noise floor. Re-scoring unchanged images measures calibration, not product change.

## Spread against Sol round 4 (stage-07 counterparts; Sol has not scored stage 08)

My totals run 0.5–1.2 lower than Sol's. Dimensions with a gap of 2 or more were re-inspected; the editor, management and pages scores were kept, with the pixel evidence above.

- Editor H 7 vs 9.
- Management Co 7 vs 9.
- Pages H and Co 7 vs 9.
- Empty Co 7 vs 9: a different image, since stage 07 had no action.
- Appearance phone A 7 vs 9: corrected to 8, as described above.

## Product delta, stage 07 → 08 (same fixture and capture conditions)

- **Changed views:** only the empty state changes in product terms. With matched calibration (stage-07 empty vectors: desktop 5/8/7/8/5/7 = 6.6, phone 5/7/6/8/5/7 = 6.3):
  - Empty desktop: +0.9.
  - Empty phone: +0.7.
  - Notes mean: 7.1 → 7.3 (+0.2).
- **Not product improvements:** save times, user initials and caret pixels.
- **Owner baseline:** the owner's raw 6/10 is an unknown-build layout rejection. It is not subtracted as a numeric baseline.

## Blocker to a scoped 8 (O5-1)

The Notes cohort sits at 7.3. The gap is visual polish present since stage 07.

**Fix, existing classes and tokens only, no new feature:**

1. **Accent `Comment` button.** `Comment` is the accent fill in every editor and management view (`styles.css:82` default button fill; the comment submit is not `.secondary`). Give it `className="secondary"`, matching the header Save contract.
2. **Comment corner stubs.** `.comments` is in the 16px radius rule (`styles.css:190`) while it draws only a `border-top`. Drop it from that rule.
3. **Invisible light avatar.** The light avatar chip uses `var(--panel-hover)` (`styles.css:484`), which equals the pane. Give it a visible token fill or border.
4. **Empty-state heading conflict.** With zero notebooks, the pane heading "Select a notebook" contradicts the list and, on phones, outranks the empty-state title, above a doubled rule. Retitle or hide it, and drop the duplicate rule.
5. **Mixed controls.** The recovery `summary` uses the UA triangle beside stroked chevrons. The section mover is a native `<select>` with the OS chevron, and the search and `+` outlines differ.

The projected gain to 8 or above after re-capture is **unproven**.

## Non-blocking

- Appearance phone: section links wrap to three rows, and the subtitle leaves an orphan "security.".
- The header `Settings` link has no current-page state.
- Empty desktop shows "● Saved to server" before anything exists.
- The empty-editor copy keys on `!selected && !queueMode`. If notebooks exist but none is selected, it would still say "Start with a notebook". Startup selects the first notebook, so this is rare. Unverified.

## Gates (screenshots alone cannot pass a gate)

| Gate | Status | Evidence |
| --- | --- | --- |
| single left region | pass (scripted) | Edge scan of the stage-08 desktop captures: only x239/240; `ffd3471`, index `00dcf80d` |
| keyboard | untested by me | `openWorkQueue` now focuses the persistent toggle (`main.tsx:1590`), as `chooseNotebook` does; parent reports 12/12 browsers; not re-run |
| focus | untested | No focus-ring captures for `New notebook` or the toggle |
| contrast | untested | Pixel samples only; the light avatar chip boundary is 1.00:1 against the pane |
| states | partial | Empty first run captured; loading, error, team, conflict and Work queue not captured |
| responsive | partial | Manifest overflow 0 at 390 and 1280; no tablet width |

I did not run Computer Use or the live preview. The fixture is reserved, the review must not mutate it, and first-notebook creation would. Root reported Computer Use on the same bundle (18105).

## Limits

- This is a scoped 8/10 progression decision only. I make no full-9, competitor or whole-suite claim.
- WebKit, the full state/theme/focus/role matrix and tablet widths are unproven.
- Gemini stays deferred until both primaries are satisfied. Its raw results and the parent audit are unchanged.
