# KyNotes Council, round 9: Claude Opus 5.5

**Verdict: Notes 8.0/10 (8.000), satisfied for scoped 8/10 progression. Settings 7.9 (separate, not pooled). Ky fit 8.0 (separate; suite_cohesion N/A).**

Scope: the stage-12 capture set (councilRound 9). It covers the KyNotes editor, the empty state, single-left-region management, the phone page chooser and Appearance. This report makes no full-9, keyboard/focus, accessibility, WebKit, competitor or whole-suite claim. Settings at 7.9 shows the same pixels as stage 10, so it does not support a whole-app 8.

## Evidence verified

**Inventory (`inventory-v11.json`)**
- All 240 rows match their SHA-256, bytes and PNG dimensions, and the PNG set on disk equals the inventory.
- There are 78 `duplicate_of` links: 32 exact and 46 near. I re-diffed every pair. All are under 0.1% changed pixels with max delta ≤ 8, the recorded counts match, and there are no chains.
- **O9-1 (non-blocking):** 10 exact-SHA groups in stages 04–07 are left unlinked. These are Appearance ×4, plus empty ×4 and pages ×2 in stages 05–07, totalling 24 rows. "162 unique" is therefore 138 by exact SHA. This is a historical overcount only; the stage-12 rows are correct.

**Current manifest (`12-after-manifest.json`)**
- All 22 captures match hash, bytes and dimensions, with overflow 0. They reduce to 18 unique: 14 Notes and 4 Settings.
- The 4 workspace aliases differ from their editor captures by 12 px (light) and 15 px (dark), max delta 4. Every changed pixel is on the left or right edge column of the selected Type chip, i.e. corner antialiasing, not a caret. They inherit the editor scores and are excluded from means.
- 6 current files are byte-identical to stages 10 and 11: empty-desktop ×2 and Appearance ×4. They stay in coverage but get no improvement credit.

**Source and bundle**
- All 9 source pins match the worktree, and all 12 vendored ky-ui 0.4.2 files match `VERSION`.
- `git -C web diff edb5425 HEAD -- src` hashes to `5fe19270…`, matching the manifest. It touches only `main.tsx` and `styles.css`.
- These all have index SHA `a43a6013…`: `web/dist`, `internal/web/dist` (`diff -qr` clean), the live 18112 server and the manifest. The live JS/CSS/CanvasPage assets are byte-equal to the embedded ones. The served CSS contains both round-9 rules.
- Worktree HEAD is `d18ef1a298b4410391d53f077d8503c9765b526f`, whose parent is the manifest head `edb5425`.

**Parent-reported checks:** I read the unit and browser logs (599/47 passed; 12 passed) and re-ran nothing. Docker, the archive repeatability SHA `c3018f48…`, Go and fuzz/race/vuln remain parent-reported.

## Native check (own incognito tab, 18112, synthetic owner; native ≠ scored Chromium 156)

| | Desktop 1280×900 | Phone 390×844 |
|---|---|---|
| Section-add | 40×40, radius 8px, SVG plus, rgb(24,35,38) | 40×40, 8px, 16px SVG |
| Page-add | 40×40, radius 8px, SVG plus, rgb(24,35,38) | 40×40, 8px, 16px SVG |
| Title vs body | title x278, body x303 (`bn-editor` padding 16px 24px, unchanged) | title text x16, body x17 (`bn-editor` padding 16px 0) |
| Overflow / regions | 0 / one visible 240px left pane | 0 |

I created and edited no content, saved no theme and did not re-test first-open focus. The tab is closed.

## Scores (ky-suite-v2, .20/.15/.20/.15/.15/.15, Decimal half-up)

Vector order is H/T/D/C/A/Co. Scores were blind-frozen at 02:44:16Z in `/tmp/opus-r9-crops/blind.json` (sha256 `527bce58…`), before I opened any prior score.

| Unique file (stage 12), both themes | Blind | Final | Total | Round 8 | Changed pixels vs stage 11 |
|---|---|---|---:|---:|---|
| editor-desktop | 8/8/8/8/8/8 | same | 8.0 | 7.9 | plus pair + timestamp only |
| editor-mobile | 8/8/8/8/8/8 | same | 8.0 | 7.8 | timestamp + body reflow |
| empty-desktop | 8/8/8/8/8/8 | same | 8.0 | 8.0 | byte-identical |
| empty-mobile | 8/8/8/8/8/8 | same | 8.0 | 7.8 | heading block moved 24px |
| navigation-desktop | 8/8/8/8/8/8 | same | 8.0 | 8.0 | timestamp only |
| navigation-mobile | 8/8/8/8/8/8 | same | 8.0 | 8.0 | timestamp + body text |
| pages-mobile | 8/8/**7**/8/8/8 (7.8) | 8/8/8/8/8/8 | 8.0 | 7.9 | the two plus controls only |
| appearance-desktop | 8/8/8/8/8/8 | same | 8.0 | 8.0 | byte-identical |
| appearance-mobile | 8/8/7/8/8/8 | same | 7.8 | 7.8 | byte-identical |

**Notes (n=14):**
- Final: sum 112.0 / 14 = **8.000 → 8.0**; minimum 8.0.
- Blind: 111.6 / 14 = 7.971 → 8.0.
- Round 8: 110.8 / 14 = 7.914.

**Settings (n=4):** 8.0 + 8.0 + 7.8 + 7.8 = 31.6 / 4 = **7.9**.

**Ky fit:** palette, type geometry, shell and accent are 8 on every file; suite_cohesion is N/A; mean **8.0**. Type geometry recovers from 7 because the 12px radius is gone.

## Drift (after the freeze I read opus-round8, sol-round8 and round8-findings-audit)

**Product-attributable changes** (every one falls inside pixels the patch changed):
- **editor-desktop, coherence 7→8 (+0.1):** the plus pair is now one control.
- **pages-mobile, coherence 7→8 (+0.1):** same fix.
- **editor-mobile, density 7→8 (+0.2):** body x33 → x17, measured on ink.
- **empty-mobile, density 7→8 (+0.2):** the status row now sits 28px below the rule and 41px above the heading. In stage 11 it was 28px and 17px, so the row read as the heading's caption.

**One calibration.** My blind pass gave pages-mobile density 7. That was for the recovery-code disclosure placement and the 9px-vs-19px tab-to-search gap. Those pixels are unchanged since stage 11, where Opus 8 and Sol 8 both read density 8 without misreading the image. That leaves no anchor, cohort, correction or artifact cause, so I kept the prior 8. This is the same rule round 8 applied to its *higher* blind reading. The verdict does not depend on it: blind 7.971 and final 8.000 both round to 8.0.

**Totals:**
- Notes mean drift is +0.0857 (110.8 → 112.0). Max |Δ| is 0.2, so no file needs a ≥0.5 explanation.
- Settings Δ is 0.
- Competitor drift is N/A.

**Spread:** I did not read sol-round9. Against Sol 8, no dimension differs by 2 or more on any file; the maximum is 1.

## Findings

- **B8-1 resolved.** Both add controls are 40×40 with an 8px radius and the same 16px strong-ink NavIcon plus, in the capture and natively, light and dark.
- **B8-2 resolved.** On phone the body aligns with the title (x17/x17) and the empty status row has separated from the heading. Desktop geometry and stored coordinates are unchanged.
- **O9-1 (non-blocking):** the inventory has 24 unlinked exact duplicates in stages 04–07. Smallest fix: link them in a new inventory version, or document the per-stage convention.
- **O9-2 (non-blocking, unchanged pixels):** the phone page chooser opens with the account-level recovery-code disclosure 44px below the Pages bar, and its tab strip sits 9px above Search versus 19px on desktop.
- **O9-3 (deliberate):** the desktop body sits at x303 against the title at x278. This preserves the stored canvas coordinates.
- **O8-3 carried items (non-blocking):**
  - Empty desktop shows "Saved to server" before anything exists.
  - Header Settings has no current state.
  - "Trusted Device" breaks sentence case.
  - Phone Settings wraps 3/2/1 and leaves an orphan "security.".
  - Dark unselected radios are UA grey.
  - Notebook commands share the nav-row style.
  - The desktop editor shows save status three times.
- **Focus residual (not re-tested):** the first phone page opening from a notebook with no open page can leave BODY focused. It blocks any keyboard/focus acceptance claim. No save or content failure is established, and it does not affect these visual scores.

## Gates (scoped)

| Gate | Result |
|---|---|
| Keyboard | Untested by me; known focus residual |
| Focus | Untested; known focus residual |
| Contrast | Untested this round. Add-control ink is the strong token; prior placeholder ratios not re-verified |
| States | Partial: empty and populated only |
| Responsive | Partial pass: 390 and 1280, overflow 0 (manifest and native) |

Still unproven: WebKit, named themes, loading/error states, dense teams, soft keyboard, tablet and the full contrast matrix. The existing BlockNote CSP/style/viewport warnings, the 603kB build warning and two narrow detector findings remain.

## Result

- **score:** 8.0. Notes mean is 8.000; Settings 7.9 is reported separately.
- **satisfied:** true. This covers scoped Notes 8/10 progression only.
- **blockers:** none.
- **Gemini:** may now run only once the second primary is also satisfied. I did not invoke it.
- **Merge/deploy:** not authorized by this review.
