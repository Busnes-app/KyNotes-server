# KyNotes Council, round 10: Claude Opus 5.5

**Verdict: Notes 8.0/10 (112.0/14 = 8.000). Settings 8.0/10 (32.0/4 = 8.000). The cohorts are never pooled. Both are satisfied for the scoped visual 8/10 progression. Ky fit is 8.0 (separate; suite_cohesion N/A).**

Scope: the stage-13 capture set (councilRound 10). It holds 14 unique Notes views (empty ×4, editor ×4, management ×4, phone page chooser ×2) and 4 Settings/Appearance views. Every unique image scores 8.0, but that is a visual result only. It is not a keyboard/focus, contrast, states, WebKit, full-9 or suite-cohesion acceptance.

**Confidence**
- **Notes: high.** Pixel changes are save timestamps only, and every vector equals round 9.
- **Settings: moderate.** The mean is exactly 8.0 with no margin. One point less in density on either phone image would give 7.9.

## Evidence verified

**Inventory (`inventory-v13.json`)**
- Inventory file: sha256 `0066dbe7…`, 85,258 bytes.
- All 262 rows match SHA-256, bytes and PNG dimensions, and the PNG set on disk equals the inventory.
- There are 198 exact-SHA groups and 148 representatives. No SHA group has more than one representative. The 114 `duplicate_of` links are all direct (no chains) and each points to the earliest filename.
- I re-diffed every link in RGBA:
  - Exact links: 0 changed pixels.
  - Near links: the recorded changed_pixels, max delta and bbox all match. The maximum changed fraction is 4.56e-5, and every max delta is ≤ 8.

**Current manifest (`13-after-manifest.json`)**
- 22 captures reduce to 18 unique views: 14 Notes and 4 Settings.
- The 4 workspace aliases differ from their editor captures by 12 px (light) and 15 px (dark), max delta 4. They inherit the editor scores and are excluded from means.
- 8 current files are byte-identical to stage 12: empty ×4, desktop Appearance ×2 and pages ×2.
- The 8 editor, workspace and navigation captures differ from stage 12 only in the save-timestamp band.
- Phone Appearance light and dark carry the substantive change: about 114k px from y130 down.

**Source and bundle**
- All 9 source pins match.
- `git -C web diff ad52fda HEAD -- src` is 971 bytes and its sha256 is `d436a733…`, which matches the manifest. The diff is exactly the three phone rules in `styles.css`.
- These index files are all `7646814…`: `web/dist`, `internal/web/dist` (`diff -qr` clean), the live 18114 server and the manifest. The live JS and CSS are byte-equal to the embedded copies.
- HEAD is `1ab04e64de747f409d88b98f02682e85862defe1` and the worktree is clean.

**Repeatability**
- The tree `155ee40d…` exists. It differs from HEAD's tree `3430e654…` only under `docs/ui-notes-eight/` and in one AGENTS.md prose line, so the code is identical.
- The parent `/tmp` json records two byte-identical binaries, `71a7029b…`.

**Parent checks:** I read the logs only and reran nothing.
- Units: 599 tests in 47 files passed.
- Browser suite: 12 passed.
- Capture: 1 passed in 26.3s.
- Probe: all 14 steps ok.
- Apply-setup: passed.
- Build: passes, with the existing >500kB chunk warning.

## Native check (own incognito tab, 18114, synthetic owner; native Chromium 154 ≠ scored Chromium 156)

| | 390×844 | 800 | 1280×900 |
|---|---|---|---|
| Settings links | 3×2 grid, each 115×40 (parent's tab measured 110; a scrollbar difference). 14px, padding 8px 4px, centred | 6 in one row, 124×40 | vertical, 203×40, 44px step |
| Subtitle | 2 balanced lines (199/172px), no orphan | — | — |
| Overflow | 0 | 0 | 0 |
| Picker | 23 radios, `system` checked, `kynotes-theme` unset; all 6 hrefs present | | |

I created and edited no content, pressed no Save and saved no theme. I did not retest focus and did not check 320px. The tab is closed.

## Scores (ky-suite-v2, H/T/D/C/A/Co = .20/.15/.20/.15/.15/.15, Decimal half-up)

I viewed all 18 images individually at original resolution and fixed my scores before opening any prior score file. I wrote no blind file, because this review may write only its two reports.

`checks.json`, which I read earlier, holds no per-image or round-9 primary scores. It does quote an earlier Gemini raw aggregate, which I disregarded.

| Unique view (stage 13), light + dark | Vector | Total | Round 9 Opus | Pixels vs stage 12 |
|---|---|---:|---:|---|
| empty-desktop | 8/8/8/8/8/8 | 8.0 | 8.0 | byte-identical |
| empty-mobile | 8/8/8/8/8/8 | 8.0 | 8.0 | byte-identical |
| editor-desktop | 8/8/8/8/8/8 | 8.0 | 8.0 | timestamp only |
| editor-mobile | 8/8/8/8/8/8 | 8.0 | 8.0 | timestamp only |
| navigation-desktop | 8/8/8/8/8/8 | 8.0 | 8.0 | timestamp only |
| navigation-mobile | 8/8/8/8/8/8 | 8.0 | 8.0 | timestamp only |
| pages-mobile | 8/8/8/8/8/8 | 8.0 | 8.0 | byte-identical |
| appearance-desktop | 8/8/8/8/8/8 | 8.0 | 8.0 | byte-identical |
| **appearance-mobile** | 8/8/**8**/8/8/8 | **8.0** | 7.8 | link grid, subtitle, content shift |

- **Notes (n=14):** 14 × 8.0 = 112.0, mean 8.000 → **8.0**, min 8.0. Round 9: 112.0.
- **Settings (n=4):** 4 × 8.0 = 32.0, mean 8.000 → **8.0**, min 8.0. Round 9: 31.6 (7.9).
- **Ky fit:** palette, type geometry, shell and accent are 8 on every file; suite_cohesion is N/A; mean **8.0**.

**Phone Appearance density 7 → 8**
- In stage 12 the six links wrapped 3/2/1, the subtitle left an orphaned "security." and the link band filled y185–390.
- In stage 13 the grid is an even 3×2 of 40px cells, the subtitle balances over two lines, and the theme cards start 44px higher (y527 vs y571).
- What remains is an alignment mix: the left-aligned "← Workspace" link sits above a centred grid. That is a minor slip, not a 7-level defect.

## Drift (after the blind pass: opus-round9, sol-round9, round9-evidence-audit)

- **Product-attributable:** only phone Appearance light and dark, +0.2 each (density 7 → 8), and only inside changed pixels.
- **Unchanged pixels:** the other 16 views were re-scored identically. No calibration was applied, and no |Δ| reached 0.5.
- **Mean change:** Notes +0.000. Settings +0.1, and all of it comes from the two changed phone files. Desktop Appearance is byte-identical and its score did not move.
- **Spread vs Sol 9 (context only):** no dimension differs by 2 or more. The maximum is 1: empty hierarchy/affordances, Appearance affordances, and phone management and phone Appearance density. I did not read sol-round10.

## Findings

- **B9-S resolved.** This was my round-9 Settings objection. The capture and my native 390 check both show the 3×2 grid and the balanced subtitle, with overflow 0.
- **O10-1 (non-blocking polish).**
  - The phone back link is left-aligned above a centred grid.
  - "Trusted Device" breaks sentence case.
  - No correction is needed for 8. If pursued, the fix is copy-only sentence case.
- **O10-2 (evidence note).** The repeatability tree is not HEAD's tree, but they differ only in docs and AGENTS prose. The binary claim stands for HEAD's code.
- **Carried, unchanged pixels (non-blocking):**
  - The phone chooser's recovery disclosure sits 44px below the bar.
  - The desktop body sits at x303 against the title at x278. This is deliberate: it preserves the stored canvas geometry.
  - The empty state shows "Saved to server" before anything is saved.
  - The header Settings link has no current state.
  - Dark unselected radios are UA grey.
  - Notebook commands share the nav-row style.
- **Focus residual (not retested).**
  - Opening the first phone page from a notebook with no open page can leave BODY focused (Sol 6–9).
  - This blocks any keyboard/focus acceptance claim.
  - No content or save failure is established.

## Gates (scoped)

| Gate | Result |
|---|---|
| Keyboard | Untested by me; known focus residual |
| Focus | Untested; known focus residual |
| Contrast | Untested by me this round |
| States | Partial: empty and populated only |
| Responsive | Partial pass: captures at 390/1280 and native 390/800/1280 show overflow 0. The unchanged 320 overflow of 15px is parent-reported |

Still unproven: WebKit, named-theme renders, roles, loading/error states, dense teams, soft keyboard and the full contrast matrix. The Settings sections below Appearance are unscored and unknown. The existing BlockNote CSP/placeholder/viewport warnings, the 603kB chunk warning and the two detector exceptions remain.

## Result

- **score:** 8.0. Notes is 8.0 and Settings is 8.0, each separate.
- **satisfied:** true for both covered cohorts' visual 8/10 progression. Every-image 8 holds visually; full behavior acceptance is not implied.
- **blockers:** none.
- **Gemini:** not invoked. It may run only after both current primaries are satisfied, and the parent consolidates.
- **Merge/deploy:** not authorized by this review.
- **Written:** `docs/ui-notes-eight/opus-round10.md` and `docs/ui-notes-eight/opus-round10.json`.
