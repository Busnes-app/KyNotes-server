# KyNotes council — GPT Sol, round 1

**7.8/10 for the notes cohort; satisfied: false.** The open editor is an 8.3-level visual result, but the expanded phone page picker falls short and two preservation/accessibility issues need correction. The current progression target is 8, not the historical 9. Gemini remains deferred.

Only these two report artifacts were written. Product source and instructions were not changed.

## Read first

1. **P1 — Opening Pages shows no pages.** In both `after-pages-mobile` captures, the 256px pane shows the notebook heading and recovery notice, then ends above Search and every page row. Native inspection of the exact after bundle measured pane y217–473, Search y505, first row y616, scrollTop 0. Rows are reachable by scrolling and native keyboard focus; this is a substantial discovery/initial-layout defect. Keep the recovery message available while showing search and useful page destinations immediately. `web/src/styles.css:449` is the fixed 16rem cap. Verify the initial pane viewport before Playwright scrolls a locator into view.

2. **P1 — Same-page dismissal acknowledges unsaved work.** `web/src/main.tsx:3012` closes/focuses on the current row but continues into `selectNote`. At `1599` that same-id call skips `flushOpenPage`; at `1604` it clears dirty unconditionally. Dirty-driven autosave/retry at `1346` then stops, and the next leave skips its flush. The encrypted draft remains queued, so this is not a claim of proven permanent loss. The shared defect predates the diff, but the new same-page dismissal branch still invokes it. Return after close/focus, or make the shared same-id selection preserve document/save state. Cover a dirty current page with a delayed/refused save. Source-confirmed; no edit/fault-injection test was run by this reviewer.

3. **P1 — Existing field boundaries fail the contrast gate.** Native computed styles for `.note-search` and `.editor-actions select` produce **1.57:1 light / 2.06:1 dark** after compositing their quiet divider borders against their surfaces. The contract requires 3:1. Use the existing `--ky-field-border`, not a new palette value, then measure every shipped theme. This inherited issue is measured separately from visual scoring.

4. **P2 — Remaining bounded polish.** Header Save is 32px and move-section is 35px against 40px canvas controls; the idle editor still shows a filled **Saved** button plus top Save. Appearance does not visibly mark the current settings section. Fix these with existing styles and routing; no shell rewrite or product feature expansion is warranted.

## Scores and duplicate correction

All sixteen AFTER files were viewed at original 1280×900 or 390×844 resolution. Scores were fixed before opening BEFORE images or any earlier reviewer scores. The supplied inventory was independently checked against hashes, byte sizes and dimensions: all 32 match.

The rubric also excludes near duplicates. Four AFTER workspace files differ from their editor counterparts by only 12–15 pixels, max channel delta 4; two BEFORE desktop workspace files differ by 9–13 pixels, max delta 7. These six aliases are **additional** to the eight exact duplicate rows. They inherit their first filename’s scores and do not increase any mean. There are **12 unique AFTER images** and **18 unique images across both stages**. The structured report records every file, exact/near pairs and measurements.

| Stage / cohort | Unique n | Mean |
|---|---:|---:|
| after / notes | 8 | 7.8 |
| after / settings | 4 | 7.9 |
| before / notes | 6 | 6.9 |
| before / settings | 0 | N/A — duplicate aliases |

These are single-product cohort summaries, not rankings. No cross-cohort or provider mean is used. Ky fit is separate and never added to quality; `suite_cohesion=N/A` because only Notes captures were inspected.

The following AFTER rows list hierarchy, typography, density/layout, color, visible affordances and coherence, in that order. The JSON supplies one concrete visible justification for **each** quality and Ky-fit dimension on every unique image, along with confidence, caveats and exact hashes.

| Unique AFTER file (screenshots/) | H/T/D/C/A/Co | Quality | Ky fit |
|---|---|---:|---:|
| kynotes-02-after-appearance-desktop-dark.png | 8/8/8/9/8/8 | 8.2 | 8.3 |
| kynotes-02-after-appearance-desktop-light.png | 8/8/8/9/8/8 | 8.2 | 8.3 |
| kynotes-02-after-appearance-mobile-dark.png | 7/8/7/9/7/8 | 7.6 | 8.0 |
| kynotes-02-after-appearance-mobile-light.png | 7/8/7/9/7/8 | 7.6 | 8.0 |
| kynotes-02-after-editor-desktop-dark.png | 8/9/8/9/8/8 | 8.3 | 8.3 |
| kynotes-02-after-editor-desktop-light.png | 8/9/8/9/8/8 | 8.3 | 8.3 |
| kynotes-02-after-editor-mobile-dark.png | 8/9/8/9/8/8 | 8.3 | 8.5 |
| kynotes-02-after-editor-mobile-light.png | 8/9/8/9/8/8 | 8.3 | 8.5 |
| kynotes-02-after-navigation-mobile-dark.png | 8/8/7/9/8/8 | 8.0 | 8.3 |
| kynotes-02-after-navigation-mobile-light.png | 8/8/7/9/8/8 | 8.0 | 8.3 |
| kynotes-02-after-pages-mobile-dark.png | 6/8/5/9/5/7 | 6.6 | 7.5 |
| kynotes-02-after-pages-mobile-light.png | 6/8/5/9/5/7 | 6.6 | 7.5 |

Weights: .20/.15/.20/.15/.15/.15. Totals and cohort means were calculated with Decimal and rounded half-up to one decimal. Confidence is high for visible facts; it does not imply behavior was proven by screenshots.

## Baseline comparison and corrections

- Desktop editor: **7.0 → 8.3** in both themes. The 28px page title, strong Space body text and smaller semibold document headings remove the competing scales. The footer is now within the captured working surface.
- Phone editor: **6.1 → 8.3** in both themes. Closing notebook/page chrome reveals the paragraph and checklist within one screen; the content heading no longer wraps as a large two-line display. This is an improvement to existing note reading, not a reason to move persisted boxes.
- Appearance is **byte-for-byte unchanged** in all four captures. Its inherited score delta is zero. Its baseline duplicate rows are excluded from counts and means.
- The notebook navigation comparison is **unmatched**: after selects Research notes, before Launch checklist. Fresh server fixtures also change account initials and times. Its numerical 7.6 → 8.0 is not a defensible matched product-improvement claim.
- The expanded Pages state is also not equivalent to the baseline’s always-present pane. Both baseline phone pane captures lack visible rows at initial scroll. The new disclosure improves editor space but still needs to reveal its promised destinations.
- The historical 145px toolbar/body gap was not reproduced here. The manifest measures 44px desktop / 34px phone after; the supplied first-line baseline finding is 38px. These fixtures do not justify changing saved canvas coordinates. The trailing empty bullet is fixture content, not a product defect.

## Behavior and source review

The existing synthetic server at `127.0.0.1:18094` served index SHA `bb1a3b7d159d985ac9e9e8cced3482bad33ed7505036d3d5119aa70fa142e8ea`, matching the AFTER manifest. Port 18080/18092 served baseline index `1a66f5d…`; no baseline login or data mutation was performed. The native collaborative browser is Chromium 154, distinct from the Chromium 156 scoring captures. No servers or suites were started.

- **Same and different page ids:** pointer selection closes the phone pane and focuses `.title-input` for both. A native Tab/Enter traversal of the current row also closes/focuses correctly. This confirms focus handling, not the dirty-state guarantee criticized above.
- **Hidden tab focus:** after dismissal, hidden page/section controls have no rendered boxes; Tab from the title reaches Type outside hidden navigation. The selected native page button has `aria-current="page"`.
- **Save preservation:** different-id selection still awaits `flushOpenPage` before changing notes, and a refused flush returns without switching. The effect changes only navigation/focus. Same-id behavior needs SOL-2. Existing draft, encryption, theme storage and CSP paths are not edited in the inspected diff.
- **Desktop scrolling:** shell measures exactly 828px beneath the 72px header at 1280×900. Editor and canvas are nested vertical scrollers; PageDown from title moved the outer editor toward its bottom controls. Nothing was proven trapped. Nested scrolling on a long document and WebKit remain unverified; do not remove canvas overflow needed for free placement.
- **Fonts/color/danger:** live `.bn-editor` reports `15px / 24px Space` with strong ink. Hovered Delete reports `rgb(180,35,24)` on light and `rgb(255,129,118)` on dark, with matching danger borders; semantic danger survives hover. The new selectors preserve token aliases. Other danger surfaces and named themes were not exhaustively sampled.

| Acceptance gate | Result | Evidence / limit |
|---|---|---|
| keyboard | untested | Exact after fixture, native Tab path: Pages toggle -> Quick Notes -> New section/group -> Create recovery code -> Search -> New page -> Research notes; Enter closes/focuses title; next Tab reaches Type, outside hidden navigation. Different-id pointer selection also focuses title. Other task paths/dialogs not exhaustively checked. |
| focus | untested | Native dark Quick Notes showed 2px accent outline and Type 3px accent outline; title focus return observed for same/different selection. Every control in both themes was not measured. |
| contrast | fail | SOL-3: computed border/background samples yield 1.57:1 light and 2.06:1 dark for Search and move-section. All other 22-theme combinations remain untested. |
| states | untested | Provided inventory covers populated editor, navigation and Appearance. No complete empty/loading/error capture set. |
| responsive | untested | Supplied after manifest records overflow=0 at 390/1280; native fixture also has zero desktop overflow and usable row navigation. Expanded phone pane composition fails SOL-1. All scope paths and WebKit not checked. |
| save_preservation | fail | SOL-2 source trace. Different-id path retains flushOpenPage; same-id path unconditionally clears dirty. No mutation-based save test run by reviewer. |

The reported 599 unit passes, initial frontend/Go build, vet/embed consistency and new e2e pass were supplied by the task, not re-executed here. Go race and full browser completion are outside this reviewer’s evidence. The new e2e covers different-id phone focus, but Playwright auto-scrolls the row and therefore does not catch SOL-1; it does not cover dirty same-id selection. All 22-theme contrast and WebKit remain unproven.

## Scope and closeout

This was the explicitly requested independent council sub-review using `ky-suite-v2`, with Impeccable principles, TypeScript guidance and the simplicity skill used as supporting review guidance. No further council agents, detector workflow, external research or unrelated capability suggestions were introduced. No other-product captures or prior scores were read; no provider spread is invented. Questions skipped: the supplied brief and evidence were sufficient.

DOX pass: root/worktree contracts were reviewed. AGENTS.md is intentionally unchanged because the deliverable is evidence and recommendations, with no implementation or new durable behavior contract. The worktree AGENTS.md still describes the old danger-color residual; the implementation owner should correct that stale sentence when closing out the actual UI change.

Review artifacts: [structured scores and verdict](sol-round1.json), [this report](sol-round1.md). The review is complete; implementation changes and verification remain with the parent task.
