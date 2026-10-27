# KyNotes UI council: Opus round 1

Reviewer: Claude Opus 5.5, acting as the review sub-agent. This was a read-only review; the only writes are this file and `opus-round1.json`.
Scope: branch `ui/notes-eight` on base `34849c4`. The AFTER bundle has `servedIndexSha256` `bb1a3b7d159d…` and the BEFORE bundle `1a66f5d20695…`.
Rubric: `ky-suite-v2`. Weights are .20/.15/.20/.15/.15/.15, with totals rounded half-up to one decimal (computed with `Decimal`).

## Verdict

**Score: 6.5/10. Not satisfied.**

The diff delivers real gains in the editor:

- Space Grotesk 15px body text in ink-strong.
- Restrained 19.5px H2 headings.
- A 28px/600 title.
- The phone editor now leads with the page.

These raise the editor captures by +0.7 on desktop and +1.6 on phone.

What keeps the scope below 8:

- The new phone "Pages in…" disclosure opens onto chrome and shows **no page rows**.
- Re-tapping the open page clears unsaved state without saving it (found in source).
- The new danger token is not theme-aware in 15 of the 22 themes.
- Several older visible defects remain on the surfaces under review.

## Inventory and duplicates

- 32 files. All 16 AFTER files were viewed at full resolution, blind to the before images and to any prior scores.
- **Correction to `inventory.json`:** in the AFTER set, each workspace capture is a rubric *near-duplicate* of its editor counterpart. At most 0.0046% of pixels differ, with a max channel delta of 4, confined to the caret/cursor box. The inventory lists them as unique. They are scored once on the editor file (first by name) and are excluded from the means.
- The 4 `before-appearance-*` files are byte-identical to their AFTER counterparts, so Appearance is unchanged by this diff.
- In the BEFORE set, mobile workspace, editor and pages are exact duplicates (`e044f9…` light, `0a8c49…` dark).
- That leaves **12 unique AFTER images**: 8 in the `notes` cohort and 4 in `settings`.

## Per-image scores (AFTER, unique)

| File | hier | type | dens | color | afford | coher | **total** | ky_fit (4-dim mean) |
|---|---|---|---|---|---|---|---|---|
| editor-desktop-light | 7 | 7 | 6 | 7 | 7 | 6 | **6.7** | 7.0 (8/7/7/6) |
| editor-desktop-dark | 7 | 7 | 6 | 7 | 7 | 6 | **6.7** | 7.0 |
| editor-mobile-light | 8 | 7 | 7 | 8 | 6 | 6 | **7.1** | 7.3 (8/7/6/8) |
| editor-mobile-dark | 8 | 7 | 7 | 8 | 6 | 6 | **7.1** | 7.3 |
| pages-mobile-light | 4 | 7 | 4 | 7 | 4 | 6 | **5.2** | 6.3 (7/7/5/6) |
| pages-mobile-dark | 4 | 7 | 4 | 7 | 4 | 6 | **5.2** | 6.3 |
| navigation-mobile-light | 7 | 6 | 6 | 8 | 7 | 6 | **6.7** | 7.0 (8/6/6/8) |
| navigation-mobile-dark | 7 | 6 | 6 | 8 | 7 | 6 | **6.7** | 7.0 |
| appearance-desktop-light | 8 | 8 | 7 | 8 | 6 | 7 | **7.4** | 7.5 (8/8/6/8) |
| appearance-desktop-dark | 8 | 8 | 7 | 8 | 6 | 7 | **7.4** | 7.5 |
| appearance-mobile-light | 8 | 8 | 7 | 8 | 5 | 7 | **7.2** | 7.5 (8/8/6/8) |
| appearance-mobile-dark | 8 | 8 | 7 | 8 | 5 | 7 | **7.2** | 7.5 |

- ky_fit columns are palette_tokens/type_geometry/shell/accent_discipline. `suite_cohesion` is N/A because only Notes was inspected.
- Cohort means (unique AFTER files): **notes 6.43 (n=8)** and **settings 7.30 (n=4)**. These are Ky-only, with no competitors in scope, so there is no Ky gap.
- `opus-round1.json` has one justification per dimension, plus confidence and caveat for each file. All rows are high confidence.

## Matched deltas against BEFORE

| Surface | Before | After | Matched | What changed |
|---|---|---|---|---|
| Editor, desktop | 6.0 | 6.7 | yes | BlockNote moved from Inter, muted grey and 36px headings to Space with ink-strong text; the 38px light title became 28px/600; the footer actions are now in view. Useful correction. |
| Editor, phone | 5.5 | 7.1 | yes | The page leads; the list collapses behind a disclosure; headings no longer wrap at 36px. Biggest win. |
| Pages, phone | 5.5 | 5.2 | **no** | Before had no disclosure. Both show the same 16rem list box holding heading plus callout and **zero rows**; after, that box is the explicit destination of a control. |
| Navigation, phone | 6.5 | 6.7 | **no** | After has Research notes open (the test picked it); before has Launch checklist. The drawer itself is unchanged. |
| Appearance | = | = | yes | Byte-identical. |

Notes cohort mean: before 6.0 (n=6), after 6.43.

## Issues, prioritised

### P1: the phone "Pages in Project Atlas" disclosure shows no pages

Evidence: `after-pages-mobile-{light,dark}`. After expanding, the region contains only:

- the section tab
- "Project Atlas / Notebook"
- the recovery callout

It ends at y≈473, and the editor resumes underneath.

Cause: a pre-existing rule caps the list at 256px with an inner scroll: `styles.css:449` sets `.workspace > .note-list { max-height: 16rem; overflow-y: auto; }`. The e2e passes because Playwright auto-scrolls `.note-row` into view; a person sees no navigation targets and no cue that the region scrolls.

Fix (one rule, no feature change): lift the cap when the user explicitly asked for the list, for example `.workspace.show-page-navigation > .note-list { max-height: none; }`. Then add a visual assertion to the e2e that the first `.note-row` is inside the viewport without scrolling (`toBeInViewport()`).

### P2: tapping the already-open page clears the dirty flag without saving (source-derived, unproven in a browser)

- `main.tsx` onClick for the same id closes the panel, focuses the title, **then still calls `selectNote(note)`**.
- `selectNote` skips `flushOpenPage` for the same id, but runs `markDirty(false)` (main.tsx ~1605).
- That cancels the 900ms and 15s autosave timers (main.tsx:1346-1361).
- It also makes the next `flushOpenPage` a no-op (main.tsx:1895), while the header reads "Saved to server" and the footer reads "Saved".
- The edits survive only in the in-memory list and the local draft.
- The path is easiest to hit on a conflicted page (never autosaved, so it stays dirty), or within 900ms of typing.
- The bug pre-dates this diff on desktop, but the diff makes "tap the current page to close the list" a deliberate phone path.

Fix: `return` after the same-id branch instead of falling through to `selectNote`. Add an e2e: type a change, open "Pages in…", tap the same page, and assert the "Unsaved changes" status and that a PUT is sent.

### P2: the new danger token is not theme-aware in 15 of 22 themes; the contrast gate likely fails

`.secondary.danger` and `.editor-actions .danger.quiet` now use `var(--danger)`. Only 5 palettes define `danger`: patina, cyber, nord, paper and oled.

For the other 15 named themes:

- `applyTheme` removes `data-theme` (theme.ts:16).
- `--danger` then resolves through `:root:not([data-theme])` to the busnes value **for the OS scheme**, not the theme's scheme (tokens.css:69-107).

Measured against each theme's panel colour:

- **2.14–2.75:1** when the OS scheme is the opposite of the theme's. Examples: Forest on a light OS gets `#b42318` on `#1f2f24` = 2.14; Light Matter on a dark OS gets `#ff8176` on `#fff8ee` = 2.30.
- Nord's own danger is 2.46:1 in every case.

The captured images use Match system, so they cannot show this. Fix in ky-ui, not as a product copy: give every palette `danger`/`success`, or derive them from `theme.scheme`. Then measure all 22 themes with computed styles.

Also:

- `styles.css:308` `.section-menu > .danger { color: #b42318 }` is still hard-coded and stays unreadable in dark themes.
- Product `AGENTS.md:36` still records "Destructive `secondary danger` controls have no danger hue: a known residual". Update it in the same change, or the contract and the code disagree.

### P2: the footer primary says "Saved" in filled accent while the page is clean

Evidence: `after-editor-desktop-*`, footer at x≈1159.

- The button is enabled (main.tsx:3149-3153), so it reads as the view's primary action when there is nothing to do.
- It sits beside the header's outlined "Save", which is a second save control.
- The result spends the accent on a no-op and splits hierarchy.

Suggested fix, which keeps the feature: style the clean state as `.secondary`, and the dirty state ("Save now") as the filled primary.

### P3: visible polish blocking 8 on Notes surfaces

- **Two unlike phone disclosures stacked** (`after-editor-mobile-*`): "Notebooks and account" is bold 16px with a 20px `+`; "Pages in…" is muted 14px with a small `+`. Give them one style; the muted one reads like a caption, not a control.
- **Sidebar action sizes**: "+ New notebook" renders about 14px next to about 17px "Rename notebook" and "Export notebook" (desktop and drawer).
- **Gaps**: the empty "Team notebooks" leaves a ~40–50px gap. Page rows carry a ~40px empty left gutter before the titles.
- **Footer spacing**: the actions are spread unevenly (Indent/Outdent/Delete/Saved at 708/875/1055/1159px) and sit right on the 900px fold, with the next section's border cut at y≈897. That reads as clipped, not scrollable.
- **Selection treatments**: there are three of them (left rail on rows, underline plus grey top border on the section tab, underline on the tool). On the phone, the notebook selection uses a bottom border where desktop uses a left rail. That clashes with the contract's "slim accent rail".
- **Heading sizes**: BlockNote H2 is overridden to `1.3em`, which equals BlockNote's default H3 (`Block.css:171`), so H2 and H3 now render the same size. This is not visible with this fixture; set level 3 lower (for example 1.15em).
- **Line height**: editor body line-height is 1.6, outside the contract's 1.4–1.5 (minor).
- **Text-box hover outline**: `.canvas-box .bn-container { border: 0 }` (0,2,0) zeroes the border width, so `.canvas-box:hover .bn-container { border-color }` no longer outlines a positioned text box on hover. The hover background is `--panel` on `--panel`, so it is invisible too. Only the 10px handle shows, and the invisible right-edge resize strip loses its visual bound. Confirm on the desktop canvas.
- **Settings/Appearance** (unchanged): no current item in the settings nav; the phone nav is clipped at "Truste" with no scroll cue; the header "Save" and "Saved to server" appear on Settings, where nothing is editable.

## Behaviour checks requested

**Phone page pick, different id.** Proven by the e2e:

- the list hides
- focus lands on the "Page title" textbox
- the editor loads Research notes

**Phone page pick, same id.**

- Focus return works in source.
- It is untested in e2e.
- It carries the dirty-state hazard described under P2.

**Focus inside hidden tabs.**

- When the list is collapsed, `.note-list` and `.section-tabs` are `display:none`, so they are not focusable. Good.
- **Risk (unproven):** on a page change, the new effect also calls `setShowNotebookNavigation(false)`. If the change starts from a button inside the notebook drawer (Work queue, or another notebook that opens a page), the drawer hides under the focused element and focus falls to `<body>`; no focus target is set because `showPageNavigation` was false. Test it, and move focus to the page title or the toggle.
- Note also that "Pages in…" reveals the section tabs too, so the label understates what it controls.

**Saving.**

- Different-id picks still go through `flushOpenPage`.
- The same-id path does not (see P2).

**Desktop scrollers.**

- The three columns scroll independently.
- The 72px header is fixed-height on desktop, so `calc(100dvh - 72px)` holds.
- The canvas keeps its own inner scroller nested in the editor scroller, as before.
- The only visible problem is the footer sitting on the fold.

**Fonts and colours.**

- The manifest confirms the AFTER editor computes `15px / 24px Space` in `rgb(24,35,38)` (light) and `rgb(242,239,232)` (dark), with no horizontal overflow at 390 or 1280.
- Only the Space and Mono font faces loaded.

**Danger hover.**

- The editor Delete hover now uses `--panel-hover` with a danger border.
- That is fine where `--danger` is right, and inherits the theme problem above.

**Canvas coordinates.** No source change writes positions; only padding and font changed, so saved boxes reflow inside their stored widths. I did not and do not ask for any rewrite of saved positions.

## Gates

Screenshots cannot pass these.

| Gate | Status |
|---|---|
| keyboard | **partial**: different-id focus is proven; same-id and drawer paths are untested |
| focus | untested |
| contrast | **likely fail**, derived from source; see the danger-token issue |
| states | untested |
| responsive | **partial**: overflow is 0 at 390 and 1280, but the phone page targets are hidden behind an inner scroll |

## What would move this to ≥8

1. Fix P1 and make the e2e prove that rows are visible.
2. Add the same-id early return, with a test.
3. Make danger theme-aware in ky-ui, measured across all 22 themes, and update `AGENTS.md:36`.
4. Give the clean-state footer Save a non-accent style.
5. Unify the two phone disclosure styles and the sidebar action sizes.
6. Make the footer read as scrollable or settled, not clipped.

Then re-capture. Expected notes cohort if these land cleanly: around 7.8–8.2. I would re-score from new images, not from this estimate.
