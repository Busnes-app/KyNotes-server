# KyNotes UI council: Opus round 4 (stage 07)

Reviewer: Claude Opus 5.5, acting as the review sub-agent. This was a read-only review; the only writes are this file and `opus-round4.json`.

**Input:** the 22 `screenshots/kynotes-07-after-*.png` files and `07-after-manifest.json` (councilRound 4).
- Head `d9c413f` plus source diff `8e2a6bd7…`.
- Served index `ec3b1526…`.
- Chromium 156.0.8078.4 at scale 1, 1280x900 and 390x844, OS light/dark emulation.
- Synthetic Project Atlas fixture.

**Rubric:** `ky-suite-v2`, weights .20/.15/.20/.15/.15/.15. Totals are rounded half-up by `Decimal` in a script.

## Verdict

**Notes: 7.7/10** (mean 7.66, n=14, min 6.5). **Settings: 8.2** (mean 8.15, n=4, min 8.0). **Satisfied: false** for the scoped 8/10 progression. This is not a 9/10 acceptance.

- **The owner's double-left objection is resolved in every captured state.** A scripted scan found exactly one full-height vertical divider at x239/240 in all six desktop captures (empty, management, editor; both themes). The stage-04 control capture shows two dividers, at x240 and x500. On phones everything sits in one column.
- **One blocker (B1): the first-run empty state hides every forward action.**
  - The four empty views average **6.70**.
  - The ten populated Notes views average **8.04** (min 7.6).
  - The empty state decides the verdict.

## Owner objection, state by state

| State | Single left region | Notes |
|---|---|---|
| Empty, desktop | Yes | Layout fixed; discoverability fails (B1) |
| Management, desktop | Yes | Management replaces the page list in the same 240px track; editor at x240 |
| Selected editor, desktop | Yes | Sections, search and pages are in the one pane. The e2e asserts list x=0, w=240, editor x=240 (`ui-council.e2e.ts:114-122`) |
| Phone | Yes | Notebook and page disclosures stack in one column |
| Settings | Yes | Same 240px shell as the workspace |

The owner's round-3 score of 6/10 is preserved separately in `owner_baseline`. Its screenshot has an unknown build, so it is a layout rule and a rejection, not a numeric baseline for stage 07.

## Blocker

**B1: the first-run empty state hides every forward action.** It occurs on all four `empty-*` captures.

- **Why it happens.** Startup selects a notebook only when one exists (`main.tsx:1438`), and no notebook is created at sign-up. A new account therefore lands on the following:
  - The pane heading says "Select a notebook" (`main.tsx:2882`), but no notebook list is visible.
  - The management toggle starts closed (`main.tsx:655`), and `.workspace > .sidebar` is `display: none` until it opens, so New notebook is hidden.
  - The new-page + is disabled.
  - The centre says "Select a note or create one", but "Create a note" renders only when a notebook is selected (`main.tsx:3226-3228`).
- **Desktop regression.** At `d9c413f`, the desktop toggle was `display: none` and the sidebar, including New notebook, was always visible. Phones already hid it behind the disclosure, so on phones this is a carried defect.
- **Smallest fix (existing state, no new feature).** While no notebook and no work queue is selected, treat management as open: derive `open = showNotebookNavigation || (!selected && !queueMode)` for the class and `aria-expanded`. Then re-capture the four empty views.

## Per-image scores (CURRENT, unique, scored before reading priors)

| File | hier | type | dens | color | afford | coher | **total** | ky_fit |
|---|---|---|---|---|---|---|---|---|
| empty-desktop-light | 6 | 8 | 6 | 8 | 5 | 6 | **6.5** | 8.3 |
| empty-desktop-dark | 6 | 8 | 6 | 8 | 5 | 6 | **6.5** | 8.3 |
| empty-mobile-light | 7 | 8 | 7 | 8 | 5 | 6 | **6.9** | 8.3 |
| empty-mobile-dark | 7 | 8 | 7 | 8 | 5 | 6 | **6.9** | 8.3 |
| navigation-desktop-light | 8 | 8 | 8 | 8 | 8 | 8 | **8.0** | 8.5 |
| navigation-desktop-dark | 8 | 8 | 8 | 9 | 8 | 8 | **8.2** | 8.8 |
| editor-desktop-light | 8 | 8 | 8 | 9 | 8 | 8 | **8.2** | 8.8 |
| editor-desktop-dark | 8 | 8 | 8 | 9 | 8 | 8 | **8.2** | 8.8 |
| editor-mobile-light | 8 | 8 | 7 | 9 | 8 | 8 | **8.0** | 8.5 |
| editor-mobile-dark | 8 | 8 | 7 | 9 | 8 | 8 | **8.0** | 8.5 |
| pages-mobile-light | 8 | 8 | 8 | 9 | 8 | 8 | **8.2** | 8.5 |
| pages-mobile-dark | 8 | 8 | 8 | 9 | 8 | 8 | **8.2** | 8.5 |
| navigation-mobile-light | 7 | 8 | 7 | 8 | 8 | 8 | **7.6** | 8.3 |
| navigation-mobile-dark | 7 | 8 | 7 | 9 | 8 | 8 | **7.8** | 8.5 |
| appearance-desktop-light | 8 | 8 | 8 | 9 | 8 | 9 | **8.3** | 8.8 |
| appearance-desktop-dark | 8 | 8 | 8 | 9 | 8 | 9 | **8.3** | 8.8 |
| appearance-mobile-light | 8 | 8 | 7 | 9 | 8 | 8 | **8.0** | 8.5 |
| appearance-mobile-dark | 8 | 8 | 7 | 9 | 8 | 8 | **8.0** | 8.5 |

- `ky_fit` is a separate 4-dimension mean (palette tokens, type geometry, shell, accent discipline). Suite cohesion is N/A. It is never added to the total; the mean over unique images is 8.5.
- Per-dimension observations are in the JSON.

## What was preserved

- **Sections:** captured. SectionTabs sit inside the page list with an add-section +.
- **Search:** captured. Page search sits beside new page, on desktop and phone.
- **Teams:** in source only, not captured.
  - The management view still renders the Team notebooks label, nested team notebooks, New team notebook, Add person and members (`main.tsx:2794-2870`).
  - Desktop now hides `.notebook-kind`, so the page view no longer says "Team notebook".
  - The visual state is unproven.
- **Keyboard:** checked in source only.
  - `chooseNotebook` focuses the always-visible toggle after a user's choice (`main.tsx:1495-1499`).
  - The startup load calls `selectContainer` directly, so it does not close management.
  - The brief reports the full suite 12/12; I did not re-run it.
- **Discoverability:**
  - Populated views: the labelled toggle and its chevron are visible in every state.
  - Empty view: fails (B1).

## Non-blocking

1. The light-theme avatar chip still shares the sidebar surface (`styles.css:484`).
2. The recovery disclosure keeps the UA's filled triangle beside the stroked chevrons.
3. `main.tsx:1493-1494`: two doc comments above `chooseNotebook` describe `selectContainer`. Move them there.
4. `docs/ui-notes-eight/AGENTS.md:28` still names `inventory-v3.json` as current, while line 9 says v6.
5. Two manifest fields were not written by the capture:
   - `councilRound` and the `e2e/people.ts` hash are added after capture; `ui-council.e2e.ts:153-154` writes neither.
   - `06-after-manifest.json` also says councilRound 4, although it describes the preliminary stage-06 set.

## Inventory and capture inputs

- **inventory-v6:** 130 PNGs and 96 unique non-duplicate entries (98 distinct SHA-256). All hashes, byte counts and dimensions were recomputed and match.
- **CURRENT:** 22 captures, of which 18 are unique (14 Notes, 4 Settings). All 22 hashes match the manifest.
- **Excluded:** the four `workspace-*` captures are near-duplicates of `editor-*`. Each differs by 12–15 px inside one caret box, with a max channel delta of 4; I measured this myself.
- **Byte-identical across stages:**
  - Settings x4 are identical to stages 04–06.
  - Empty x4 and pages x2 are identical to stages 05–06.
  - The phone editor and phone navigation captures differ from stage 04 only in the save timestamp.
- **Source and served bundle:**
  - All `sourceFiles` hashes match `web/`.
  - The embedded `index.html` and live `http://127.0.0.1:18104/` both hash to `servedIndexSha256` `ec3b1526…`.
  - HEAD moved to `701a97e`/`98b63f8` during the review. `git diff d9c413f HEAD -- web/src` hashes exactly to the manifest's `sourceDiffSha256`, so the committed source is the captured source.

## Drift (disclosed)

**What I saw before scoring.** I scored blind, with one exception: inspecting the `opus-round3.json` schema showed me its 8.1 verdict and two per-file vectors before I scored. Every other prior report was opened only after scoring.

**Reviewer drift on unchanged pixels** (same bytes or timestamp-only differences):

| File | Round 3 | Round 4 |
|---|---|---|
| appearance-desktop | 8.8/8.7 | 8.3 |
| editor-mobile | 8.2 | 8.0 |
| navigation-mobile | 8.0/8.2 | 7.6/7.8 |

**Product change:**

| File | Round 3 | Round 4 | Cause |
|---|---|---|---|
| editor-desktop-light | 8.0 | 8.2 | Adjacent page column removed; notebook title reduced |
| pages-mobile | 8.0 | 8.2 | Section tabs nested in the list |

**Sensitivity:** with my round-3 vectors substituted for the timestamp-only phone captures, Notes = 108.4/14 = 7.74, which rounds to **7.7**. The verdict does not change.

## Gates and limits

- **Single-left geometry: pass (scripted pixel scan).**
- **Keyboard: claimed pass, not re-run here.** The brief reports it.
- **Focus: untested.** There are no focus-ring captures.
- **Contrast: untested.** I took no computed measurement.
- **States: partial.** Loading, error, team, work-queue and conflict states are uncaptured.
- **Responsive: partial.** Overflow is 0 at 390 and 1280. The 801–1100px breakpoint was removed, and there is no capture at that width.
- **Full 9/10: unproven.** It needs WebKit, every state, focus in both themes, and a tablet width.
- **No competitor score and no whole-suite claim.** Gemini was not invoked.
- **Live inspection:** `GET /` on :18104 only. No sign-in, no mutation, no source edits.

## Path to 8

Fix B1 and re-capture the four empty views. The populated Notes views already average 8.04 (min 7.6), so the empty views decide the cohort mean.
