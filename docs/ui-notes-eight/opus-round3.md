# KyNotes UI council: Opus round 3 (stage 04)

Reviewer: Claude Opus 5.5, acting as the review sub-agent. This was a read-only review; the only writes are this file and `opus-round3.json`.
Input: the 16 `screenshots/kynotes-04-after-*.png` files and `04-after-manifest.json`. They were captured at head `34849c4` with served index `191fb200e296…` in Chromium 156.0.8078.4 at scale 1, using the synthetic Project Atlas fixture with 4 pages and OS light/dark emulation.
Rubric: `ky-suite-v2`. Weights are .20/.15/.20/.15/.15/.15, and totals are rounded half-up by `Decimal` in a script.

## Verdict

**Notes: 8.1/10 (mean 8.10, n=8, every view ≥ 8.0). Settings: 8.4 (mean 8.38, n=4). Satisfied: true** for the 8/10 visual progression. This is not a 9/10 acceptance.

Every round-2 blocker is visibly fixed:

- The picker's first row now sits around y≈360, down from y≈590.
- The footer select renders in Space.
- Both navigation disclosures use the same chevron.
- There is one green status voice, and the tab is flat.
- The id-tail avatar is gone.
- On phone, Settings leads with its h1.

The margin is thin. Four Notes views sit at exactly 8.0, each held there by a coherence slip.

## Inventory

- 16 CURRENT files. SHA-256, bytes and dimensions were recomputed and match `inventory-v3.json` and the manifest.
- `web/src/styles.css` and `main.tsx` hash to the manifest's `sourceFiles`.
- Each `workspace-*` capture is a near duplicate of its `editor-*` counterpart. Each pair differs by 12–15 px (≤0.0046%) at the caret, with a max channel delta of 4. Each pair is scored once, on the editor file.
- That leaves **12 unique images**: 8 `notes` and 4 `settings`.
- The other 48 files in inventory-v3 are earlier stages and were not scored.

## Per-image scores (CURRENT, unique, scored blind)

| File | hier | type | dens | color | afford | coher | **total** | ky_fit (4-dim) |
|---|---|---|---|---|---|---|---|---|
| editor-desktop-light | 8 | 8 | 8 | 9 | 8 | 7 | **8.0** | 8.3 (9/8/7/9) |
| editor-desktop-dark | 8 | 8 | 8 | 9 | 8 | 8 | **8.2** | 8.3 |
| editor-mobile-light | 8 | 8 | 8 | 9 | 8 | 8 | **8.2** | 8.5 (9/8/8/9) |
| editor-mobile-dark | 8 | 8 | 8 | 9 | 8 | 8 | **8.2** | 8.5 |
| pages-mobile-light | 8 | 8 | 8 | 9 | 8 | 7 | **8.0** | 8.5 |
| pages-mobile-dark | 8 | 8 | 8 | 9 | 8 | 7 | **8.0** | 8.5 |
| navigation-mobile-light | 8 | 8 | 8 | 9 | 8 | 7 | **8.0** | 8.3 (9/8/7/9) |
| navigation-mobile-dark | 8 | 8 | 8 | 9 | 8 | 8 | **8.2** | 8.3 |
| appearance-desktop-light | 9 | 9 | 8 | 9 | 9 | 9 | **8.8** | 8.5 (9/9/7/9) |
| appearance-desktop-dark | 9 | 9 | 8 | 9 | 8 | 9 | **8.7** | 8.5 |
| appearance-mobile-light | 8 | 8 | 7 | 9 | 8 | 8 | **8.0** | 8.5 (9/8/8/9) |
| appearance-mobile-dark | 8 | 8 | 7 | 9 | 8 | 8 | **8.0** | 8.5 |

- The ky_fit columns are palette_tokens/type_geometry/shell/accent_discipline. `suite_cohesion` is N/A because only KyNotes was inspected. The ky_fit mean across unique files is 8.4, and it is never added to the total.
- All rows are high confidence.
- The JSON has one visible observation per dimension for every file.

### Visible facts behind the scores

**Editor, desktop**

- "Launch checklist" leads the page, and Save is the only quiet 40px header button.
- Colour is restrained: one green "Saved to server", orange only on selection, and a muted meta timestamp.
- Three things keep it at 8:
  - "Project Atlas" in the list column renders at the same glyph height as the page title (17px caps), so two titles compete.
  - Canvas text starts 25px right of the title edge (x564 vs x538).
  - The Comments area opens as a rounded bordered box, and the recovery disclosure uses the UA filled triangle.

**Light-only defect (pixel-sampled)**

- In light, the "O" avatar has no visible chip. Every sample around it equals the sidebar colour (242,239,231), because `.avatar` takes `var(--panel-hover)` (`web/src/styles.css:474`).
- Beside "owner" it reads like a stray zero.
- In dark the chip is visible. This is why the light desktop editor and light phone navigation views score coherence 7, and their dark twins score 8.

**Editor, phone**

- Both disclosures are 48px rows with the same stroked chevron.
- The select is in Space, and the edges hold at 16px.
- The canvas is inset 17px for the BlockNote gutter.

**Pages, phone**

- All four rows fit, and the first row band starts around y≈360.
- There is no repeated notebook heading.
- Coherence is 7 for two reasons:
  - The recovery summary's native filled triangle sits on the same screen as the two chevron disclosures.
  - The dividers mix full-bleed and 16px-inset styles.

**Navigation, phone**

- The rows keep an even rhythm and use SVG icons.
- The gap after Project Atlas is larger than the others.
- The account region shows a name only, with no role or sign-out (Lock is in the header).

**Appearance, desktop**

- The type follows the contract exactly: 24/17/15/13px.
- The 5-column shared radio-card grid is clean, and orange marks only the current item and the selected card.
- "← Workspace" sits 4px left of the nav labels.
- In dark, unselected radios are filled grey discs that read closer to disabled than unchecked.

**Appearance, phone**

- The h1 now leads.
- The nav block takes about 205px in three wrapped rows, with three left edges (x16/26/30).
- The subtitle leaves the orphan "security.".

## Blockers below 8

None. The non-blocking fixes below are cheap and would add margin:

1. Give `.avatar` a surface that differs from the sidebar in both themes. The round-2 avatar fix works only in dark.
2. Use the shared chevron for the "Save a recovery code" summary instead of the UA triangle.
3. Drop the desktop list-column notebook title one size step, so the page title is the only 24px title.
4. Align the phone Settings nav block to the 16px edge.

## Gates (separate from scores)

| Gate | Status | Evidence |
|---|---|---|
| keyboard | untested here (claimed pass) | The brief reports passes for the stage-04 focus, held-save and recovery-disclosure keyboard tests. I did not re-run them. |
| focus | untested | No focus captures. The source rule `.recovery-notice summary:focus-visible` exists (styles.css:477). |
| contrast | untested (source improved) | `styles.css:7` routes every text input, textarea and select border to `--ky-field-border`, and the auth, settings, comment, check-code and admin selectors use it. That clears the round-2 source finding. No computed measurement here. |
| states | untested | No empty, loading or error captures. |
| responsive | partial | Overflow is 0 at 390 and 1280 in all 16 captures. Target sizes were not measured. |

These remain unproven: WebKit, focus rings in both themes, and the empty/loading/error matrix.

## Drift and disagreement audit (prior reports opened after scoring)

| View | Opus r2 | Sol r2 | Opus r3 | Δ vs Opus r2 | Cause |
|---|---|---|---|---|---|
| editor-desktop L/D | 7.5 | 8.2 | 8.0 / 8.2 | +0.5 / +0.7 | product: compact notice, one status voice, flat tab, Space select. Light is held by the avatar. |
| editor-mobile L/D | 7.5 | 8.2 | 8.2 | +0.7 | product: Space select, chevrons, editor padding 24→16 |
| pages-mobile L/D | 6.8 | 7.8 | 8.0 | +1.2 | product: first row moved from y≈590 to y≈360; repeated heading removed |
| navigation-mobile L/D | 7.7 | 8.2 | 8.0 / 8.2 | +0.3 / +0.5 | product: avatar and chevrons. Light is held by the invisible chip. |
| appearance-desktop L/D | 7.8 | 8.7 | 8.8 / 8.7 | +1.0 / +0.9 | **correction, not product.** See below. |
| appearance-mobile L/D | 7.5 | 8.1 | 8.0 | +0.5 | product: h1 first. Colour 8→9 is a correction. |

**Appearance, desktop.** Stage 03 and stage 04 differ only by a ~6px vertical shift of the content. My +1.0 is therefore Opus-reviewer drift toward the anchors, and it lands near Sol's 8.7.

- Round 2 Opus scored contract-exact type and an unambiguous grid at 8, and density at 7.
- Part of the reason was cross-screen and source-contrast findings that are not visible in this capture.
- This drift moves only the Settings mean, not the Notes verdict.

**Mean drift.** The mean Ky delta is +0.7. Excluding the two corrections it is also +0.7: Notes moves through product change.

**Dimension disagreements of 2 or more points**, resolved by re-inspection rather than averaging:

- **Pages hierarchy and density: 6/6 → 8/8.** Rows now start around y≈360 with no repeated heading. Product change.
- **Pages coherence: Sol r2 8, Opus r3 7.** Kept at 7. The triangle and the chevrons are both visible on one screen.
- **Light vs dark (new this round).** I split light and dark only where the avatar chip disappears. The pixel samples are in the JSON.

Live fixture: not used, and no content was mutated. Scratch scripts were run from `/tmp/opus-r3-scripts` and are outside the product.
