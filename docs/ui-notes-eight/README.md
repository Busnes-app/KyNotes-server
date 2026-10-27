# KyNotes: scoped 8/10 progression

The current stage is **13-after**, Council round10. Both primary reviewers are
satisfied across the covered visual cohorts: **Notes Opus8.0 / Sol8.1** and
**Appearance Opus8.0 / Sol8.2**. KyNotes clears this evidence-supported visual8
progression gate; KyPulse is next. Opus Appearance confidence is moderate at
exactly8.0. Sol's expanded phone management is7.8 within its Notes mean, so
this is not an every-image agreement or full-product acceptance.

Gemini's round10 raw **Notes8.0 / Appearance8.1**, satisfied, is retained but
excluded from the screenshot progression rating: its harness could not visually
read original PNGs and it used the live browser instead. The [round10 audit](gemini-round10-audit.md)
checks the arithmetic, supports the main layout facts, and corrects the input
path, pixel counts and unsupported precise recovery spacing. No further Gemini
run or product change follows that audit.

Round10 uses three phone Settings CSS rules for even wrapping links and a
balanced subtitle; Appearance starts44px higher at390px. All23 theme choices
remain. Its599units/12full browsers, fresh capture, Docker/probe/setup and
repeatable build checks passed. First-open phone focus and full9/browser/state/
role/theme/contrast/softkeyboard limits remain explicitly unproven.

Gemini’s raw **8.1/10, satisfied** is retained in `argon-round3.md/json`.
Its changed weights, inconsistent Settings scores and unsupported claims make it
unsuitable for the progression decision. [Parent audit](gemini-audit.md) records
every supported, rejected and deferred item. No product changes followed the audit.

## Review entry points

- [Round history](COUNCIL.md), with original model reports beside it.
- [Spreadsheet](KyNotes-Council.xlsx): raw round verdicts, per-image dimensions,
  inventory, matched pairs, checks and method notes.
- [Offline before/current comparison](comparison.html).
- [Verification record](checks.json).
- Shared source change: [ky-ui #25](https://github.com/Busnes-app/ky-ui/pull/25),
  version 0.4.2, commit `cbc37bf9d607f2a3558c899f139165818202434d`.

- Original UI pass: [KyNotes #118](https://github.com/Busnes-app/KyNotes-server/pull/118), merged.
- Current single-pane correction: [KyNotes #119](https://github.com/Busnes-app/KyNotes-server/pull/119).

## What changed

- One left navigation pane; keyboard focus returns when choosing a notebook or Work queue. A late background load cannot close management.
- Visible first-notebook creation in the empty editor; no management detour or hidden key/setup guidance.
- Strong-ink Space editor text and restrained headings; desktop panels fit the viewport.
- Phone notebook/account disclosure and a separate page chooser that shows all four
  fixture pages immediately. Later page-chooser selections return focus to the title; the first-open limitation is documented below.
- Reselecting the current page preserves pending saves and the live editor content.
- One outlined header Save, consistent navigation icons and Settings selection.
- A compact recovery-code disclosure retains the original warning and action.
  Other key/conflict warnings remain visible.
- Shared status colors follow the selected named palette's scheme, independently
  of the OS. Shared field borders have measurable contrast.

## Capture provenance

Original base: `34849c4d0766901fdf33556855373aa122666049`. Current captures
are from head `ad52fda1ad5f06c0b4f71ef55deb50cfad9b5b10` plus the recorded source patch and
explicit file hashes. Current served index SHA256:
`764681485d4035a7b5b95e6253a418dcab1ff0315676588d8349fe0b166e4810`.

`inventory-v13.json` contains262 PNGs /148 normalized unique across all stages. Current stage13
has22captures/18unique:14Notes (including4empty and2desktop management views)
and4Settings. Four workspace aliases are excluded from means. Stages05/06 were
preliminary attempts whose reviews were interrupted before completion; earlier
inputs and completed round4/5/6/7 reviews remain frozen. The comparison uses stage12 and stage13, including matched empty screens. Stage13 capture passed on its first attempt. Its9source-file pins now include CanvasPage.tsx. inventory-v9 added exact near-duplicate diff bounds and neutral rasterization labels; duplicate-metadata-audit.json records corrections to earlier caret wording without rewriting frozen inventories, images or scores.

Chromium 156.0.8078.4, scale 1; desktop 1280×900 and phone 390×844; OS light/dark
emulation, no saved theme choice, real disposable server, synthetic owner and
Project Atlas with four populated pages. Screenshots come through the real UI.
A supplemental light960x900 native T3 capture verifies one-pane geometry and computed control styles; it is not full tablet acceptance. Native T3 Computer Use navigation and CSS inspection supplement the full-resolution
capture set; native preview snapshots are not substituted into scored inputs.

Rubric: `ky-suite-v2`, hierarchy .20 / typography .15 / density .20 / color .15 /
visible affordances .15 / coherence .15. Decimal half-up totals; raw reviewer
verdicts are preserved independently, never averaged across models. Ky fit is separate.

Historical6.7 and current scores have different coverage and cannot establish a
controlled improvement. Page-picker/navigation comparisons also change state;
the workbook identifies those unmatched pairs. The trailing empty bullet is fixture
content. No new competitor ranking or whole-suite cohesion score is claimed.

## Limits and remaining polish

Sol round6 observed BODY focus on a first phone page opening from a no-open-note list; later chooser selection focuses its title. This existing startup-path residual is retained outside the bounded CSS pass. Full focus acceptance is not claimed.

WebKit, the complete empty/loading/error matrix and every product theme/focus/role
path are not certified by this pass. Shared palette probes do not certify all product
overrides. Optional polish remains in small metadata,
light avatar separation and minor icon/divider consistency. These remain outside this bounded visual pass. Round10 covered visual verdicts are complete and satisfied.

The design detector retains two narrow existing findings: the semantic 3px key/conflict
warning rail and the legacy 4px user-colored section border overridden to 2px.
These are intentional semantic indicators; no broad suppression was added.
The existing approximately 603kB lazy BlockNote chunk-size warning remains. Native
Chromium154 also reports BlockNote CSP/style-insertion and viewport-widget warnings;
the dependency lock, integration and strict CSP are unchanged from the baseline.
Dynamic placeholder styling and soft-keyboard resizing remain uncertified.
govulncheck reports zero reachable vulnerabilities and one module-only advisory
in an uncalled dependency path.

## Reproduce the reports

Run `python3 docs/ui-notes-eight/build-report.py` from the repository root.
It validates inventory hashes/dimensions and score arithmetic, then generates the
workbook, round table and self-contained comparison. The evidence AGENTS.md records
capture commands and isolation requirements. `checks.json` records the local checks;
current-head CI and autonomous review are separate PR gates. No merge or deployment
is authorized by this report.

Historical inventory counts were corrected without changing any image or score; see [round9-evidence-audit.json](round9-evidence-audit.json). The corrected stage12 has184 exact SHA groups and138 normalized representatives; stage13 extends that record to262 images/148 representatives. Earlier inventories remain frozen.

An extra native320px check reproduced15px horizontal overflow from the unchanged body min-width320px and classic scrollbar; the round9 fixture shows the same result. Scored390/1280 and the extra800px native check have zero overflow. This is not full small-device acceptance.
