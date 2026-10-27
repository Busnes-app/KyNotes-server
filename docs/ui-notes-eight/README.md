# KyNotes: scoped 8/10 progression

The current stage is **11-after**, Council round8. The owner rejected the old
adjacent columns at6/10. Round7 Opus7.8/Sol8.2 confirmed the control corrections,
but Opus found dark placeholders at3.16:1 and workspace affordance slips. The
[findings audit](round7-findings-audit.json) accepts both. Round8 themes placeholders,
separates toolbar modes/commands, gives section creation a bordered40px plus and
uses a neutral inbox for Work queue. Native placeholder samples measure6.19:1
light/7.48:1 dark. Fresh reviews are pending after599units/12full browsers passed.
No current8/10 or full9/10 is claimed.

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
  fixture pages immediately. Choosing a page returns focus to its title.
- Reselecting the current page preserves pending saves and the live editor content.
- One outlined header Save, consistent navigation icons and Settings selection.
- A compact recovery-code disclosure retains the original warning and action.
  Other key/conflict warnings remain visible.
- Shared status colors follow the selected named palette's scheme, independently
  of the OS. Shared field borders have measurable contrast.

## Capture provenance

Original base: `34849c4d0766901fdf33556855373aa122666049`. Current captures
are from head `f32660ce9ebd55094d251dca0e8039343fdea2be` plus the recorded source patch and
explicit file hashes. Current served index SHA256:
`8ef267ad2fa8339725c1fbf7ea6f469efddb7877c1afb014dc71331c04c4debc`.

`inventory-v10.json` contains218 PNGs /150 unique across all stages. Current stage11
has22captures/18unique:14Notes (including4empty and2desktop management views)
and4Settings. Four workspace aliases are excluded from means. Stages05/06 were
preliminary attempts whose reviews were interrupted before completion; earlier
inputs and completed round4/5/6/7 reviews remain frozen. The comparison uses stage10 and stage11, including matched empty screens. Stage11 capture passed on its first attempt. Its9source-file pins now include CanvasPage.tsx. inventory-v9 added exact near-duplicate diff bounds and neutral rasterization labels; duplicate-metadata-audit.json records corrections to earlier caret wording without rewriting frozen inventories, images or scores.

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
overrides. Optional polish remains in phone Settings spacing, small metadata,
light avatar separation and minor icon/divider consistency. These remain outside the bounded round6 polish; its verdicts are pending.

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
