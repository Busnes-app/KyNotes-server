# KyNotes: scoped 8/10 progression

The current stage is **08-after**, Council round5. The owner rated the adjacent
left columns **6/10**, reopening progression. Stage07 removed the double-left
layout; Opus rated it7.7 and blocked first-run guidance, while Sol rated it8.2.
The empty editor now exposes **New notebook** through the existing creation flow,
above the phone fold in both themes. Key/setup notices remain visible, and Work
queue restores focus to the persistent navigation toggle. Fresh Opus/Sol reviews
are pending after599units and12full browser tests passed. No current8/10 or
full9/10 acceptance is claimed.

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
are from head `5dbf6df0a028c810f7dda767ddb09b8cd7f841fd` plus the recorded source patch and
explicit file hashes. Current served index SHA256:
`00dcf80d36040710ede88cc0e47fd1807933d3969a345497a5ba78403c113343`.

`inventory-v7.json` contains152 PNGs /108 unique across all stages. Current stage08
has22captures/18unique:14Notes (including4empty and2desktop management views)
and4Settings. Four workspace aliases are excluded from means. Stages05/06 were
preliminary attempts whose reviews were interrupted before completion; earlier
inputs and completed stage07 round4 reviews remain frozen. The comparison uses
stage07 and stage08, including matched empty screens. A first stage08 capture
stopped on a test focus race; the final isolated capture passed after waiting for
notebook creation's focus handoff before the recovery keypress. No product focus
workaround or security change was added.

Chromium 156.0.8078.4, scale 1; desktop 1280×900 and phone 390×844; OS light/dark
emulation, no saved theme choice, real disposable server, synthetic owner and
Project Atlas with four populated pages. Screenshots come through the real UI.
Native T3 Computer Use navigation and CSS inspection supplement the full-resolution
capture set; native preview snapshots are not substituted into scored inputs.

Rubric: `ky-suite-v2`, hierarchy .20 / typography .15 / density .20 / color .15 /
visible affordances .15 / coherence .15. Decimal half-up totals; raw reviewer
verdicts are preserved independently, never averaged across models. Ky fit is separate.

Historical6.7 and current scores have different coverage and cannot establish a
controlled improvement. Page-picker/navigation comparisons also change state;
the workbook identifies those unmatched pairs. The trailing empty bullet is fixture
content. No new competitor ranking or whole-suite cohesion score is claimed.

## Limits and remaining polish

WebKit, the complete empty/loading/error matrix and every product theme/focus/role
path are not certified by this pass. Shared palette probes do not certify all product
overrides. Optional polish remains in phone Settings spacing, small metadata,
light avatar separation and minor icon/divider consistency. These were nonblocking in round4; round5 verdicts are pending.

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
