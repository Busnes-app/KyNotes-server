# Sol Council Round 5 — stage08

**Notes 8.2/10; Settings 8.5/10. Satisfied: true for the scoped 8/10 progression.** No in-scope P1 blocker remains. The visible first-notebook action and the Work queue focus handoff resolve the two prior objections. The owner’s adjacent-left-region layout is absent in current evidence. No owner approval, merge or deployment is inferred.

**Checked:** all152 inventory hashes/sizes/dimensions,44duplicate links,18current original-resolution images, source/diff/live/embed provenance, exact arithmetic and native T3 navigation. **Not accepted:** full9, every unrounded image≥8, all product states/roles/themes, all keyboard/focus/contrast paths, WebKit, competitor ranking or whole-suite cohesion. **You need to:** nothing for this review; the parent owns Council synthesis.

## Method and provenance

Reviewer: gpt-6.1-sol, high effort, T3 Code through Codex. Single independent Council review using Impeccable Operate/Read and fixed ky-suite-v2. This is not the nested dual-assessment Impeccable critique workflow; the user prohibited nested delegation. Questions skipped: the brief supplies the needed scope.

- Frozen product HEAD: `022d5e2d4163ea12012d5da139c4de40abdc1ffe`.
- Checkout advanced at closeout to `022d5e2d4163ea12012d5da139c4de40abdc1ffe` in a parent evidence/delivery commit affecting only workbook, README and delivery.json. All8 source hashes, web/embed indices and reconstructed source diff were rechecked and still match frozen `ffd3471`; scoring inputs did not change.
- Capture HEAD: `5dbf6df0a028c810f7dda767ddb09b8cd7f841fd`; final source is validated by all8 recorded file hashes and the exact reconstructed `git diff capture_head HEAD -- web/src` hash.
- Source diff SHA256: `bf7bd2546daf3e21c5238e1c3518879be1c8f3782b46df234bc6c10690d50200`.
- Web, embedded and live18106 index SHA256: `00dcf80d36040710ede88cc0e47fd1807933d3969a345497a5ba78403c113343`.
- Manifest SHA256: `3c5acef7ea6b40e440b3d7c52c5caecf51f95b79f03c9805b891364dc1474c9e`; inventory-v7 SHA256: `79dd31cdbf0a2f30ee21ce3be033821e7e6b1db1df4520b78a677b7e3ab64c66`.
- Captured 2026-10-27T01:02:00.624Z; Chromium 156.0.8078.4, scale1;1280×900/390×844; OS light/dark emulation with no saved theme; synthetic Project Atlas, four populated pages created through the real app.

**Prior exposure:** User brief disclosed prior satisfaction/objections but no primary numeric totals. Vectors were chosen after viewing all 18 originals, before reading build-report.py. That script then exposed hardcoded historical Gemini 8.1, historical Opus handoff 6.7 and owner 6; no primary numeric report had been loaded when vectors were fixed. Persisted freeze occurs immediately afterward; no vector was changed. Primary Round4 MD/JSON and earlier Sol numeric reports were opened only after the persisted freeze. Frozen score-vector SHA256: `5b342809185384b2302575094785ca49ac5b13744436440e7b8054eb5fae40aa`. No scores changed during drift analysis.

## Current cohort arithmetic

Weights, in column order below: hierarchy .20, typography .15, density_layout .20, color .15, visible_affordances .15, coherence .15. Every dimension is an integer. Brand fit is separate.

| Cohort | n unique | Sum of rounded file totals | Exact mean | Half-up mean | Minimum |
| --- | ---: | ---: | ---: | ---: | ---: |
|notes|14|115.2|8.228571428571428571428571429|8.2|8.0|
|settings|4|34.0|8.5|8.5|8.3|

The Notes raw weighted mean before per-file rounding is114.90/14 =8.207142857…; Settings is33.80/4 =8.45. The prescribed rounded-file mean gives8.2/8.5. Minimum Notes raw total is7.95 (expanded phone management), which rounds half-up to8.0. This progression decision uses the scoped cohort and resolved blockers; it does not claim that every raw image is≥8.

**Ky brand fit:**8.5, n18, minimum8.5; equal mean of palette9/type-geometry8/shell8/accent9. `suite_cohesion` is N/A because no second Ky product was visually reviewed. It is never added to quality.

```python
from decimal import Decimal, ROUND_HALF_UP
weights = dict(hierarchy=".20", typography=".15", density_layout=".20",
               color=".15", visible_affordances=".15", coherence=".15")
def half_up(value):
    return value.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
def total(row):
    return half_up(sum(Decimal(w) * row["scores"][k] for k, w in weights.items()))
current = [r for r in report["files"] if r.get("included_in_current_mean")]
for cohort in ("notes", "settings"):
    rows = [r for r in current if r["cohort"] == cohort]
    totals = [total(r) for r in rows]
    print(cohort, len(rows), sum(totals),
          half_up(sum(totals) / Decimal(len(rows))), min(totals))
# notes 14 115.2 8.2 8.0
# settings 4 34.0 8.5 8.3
```

## Per-image scores

All18 current unique images were viewed at original resolution. Each JSON row records observations for all6dimensions, observed surface/state/cohort, theme/viewport, provenance/hash, confidence and caveat. Confidence is high for the visible pixels; still images alone prove no interaction, save, screen-reader or computed-contrast behavior.

| Current file | H/T/D/C/A/C | Total | SHA256 |
| --- | --- | ---: | --- |
|[kynotes-08-after-appearance-desktop-dark.png](screenshots/kynotes-08-after-appearance-desktop-dark.png)|9/8/8/9/9/9|8.7|7ddd736539fee331b093308c0dd1ff4c85e8476fc5a9be29c3b24476bb791f4c|
|[kynotes-08-after-appearance-desktop-light.png](screenshots/kynotes-08-after-appearance-desktop-light.png)|9/8/8/9/9/9|8.7|9e8b869d90fb1dbb3d61bc5165794e4c0d50d7003d3607378e091755b050f704|
|[kynotes-08-after-appearance-mobile-dark.png](screenshots/kynotes-08-after-appearance-mobile-dark.png)|8/8/7/9/9/9|8.3|72b2894e5a5204a913f362c7be193442de97ece5db425a294540f17c18cf7520|
|[kynotes-08-after-appearance-mobile-light.png](screenshots/kynotes-08-after-appearance-mobile-light.png)|8/8/7/9/9/9|8.3|a48727c6f46ce1f3c40512a14cfaab32aa9233280c3d8ace4c42901f8fc54eab|
|[kynotes-08-after-editor-desktop-dark.png](screenshots/kynotes-08-after-editor-desktop-dark.png)|8/9/8/9/8/8|8.3|05a9187350416aa3b1cf40880e5ff5646635ab0069ff1d9e87a7166e58a9256d|
|[kynotes-08-after-editor-desktop-light.png](screenshots/kynotes-08-after-editor-desktop-light.png)|8/9/8/9/8/8|8.3|c36eec5234ec3d74e1e16082fc58cd1308469f106f00a5ca3aca907543b96950|
|[kynotes-08-after-editor-mobile-dark.png](screenshots/kynotes-08-after-editor-mobile-dark.png)|8/9/8/9/8/8|8.3|bb72aadfd10dc888385c654c25d2a8b8ea47921b0ad8c59fe46a392dcb4e1ab4|
|[kynotes-08-after-editor-mobile-light.png](screenshots/kynotes-08-after-editor-mobile-light.png)|8/9/8/9/8/8|8.3|1a2066d9b8c44ddd297e2e0485929fa4cb69826f3625a1049dd8082a6d1dd5b5|
|[kynotes-08-after-empty-desktop-dark.png](screenshots/kynotes-08-after-empty-desktop-dark.png)|8/8/8/9/8/8|8.2|67688db5fc72189cbcb4af5f0b559d69f96f9bfb385688d421e3cc3456c5c4cb|
|[kynotes-08-after-empty-desktop-light.png](screenshots/kynotes-08-after-empty-desktop-light.png)|8/8/8/9/8/8|8.2|ad6a6b843ad7f0327b7ccdf93ffdcde7eb4cce8137e1b33bad03a7b3dd3b92c9|
|[kynotes-08-after-empty-mobile-dark.png](screenshots/kynotes-08-after-empty-mobile-dark.png)|8/8/8/9/8/8|8.2|cf5201ca043db6727c20daf1d4f15e4009bf3193d0405c5088afc94dcc7be040|
|[kynotes-08-after-empty-mobile-light.png](screenshots/kynotes-08-after-empty-mobile-light.png)|8/8/8/9/8/8|8.2|38ea2008811c859c52500f203c7be160abca2f187368625cda147a4f72257320|
|[kynotes-08-after-navigation-desktop-dark.png](screenshots/kynotes-08-after-navigation-desktop-dark.png)|8/9/8/9/8/8|8.3|ff86ee660c83becc1d81e5998d5c4c6b42d26c8621d7d7f0fcde69fa070151b3|
|[kynotes-08-after-navigation-desktop-light.png](screenshots/kynotes-08-after-navigation-desktop-light.png)|8/9/8/9/8/8|8.3|8085c2811af8b5ef488674e105f72ebed314b82f007095ad2ea1949dd6780d0c|
|[kynotes-08-after-navigation-mobile-dark.png](screenshots/kynotes-08-after-navigation-mobile-dark.png)|8/8/7/9/8/8|8.0|953ce6476d79b4c6b0b2b0dfc49d2e9dc2d4ef841dbfbac1d5b053d262e98158|
|[kynotes-08-after-navigation-mobile-light.png](screenshots/kynotes-08-after-navigation-mobile-light.png)|8/8/7/9/8/8|8.0|27238c23a549a97252fe2140492add53efe15a7d3f2e4f1f788def3f95dbe36c|
|[kynotes-08-after-pages-mobile-dark.png](screenshots/kynotes-08-after-pages-mobile-dark.png)|8/8/8/9/8/9|8.3|34e628e3ffaa2f7f0d7de149e187185c15818fe9ae67b96c928093f186de5fef|
|[kynotes-08-after-pages-mobile-light.png](screenshots/kynotes-08-after-pages-mobile-light.png)|8/8/8/9/8/9|8.3|6bef7ce282a47256d80c1d2b28cdd2ef3d6111ad032d2d11e4bab46539525aec|

## Inventory, aliases and provenance

inventory-v7 is the complete152-PNG history:108declared independent groups,114distinct hashes. All152hashes,byte sizes and dimensions match; the inventory file set equals the actual screenshots directory. All44declared duplicate relationships were remeasured and satisfy the fixed exact/near rule.

The current set has22captures and18unique states:14Notes (4empty,4editor,4management/navigation,2phone chooser) and4Settings. Only the4current workspace→editor aliases are excluded from current counts/means. Each differs by12/light or15/dark pixels, max channel delta4; pixel fractions are0.0000104167/0.0000130208 on desktop and0.0000364564/0.0000455705 on phone. Workspace filenames depict the editor and inherit its score.

All4current Settings images equal historical stage04–07pixels, and both page-chooser images equal historical stage05–07pixels. Their inventory duplicate links are historical provenance, not extra current aliases: they remain represented exactly once each in current cohort means. Historical130files are retained with explicit unscored reasons; no history was rewritten or counted as new quality. The trailing empty bullet is synthetic document content, not an application failure.

## Findings and prior objections

**R5-first-notebook — resolved prior B1.** Direct New notebook is prominent with notebook-specific guidance; at390px its entire button is y542–589, above844px fold. This resolves the hidden-forward-action objection without opening management and hiding page-pane key notices. Evidence: all four stage08 empty captures and /tmp/kynotes-first-notebook-capture-final.log.

**R5-workqueue-focus — resolved prior P2.** Selecting Work queue closes management and activeElement becomes BUTTON Notebooks and account with aria-expanded=false; observed directly at both widths. Evidence: own native T3 tab18106; desktop1280×900 and phone390×844.

**R5-phone-density — P3.** Expanded phone management uses about430px below the toggle; Settings navigation also delays the first preview cards to y570. Both remain labeled and reachable. Deferred spacing polish is justified. Evidence: navigation-mobile and appearance-mobile light/dark.

**R5-icon-polish — P3.** Native recovery triangle differs from stroked toggle chevrons; light account initial has weak chip separation and section/new-page plus glyphs depend on context. Optional polish, not a reason to restart layout. Evidence: navigation and pages captures.

**R5-native-no-open-page — P2 residual outside scored open-page/first-notebook state.** The no-open-page phone state keeps notebook/section headings within a bounded inner-scrolling list above the desk, so the four rows require internal scrolling. Opening an existing page then opening Pages exposes all4 rows at y354–633, as captured. This is a separate uncaptured state, not evidence of an inaccessible row or regression from07. Evidence: own native phone tab after selecting notebook, before opening a page.

B1 is resolved by exposing the existing creation action in the desk, without forcing management open and hiding key/setup notices. The actual no-notebook handler was exercised by the implementation’s exact final capture; I did not create another notebook because this review forbids content mutation. The no-notebook action is wholly above the fold in both phone themes. Existing authorization/key behavior is not claimed changed.

## Native Computer Use and verification

Used preview_status, then preview_open(reuseExistingTab:false) on my own new18106tab. Signed in only as the reserved synthetic owner. Native browser: Chromium154/deviceScale2;1280×900 and390×844. The supplemental native browser differs from the scored Chromium156/scale1captures; its evidence is behavioral.

- Desktop pages: list x0,width240, management hidden; editor x240,width1040. Management: sidebar x0,width240, pages hidden; editor unchanged. Horizontal overflow0.
- Work queue selection closes management and activeElement becomes BUTTON “Notebooks and account”, aria-expanded=false, at both widths. Notebook selection returns there too.
- Phone different-page selection settled to “Page title” input for Team handover; open-page chooser has all4rows at y354–633. Tab/Enter expands/collapses recovery, retaining its warning and Create recovery code.
- Dark focus rings observed on the Pages toggle and recovery summary. Settings has23native radio choices with system checked, no saved browser-local theme choice, no horizontal overflow. No named-theme choice was changed.
- Initial assumed-submit CSS and malformed/ambiguous locators were corrected; these were tool-targeting errors. One early selection sample caught transient BODY focus; the completed distinct-page selection focused its title. I do not turn transient samples into product failures.
- Existing CSP inline-style refusals, placeholder insertion and interactive-widget viewport advice reproduced. No CSP relaxation, suppression, soft-keyboard certification or new product failure is inferred.

Inspected the final implementation-owned logs:599units/47files;12/12fresh-server browser tests; exact stage08capture/regression1/1 in20.6s; production/TypeScript; Docker build,14-step probe and apply-setup; repeatability with two identical hashes `f899bddbf75e2dc615262ad1ee085b6657c6d14f7075989ebb77679e964a8be9`. Log paths and SHA256values are in JSON. checks.json records Go build/vet/embed, retained Go race/fuzz/govulncheck on unchanged Go/deps, shared theme and vendor checks. These are reviewed executions, not tests I reran.

The initial capture focus race and wrong Docker transport invocation were corrected before this review. The final logs pass; no unresolved product-test failure is evident. I did not run broad suites, builds, capture drivers or build-report.py, which rewrites common artifacts.

## Drift: stage07 → stage08

Same synthetic content and capture conditions. Diff measurements show all nonempty Notes changes confined to save-time pixels; Settings and chooser pixels are identical. The four empty views change the central instruction/action. Save times and user IDs are never scored as product improvements.

| Surface, both themes | Prior Sol | Current Sol | Delta | Cause |
| --- | ---: | ---: | ---: | --- |
|empty-desktop|8.0|8.2|0.2|Product change: direct New notebook and notebook-specific guidance replace the indirect select/create-note instruction. Hierarchy and affordance improve. Independent coherence 9→8 still accounts for unused search/disabled plus.|
|empty-mobile|7.6|8.2|0.6|Product change: New notebook is now visible at y542–589 with prerequisite-specific guidance. Hierarchy 7→8, affordance 7→8 and density 7→8 reflect a complete first action inside the initial viewport, rather than rewarding more content.|
|editor-desktop|8.4|8.3|-0.1|anchor: only save-time pixels differ; typography 8→9 values the strong body/heading scale, hierarchy 9→8 retains competition from toolbar/comments. No product improvement.|
|editor-mobile|8.2|8.3|0.1|anchor: only save-time pixels differ; typography 8→9 values readable phone paragraphs and bullets. No product improvement.|
|navigation-desktop|8.3|8.3|0.0|anchor: only save-time pixels differ; typography 8→9 and coherence 9→8 offset. No product improvement.|
|navigation-mobile|8.0|8.0|0.0|No numeric drift; only save-time pixels differ. Expanded management remains spatially heavy. No product improvement.|
|pages-mobile|8.7|8.3|-0.4|anchor: exact same pixels; clear four-row chooser remains solid, but the recovery/section/search preamble and generic plus glyphs keep hierarchy/density at 8 rather than 9. The -0.4 is reviewer drift, not regression.|
|appearance-desktop|8.5|8.7|0.2|anchor: unchanged pixels; independent hierarchy judgment values the clear Settings → Appearance → Theme sequence one point higher. No product improvement.|
|appearance-mobile|8.1|8.3|0.2|anchor: unchanged pixels; repeated equal-width cards and common navigation vocabulary earn coherence 9 rather than 8. No product improvement.|

Every |delta|≥0.5 occurs in the two empty-phone views:7.6→8.2 (+0.6) because the new visible notebook action and prerequisite-specific copy make the initial viewport actionable. Desktop empty scores rise8.0→8.2. Other changes are independent anchor drift: in particular the exact-same-pixel page chooser is8.7→8.3 and exact-same-pixel Settings8.3→8.5 by cohort mean. These are not product gains/regressions.

Mean current Notes delta against prior rounded per-file totals is0.05714285714285714285714285714; Settings delta is+0.2. Overall paired mean delta is0.08888888888888888888888888889 (coverage summary, not a ranking). Among14unchanged/timestamp-only images the mean delta is0.0: no broad upward drift is being credited to the product. Competitor drift is N/A. No dimension differs by≥2from prior Sol. Current Opus5was not opened, so no current independent spread/agreement is invented.

## Council history

| Reviewer | R1 | R2 | R3 | R4 | R5 |
| --- | ---: | ---: | ---: | --- | --- |
| Claude Opus5.5 |6.5|7.4|8.1|7.7, not satisfied|Pending/not read|
| GPT Sol |7.8|8.1|8.2|8.2, satisfied|8.2, satisfied|
| Gemini4Argon |Unused|Unused|Raw8.1, nonconforming advisory|Deferred|Deferred until both current primaries satisfied|
| Owner |—|—|6, double-left rejection|No new score|No new score|

The owner6has unknown build provenance: it is an authoritative rejected layout, not a controlled numeric baseline. Prior approvals do not carry through that rejection. Round4 Opus B1 is addressed above; my satisfied verdict does not claim Opus5agreement. Historical Gemini weights/contradicted claims and parent audit remain untouched; Gemini was not delegated and is not the gatekeeper.

## Limits and closeout

Full9is not accepted: quality/brand fit remain below9; full state/loading/error/announcement/role/theme/focus/contrast coverage, dense teams/groups, tablet/soft-keyboard cases, screen readers and WebKit remain unproven. Shared contrast tests cannot certify every product control. The native no-open-page inner-scroll state remains a documented residual. The only visual-change credit is the measured first-notebook guidance/action; behavior credit is separately identified.

Only sol-round5.md and sol-round5.json were written. DOX pass completed: ancestor/root/product/evidence contracts inspected; AGENTS left unchanged because no durable contract changed and writes were limited to these reports. Common reports, historical evidence, source, fixtures, tests and generated bundles were untouched. Native tab closed; no server stopped or started. No nested delegation, merge or deployment. Review complete.
