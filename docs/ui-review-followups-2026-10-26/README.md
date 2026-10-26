# KyNotes review follow-up R3 (2026-10-26)

Evidence-only follow-up to the independent refinement review (`ky-ui` `reviews/2026-10-26-fleet/refinement-runtime-review.md`, finding R3). No runtime source changed. This claims no score.

## What R3 disclosed

The visual-refinement batch excluded `.secondary` (and `.toast`, and the phone toggle) from the global rule that fills buttons with the accent (`web/src/styles.css:81`), and gave `.secondary` a neutral outline (`:432`). The batch described only the controls it added the class to. The same rule also restyles every **pre-existing** `.secondary` control, from accent fill to neutral outline, and the error toast changes the same way as the commit toast. That outline is the intended look and is kept.

| Control | Source | Captured here |
|---|---|---|
| Cancel; Cancel; Codes differ (Link this browser) | `DeviceLink.tsx:122,132,137` | **N/A**: they render only in a browser that lacks the key while linking. With this password fixture a second browser unlocks the same key, so "Link this browser" is never offered (`secondBrowserOfferedLink: false` in every `*-facts.jsonl` row) |
| Not me; Cancel; Codes differ (Link another browser) | `DeviceLink.tsx:274,280,292` | **N/A** for the same reason: no request arrives. `link-request` captures the real idle card ("No browser is asking to be linked") with the neighbouring Forget and Reset buttons |
| Trust new key | `PinnedKeys.tsx:80` | **N/A**: needs a colleague whose pinned key changed (a second account in a shared team, then a key reset) |
| Reset encryption key… | `RecoveryCode.tsx:277` (`secondary danger`) | partly, at the bottom of the `link-request` frames; `recovery-reset` clicks it, which replaces it with the form |
| Continue (reset form) | `RecoveryCode.tsx:291` (`secondary danger`) | **yes**, `recovery-reset`: the opened form, disabled until the phrase is typed; nothing is typed |
| Try the reset again | `RecoveryCode.tsx:298` (`secondary danger`) | **N/A**: needs a reset that failed after preparation |
| Discard unsent edits | `UnsentEdits.tsx:61` (`secondary danger`) | **N/A**: needs this browser to hold edits it can never send (a notebook the account lost, or edits waiting on a key across a reset); a one-owner fixture has none |
| Sign out (locked session) | `main.tsx:569` (`secondary small`) | **yes**, `locked-session`, **modelled**: see below |
| Forget this device & sign out | `main.tsx:3500` (`secondary danger`) | **yes**, `forget-device` (shown, never clicked) |
| Error toast | `main.tsx:3234` (`toast error`) | **N/A**: needs a failing action; none was triggered |

**Known design residual:** destructive `secondary danger` controls (reset key, discard unsent edits, forget device) now have the same neutral outline as Cancel. They had no danger hue before either (all were accent-filled). No danger styling was added here; this is recorded, not fixed.

## How each state was reached

- **link-request:** a second browser context signs in as the same owner and opens Settings; the captured page is the first browser's Settings › Link another browser.
- **recovery-reset:** Settings › Reset encryption key › "Reset encryption key…" opens the warning and form. Nothing is typed or submitted.
- **forget-device:** Settings, scrolled to Trusted Device. Not clicked.
- **locked-session:** a live session without the key in this browser, where KyNotes asks for the password and offers Sign out. On this loopback fixture the browser keeps a trusted device key: a reload unlocks by itself, and the header Lock ends the session (plain unlock form, no Sign out). So the state is **modelled**: the origin's IndexedDB and local storage are cleared through CDP `Storage.clearDataForOrigin`, cookies kept, then the page reloads. It is the real app's screen for that state, reached by clearing storage, not through UI.

## Stages

Same driver, fixture, surfaces and order for both. Each manifest in `screenshots/` records the source commit of this worktree, a hash of its uncommitted diff (this directory excluded), the embedded bundle's `index.html` hash, **`server_source`**, OS, driver, fixture, loaded fonts and each PNG's SHA-256. `*-facts.jsonl` records what each surface found. `SHA256SUMS` covers every file in `screenshots/`.

| Prefix | Server built from | Embedded index |
|---|---|---|
| `kynotes-00-before` | `git archive` of `e1b726b` (pre-refinement, pinned in `refinement-source-inputs.json`) into `/tmp/kynotes-src-e1b726b…`; no worktree modified | `ce3c13068f87` (equals `e1b726b:internal/web/dist/index.html`) |
| `kynotes-01-current` | this worktree, clean `85dd3e3` (master after #115) | `1a66f5d20695` (equals the visual-refinement `02-current-bundle`) |

Both are OS light and dark × 1280×900 and 390×844, device scale 1, this repository's Playwright 1.64.1 with Chromium 156.0.8078.4, synthetic owner and notebook. `--verify` on the current build passes 23/23. Before and current differ in the restyled buttons and in live data: the per-run user id and fingerprints in the Trusted Device text, and scroll offsets that follow them.

## Checks

No runtime source changed, so the unchanged suites were not re-run for this docs-only addition. The last full run on this code is recorded in `UI-VERIFICATION.md` (visual refinement, post-merge), and host CI covers the merged head. The affected capture verification above was run.

## Reproduce

From the repository root: `[CAPTURE_SOURCE_COMMIT=<sha>] node docs/ui-review-followups-2026-10-26/capture.mjs <prefix> [surface,...]`, or `... --verify <prefix>`. The driver builds the server into a temporary directory on loopback port 18091 and removes it afterwards.

Historical source revisions must be 7–40 hexadecimal commit IDs. Each run extracts
`git archive` into a new private directory made by `mkdtemp`; Git and tar receive
literal arguments, without a shell. The directory is removed after the capture
or a startup/extraction failure. The commit-named path in the original stage
record above is historical and is never reused by the corrected driver.

Run `node --test docs/ui-review-followups-2026-10-26/capture.test.mjs` to verify
source isolation. The planted-cache regression failed before the correction;
all three checks pass afterward. Application source, bundles and recorded
screenshots remain unchanged.
