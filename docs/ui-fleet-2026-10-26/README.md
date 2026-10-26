# KyNotes fleet Appearance — 2026-10-26

Applies the approved Busnes look to KyNotes's web shell and gives it the shared ky-ui 0.4.0 Appearance theme-preview cards (native radios) over the suite catalog: Match system plus every catalog theme, read dynamically from `web/src/ky-ui/themes.js`. Shared files come from ky-ui `4f83f34` and pass `sync-consumers --check`; they are generated, never hand-edited. No score is claimed here: the council rates these captures.

## Stages

- **00 before**: base commit, current theme control and main view.
- **01 after**: suite shell scale (240px sidebar, 24px title, 40px controls and nav rows, shared field border and type) and the Appearance cards.
- **02 after**: owner correction — shared description class and copy, consistent wrapping, preview hairline, no theme selector in the shell navigation. Only affected Appearance/shell views were recaptured.
- **02 confirm**: one confirmation recapture after the single stage 02 fix batch, where a fix was needed.

Surfaces: workspace (owner with one synthetic notebook and note) and Settings → Appearance.

## Catalog and saved choice

- Storage key `kynotes-theme`; theme names saved by earlier versions (the 17 suite names) still select their theme; new choices are saved by catalog name, and Match system as `system`.
- Match system follows the device until a choice is saved; that default is unchanged.

## Product notes

- Applying a theme no longer needs the Apply button: a card choice applies at once, matching the other products.
- The notes canvas, BlockNote editor and admin console internals are untouched; the admin console keeps its own heading sizes.

## Capture batches

Every manifest in `screenshots/` lists the source commit, a hash of any uncommitted diff, OS, driver, viewport, theme source, fixture and the SHA-256 of every PNG. `results.csv` pairs each after image with its stage 00 before; `checks.csv` holds the in-app checks. `source.patch` is the source-only diff (no vendored or built files) for independent review.

| Batch | Source commit | Uncommitted diff | Images | Surfaces | Captured |
| --- | --- | --- | --- | --- | --- |
| `kynotes-00-before` | `d172a514e4` | none | 8 | appearance, workspace | 2026-10-26T10:59Z |
| `kynotes-01-after` | `83d9750d58` | `8037736037f0…` | 8 | appearance, workspace | 2026-10-26T11:21Z |
| `kynotes-02-after` | `8b8a6eed32` | none | 4 | appearance | 2026-10-26T11:37Z |
| `kynotes-02-confirm` | `17547b32fc` | none | 4 | appearance | 2026-10-26T11:39Z |

Conditions: linux 7.2.10-1-cachyos, playwright chromium 156.0.8078.4 (headless), device scale 1, 1280×900 and 390×844, light/dark by OS emulation with no saved choice, America/Chicago, en-US. Fixture: fresh data dir (web/e2e/server.sh config on port 18091, dev_insecure_cookies on loopback); first-run setup through the UI creating administrator "admin" and everyday "owner"; owner creates notebook "Field notes" with one note typed "Garden plan: order seeds by Friday."; captures are the owner.

## In-app theme check

`node docs/ui-fleet-2026-10-26/capture.mjs --verify <prefix>`: Sky and Sun (light named themes), Busnes Dark, Busnes Light and Match system, asserting the page background, the hovered idle navigation row and the selected row at 4.5:1 or better from computed colours in the running product, then arrow-key selection with a visible focus ring.

| Run | Source commit | Passed |
| --- | --- | --- |
| `kynotes-01-after` | `83d9750d58` | 16/16 |
| `kynotes-02-after` | `8b8a6eed32` | 16/16 |

## Checks

| Check | Result |
| --- | --- |
| Web unit tests (vitest) | 599/599 pass |
| Web build and `internal/web/dist` equals `web/dist` | pass |
| Browser e2e (`npm run e2e`, throwaway server) | 10/10 pass |
| `npm audit` (all and `--omit=dev`) | 0 vulnerabilities |
| Vendored ky-ui check | pass at 4f83f34 |
| Fuzz targets, govulncheck, reproducible-build and Docker probe | not run locally: CI runs them |

Go: `go build ./...`, `go vet ./...`, gofmt and the full `go test -race -count=1 ./...` passed locally on this machine (CachyOS, Go 1.27.1); Go code is unchanged by this work. Docker image, publish and attestation jobs were not run locally: CI runs them on this PR.

## Reproduce

```sh
cd web && npm ci && npm run build   # then any product-specific bundle step in AGENTS.md
cd .. && KY_PLAYWRIGHT=<path to @playwright/test/index.mjs, if web/ has none> \
  node docs/ui-fleet-2026-10-26/capture.mjs <prefix> [surface,...]
node docs/ui-fleet-2026-10-26/capture.mjs --verify <prefix>
node docs/ui-fleet-2026-10-26/results.mjs
```

Each run starts a disposable loopback server on its own port with generated secrets and removes its data directory afterwards. No live service, personal data or authentication bypass is used.
