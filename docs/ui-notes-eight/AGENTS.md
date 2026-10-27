# KyNotes UI council evidence

## Purpose

- Record the KyNotes editor and phone-navigation pass toward the owner's 8/10 progression gate.

## Ownership

- `screenshots/` and the versioned `inventory*.json` files own the scored source images and capture provenance; `inventory-v9.json` is current and earlier inventories stay frozen.
- Reviewer reports preserve independent scores and objections by model and round. Gemini’s original files are named `argon-round3.md/json`; `gemini-audit.md/json` owns corrections. Nonconforming raw scores remain visible and are excluded from progression decisions.
- `theme-checks/` holds supplemental interaction checks, outside the scored source set.

## Local Contracts

- Keep original round inputs and reviewer scores intact; corrections and rejected findings need an explicit audit.
- Separate screenshot quality, cohort coverage and verified behavior. Missing evidence stays untested.
- Capture synthetic content through the real application. Record revision or source-patch hash, served bundle hash, browser, viewport and theme.
- Claude Opus and GPT Sol review first. Gemini 4 Argon is advisory after both are satisfied; audit its findings against evidence before acting.

## Work Guidance

- Keep a round-by-round score table in the report and spreadsheet.
- Keep product changes focused on editor readability and navigation; preserve encryption, saves, themes and stored canvas geometry.

## Verification

- `KYNOTES_COUNCIL_STAGE=before|after KYNOTES_COUNCIL_ROUND=<stage number> KYNOTES_COUNCIL_REVIEW_ROUND=<review round> npm run e2e -- ui-council.e2e.ts --output=../.playwright-mcp/council-<stage number>` from `web/` captures the source set. Give captures a fixture separate from the full suite's default server and an owned Playwright output directory. Use `KYNOTES_E2E_URL` only for that isolated loopback fixture. Stage 02 is round1, stage03 round2 and stage04 round3. Stages05/06 are interrupted preliminary single-pane attempts; stage07 is round4; stage08 is round5; stage09 is round6; stage10 is current round7 (manifest councilRound). Preserve earlier captures.
- `python3 docs/ui-notes-eight/build-report.py` verifies current source/bundle hashes, image hashes/dimensions and reviewer arithmetic and generates the round table, workbook and self-contained comparison page. `inventory-v9.json` is the current source inventory; earlier inventories remain frozen.
- Recompute image hashes, duplicates and weighted totals before publishing scores.
- Run the product's root verification checks for implementation changes.

## Child DOX Index

- None.
