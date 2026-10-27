"""Validate frozen evidence and export the council workbook using the standard library."""
from pathlib import Path
from decimal import Decimal, ROUND_HALF_UP
from xml.sax.saxutils import escape
import base64
import hashlib
import html
import json
import re
import struct
import zipfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
WEIGHTS = dict(hierarchy=".20", typography=".15", density_layout=".20", color=".15", visible_affordances=".15", coherence=".15")
inventory_path = max(ROOT.glob("inventory-v*.json"), key=lambda path: int(re.search(r"-v(\d+)", path.name)[1]))
inventory = json.loads(inventory_path.read_text())
current_stage = max(int(re.search(r"kynotes-(\d+)-after", row["file"])[1]) for row in inventory if re.search(r"kynotes-(\d+)-after", row["file"]))
manifest = json.loads((ROOT / f"screenshots/{current_stage:02}-after-manifest.json").read_text())
for file, expected in manifest["sourceFiles"].items():
    assert hashlib.sha256((ROOT.parents[1] / "web" / file).read_bytes()).hexdigest() == expected, file
assert hashlib.sha256((ROOT.parents[1] / "internal/web/dist/index.html").read_bytes()).hexdigest() == manifest["servedIndexSha256"]
for row in inventory:
    data = (ROOT / row["file"]).read_bytes()
    assert hashlib.sha256(data).hexdigest() == row["sha256"], row["file"]
    assert len(data) == row["bytes"], row["file"]
    assert data[:8] == b"\x89PNG\r\n\x1a\n" and struct.unpack(">II", data[16:24]) == (row["width"], row["height"]), row["file"]

reports = {}
score_rows = [["Reviewer", "Round", "File", "Cohort", *WEIGHTS, "Fixed-rubric quality", "Raw reported quality", "Duplicate of", "Confidence", "Caveat", "Declared weights conform"]]
for name in ("opus", "sol", "gemini"):
    for path in sorted(ROOT.glob(f"{'argon' if name == 'gemini' else name}-round*.json")):
        number = int(path.stem.split("round")[-1])
        report = json.loads(path.read_text())
        verdict = report.get("verdict", report)
        conforms = all(Decimal(str(report.get("weights", WEIGHTS)[key])) == Decimal(weight) for key, weight in WEIGHTS.items())
        reports[name, number] = {"score": verdict.get("score", verdict.get("notes_mean")), "satisfied": verdict.get("satisfied"), "report": path.name, "rubric_conforms": conforms, "basis": verdict.get("score_basis", verdict.get("scope", verdict.get("reason", verdict.get("summary", ""))))}
        if not conforms:
            assert name == "gemini" and (ROOT / "gemini-audit.json").exists(), path.name
            reports[name, number]["basis"] = "Raw advisory score; nonconforming weights and contradicted observations. See gemini-audit.json; excluded from progression gate."
        for row in report.get("files", []):
            scores = row.get("scores", {})
            if not all(isinstance(scores.get(key), (int, float)) for key in WEIGHTS):
                continue
            assert all(0 <= scores[key] <= 10 for key in WEIGHTS), row["file"]
            total = sum(Decimal(str(scores[key])) * Decimal(weight) for key, weight in WEIGHTS.items()).quantize(Decimal(".1"), rounding=ROUND_HALF_UP)
            reported = row.get("total")
            if isinstance(reported, (int, float)) and conforms:
                assert Decimal(str(reported)) == total, (path.name, row["file"], reported, total)
            elif isinstance(reported, (int, float)):
                raw_total = sum(Decimal(str(scores[key])) * Decimal(str(report["weights"][key])) for key in WEIGHTS).quantize(Decimal(".1"), rounding=ROUND_HALF_UP)
                assert Decimal(str(reported)) == raw_total, (path.name, row["file"], reported, raw_total)
            score_rows.append([name, number, row["file"], row.get("cohort"), *[scores[key] for key in WEIGHTS], float(total), reported, row.get("duplicate_of"), row.get("confidence"), row.get("caveat"), conforms])

round_count = max([manifest.get("councilRound", current_stage - 1), *[number for _, number in reports]])
owner_path = ROOT / "owner-review.json"
owner = json.loads(owner_path.read_text()) if owner_path.exists() else {}
rounds = []
round_rows = [["Round", "Claude Opus 5.5", "Satisfied", "GPT Sol", "Satisfied", "Gemini 4 Argon", "Satisfied", "Basis", "Owner"]]
markdown = ["# KyNotes council score history", "", "Raw reviewer verdicts; scores are not averaged across reviewers or cohorts. Owner rejection reopens progression.", "", "| Round | Claude Opus 5.5 | GPT Sol | Gemini 4 Argon | Owner |", "| --- | ---: | ---: | ---: | --- |"]
for number in range(1, round_count + 1):
    row = {"round": number, **{name: reports.get((name, number), {}) for name in ("opus", "sol", "gemini")}}
    rounds.append(row)
    cells = []
    values = [number]
    for name in ("opus", "sol", "gemini"):
        review = row[name]
        score = review.get("score")
        pending_advisory = name == "gemini" and all(row[primary].get("satisfied") is True for primary in ("opus", "sol"))
        cells.append((f"{score:.1f}/10" + (" (raw*)" if not review.get("rubric_conforms", True) else "")) if score is not None else ("Pending advisory" if pending_advisory else "Deferred" if name == "gemini" else "Pending"))
        values.extend([score if score is not None and review.get("rubric_conforms", True) else cells[-1], review.get("satisfied", "")])
    values.append("Separate raw verdicts; Gemini raw* is excluded from progression because its weights/claims fail the audit. See original reviews and Gemini audit.")
    owner_cell = f"{owner['score']}/10 — rejected double left navigation" if number == owner.get("round") else "Not scored"
    values.append(owner_cell)
    row["owner"] = owner if number == owner.get("round") else {"status": owner_cell}
    round_rows.append(values)
    markdown.append(f"| {number} | {' | '.join(cells)} | {owner_cell} |")
(ROOT / "council-rounds.json").write_text(json.dumps(rounds, indent=2) + "\n")
if any(not report["rubric_conforms"] for report in reports.values()):
    markdown.extend(["", "*Gemini's raw 8.1 is retained. Its weights and several factual claims fail the audit; owner rejection supersedes the prior approvals. See gemini-audit.md and the workbook audit sheet."])
(ROOT / "COUNCIL.md").write_text("\n".join(markdown) + "\n")

evidence_rows = [["File", "SHA-256", "Bytes", "Width", "Height", "Duplicate of", "Kind", "Changed pixels", "Max channel delta"]]
for row in inventory:
    evidence_rows.append([row.get(key) for key in ("file", "sha256", "bytes", "width", "height", "duplicate_of", "duplicate_kind", "changed_pixels", "max_channel_delta")])
pair_rows = [["Surface", "Device", "Theme", "Original baseline", "Current implementation", "Matched", "Limit"]]
for device in ("desktop", "mobile"):
    for theme in ("light", "dark"):
        for surface in ("editor", "empty", "appearance", "pages", "navigation"):
            baseline = f"{current_stage - 1:02}-after" if current_stage >= 8 else "04-after" if current_stage >= 5 else "02-before"
            before = f"screenshots/kynotes-{baseline}-{surface}-{device}-{theme}.png"
            after = f"screenshots/kynotes-{current_stage:02}-after-{surface}-{device}-{theme}.png"
            if not (ROOT / before).exists() or not (ROOT / after).exists():
                continue
            matched = surface not in ("pages", "navigation")
            pair_rows.append([surface, device, theme, before, after, matched, "Fresh accounts change initials/times; same content" if matched else "Different navigation state; no controlled improvement claim"])
checks_path = ROOT / "checks.json"
checks = json.loads(checks_path.read_text()) if checks_path.exists() else []
check_rows = [["Check", "Result", "Evidence / limitation"], *[[row["check"], row["result"], row.get("detail", "")] for row in checks]]
notes = [["Method", "Value"], ["Rubric", "ky-suite-v2; .20/.15/.20/.15/.15/.15; Decimal half-up to one decimal"], ["Scope", "KyNotes editor, phone navigation and Appearance; shared status/field contrast. Not whole-suite acceptance."], ["Source", "Base34849c4 plus recorded source patch hash and served index hashes in capture manifests"], ["Current input", f"Stage{current_stage:02} after; all earlier inputs retained"], ["Missing evidence", "Full empty/loading/error matrix, every product theme/focus path and WebKit remain unproven"], ["Gemini", "Raw advisory8.1 retained; nonconforming weights and unsupported facts audited. Opus/Sol determine progression; see Gemini audit."], ["History", "Handoff6.7 is historical Opus evidence with different coverage; do not treat it as a matched baseline mean"]]
delivery_path = ROOT / "delivery.json"
delivery = json.loads(delivery_path.read_text()) if delivery_path.exists() else []
delivery_rows = [["Repository", "Pull request", "Branch", "Scope"], *[[row.get(key) for key in ("repository", "url", "branch", "scope")] for row in delivery]]
audit_path = ROOT / "gemini-audit.json"
audit = json.loads(audit_path.read_text()) if audit_path.exists() else {}
for file, expected in audit.get("raw_reports", {}).items():
    assert hashlib.sha256((ROOT / file).read_bytes()).hexdigest() == expected, file
audit_rows = [["Finding", "Disposition", "Evidence", "Rationale"], *[[row.get(key) for key in ("id", "status", "evidence", "reason")] for row in audit.get("findings", [])]]

# Minimal XLSX with typed cells, frozen headers and filters. All text is inline
# strings, so report text cannot become an Excel formula.
NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
def column(index):
    result = ""
    while index:
        index, rem = divmod(index - 1, 26)
        result = chr(65 + rem) + result
    return result

def sheet(rows):
    widths = [min(70, max(12, max(len(str(row[c])) if c < len(row) and row[c] is not None else 0 for row in rows) + 2)) for c in range(max(map(len, rows)))]
    cols = "".join(f'<col min="{i}" max="{i}" width="{width}" customWidth="1"/>' for i, width in enumerate(widths, 1))
    out = [f'<worksheet xmlns="{NS}"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><cols>{cols}</cols><sheetData>']
    for r, row in enumerate(rows, 1):
        out.append(f'<row r="{r}">')
        for c, value in enumerate(row, 1):
            ref = f"{column(c)}{r}"
            if value is None:
                continue
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                out.append(f'<c r="{ref}"><v>{value}</v></c>')
            else:
                out.append(f'<c r="{ref}" t="inlineStr"><is><t xml:space="preserve">{escape(str(value))}</t></is></c>')
        out.append("</row>")
    out.append(f'</sheetData><autoFilter ref="A1:{column(max(map(len, rows)))}{len(rows)}"/></worksheet>')
    return "".join(out)

sheets = [("Rounds", round_rows), ("Scores", score_rows), ("Evidence", evidence_rows), ("Matched pairs", pair_rows), ("Checks", check_rows), ("Read me", notes), ("Pull requests", delivery_rows), ("Gemini audit", audit_rows)]
workbook = ROOT / "KyNotes-Council.xlsx"
with zipfile.ZipFile(workbook, "w", zipfile.ZIP_DEFLATED) as z:
    types = ['<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>']
    for i in range(1, len(sheets) + 1):
        types.append(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>')
    z.writestr("[Content_Types].xml", "".join(types) + "</Types>")
    z.writestr("_rels/.rels", '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
    z.writestr("xl/workbook.xml", f'<workbook xmlns="{NS}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>' + "".join(f'<sheet name="{name}" sheetId="{i}" r:id="rId{i}"/>' for i, (name, _) in enumerate(sheets, 1)) + "</sheets></workbook>")
    z.writestr("xl/_rels/workbook.xml.rels", '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' + "".join(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>' for i in range(1, len(sheets) + 1)) + "</Relationships>")
    for i, (_, rows) in enumerate(sheets, 1):
        z.writestr(f"xl/worksheets/sheet{i}.xml", sheet(rows))
with zipfile.ZipFile(workbook) as z:
    assert z.testzip() is None
    for file in z.namelist():
        ET.fromstring(z.read(file))

panels = []
for surface, device in [("editor", "desktop"), ("empty", "desktop"), ("empty", "mobile"), ("editor", "mobile"), ("pages", "mobile"), ("appearance", "mobile")]:
    for theme in ("light", "dark"):
        pair = []
        for stage, prefix in [("Before", "02-before"), ("Current", f"{current_stage:02}-after")]:
            if stage == "Before" and current_stage >= 5:
                prefix = f"{current_stage - 1:02}-after" if current_stage >= 8 else "04-after"
            path = ROOT / f"screenshots/kynotes-{prefix}-{surface}-{device}-{theme}.png"
            data = base64.b64encode(path.read_bytes()).decode()
            pair.append(f'<figure><figcaption>{stage}</figcaption><img src="data:image/png;base64,{data}" alt="{stage} {surface}, {device}, {theme}"/></figure>')
        panels.append(f'<section class="comparison" data-view="{surface}-{device}-{theme}"><h2>{surface.title()} · {device} · {theme}</h2><div class="pair">{"".join(pair)}</div></section>')
table = "".join("<tr>" + "".join(f"<{'th scope=col' if i == 0 else 'td'}>{html.escape(str(cell))}</{'th' if i == 0 else 'td'}>" for cell in row) + "</tr>" for i, row in enumerate([round_rows[0][0:1] + ["Claude Opus 5.5", "GPT Sol", "Gemini 4 Argon", "Owner"], *[[r[0], r[1], r[3], r[5], r[8]] for r in round_rows[1:]]]))
options = "".join(f'<option value="{surface}-{device}-{theme}">{surface.title()} · {device} · {theme}</option>' for surface, device in [("editor", "desktop"), ("empty", "desktop"), ("empty", "mobile"), ("editor", "mobile"), ("pages", "mobile"), ("appearance", "mobile")] for theme in ("light", "dark"))
page = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>KyNotes council</title><style>
:root{font:16px/1.5 system-ui,sans-serif;color:#182326;background:#f8f6f0}body{margin:0}main{max-width:88rem;margin:auto;padding:1.5rem}h1{font-size:1.5rem}h2{font-size:1.1rem}p{max-width:75ch}table{border-collapse:collapse;width:100%;margin:1.5rem 0}th,td{text-align:left;padding:.75rem;border-bottom:1px solid #566461}select{font:inherit;background:#fff;color:#182326;border:1px solid #566461;padding:.5rem;max-width:100%}:focus-visible{outline:2px solid #bf3f18;outline-offset:3px}.pair{display:grid;grid-template-columns:1fr 1fr;gap:1rem}figure{margin:0;min-width:0}figcaption{font-weight:600;margin:.5rem 0}img{display:block;max-width:100%;height:auto}.comparison{display:none}.comparison.active{display:block}.note{font-size:.875rem;color:#566461}@media(max-width:600px){main{padding:1rem}.pair{grid-template-columns:1fr}}@media(prefers-color-scheme:dark){:root{color:#f2efe8;background:#182326}.note{color:#b3bcb8}select{background:#1f2b2e;color:#f2efe8;border-color:#b3bcb8}:focus-visible{outline-color:#f5865f}}
</style><main><h1>KyNotes council</h1><p>Independent review scores and real application captures. Current scope: editor, one left navigation region, phone navigation and Appearance. The owner rejected the prior adjacent left columns at6/10; the revised layout is under fresh review. The progression target is8/10; full9/10 acceptance remains separate.</p><table>TABLE</table><p class="note">Raw reviewer verdicts are retained. Gemini raw* uses nonconforming weights and contains unsupported claims; its score is excluded from progression. The parent audit is in the workbook and gemini-audit.md. Notes and settings cohort means are separate in the source reports. Navigation/picker comparisons change state; they do not establish a controlled numeric improvement.</p><label for="view">Compare a view</label><br><select id="view">OPTIONS</select>PANELS<p class="note">Synthetic Project Atlas with four populated pages. Chromium156, scale1, desktop1280×900 or phone390×844; OS light/dark emulated. Before is the previous reviewed stage; manifests record revisions, patch and served-bundle hashes. Fresh fixtures change initials and save times. The empty trailing bullet is captured fixture content. WebKit and a complete empty/loading/error matrix remain unverified.</p></main><script>const picker=document.getElementById('view');function show(){for(const panel of document.querySelectorAll('.comparison'))panel.classList.toggle('active',panel.dataset.view===picker.value)}picker.addEventListener('change',show);show();</script></html>'''
(ROOT / "comparison.html").write_text(page.replace("TABLE", table).replace("OPTIONS", options).replace("PANELS", "".join(panels)))
print(f"Verified {len(inventory)} image hashes and {len(score_rows)-1} score rows; wrote {len(sheets)}-sheet workbook and self-contained comparison page.")
