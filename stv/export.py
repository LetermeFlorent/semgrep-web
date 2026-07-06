"""Export des resultats : SARIF 2.1, CSV, rapport HTML imprimable.
Fonctions pures (job dict -> texte) — pas de Flask ici."""
import io, csv, html

_SARIF_LEVEL = {"ERROR": "error", "WARNING": "warning", "INFO": "note"}


def build_sarif(job):
    rules, results = {}, []
    for finding in (job.get("results") or []):
        rule_id = finding.get("check_id") or "finding"
        rules.setdefault(rule_id, {"id": rule_id,
            "shortDescription": {"text": (finding.get("message") or rule_id)[:120]}})
        try:
            line = int(finding.get("line"))
        except (TypeError, ValueError):
            line = 1
        results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(finding.get("severity"), "note"),
            "message": {"text": finding.get("message") or ""},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": (finding.get("file") or "").replace("\\", "/")},
                "region": {"startLine": max(1, line)}}}],
            "properties": {"status": finding.get("status", "open"),
                           "code": finding.get("code", "")},
        })
    return {"version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "STV",
            "informationUri": "https://local", "rules": list(rules.values())}},
            "results": results}]}


def build_csv(job):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["severity", "file", "line", "check_id", "status", "message", "code"])
    for finding in (job.get("results") or []):
        writer.writerow([
            finding.get("severity"), finding.get("file"), finding.get("line"),
            finding.get("check_id"), finding.get("status", "open"),
            (finding.get("message") or "").replace("\n", " "),
            (finding.get("code") or "").replace("\n", " ")[:300]])
    return buffer.getvalue()


def _report_row(finding):
    return ("<tr class='%s'><td>%s</td><td class='f'>%s:%s</td>"
            "<td>%s</td><td>%s</td><td><code>%s</code></td></tr>" % (
                finding.get("severity"), finding.get("severity"),
                html.escape(str(finding.get("file"))), finding.get("line"),
                html.escape(str(finding.get("check_id"))),
                html.escape(str(finding.get("message") or "")),
                html.escape(str(finding.get("code") or ""))[:400]))


def build_html_report(job):
    counts = job.get("counts") or {}
    findings = job.get("results") or []
    rows = "".join(_report_row(f) for f in findings)
    return _REPORT_TEMPLATE % (
        html.escape(str(job.get("path"))), len(findings),
        counts.get("ERROR", 0), counts.get("WARNING", 0), counts.get("INFO", 0), rows)


_REPORT_TEMPLATE = """<!doctype html><meta charset=utf-8><title>Rapport STV</title>
<style>body{font:13px system-ui;margin:24px;color:#222}
h1{font-size:18px}.meta{color:#666;margin-bottom:16px}
.cards{display:flex;gap:12px;margin:16px 0}
.card{border:1px solid #ddd;border-radius:6px;padding:8px 14px}
.card b{font-size:20px;display:block}
table{border-collapse:collapse;width:100%%;font-size:12px}
td,th{border:1px solid #e2e2e2;padding:5px 8px;text-align:left;vertical-align:top}
th{background:#f6f6f6}
tr.ERROR td:first-child{color:#c0392b;font-weight:600}
tr.WARNING td:first-child{color:#b8860b;font-weight:600}
tr.INFO td:first-child{color:#2980b9}
.f{font-family:ui-monospace,monospace;white-space:nowrap}
code{font-size:11px;color:#555}
@media print{@page{margin:12mm}}
</style>
<h1>Rapport de securite STV</h1>
<div class=meta>%s &middot; %d problemes</div>
<div class=cards>
 <div class=card><b>%d</b>Critiques</div>
 <div class=card><b>%d</b>Moyens</div>
 <div class=card><b>%d</b>Infos</div></div>
<table><tr><th>Severite</th><th>Emplacement</th><th>Regle</th>
<th>Message</th><th>Extrait</th></tr>%s</table>
<script>print()</script>"""
