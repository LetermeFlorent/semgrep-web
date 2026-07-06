"""Detection de secrets via gitleaks (mode --no-git, sur un dossier)."""
import os, json, tempfile

from stv.scanners.runner import run_command


def scan_secrets(root, on_progress=None, cancelled=None):
    if on_progress:
        on_progress(0, 1)
    findings = []
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = tmp.name
    try:
        run_command(["gitleaks", "detect", "--no-git", "--source", root,
                     "--report-format", "json", "--report-path", report_path,
                     "--redact", "--exit-code", "0"])
        try:
            with open(report_path, encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception:
            data = []
        for item in data or []:
            if cancelled and cancelled():
                break
            findings.append({
                "severity": "ERROR",
                "file": item.get("File", "?"),
                "line": item.get("StartLine", "-"),
                "message": "Secret detecte : %s" % (
                    item.get("Description") or item.get("RuleID") or "secret"),
                "check_id": "secret.%s" % (item.get("RuleID") or "gitleaks"),
                "code": (item.get("Match") or item.get("Secret") or "").strip()[:200]})
    finally:
        try:
            os.remove(report_path)
        except OSError:
            pass
    if on_progress:
        on_progress(1, 1)
    return findings
