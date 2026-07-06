"""Secrets presents dans l'historique git (mode GIT de gitleaks)."""
import os, json, tempfile

from stv.scanners.runner import run_command


def scan_secrets_history(root, on_progress=None, cancelled=None):
    if on_progress:
        on_progress(0, 1)
    if not os.path.isdir(os.path.join(root, ".git")):
        if on_progress:
            on_progress(1, 1)
        return []
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = tmp.name
    findings = []
    try:
        run_command(["gitleaks", "detect", "--source", root,
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
            commit = (item.get("Commit") or "")[:8]
            findings.append({
                "severity": "ERROR",
                "file": item.get("File", "?"),
                "line": item.get("StartLine", "-"),
                "message": "Secret dans l'historique git : %s" % (
                    item.get("Description") or item.get("RuleID") or "secret"),
                "check_id": "secret.history.%s" % (item.get("RuleID") or "gitleaks"),
                "code": ("commit %s" % commit) if commit else ""})
    finally:
        try:
            os.remove(report_path)
        except OSError:
            pass
    if on_progress:
        on_progress(1, 1)
    return findings
