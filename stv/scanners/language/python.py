"""SAST Python : bandit (code) + pip-audit (dependances des requirements)."""
import os, json

from stv.scanners.runner import run_command

_BANDIT_SEV = {"HIGH": "ERROR", "MEDIUM": "WARNING", "LOW": "INFO"}


def _bandit(root, skip_dirs, findings):
    cmd = ["bandit", "-r", root, "-f", "json", "-q"]
    if skip_dirs:
        cmd += ["--exclude", ",".join(skip_dirs)]
    _, out, _ = run_command(cmd, timeout=1200)
    try:
        data = json.loads(out or "{}")
    except json.JSONDecodeError:
        data = {}
    for r in data.get("results", []) or []:
        findings.append({
            "severity": _BANDIT_SEV.get((r.get("issue_severity") or "").upper(), "INFO"),
            "file": r.get("filename", "?"), "line": r.get("line_number", "-"),
            "message": r.get("issue_text", ""),
            "check_id": "python.bandit.%s" % r.get("test_id", ""),
            "code": ""})


def _requirements(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", "vendor")]
        for name in filenames:
            if name.startswith("requirements") and name.endswith(".txt"):
                yield os.path.join(dirpath, name)


def _pip_audit(root, findings, cancelled):
    for req in _requirements(root):
        if cancelled and cancelled():
            break
        _, out, _ = run_command(
            ["pip-audit", "-r", req, "-f", "json", "--progress-spinner", "off"],
            timeout=600)
        try:
            data = json.loads(out or "{}")
        except json.JSONDecodeError:
            continue
        for dep in data.get("dependencies", []) or []:
            for vuln in dep.get("vulns", []) or []:
                findings.append({
                    "severity": "ERROR", "file": req, "line": "-",
                    "message": "%s %s : %s" % (dep.get("name", ""),
                        dep.get("version", ""), vuln.get("id", "")),
                    "check_id": "cve.%s" % vuln.get("id", ""),
                    "code": (vuln.get("description") or "")[:200]})


def scan_python(root, skip_dirs, on_progress=None, cancelled=None):
    if on_progress:
        on_progress(0, 1)
    findings = []
    try:
        _bandit(root, skip_dirs, findings)
    except Exception:
        pass
    try:
        _pip_audit(root, findings, cancelled)
    except Exception:
        pass
    if on_progress:
        on_progress(1, 1)
    return findings
