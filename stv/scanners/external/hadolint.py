"""Lint des Dockerfile via hadolint (bonnes pratiques + securite)."""
import os, json

from stv.scanners.runner import run_command

_SKIP = {".git", "node_modules", "vendor", "target"}
_LEVELS = {"error": "ERROR", "warning": "WARNING", "info": "INFO", "style": "INFO"}


def _dockerfiles(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP]
        for name in filenames:
            low = name.lower()
            if low == "dockerfile" or low.endswith(".dockerfile"):
                yield os.path.join(dirpath, name)


def scan_hadolint(root, on_progress=None, cancelled=None):
    if on_progress:
        on_progress(0, 1)
    files = list(_dockerfiles(root))
    findings = []
    for idx, path in enumerate(files):
        if cancelled and cancelled():
            break
        _, out, _ = run_command(["hadolint", "--format", "json", path], timeout=120)
        try:
            issues = json.loads(out or "[]")
        except json.JSONDecodeError:
            issues = []
        for it in issues:
            findings.append({
                "severity": _LEVELS.get((it.get("level") or "").lower(), "INFO"),
                "file": path, "line": it.get("line", "-"),
                "message": "%s : %s" % (it.get("code", ""), it.get("message", "")),
                "check_id": "docker.%s" % it.get("code", "hadolint"),
                "code": ""})
        if on_progress:
            on_progress(idx + 1, len(files) or 1)
    if on_progress:
        on_progress(1, 1)
    return findings
