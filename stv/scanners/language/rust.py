"""CVE des crates Rust via cargo-audit (sur chaque Cargo.lock trouve)."""
import os, json

from stv.scanners.runner import run_command


def _locks(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", "target")]
        if "Cargo.lock" in filenames:
            yield os.path.join(dirpath, "Cargo.lock")


def scan_rust(root, on_progress=None, cancelled=None):
    if on_progress:
        on_progress(0, 1)
    findings = []
    for lock in _locks(root):
        if cancelled and cancelled():
            break
        _, out, _ = run_command(
            ["cargo-audit", "audit", "--file", lock, "--json"], timeout=600)
        try:
            data = json.loads(out or "{}")
        except json.JSONDecodeError:
            continue
        for v in (data.get("vulnerabilities") or {}).get("list", []) or []:
            adv, pkg = v.get("advisory") or {}, v.get("package") or {}
            findings.append({
                "severity": "ERROR", "file": lock, "line": "-",
                "message": "%s %s : %s — %s" % (pkg.get("name", ""),
                    pkg.get("version", ""), adv.get("id", ""), adv.get("title", "")),
                "check_id": "cve.%s" % adv.get("id", ""), "code": ""})
        for w_list in (data.get("warnings") or {}).values():
            for w in w_list or []:
                adv, pkg = w.get("advisory") or {}, w.get("package") or {}
                findings.append({
                    "severity": "WARNING", "file": lock, "line": "-",
                    "message": "%s %s : %s" % (pkg.get("name", ""),
                        pkg.get("version", ""),
                        adv.get("title") or w.get("kind", "avertissement")),
                    "check_id": "cve.%s" % (adv.get("id") or w.get("kind", "warn")),
                    "code": ""})
    if on_progress:
        on_progress(1, 1)
    return findings
