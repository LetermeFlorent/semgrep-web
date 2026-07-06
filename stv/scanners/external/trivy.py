"""Scans Trivy : vulnerabilites de dependances (CVE), mauvaises configs (IaC),
licences a risque. Complete le CVE avec OSV.dev (marche sans lockfile)."""
import json

from stv.scanners.runner import run_command, severity_of
from stv.versions import scan_osv

_RISKY_LICENSES = {"GPL", "AGPL", "LGPL", "SSPL"}


def _trivy(root, scanners, timeout=2400):
    _, out, _ = run_command(["trivy", "fs", "--quiet", "--format", "json",
                             "--scanners", scanners, root], timeout=timeout)
    try:
        return json.loads(out or "{}")
    except json.JSONDecodeError:
        return {}


def scan_cve(root, skip_dirs=None, on_progress=None, cancelled=None):
    # Trivy (lockfile/arbre installe) + OSV.dev (manifestes), fusion dedupliquee
    if on_progress:
        on_progress(0, 1)
    findings, seen = [], set()

    def add(item):
        key = (item["check_id"], item["file"])
        if key not in seen:
            seen.add(key)
            findings.append(item)

    for result in _trivy(root, "vuln").get("Results", []) or []:
        if cancelled and cancelled():
            break
        target = result.get("Target", "?")
        for vuln in result.get("Vulnerabilities", []) or []:
            add({
                "severity": severity_of(vuln.get("Severity")),
                "file": target, "line": "-",
                "message": "%s %s : %s (%s)" % (
                    vuln.get("PkgName", "?"), vuln.get("InstalledVersion", ""),
                    vuln.get("VulnerabilityID", ""),
                    (vuln.get("Title") or vuln.get("Description") or "")[:120]),
                "check_id": "cve.%s" % vuln.get("VulnerabilityID", "trivy"),
                "code": ("Fixe dans: %s" % vuln.get("FixedVersion")) if vuln.get("FixedVersion") else ""})

    try:
        for item in scan_osv(root, skip_dirs or set(), cancelled=cancelled):
            add(item)
    except Exception:
        pass

    if on_progress:
        on_progress(1, 1)
    return findings


def scan_iac(root, on_progress=None, cancelled=None):
    if on_progress:
        on_progress(0, 1)
    findings = []
    for result in _trivy(root, "misconfig").get("Results", []) or []:
        if cancelled and cancelled():
            break
        target = result.get("Target", "?")
        for miscfg in result.get("Misconfigurations", []) or []:
            findings.append({
                "severity": severity_of(miscfg.get("Severity")),
                "file": target,
                "line": miscfg.get("CauseMetadata", {}).get("StartLine", "-"),
                "message": "%s : %s" % (miscfg.get("ID", ""),
                    miscfg.get("Title") or miscfg.get("Description", "")[:120]),
                "check_id": "iac.%s" % miscfg.get("ID", "trivy"),
                "code": (miscfg.get("Resolution") or "")[:200]})
    if on_progress:
        on_progress(1, 1)
    return findings


def scan_license(root, on_progress=None, cancelled=None):
    if on_progress:
        on_progress(0, 1)
    findings = []
    for result in _trivy(root, "license").get("Results", []) or []:
        if cancelled and cancelled():
            break
        for lic in result.get("Licenses", []) or []:
            name = lic.get("Name", "")
            risky = any(name.upper().startswith(prefix) for prefix in _RISKY_LICENSES)
            findings.append({
                "severity": "WARNING" if risky else "INFO",
                "file": lic.get("FilePath") or result.get("Target", "?"), "line": "-",
                "message": "Licence %s : %s" % (name, lic.get("PkgName", "")),
                "check_id": "license.%s" % (name or "unknown"),
                "code": lic.get("Category", "")})
    if on_progress:
        on_progress(1, 1)
    return findings
