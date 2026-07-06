"""CVE des projets Java (pom.xml, jar, gradle) via trivy (filtre lang-pkgs Java)."""
from stv.scanners.runner import severity_of
from stv.scanners.external.trivy import _trivy

_JAVA_TYPES = {"jar", "pom", "gradle", "java"}


def _is_java(result):
    if result.get("Class") != "lang-pkgs":
        return False
    typ = (result.get("Type") or "").lower()
    target = (result.get("Target") or "").lower()
    return typ in _JAVA_TYPES or target.endswith((".jar", "pom.xml", ".gradle"))


def scan_java(root, skip_dirs, on_progress=None, cancelled=None):
    if on_progress:
        on_progress(0, 1)
    findings = []
    for result in _trivy(root, "vuln").get("Results", []) or []:
        if cancelled and cancelled():
            break
        if not _is_java(result):
            continue
        target = result.get("Target", "?")
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append({
                "severity": severity_of(vuln.get("Severity")),
                "file": target, "line": "-",
                "message": "%s %s : %s (%s)" % (vuln.get("PkgName", "?"),
                    vuln.get("InstalledVersion", ""), vuln.get("VulnerabilityID", ""),
                    (vuln.get("Title") or vuln.get("Description") or "")[:120]),
                "check_id": "cve.%s" % vuln.get("VulnerabilityID", "trivy"),
                "code": ("Fixe dans: %s" % vuln.get("FixedVersion")) if vuln.get("FixedVersion") else ""})
    if on_progress:
        on_progress(1, 1)
    return findings
