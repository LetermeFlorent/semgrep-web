"""Scanners securite additionnels : secrets (gitleaks), CVE deps / IaC / licences (trivy),
permissions de fichiers et fichiers sensibles (maison). Lecture seule."""
import os, re, json, subprocess, tempfile, stat

def _run(cmd, timeout=1800):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate(timeout=timeout)
    return p.returncode, out, err

def _sev_map(s):
    s = (s or "").upper()
    if s in ("CRITICAL", "HIGH"):
        return "ERROR"
    if s in ("MEDIUM", "MODERATE"):
        return "WARNING"
    return "INFO"

# ---- Secrets : gitleaks ----
def scan_secrets(root, on_progress=None, cancelled=None):
    if on_progress: on_progress(0, 1)
    findings = []
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        rep = tf.name
    try:
        # detect sur le repertoire (pas de git requis avec --no-git)
        _run(["gitleaks", "detect", "--no-git", "--source", root,
              "--report-format", "json", "--report-path", rep, "--redact", "--exit-code", "0"])
        try:
            with open(rep, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = []
        for it in data or []:
            if cancelled and cancelled(): break
            findings.append({
                "severity": "ERROR",
                "file": it.get("File", "?"),
                "line": it.get("StartLine", "-"),
                "message": "Secret detecte : %s" % (it.get("Description") or it.get("RuleID") or "secret"),
                "check_id": "secret.%s" % (it.get("RuleID") or "gitleaks"),
                "code": (it.get("Match") or it.get("Secret") or "").strip()[:200],
            })
    finally:
        try: os.remove(rep)
        except Exception: pass
    if on_progress: on_progress(1, 1)
    return findings

# ---- Trivy : vuln deps (CVE) + IaC/config + licences ----
def _trivy(root, scanners, timeout=2400):
    rc, out, err = _run(["trivy", "fs", "--quiet", "--format", "json",
                         "--scanners", scanners, root], timeout=timeout)
    try:
        return json.loads(out or "{}")
    except Exception:
        return {}

def scan_cve(root, skip_dirs=None, on_progress=None, cancelled=None):
    # Trivy (precis, si lockfile) + OSV.dev depuis les manifestes (marche sans lock). Fusion dedupe.
    import verscan
    if on_progress: on_progress(0, 1)
    findings, seen = [], set()

    def add(item):
        key = (item["check_id"], item["file"])
        if key not in seen:
            seen.add(key)
            findings.append(item)

    # --- Trivy (arbre de deps installe / lockfile) ---
    data = _trivy(root, "vuln")
    for res in data.get("Results", []) or []:
        if cancelled and cancelled(): break
        tgt = res.get("Target", "?")
        for v in res.get("Vulnerabilities", []) or []:
            add({
                "severity": _sev_map(v.get("Severity")),
                "file": tgt, "line": "-",
                "message": "%s %s : %s (%s)" % (
                    v.get("PkgName", "?"), v.get("InstalledVersion", ""),
                    v.get("VulnerabilityID", ""),
                    (v.get("Title") or v.get("Description") or "")[:120]),
                "check_id": "cve.%s" % v.get("VulnerabilityID", "trivy"),
                "code": ("Fixe dans: %s" % v.get("FixedVersion")) if v.get("FixedVersion") else "",
            })

    # --- OSV depuis les manifestes (comble l'absence de lockfile) ---
    try:
        for item in verscan.scan_osv(root, skip_dirs or set(), cancelled=cancelled):
            add(item)
    except Exception:
        pass

    if on_progress: on_progress(1, 1)
    return findings

def scan_iac(root, on_progress=None, cancelled=None):
    if on_progress: on_progress(0, 1)
    findings = []
    data = _trivy(root, "misconfig")
    for res in data.get("Results", []) or []:
        if cancelled and cancelled(): break
        tgt = res.get("Target", "?")
        for m in res.get("Misconfigurations", []) or []:
            cl = m.get("CauseMetadata", {}).get("StartLine", "-")
            findings.append({
                "severity": _sev_map(m.get("Severity")),
                "file": tgt,
                "line": cl,
                "message": "%s : %s" % (m.get("ID", ""), m.get("Title") or m.get("Description", "")[:120]),
                "check_id": "iac.%s" % m.get("ID", "trivy"),
                "code": (m.get("Resolution") or "")[:200],
            })
    if on_progress: on_progress(1, 1)
    return findings

def scan_license(root, on_progress=None, cancelled=None):
    if on_progress: on_progress(0, 1)
    findings = []
    data = _trivy(root, "license")
    RISK = {"GPL", "AGPL", "LGPL", "SSPL"}
    for res in data.get("Results", []) or []:
        if cancelled and cancelled(): break
        for lic in res.get("Licenses", []) or []:
            name = lic.get("Name", "")
            risky = any(name.upper().startswith(r) for r in RISK)
            findings.append({
                "severity": "WARNING" if risky else "INFO",
                "file": lic.get("FilePath") or res.get("Target", "?"),
                "line": "-",
                "message": "Licence %s : %s" % (name, lic.get("PkgName", "")),
                "check_id": "license.%s" % (name or "unknown"),
                "code": lic.get("Category", ""),
            })
    if on_progress: on_progress(1, 1)
    return findings

# ---- Permissions de fichiers (maison) ----
SENSITIVE_EXT = {".pem", ".key", ".p12", ".pfx", ".keystore", ".jks"}

def scan_perms(root, skip_dirs, on_progress=None, cancelled=None):
    if on_progress: on_progress(0, 1)
    findings = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in skip_dirs and not d.startswith(".")]
        if cancelled and cancelled(): break
        for fn in fns:
            path = os.path.join(dp, fn)
            ext = os.path.splitext(fn)[1].lower()
            try:
                mode = os.stat(path).st_mode
            except Exception:
                continue
            # world-writable
            if mode & stat.S_IWOTH:
                findings.append({
                    "severity": "WARNING", "file": path, "line": "-",
                    "message": "Fichier accessible en ecriture par tous (world-writable)",
                    "check_id": "perms.world_writable",
                    "code": oct(stat.S_IMODE(mode)),
                })
            # cle/certif lisible par tous
            if ext in SENSITIVE_EXT and (mode & (stat.S_IROTH | stat.S_IRGRP)):
                findings.append({
                    "severity": "ERROR", "file": path, "line": "-",
                    "message": "Cle/certificat lisible au-dela du proprietaire",
                    "check_id": "perms.key_readable",
                    "code": oct(stat.S_IMODE(mode)),
                })
    if on_progress: on_progress(1, 1)
    return findings

# ---- Fichiers sensibles presents (maison) ----
SENSITIVE_NAMES = {".env", ".env.local", ".env.production", "id_rsa", "id_dsa",
    "id_ecdsa", "id_ed25519", ".npmrc", ".pypirc", ".htpasswd",
    "credentials", ".netrc", "secrets.json", ".aws"}
SENSITIVE_SUFFIX = (".pem", ".key", ".p12", ".pfx", ".keystore", ".jks",
    ".sql", ".sqlite", ".db", ".dump", ".bak", ".backup", ".pcap")

def scan_sensitive(root, skip_dirs, on_progress=None, cancelled=None):
    if on_progress: on_progress(0, 1)
    findings = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in skip_dirs and not d.startswith(".") or d == ".env"]
        if cancelled and cancelled(): break
        for fn in fns:
            low = fn.lower()
            hit = low in SENSITIVE_NAMES or low.endswith(SENSITIVE_SUFFIX)
            if hit:
                path = os.path.join(dp, fn)
                findings.append({
                    "severity": "WARNING", "file": path, "line": "-",
                    "message": "Fichier sensible present dans le projet : %s" % fn,
                    "check_id": "sensitive.file",
                    "code": "",
                })
    if on_progress: on_progress(1, 1)
    return findings
