"""Verifications maison sur l'arborescence : permissions dangereuses et
presence de fichiers sensibles. Lecture seule."""
import os, stat

_KEY_EXT = {".pem", ".key", ".p12", ".pfx", ".keystore", ".jks"}

_SENSITIVE_NAMES = {".env", ".env.local", ".env.production", "id_rsa", "id_dsa",
    "id_ecdsa", "id_ed25519", ".npmrc", ".pypirc", ".htpasswd",
    "credentials", ".netrc", "secrets.json", ".aws"}
_SENSITIVE_SUFFIX = (".pem", ".key", ".p12", ".pfx", ".keystore", ".jks",
    ".sql", ".sqlite", ".db", ".dump", ".bak", ".backup", ".pcap")


def _walk(root, skip_dirs, keep_env=False):
    # parcourt en ignorant dossiers exclus/caches (option: garder .env)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if (d not in skip_dirs and not d.startswith("."))
                       or (keep_env and d == ".env")]
        for name in filenames:
            yield os.path.join(dirpath, name), name


def scan_perms(root, skip_dirs, on_progress=None, cancelled=None):
    if on_progress:
        on_progress(0, 1)
    findings = []
    for path, name in _walk(root, skip_dirs):
        if cancelled and cancelled():
            break
        try:
            mode = os.stat(path).st_mode
        except OSError:
            continue
        if mode & stat.S_IWOTH:
            findings.append({
                "severity": "WARNING", "file": path, "line": "-",
                "message": "Fichier accessible en ecriture par tous (world-writable)",
                "check_id": "perms.world_writable", "code": oct(stat.S_IMODE(mode))})
        ext = os.path.splitext(name)[1].lower()
        if ext in _KEY_EXT and (mode & (stat.S_IROTH | stat.S_IRGRP)):
            findings.append({
                "severity": "ERROR", "file": path, "line": "-",
                "message": "Cle/certificat lisible au-dela du proprietaire",
                "check_id": "perms.key_readable", "code": oct(stat.S_IMODE(mode))})
    if on_progress:
        on_progress(1, 1)
    return findings


def scan_sensitive(root, skip_dirs, on_progress=None, cancelled=None):
    if on_progress:
        on_progress(0, 1)
    findings = []
    for path, name in _walk(root, skip_dirs, keep_env=True):
        if cancelled and cancelled():
            break
        low = name.lower()
        if low in _SENSITIVE_NAMES or low.endswith(_SENSITIVE_SUFFIX):
            findings.append({
                "severity": "WARNING", "file": path, "line": "-",
                "message": "Fichier sensible present dans le projet : %s" % name,
                "check_id": "sensitive.file", "code": ""})
    if on_progress:
        on_progress(1, 1)
    return findings
