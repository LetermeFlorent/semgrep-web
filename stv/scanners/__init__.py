"""Scanners de securite additionnels : secrets (gitleaks), CVE/IaC/licences (trivy),
permissions et fichiers sensibles (maison). Tout en lecture seule."""
from stv.scanners.secrets import scan_secrets
from stv.scanners.trivy import scan_cve, scan_iac, scan_license
from stv.scanners.local import scan_perms, scan_sensitive

__all__ = ["scan_secrets", "scan_cve", "scan_iac", "scan_license",
           "scan_perms", "scan_sensitive"]
