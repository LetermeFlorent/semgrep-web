"""Scanners externes (outils tiers) : secrets, CVE/IaC/licences, Dockerfile, historique git."""
from stv.scanners.external.secrets import scan_secrets
from stv.scanners.external.trivy import scan_cve, scan_iac, scan_license
from stv.scanners.external.hadolint import scan_hadolint
from stv.scanners.external.history import scan_secrets_history

__all__ = ["scan_secrets", "scan_cve", "scan_iac", "scan_license",
           "scan_hadolint", "scan_secrets_history"]
