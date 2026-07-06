"""Scan des versions de dependances : detecte la techno, compare a la derniere
version publiee (registres publics) et interroge OSV.dev pour les CVE sans lockfile."""
from stv.versions.scan import scan_versions, scan_osv

__all__ = ["scan_versions", "scan_osv"]
