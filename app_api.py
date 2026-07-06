"""Surface publique testable en headless (sans Flask ni Docker).
Reexporte les fonctions pures des modules stv/. C'est le "seam" des tests."""
from stv.paths import map_path, path_allowed, list_targets, path_slug, base_name
from stv.findings import finding_key, dedupe, diff_results
from stv.export import build_sarif, build_csv, build_html_report

__all__ = ["map_path", "path_allowed", "list_targets", "path_slug", "base_name",
           "finding_key", "dedupe", "diff_results",
           "build_sarif", "build_csv", "build_html_report"]
