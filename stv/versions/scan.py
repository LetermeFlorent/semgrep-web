"""Deux scans bases sur les manifestes : versions obsoletes (registres) et
CVE via OSV.dev (batch). Meme forme de finding que les autres scanners."""
import json, urllib.request

from stv.versions.registries import latest, OSV_ECOSYSTEM, _UA
from stv.versions.semver import is_outdated, severity_for, parts_str
from stv.versions.parsers import collect_deps

_OSV_BATCH = 100        # limite de l'API querybatch


def scan_versions(root, skip_dirs, on_progress=None, cancelled=None):
    # signale chaque dependance en retard sur sa derniere version publiee
    deps = collect_deps(root, skip_dirs)
    findings, total = [], len(deps)
    for index, (ecosystem, name, version, path) in enumerate(deps):
        if cancelled and cancelled():
            break
        if on_progress:
            on_progress(index, total)
        newest = latest(ecosystem, name)
        if newest and is_outdated(version, newest):
            findings.append({
                "severity": severity_for(version, newest),
                "file": path, "line": "-",
                "message": "%s %s est obsolete : derniere version %s (%s)" % (
                    name, version, newest, ecosystem),
                "check_id": "version.outdated.%s" % ecosystem,
                "code": "%s: %s -> %s" % (name, version, newest)})
    if on_progress:
        on_progress(total, total)
    return findings


def _osv_query_batch(deps):
    # deps: [(eco,name,version)] -> resultats OSV alignes sur l'ordre d'entree
    queries = []
    for ecosystem, name, version in deps:
        package = {"name": name}
        osv_name = OSV_ECOSYSTEM.get(ecosystem)
        if osv_name:
            package["ecosystem"] = osv_name
        queries.append({"version": parts_str(version), "package": package})
    body = json.dumps({"queries": queries}).encode()
    request = urllib.request.Request("https://api.osv.dev/v1/querybatch",
        data=body, headers={**_UA, "Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read()).get("results", [])


def scan_osv(root, skip_dirs, on_progress=None, cancelled=None):
    # CVE sans lockfile : interroge OSV.dev par lot depuis les manifestes
    deps = collect_deps(root, skip_dirs)
    findings, total = [], len(deps)
    if not total:
        if on_progress:
            on_progress(1, 1)
        return findings
    done = 0
    for start in range(0, total, _OSV_BATCH):
        if cancelled and cancelled():
            break
        chunk = deps[start:start + _OSV_BATCH]
        try:
            results = _osv_query_batch([(e, n, v) for e, n, v, _ in chunk])
        except Exception:
            results = []
        for (ecosystem, name, version, path), result in zip(chunk, results):
            for vuln in (result or {}).get("vulns", []) or []:
                vuln_id = vuln.get("id", "")
                findings.append({
                    "severity": "ERROR", "file": path, "line": "-",
                    "message": "%s %s : %s (%s)" % (name, version, vuln_id, ecosystem),
                    "check_id": "cve.%s" % vuln_id, "code": ""})
        done += len(chunk)
        if on_progress:
            on_progress(done, total)
    return findings
