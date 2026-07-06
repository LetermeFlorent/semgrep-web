"""Implementation des 7 scans (un thread chacun). Ecrit dans results/counts
partages sous RLOCK et publie la progression via step_update/touch."""
import subprocess, json
from stv.paths import list_targets
from stv.config import load_config
from stv.jobs.store import RLOCK, touch, step_update
from stv import scanners
from stv import versions


class Cancelled(Exception):
    pass


def _safe_json(s):
    try:
        return json.loads(s or "{}")
    except Exception:
        return {}


def parse_results(data, results, counts):
    new = []
    for r in data.get("results", []):
        sev = r.get("extra", {}).get("severity", "INFO")
        if sev not in counts:
            sev = "INFO"
        counts[sev] += 1
        item = {
            "severity": sev,
            "file": r.get("path", "?"),
            "line": r.get("start", {}).get("line", "?"),
            "message": r.get("extra", {}).get("message", ""),
            "check_id": r.get("check_id", ""),
            "code": (r.get("extra", {}).get("lines", "") or "").strip()[:500],
        }
        results.append(item)
        new.append(item)
    return new


def _cfg(job):
    return job.get("cfg") or load_config()


def _collect(job, name, results, counts, found):
    with RLOCK:
        for item in found:
            counts[item["severity"]] = counts.get(item["severity"], 0) + 1
            results.append(item)
    touch(job, counts=dict(counts))
    step_update(job, name, pct=100, phase="Termine", remaining=0)


def _scan_semgrep(job, target, results, counts):
    step_update(job, "semgrep", phase="Recensement", pct=1, done=0, remaining=0)
    cfg = _cfg(job)
    targets = list_targets(target, set(cfg["skip_dirs"]), set(cfg["skip_ext"]))
    total = len(targets)
    step_update(job, "semgrep", total=total, done=0, remaining=total)
    if total == 0:
        step_update(job, "semgrep", pct=100, phase="Aucun fichier")
        return
    cmd = ["semgrep", "scan", "--config", "auto", "--json", "--quiet"]
    MAXARG = 30
    try:
        done = 0
        for i in range(0, total, MAXARG):
            if job.get("cancel"):
                raise Cancelled()
            batch = targets[i:i + MAXARG]
            ph = "Chargement des regles" if done == 0 else "Analyse du code"
            step_update(job, "semgrep", phase=ph, remaining=total - done,
                        pct=max(job["steps"].get("semgrep", {}).get("pct", 0), 2))
            proc = subprocess.Popen(cmd + batch, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
            job["proc"] = proc
            out, _ = proc.communicate(timeout=1800)
            if job.get("cancel"):
                raise Cancelled()
            with RLOCK:
                parse_results(_safe_json(out), results, counts)
            done += len(batch)
            step_update(job, "semgrep", pct=min(99, round(done / total * 99)),
                        phase="Analyse du code", done=done, remaining=total - done)
            touch(job, counts=dict(counts))
        step_update(job, "semgrep", pct=100, phase="Termine", remaining=0)
    finally:
        job["proc"] = None


def _scan_versions(job, target, results, counts):
    step_update(job, "versions", phase="Recherche des manifestes", pct=1)
    skip_dirs = set(_cfg(job)["skip_dirs"])

    def prog(done, total):
        if job.get("cancel"):
            return
        pct = 100 if not total else min(99, round(done / total * 99))
        step_update(job, "versions", pct=pct,
                    phase="Verification des versions" if total else "Aucune dependance",
                    total=total, done=done, remaining=max(0, total - done))

    found = versions.scan_versions(target, skip_dirs, on_progress=prog,
                                   cancelled=lambda: job.get("cancel"))
    _collect(job, "versions", results, counts, found)


def _mk_step(name, phase, fn_needs_skip=False, scanfn=None):
    # fabrique un _scan_* base sur un scanner (progression simple 0->100)
    def run(job, target, results, counts):
        step_update(job, name, phase=phase, pct=1)

        def prog(done, total):
            if job.get("cancel"):
                return
            pct = 100 if not total else min(99, round(done / total * 99))
            step_update(job, name, pct=pct, phase=phase,
                        total=total, done=done, remaining=max(0, total - done))
        try:
            if fn_needs_skip:
                skip = set(_cfg(job)["skip_dirs"])
                found = scanfn(target, skip, on_progress=prog, cancelled=lambda: job.get("cancel"))
            else:
                found = scanfn(target, on_progress=prog, cancelled=lambda: job.get("cancel"))
        except Exception as e:
            step_update(job, name, pct=100, phase="Erreur: " + str(e)[:60])
            found = []
        _collect(job, name, results, counts, found)
    return run


SCAN_FNS = {
    "semgrep": _scan_semgrep,
    "versions": _scan_versions,
    "secrets": _mk_step("secrets", "Recherche de secrets", scanfn=scanners.scan_secrets),
    "cve": _mk_step("cve", "Vulnerabilites (CVE)", fn_needs_skip=True, scanfn=scanners.scan_cve),
    "iac": _mk_step("iac", "Config / IaC", scanfn=scanners.scan_iac),
    "license": _mk_step("license", "Licences", scanfn=scanners.scan_license),
    "sensitive": _mk_step("sensitive", "Fichiers sensibles", fn_needs_skip=True, scanfn=scanners.scan_sensitive),
    "secrets_history": _mk_step("secrets_history", "Secrets historique git", scanfn=scanners.scan_secrets_history),
    "perms": _mk_step("perms", "Permissions fichiers", fn_needs_skip=True, scanfn=scanners.scan_perms),
    "hadolint": _mk_step("hadolint", "Dockerfile", scanfn=scanners.scan_hadolint),
    "python": _mk_step("python", "Python SAST", fn_needs_skip=True, scanfn=scanners.scan_python),
    "rust": _mk_step("rust", "Rust CVE", scanfn=scanners.scan_rust),
    "java": _mk_step("java", "Java CVE", fn_needs_skip=True, scanfn=scanners.scan_java),
}
