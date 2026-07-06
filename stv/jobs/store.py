"""Etat partage des jobs de scan + notifications SSE.
JOBS est la source unique : tout le monde l'importe d'ici (pas de cycle)."""
import os, json, threading

# scan_id -> job dict (voir new_job dans runner.py)
JOBS = {}
JLOCK = threading.Lock()
JCOND = threading.Condition(JLOCK)   # reveille les streams a chaque update
RLOCK = threading.Lock()             # protege results/counts partages entre threads

STATE_FILE = os.environ.get("STV_STATE", "/state/jobs.json")

LABELS = {"semgrep": "Code", "versions": "Deps", "secrets": "Secrets",
          "cve": "CVE", "iac": "IaC", "license": "Licences",
          "sensitive": "Fichiers", "secrets_history": "Secrets git",
          "perms": "Permissions", "hadolint": "Dockerfile",
          "python": "Python SAST", "rust": "Rust CVE", "java": "Java CVE"}
ALL_SCANS = ["semgrep", "versions", "secrets", "cve", "iac", "license", "sensitive",
             "secrets_history", "perms", "hadolint", "python", "rust", "java"]


def snapshot(job):
    # etat serialisable expose au client
    return {
        "scan_id": job["scan_id"], "path": job["path"], "status": job["status"],
        "pct": job["pct"], "phase": job["phase"], "total": job["total"],
        "counts": job["counts"], "version": job["version"],
        "done": job.get("done", 0), "remaining": job.get("remaining", 0),
        "scans": job.get("scans", ["semgrep"]), "steps": job.get("steps", {}),
        "results": job["results"],
        "error": job.get("error"),
    }


def persist():
    # sauve un resume leger (sans les resultats volumineux) pour reprise.
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with JLOCK:
            data = {sid: {"scan_id": j["scan_id"], "path": j["path"],
                          "status": j["status"], "scans": j.get("scans")}
                    for sid, j in JOBS.items()}
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, STATE_FILE)
    except Exception:
        pass


def touch(job, **kw):
    # met a jour l'etat + incremente version + reveille les streams
    with JCOND:
        job.update(kw)
        job["version"] += 1
        JCOND.notify_all()


def step_update(job, name, **kw):
    # met a jour un scan (steps[name]) + recalcule le pct global (moyenne)
    with JCOND:
        st = job["steps"].setdefault(name, {})
        st.update(kw)
        pcts = [s.get("pct", 0) for s in job["steps"].values()]
        job["pct"] = round(sum(pcts) / len(pcts)) if pcts else 0
        job["phase"] = " · ".join(
            "%s: %s" % (LABELS.get(k, k), (v.get("phase") or ""))
            for k, v in job["steps"].items() if v.get("phase"))
        job["version"] += 1
        JCOND.notify_all()
