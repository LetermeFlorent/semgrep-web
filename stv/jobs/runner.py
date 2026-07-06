"""Orchestration des jobs : lance les scans selectionnes en parallele, dedup +
tri + statut a la fin, persiste et sauve l'historique. Reprise au demarrage."""
import os, uuid, threading
from stv.paths import map_path
from stv.config import load_config
from stv.findings import dedupe
from stv.jobs.store import (JOBS, JLOCK, JCOND, RLOCK, STATE_FILE, ALL_SCANS,
                            touch, persist)
from stv.jobs.status import load_status, save_history
from stv.jobs.scans import SCAN_FNS, Cancelled

_ORDER = {"ERROR": 0, "WARNING": 1, "INFO": 2}


def run_scan(job, target):
    results, counts = [], {"ERROR": 0, "WARNING": 0, "INFO": 0}
    scans = [s for s in ALL_SCANS if s in (job.get("scans") or ["semgrep"])]
    job["steps"] = {s: {"pct": 0, "phase": "En attente"} for s in scans}
    try:
        threads = []
        for s in scans:
            t = threading.Thread(target=SCAN_FNS[s],
                                 args=(job, target, results, counts), daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        if job.get("cancel"):
            raise Cancelled()
        with RLOCK:
            results[:] = dedupe(results)          # fusionne les doublons multi-scanners
            results.sort(key=lambda x: _ORDER.get(x["severity"], 2))
        counts = {"ERROR": 0, "WARNING": 0, "INFO": 0}
        st = load_status()
        for r in results:
            counts[r["severity"]] = counts.get(r["severity"], 0) + 1
            r["status"] = st.get(r["key"], "open")   # open / ignored / resolved
        touch(job, pct=100, phase="Termine", status="done",
              counts=counts, results=results)
        save_history(job)
    except Cancelled:
        touch(job, status="cancelled", phase="Annule")
    except Exception as e:
        touch(job, status="err", error=str(e), results=results, counts=counts)
    persist()


def new_job(path, target, cfg=None, scans=None):
    scan_id = uuid.uuid4().hex
    job = {"scan_id": scan_id, "path": path, "status": "run", "pct": 0,
           "phase": "Preparation", "total": 0,
           "counts": {"ERROR": 0, "WARNING": 0, "INFO": 0},
           "results": [], "error": None, "version": 0, "cfg": cfg or load_config(),
           "scans": scans or ["semgrep"], "steps": {}}
    with JLOCK:
        JOBS[scan_id] = job
    persist()
    threading.Thread(target=run_scan, args=(job, target), daemon=True).start()
    return job


def resume_jobs():
    # au demarrage : relance les scans qui etaient "run" (process mort au restart).
    import json
    try:
        with open(STATE_FILE) as f:
            saved = json.load(f)
    except Exception:
        return
    for sid, s in saved.items():
        if s.get("status") == "run":
            target = map_path(s["path"])
            if os.path.isdir(target):
                new_job(s["path"], target, scans=s.get("scans"))
