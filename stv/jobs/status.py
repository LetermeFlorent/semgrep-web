"""Etat des findings (ignore/resolu) persiste globalement + historique des scans
(un dossier par chemin, un fichier JSON par run)."""
import os, json, time, threading
from stv.paths import path_slug

STATUS_FILE = os.environ.get("STV_STATUS", "/state/status.json")
HIST_DIR = os.environ.get("STV_HIST", "/state/history")
_STLOCK = threading.Lock()
_HLOCK = threading.Lock()


def load_status():
    try:
        with open(STATUS_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def save_status(data):
    with _STLOCK:
        os.makedirs(os.path.dirname(STATUS_FILE), exist_ok=True)
        tmp = STATUS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, STATUS_FILE)


def save_history(job):
    # sauve le resultat complet d'un scan termine, pour diff/historique ulterieur
    try:
        d = os.path.join(HIST_DIR, path_slug(job["path"]))
        with _HLOCK:
            os.makedirs(d, exist_ok=True)
            ts = int(time.time())
            rec = {"scan_id": job["scan_id"], "path": job["path"], "ts": ts,
                   "scans": job.get("scans"), "counts": job.get("counts"),
                   "results": job.get("results") or []}
            tmp = os.path.join(d, "%d.json.tmp" % ts)
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(rec, f)
            os.replace(tmp, os.path.join(d, "%d.json" % ts))
    except Exception:
        pass


def list_history(path):
    d = os.path.join(HIST_DIR, path_slug(path))
    out = []
    try:
        for fn in os.listdir(d):
            if fn.endswith(".json"):
                out.append(int(fn[:-5]))
    except Exception:
        pass
    return sorted(out)


def read_history(path, ts):
    try:
        with open(os.path.join(HIST_DIR, path_slug(path), "%d.json" % ts), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None
