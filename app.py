import subprocess, json, os, threading, queue, uuid, time
from flask import Flask, request, Response, render_template_string, jsonify
import verscan, scanners

app = Flask(__name__)

# scan_id -> {"q": Queue, "done": bool, "result": dict}
JOBS = {}

def map_path(path):
    # "W:\security\stv" -> /host/w/security/stv  (chaque disque monte sous /host/<lettre>)
    p = path.replace("\\", "/")
    if len(p) > 1 and p[1] == ":":
        p = "/host/" + p[0].lower() + "/" + p[2:].lstrip("/")
    elif not p.startswith("/host"):
        p = "/host/" + p.lstrip("/")
    return p

CODE_EXT = {".py",".js",".jsx",".ts",".tsx",".java",".go",".rb",".php",".c",".h",
    ".cpp",".cc",".cs",".rs",".kt",".swift",".scala",".sh",".bash",".pl",".lua",
    ".vue",".html",".yaml",".yml",".json",".tf",".dockerfile",".sql",".m",".r"}
SKIP_DIR = {"node_modules",".git","venv",".venv","__pycache__","dist","build",
    "vendor",".next","target",".idea",".vscode","site-packages"}
CHUNK = 8

# ---- Config globale (persistee) : racines autorisees + exclusions ----
CONFIG_FILE = os.environ.get("STV_CONFIG", "/state/config.json")
DEFAULT_CONFIG = {
    "roots": ["F:\\", "W:\\"],                       # liste blanche d'emplacements
    "skip_dirs": sorted(SKIP_DIR | {"run"}),         # dossiers ignores
    "skip_ext": [".md", ".log"],                     # extensions ignorees (en plus du filtre code)
}
CFG_LOCK = threading.Lock()

def _clean_ext(e):
    e = (e or "").strip().lower()
    if not e:
        return None
    return e if e.startswith(".") else "." + e

def normalize_config(raw):
    raw = raw if isinstance(raw, dict) else {}
    roots = [str(r).strip() for r in raw.get("roots", DEFAULT_CONFIG["roots"]) if str(r).strip()]
    dirs = sorted({str(d).strip() for d in raw.get("skip_dirs", DEFAULT_CONFIG["skip_dirs"]) if str(d).strip()})
    exts = sorted({x for x in (_clean_ext(e) for e in raw.get("skip_ext", DEFAULT_CONFIG["skip_ext"])) if x})
    return {"roots": roots or list(DEFAULT_CONFIG["roots"]), "skip_dirs": dirs, "skip_ext": exts}

def load_config():
    try:
        with open(CONFIG_FILE) as f:
            return normalize_config(json.load(f))
    except Exception:
        return normalize_config({})

def save_config(cfg):
    cfg = normalize_config(cfg)
    with CFG_LOCK:
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        tmp = CONFIG_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cfg, f, indent=2)
        os.replace(tmp, CONFIG_FILE)
    return cfg

def path_allowed(win_path):
    # verifie que le chemin Windows saisi est sous une racine autorisee
    p = (win_path or "").replace("/", "\\").lower().rstrip("\\")
    for root in load_config()["roots"]:
        r = root.replace("/", "\\").lower().rstrip("\\")
        if p == r or p.startswith(r + "\\"):
            return True
    return False

def list_targets(root, cfg=None):
    cfg = cfg or load_config()
    skip_dirs = set(cfg["skip_dirs"])
    skip_ext = set(cfg["skip_ext"])
    files = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in skip_dirs and not d.startswith(".")]
        for fn in fns:
            ext = os.path.splitext(fn)[1].lower()
            if ext in skip_ext:
                continue
            if ext in CODE_EXT or fn.lower() in ("dockerfile",):
                files.append(os.path.join(dp, fn))
    return files

class Cancelled(Exception):
    pass

def _safe_json(s):
    try:
        return json.loads(s or "{}")
    except Exception:
        return {}

def parse_results(data, results, counts):
    order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
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

# Persistance des jobs sur disque (survit au redemarrage du conteneur).
STATE_FILE = os.environ.get("STV_STATE", "/state/jobs.json")
JLOCK = threading.Lock()
JCOND = threading.Condition(JLOCK)  # notifie les streams a chaque update

def snapshot(job):
    # etat serialisable expose au client
    return {
        "scan_id": job["scan_id"], "path": job["path"], "status": job["status"],
        "pct": job["pct"], "phase": job["phase"], "total": job["total"],
        "counts": job["counts"], "version": job["version"],
        "done": job.get("done", 0), "remaining": job.get("remaining", 0),
        "scans": job.get("scans", ["semgrep"]), "steps": job.get("steps", {}),
        "results": job["results"] if job["status"] == "done" else None,
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

RLOCK = threading.Lock()   # protege results/counts partages entre threads de scan

def step_update(job, name, **kw):
    # met a jour l'etat d'un scan (steps[name]) + recalcule le pct global (moyenne)
    with JCOND:
        st = job["steps"].setdefault(name, {})
        st.update(kw)
        pcts = [s.get("pct", 0) for s in job["steps"].values()]
        job["pct"] = round(sum(pcts) / len(pcts)) if pcts else 0
        # phase globale = concat des phases de chaque scan encore actif
        job["phase"] = " · ".join(
            "%s: %s" % (LABELS.get(k, k), (v.get("phase") or ""))
            for k, v in job["steps"].items() if v.get("phase"))
        job["version"] += 1
        JCOND.notify_all()

LABELS = {"semgrep": "Code", "versions": "Deps", "secrets": "Secrets",
          "cve": "CVE", "iac": "IaC", "license": "Licences",
          "sensitive": "Fichiers"}
ALL_SCANS = ["semgrep", "versions", "secrets", "cve", "iac", "license", "sensitive"]

def _scan_semgrep(job, target, results, counts):
    step_update(job, "semgrep", phase="Recensement", pct=1, done=0, remaining=0)
    targets = list_targets(target, job.get("cfg"))
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
            batch = targets[i:i+MAXARG]
            ph = "Chargement des regles" if done == 0 else "Analyse du code"
            step_update(job, "semgrep", phase=ph, remaining=total - done,
                        pct=max(job["steps"].get("semgrep", {}).get("pct", 0), 2))
            proc = subprocess.Popen(cmd + batch,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True)
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
    skip_dirs = set((job.get("cfg") or load_config())["skip_dirs"])

    def prog(done, total):
        if job.get("cancel"):
            return
        rem = max(0, total - done)
        pct = 100 if not total else min(99, round(done / total * 99))
        step_update(job, "versions", pct=pct,
                    phase="Verification des versions" if total else "Aucune dependance",
                    total=total, done=done, remaining=rem)

    found = verscan.scan_versions(target, skip_dirs,
                                  on_progress=prog,
                                  cancelled=lambda: job.get("cancel"))
    with RLOCK:
        for item in found:
            counts[item["severity"]] = counts.get(item["severity"], 0) + 1
            results.append(item)
    touch(job, counts=dict(counts))
    step_update(job, "versions", pct=100, phase="Termine", remaining=0)

def _collect(job, name, results, counts, found):
    with RLOCK:
        for item in found:
            counts[item["severity"]] = counts.get(item["severity"], 0) + 1
            results.append(item)
    touch(job, counts=dict(counts))
    step_update(job, name, pct=100, phase="Termine", remaining=0)

# ---- Cle stable d'un finding (pour dedup, etat, diff entre scans) ----
def finding_key(r):
    f = (r.get("file") or "").replace("\\", "/").lower()
    return "%s|%s|%s" % (r.get("check_id", ""), f, r.get("line", ""))

def dedupe(results):
    # fusionne les doublons (meme check_id+file+line issus de scanners differents)
    seen, out = {}, []
    for r in results:
        k = finding_key(r)
        if k in seen:
            continue
        seen[k] = True
        r = dict(r)
        r["key"] = k
        out.append(r)
    return out

# ---- Etat des findings (ignore / resolu), persiste globalement ----
STATUS_FILE = os.environ.get("STV_STATUS", "/state/status.json")
STLOCK = threading.Lock()

def load_status():
    try:
        with open(STATUS_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def save_status(data):
    with STLOCK:
        os.makedirs(os.path.dirname(STATUS_FILE), exist_ok=True)
        tmp = STATUS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, STATUS_FILE)

# ---- Historique des scans (un dossier par chemin, un fichier par run) ----
HIST_DIR = os.environ.get("STV_HIST", "/state/history")
HLOCK = threading.Lock()

def _path_slug(path):
    import hashlib
    return hashlib.sha1((path or "").encode("utf-8", "ignore")).hexdigest()[:16]

def save_history(job):
    # sauve le resultat complet d'un scan termine, pour diff/historique ulterieur
    try:
        slug = _path_slug(job["path"])
        d = os.path.join(HIST_DIR, slug)
        with HLOCK:
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
    slug = _path_slug(path)
    d = os.path.join(HIST_DIR, slug)
    out = []
    try:
        for fn in os.listdir(d):
            if fn.endswith(".json"):
                out.append(int(fn[:-5]))
    except Exception:
        pass
    return sorted(out)

def read_history(path, ts):
    slug = _path_slug(path)
    try:
        with open(os.path.join(HIST_DIR, slug, "%d.json" % ts), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def diff_results(prev, cur):
    # compare 2 listes de findings par cle -> nouveaux / disparus / communs
    pk = {finding_key(r) for r in (prev or [])}
    ck = {finding_key(r) for r in (cur or [])}
    new = [r for r in cur if finding_key(r) not in pk]
    gone = [r for r in (prev or []) if finding_key(r) not in ck]
    return {"new": new, "gone": gone,
            "new_count": len(new), "gone_count": len(gone),
            "same_count": len(ck & pk)}

def _mk_step(name, phase, fn_needs_skip=False, scanfn=None):
    # fabrique un _scan_* base sur une fonction de scanners.py (progression simple 0->100)
    def run(job, target, results, counts):
        step_update(job, name, phase=phase, pct=1)

        def prog(done, total):
            if job.get("cancel"): return
            pct = 100 if not total else min(99, round(done / total * 99))
            step_update(job, name, pct=pct, phase=phase,
                        total=total, done=done, remaining=max(0, total - done))
        try:
            if fn_needs_skip:
                skip = set((job.get("cfg") or load_config())["skip_dirs"])
                found = scanfn(target, skip, on_progress=prog, cancelled=lambda: job.get("cancel"))
            else:
                found = scanfn(target, on_progress=prog, cancelled=lambda: job.get("cancel"))
        except Exception as e:
            step_update(job, name, pct=100, phase="Erreur: " + str(e)[:60])
            found = []
        _collect(job, name, results, counts, found)
    return run

_scan_secrets = _mk_step("secrets", "Recherche de secrets", scanfn=scanners.scan_secrets)
_scan_cve = _mk_step("cve", "Vulnerabilites (CVE)", fn_needs_skip=True, scanfn=scanners.scan_cve)
_scan_iac = _mk_step("iac", "Config / IaC", scanfn=scanners.scan_iac)
_scan_license = _mk_step("license", "Licences", scanfn=scanners.scan_license)
_scan_sensitive = _mk_step("sensitive", "Fichiers sensibles", fn_needs_skip=True, scanfn=scanners.scan_sensitive)

def run_scan(job, target):
    results, counts = [], {"ERROR": 0, "WARNING": 0, "INFO": 0}
    scans = [s for s in ALL_SCANS if s in (job.get("scans") or ["semgrep"])]
    job["steps"] = {s: {"pct": 0, "phase": "En attente"} for s in scans}
    try:
        # lance tous les scans en parallele
        fns = {"semgrep": _scan_semgrep, "versions": _scan_versions,
               "secrets": _scan_secrets, "cve": _scan_cve, "iac": _scan_iac,
               "license": _scan_license, "sensitive": _scan_sensitive}
        threads = []
        for s in scans:
            t = threading.Thread(target=fns[s], args=(job, target, results, counts), daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        if job.get("cancel"):
            raise Cancelled()
        order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
        with RLOCK:
            results[:] = dedupe(results)          # fusionne les doublons multi-scanners
            results.sort(key=lambda x: order.get(x["severity"], 2))
        # recompte apres dedup (les doublons ne doivent plus compter double)
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
    # au demarrage: relance les scans qui etaient "run" (process mort au restart).
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

@app.route("/")
def index():
    return render_template_string(PAGE)

@app.route("/jobs")
def jobs():
    # snapshot de tous les jobs connus (pour reconstruire les onglets au reload)
    with JLOCK:
        return jsonify([snapshot(j) for j in JOBS.values()])

@app.route("/config", methods=["GET", "POST"])
def config():
    if request.method == "POST":
        return jsonify(save_config(request.json or {}))
    return jsonify(load_config())

@app.route("/start", methods=["POST"])
def start():
    body = request.json or {}
    path = (body.get("path") or "").strip()
    if not path_allowed(path):
        allowed = ", ".join(load_config()["roots"]) or "(aucune)"
        return jsonify({"error": "Emplacement non autorise: " + path +
                        " · racines permises: " + allowed}), 403
    target = map_path(path)
    if not os.path.isdir(target):
        return jsonify({"error": "Dossier introuvable: " + path + " (disques montes: C D F G H I M W)"}), 400
    # override ponctuel des exclusions pour ce scan (fusionne avec le global)
    cfg = load_config()
    ov = body.get("exclude") or {}
    if ov.get("skip_dirs") or ov.get("skip_ext"):
        cfg = normalize_config({
            "roots": cfg["roots"],
            "skip_dirs": list(cfg["skip_dirs"]) + list(ov.get("skip_dirs") or []),
            "skip_ext": list(cfg["skip_ext"]) + list(ov.get("skip_ext") or []),
        })
    scans = [s for s in (body.get("scans") or ["semgrep"]) if s in ALL_SCANS]
    if not scans:
        return jsonify({"error": "Aucun scan selectionne"}), 400
    job = new_job(path, target, cfg, scans)
    return jsonify({"scan_id": job["scan_id"]})

@app.route("/close/<scan_id>", methods=["POST"])
def close(scan_id):
    job = JOBS.get(scan_id)
    if job:
        job["cancel"] = True            # signale l'annulation au thread de scan
        p = job.get("proc")
        if p:
            try:
                p.kill()                 # tue le process semgrep en cours
            except Exception:
                pass
    with JLOCK:
        JOBS.pop(scan_id, None)
    persist()
    return jsonify({"ok": True})

@app.route("/stream/<scan_id>")
def stream(scan_id):
    job = JOBS.get(scan_id)
    if not job:
        return "no job", 404
    def gen():
        last = -1
        while True:
            with JCOND:
                if job["version"] == last:
                    JCOND.wait(timeout=25)
                if job["version"] == last:
                    yield ": ping\n\n"
                    continue
                last = job["version"]
                snap = snapshot(job)
            yield "event: state\ndata: " + json.dumps(snap) + "\n\n"
            if snap["status"] in ("done", "err"):
                break
    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

# ============ Etat des findings (ignore / resolu) ============
@app.route("/finding-status", methods=["POST"])
def finding_status():
    body = request.json or {}
    key = body.get("key")
    state = body.get("state")   # open / ignored / resolved
    if not key or state not in ("open", "ignored", "resolved"):
        return jsonify({"error": "params invalides"}), 400
    data = load_status()
    if state == "open":
        data.pop(key, None)
    else:
        data[key] = state
    save_status(data)
    # repercute sur le job en memoire pour que les prochains snapshots soient a jour
    for j in JOBS.values():
        for r in (j.get("results") or []):
            if r.get("key") == key:
                r["status"] = state
    return jsonify({"ok": True, "key": key, "state": state})

# ============ Historique + diff ============
@app.route("/history/<scan_id>")
def history(scan_id):
    job = JOBS.get(scan_id)
    if not job:
        return jsonify({"error": "job inconnu"}), 404
    return jsonify({"path": job["path"], "runs": list_history(job["path"])})

@app.route("/diff/<scan_id>")
def diff(scan_id):
    # compare le scan courant a un run precedent (ts en query, sinon l'avant-dernier)
    job = JOBS.get(scan_id)
    if not job or job.get("status") != "done":
        return jsonify({"error": "scan non termine"}), 400
    hist = list_history(job["path"])
    ts = request.args.get("ts", type=int)
    if not ts:
        # avant-dernier run (le dernier == scan courant qu'on vient de sauver)
        prev_ts = [t for t in hist][:-1]
        if not prev_ts:
            return jsonify({"error": "aucun scan precedent", "runs": hist}), 200
        ts = prev_ts[-1]
    rec = read_history(job["path"], ts)
    prev = rec.get("results") if rec else []
    d = diff_results(prev, job.get("results") or [])
    d["ts"] = ts
    d["runs"] = hist
    return jsonify(d)

# ============ Export : json / sarif / csv / html ============
def _sarif(job):
    lvl = {"ERROR": "error", "WARNING": "warning", "INFO": "note"}
    rules, results = {}, []
    for r in (job.get("results") or []):
        rid = r.get("check_id") or "finding"
        rules.setdefault(rid, {"id": rid,
            "shortDescription": {"text": (r.get("message") or rid)[:120]}})
        try:
            line = int(r.get("line"))
        except Exception:
            line = 1
        results.append({
            "ruleId": rid,
            "level": lvl.get(r.get("severity"), "note"),
            "message": {"text": r.get("message") or ""},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": (r.get("file") or "").replace("\\", "/")},
                "region": {"startLine": max(1, line)}}}],
            "properties": {"status": r.get("status", "open"),
                           "code": r.get("code", "")},
        })
    return {"version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "STV",
            "informationUri": "https://local", "rules": list(rules.values())}},
            "results": results}]}

def _csv(job):
    import csv, io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["severity", "file", "line", "check_id", "status", "message", "code"])
    for r in (job.get("results") or []):
        w.writerow([r.get("severity"), r.get("file"), r.get("line"),
                    r.get("check_id"), r.get("status", "open"),
                    (r.get("message") or "").replace("\n", " "),
                    (r.get("code") or "").replace("\n", " ")[:300]])
    return buf.getvalue()

def _html_report(job):
    c = job.get("counts") or {}
    import html as _h
    rows = []
    for r in (job.get("results") or []):
        rows.append(
            "<tr class='%s'><td>%s</td><td class='f'>%s:%s</td>"
            "<td>%s</td><td>%s</td><td><code>%s</code></td></tr>" % (
                r.get("severity"), r.get("severity"),
                _h.escape(str(r.get("file"))), r.get("line"),
                _h.escape(str(r.get("check_id"))),
                _h.escape(str(r.get("message") or "")),
                _h.escape(str(r.get("code") or ""))[:400]))
    return """<!doctype html><meta charset=utf-8><title>Rapport STV</title>
<style>body{font:13px system-ui;margin:24px;color:#222}
h1{font-size:18px}.meta{color:#666;margin-bottom:16px}
.cards{display:flex;gap:12px;margin:16px 0}
.card{border:1px solid #ddd;border-radius:6px;padding:8px 14px}
.card b{font-size:20px;display:block}
table{border-collapse:collapse;width:100%%;font-size:12px}
td,th{border:1px solid #e2e2e2;padding:5px 8px;text-align:left;vertical-align:top}
th{background:#f6f6f6}
tr.ERROR td:first-child{color:#c0392b;font-weight:600}
tr.WARNING td:first-child{color:#b8860b;font-weight:600}
tr.INFO td:first-child{color:#2980b9}
.f{font-family:ui-monospace,monospace;white-space:nowrap}
code{font-size:11px;color:#555}
@media print{@page{margin:12mm}}
</style>
<h1>Rapport de securite STV</h1>
<div class=meta>%s &middot; %d problemes</div>
<div class=cards>
 <div class=card><b>%d</b>Critiques</div>
 <div class=card><b>%d</b>Moyens</div>
 <div class=card><b>%d</b>Infos</div></div>
<table><tr><th>Severite</th><th>Emplacement</th><th>Regle</th>
<th>Message</th><th>Extrait</th></tr>%s</table>
<script>print()</script>""" % (
        _h.escape(str(job.get("path"))), len(job.get("results") or []),
        c.get("ERROR", 0), c.get("WARNING", 0), c.get("INFO", 0),
        "".join(rows))

@app.route("/export/<scan_id>.<fmt>")
def export(scan_id, fmt):
    job = JOBS.get(scan_id)
    if not job:
        return "job inconnu", 404
    name = base_name(job["path"])
    if fmt == "json":
        payload = {"path": job["path"], "scans": job.get("scans"),
                   "counts": job.get("counts"), "results": job.get("results") or []}
        return Response(json.dumps(payload, indent=2, ensure_ascii=False),
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=%s.json" % name})
    if fmt == "sarif":
        return Response(json.dumps(_sarif(job), indent=2, ensure_ascii=False),
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=%s.sarif" % name})
    if fmt == "csv":
        return Response(_csv(job), mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=%s.csv" % name})
    if fmt in ("html", "pdf"):
        # 'pdf' = page HTML imprimable (Ctrl+P -> Enregistrer en PDF), sans dependance
        return Response(_html_report(job), mimetype="text/html")
    return "format inconnu (json|sarif|csv|html)", 400

def base_name(path):
    p = (path or "").replace("\\", "/").rstrip("/")
    return p.split("/")[-1] or "scan"

# ============ Mode CI : scan synchrone + verdict pass/fail ============
@app.route("/ci")
def ci():
    # GET /ci?path=W:\proj&scans=semgrep,secrets&fail_on=ERROR
    # renvoie 200 si sous le seuil, 422 sinon (exploitable en pipeline).
    path = (request.args.get("path") or "").strip()
    if not path_allowed(path):
        return jsonify({"error": "emplacement non autorise"}), 403
    target = map_path(path)
    if not os.path.isdir(target):
        return jsonify({"error": "dossier introuvable"}), 400
    scans = [s for s in (request.args.get("scans", "").split(",")) if s in ALL_SCANS] or list(ALL_SCANS)
    fail_on = (request.args.get("fail_on") or "ERROR").upper()
    thresh = {"ERROR": ["ERROR"], "WARNING": ["ERROR", "WARNING"],
              "INFO": ["ERROR", "WARNING", "INFO"], "NONE": []}.get(fail_on, ["ERROR"])
    job = new_job(path, target, load_config(), scans)
    # attend la fin (synchrone pour un usage CI)
    while job.get("status") == "run":
        with JCOND:
            JCOND.wait(timeout=5)
    c = job.get("counts") or {}
    blocking = sum(c.get(s, 0) for s in thresh)
    verdict = {"path": path, "scans": scans, "fail_on": fail_on,
               "counts": c, "blocking": blocking,
               "passed": blocking == 0}
    with JLOCK:
        JOBS.pop(job["scan_id"], None)
    return jsonify(verdict), (200 if blocking == 0 else 422)

PAGE = r"""
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>STV &middot; Semgrep Scanner</title>
<style>
 /* ---- Palette Zed (One Dark) ---- */
 :root{color-scheme:dark}
 :root{
   --editor:#282c33;   /* zone contenu, la plus sombre */
   --panel:#2f343e;    /* sidebar, barre onglets */
   --titlebar:#3b414d; /* barre de titre */
   --bd:#464b57; --bd2:#363c46;
   --tx:#dce0e5; --mut:#a9afbc; --ph:#878a98;
   --acc:#74ade8; --hi:#d07277; --med:#dec184; --lo:#a1c181;
   --r:4px; --r6:6px;
   --fui:"Zed Plex Sans","IBM Plex Sans",-apple-system,"Segoe UI",system-ui,sans-serif;
   --fmono:"Zed Plex Mono","Lilex","IBM Plex Mono",ui-monospace,Consolas,monospace;
 }
 @media (prefers-color-scheme: light){:root{
   --editor:#fafafa;--panel:#ececec;--titlebar:#e0e0e0;--bd:#d3d3d3;--bd2:#e0e0e0;
   --tx:#242529;--mut:#5a5c63;--ph:#9295a0;--acc:#5c78e2;
   --hi:#c04a4a;--med:#b08500;--lo:#5a9e3a}}
 *{box-sizing:border-box}
 html,body{height:100%}
 body{margin:0;background:var(--editor);color:var(--tx);
   font:13px/1.5 var(--fui);
   display:flex;flex-direction:column;height:100vh;overflow:hidden}
 /* titlebar */
 .top{display:flex;align-items:center;gap:10px;padding:8px 14px;flex:0 0 auto;
   background:var(--titlebar);border-bottom:1px solid var(--bd2);height:36px}
 .logo{font-size:13px;font-weight:600;letter-spacing:.2px;display:flex;align-items:center;gap:7px}
 .logo .dot{width:7px;height:7px;border-radius:50%;background:var(--acc)}
 .top .sub{color:var(--mut);font-size:12px}
 .top .spacer{flex:1}
 .badge{font-size:11px;color:var(--mut);border:1px solid var(--bd);border-radius:var(--r);
   padding:2px 8px}
 /* layout */
 .app{display:grid;grid-template-columns:280px 1fr;flex:1;min-height:0;overflow:hidden}
 .side{background:var(--panel);border-right:1px solid var(--bd2);padding:14px;
   overflow-y:auto;display:flex;flex-direction:column;gap:16px}
 .main{overflow-y:auto;padding:16px 20px;background:var(--editor)}
 .main .inner{max-width:none;margin:0;width:100%}
 /* form */
 label{font-size:11px;font-weight:500;color:var(--mut);
   display:block;margin-bottom:6px}
 .field{display:flex;flex-direction:column;gap:8px}
 input[type=text]{background:var(--editor);border:1px solid var(--bd);color:var(--tx);
   padding:7px 9px;border-radius:var(--r);font:13px var(--fmono);width:100%;transition:border .12s}
 input[type=text]::placeholder{color:var(--ph)}
 input[type=text]:focus{outline:0;border-color:var(--acc)}
 button{background:var(--acc);color:#1a1d23;border:0;padding:7px 12px;border-radius:var(--r);
   font:13px/1 var(--fui);font-weight:500;cursor:pointer;width:100%;transition:filter .12s}
 button:hover:not(:disabled){filter:brightness(1.08)}
 button:disabled{opacity:.5;cursor:default}
 .hint{font-size:11px;color:var(--ph);line-height:1.4}
 label.ck{display:flex;align-items:center;gap:7px;font-size:12.5px;color:var(--tx);
   font-weight:400;margin:4px 0;cursor:pointer;text-transform:none}
 label.ck input{accent-color:var(--acc);cursor:pointer}
 /* progress */
 .prog{display:none;flex-direction:column;gap:8px;background:var(--editor);
   border:1px solid var(--bd2);border-radius:var(--r6);padding:12px}
 .prog.on{display:flex}
 .phead{display:flex;justify-content:space-between;align-items:baseline}
 .phead .pct{font-size:20px;font-weight:600;font-variant-numeric:tabular-nums;font-family:var(--fmono)}
 .phead .lbl{font-size:11px;color:var(--mut)}
 .bar{height:5px;background:var(--panel);border-radius:99px;overflow:hidden}
 .bar>i{display:block;height:100%;width:0;border-radius:99px;
   background:var(--acc);transition:width .4s ease}
 .log{font:11px/1.45 var(--fmono);color:var(--ph);
   max-height:100px;overflow:auto;white-space:pre-wrap;
   background:var(--panel);border-radius:var(--r);padding:6px 8px}
 .log:empty{display:none}
 /* progression par scan */
 .steps{display:flex;flex-direction:column;gap:8px;margin:12px 0}
 .steps:empty{display:none}
 .step{background:var(--panel);border:1px solid var(--bd2);border-radius:var(--r6);padding:8px 12px}
 .step.done{opacity:.7}
 .srow{display:flex;align-items:baseline;gap:10px;margin-bottom:6px}
 .srow .sname{font-weight:600;font-size:12px;min-width:80px}
 .srow .sphase{color:var(--mut);font-size:11px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
 .srow .spct{font-family:var(--fmono);font-size:12px;font-variant-numeric:tabular-nums;color:var(--acc)}
 .sbar{height:4px;background:var(--editor);border-radius:99px;overflow:hidden}
 .sbar>i{display:block;height:100%;background:var(--acc);border-radius:99px;transition:width .4s ease}
 .step.done .sbar>i{background:var(--lo)}
 .log div{padding:.5px 0}
 /* stat cards */
 .stats-wrap{margin:16px 0}
 .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;width:100%}
 .stat{background:var(--panel);border:1px solid var(--bd2);border-radius:var(--r6);padding:12px 14px}
 .stat .n{font-size:24px;font-weight:600;line-height:1;font-variant-numeric:tabular-nums;font-family:var(--fmono)}
 .stat .k{font-size:11px;color:var(--mut);margin-top:5px}
 .stat.c-hi .n{color:var(--hi)}
 .stat.c-med .n{color:var(--med)}
 .stat.c-lo .n{color:var(--lo)}
 .stat.c-all .n{color:var(--acc)}
 /* findings : grille qui remplit toute la largeur ecran (app desktop) */
 .out{display:grid;grid-template-columns:repeat(auto-fill,minmax(520px,1fr));gap:6px;align-items:start}
 .out .toolbar{grid-column:1/-1}
 .f{background:var(--panel);border:1px solid var(--bd2);border-left:2px solid var(--bd);
   border-radius:var(--r);padding:10px 12px}
 .f.ERROR{border-left-color:var(--hi)}.f.WARNING{border-left-color:var(--med)}
 .f.INFO{border-left-color:var(--lo)}
 .frow{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
 .sev{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.4px;
   padding:2px 6px;border-radius:var(--r)}
 .ERROR .sev{color:var(--hi);background:rgba(208,114,119,.14)}
 .WARNING .sev{color:var(--med);background:rgba(222,193,132,.14)}
 .INFO .sev{color:var(--lo);background:rgba(161,193,129,.14)}
 .loc{color:var(--tx);font-size:12px;font-family:var(--fmono)}
 .loc .ln{color:var(--acc)}
 .msg{margin:6px 0 0;color:var(--tx);font-size:12.5px}
 .rid{color:var(--ph);font-size:11px;margin-top:5px;font-family:var(--fmono)}
 pre{background:var(--editor);border:1px solid var(--bd2);border-radius:var(--r);padding:8px 10px;
   overflow:auto;font:11.5px/1.5 var(--fmono);margin:8px 0 0}
 .err{color:var(--hi);background:rgba(208,114,119,.1);border:1px solid var(--hi);
   border-radius:var(--r);padding:10px 12px;margin-bottom:12px;font-size:12.5px}
 .toolbar{display:flex;justify-content:flex-end;gap:8px;margin-bottom:10px}
 .copybtn{width:auto;background:var(--panel);color:var(--tx);border:1px solid var(--bd);
   padding:5px 12px;font-size:12px;font-weight:500}
 .copybtn:hover:not(:disabled){filter:none;background:var(--bd2);border-color:var(--acc)}
 .empty{color:var(--mut);padding:50px 20px;text-align:center;font-size:13px;grid-column:1/-1}
 .empty .big{font-size:38px;margin-bottom:10px}
 .welcome{color:var(--mut);padding:70px 20px;text-align:center}
 .welcome .big{font-size:44px;margin-bottom:12px;opacity:.4}
 .welcome h2{color:var(--tx);font-weight:600;margin:0 0 6px;font-size:16px}
 .welcome div{font-size:12.5px;line-height:1.6}
 /* onglets style Zed - liste verticale en bas de la sidebar */
 .tabs{display:flex;flex-direction:column;gap:3px;margin-top:auto;
   border-top:1px solid var(--bd2);padding-top:10px;overflow-y:auto;max-height:45%}
 .tabs:empty{display:none;margin-top:0;border-top:0;padding-top:0}
 .tab{display:flex;align-items:center;gap:8px;padding:6px 8px;cursor:pointer;
   color:var(--mut);font-size:12px;white-space:nowrap;border-radius:var(--r)}
 .tab:hover{color:var(--tx);background:var(--editor)}
 .tab.active{color:var(--tx);background:var(--editor)}
 .tab.active .tname{font-weight:500}
 .tab .tname{overflow:hidden;text-overflow:ellipsis;flex:1}
 .tab .tdot{width:7px;height:7px;min-width:7px;min-height:7px;border-radius:50%;
   flex:0 0 7px;align-self:center}
 .tab .tdot.run{background:var(--acc);animation:pulse 1.1s infinite}
 .tab .tdot.done{background:var(--lo)}
 .tab .tdot.err{background:var(--hi)}
 @keyframes pulse{50%{opacity:.3}}
 .tab .x{opacity:0;font-size:14px;line-height:1;padding:1px 4px;border-radius:var(--r);color:var(--ph);flex:0 0 auto}
 .tab:hover .x{opacity:.7}
 .tab .x:hover{opacity:1;background:var(--bd)}
 .view{display:none}.view.active{display:block}
 /* bouton icone titlebar */
 .iconbtn{width:auto;background:transparent;color:var(--mut);border:1px solid var(--bd);
   border-radius:var(--r);padding:2px 8px;font-size:14px;line-height:1;cursor:pointer}
 .iconbtn:hover{color:var(--tx);background:var(--bd2);filter:none}
 textarea{background:var(--editor);border:1px solid var(--bd);color:var(--tx);
   padding:7px 9px;border-radius:var(--r);font:12px var(--fmono);width:100%;resize:vertical}
 textarea:focus{outline:0;border-color:var(--acc)}
 /* modal parametres */
 .modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:50;
   align-items:flex-start;justify-content:center;padding:60px 16px}
 .modal.on{display:flex}
 .sheet{background:var(--panel);border:1px solid var(--bd);border-radius:var(--r6);
   width:100%;max-width:460px;padding:16px 18px;box-shadow:0 8px 30px rgba(0,0,0,.4)}
 .shead{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;font-size:14px}
 .shead .x{cursor:pointer;color:var(--ph);font-size:18px;line-height:1;padding:2px 6px;border-radius:var(--r)}
 .shead .x:hover{color:var(--tx);background:var(--bd)}
 /* boutons export (liens stylises comme des boutons) */
 a.copybtn.dl{display:inline-flex;align-items:center;text-decoration:none;
   width:auto;justify-content:center}
 /* actions sur un finding */
 .frow{align-items:center}
 .fsp{flex:1}
 .fact{display:flex;gap:4px}
 .fact .tag{cursor:pointer;font-size:10px;color:var(--mut);border:1px solid var(--bd);
   padding:1px 7px;border-radius:99px;user-select:none;text-transform:uppercase;letter-spacing:.3px}
 .fact .tag:hover{color:var(--tx);border-color:var(--acc)}
 .nb{font-size:9px;font-weight:700;color:#1a1d23;background:var(--med);
   padding:1px 6px;border-radius:99px;letter-spacing:.5px}
 /* etats findings */
 .f.st-ignored{opacity:.45}
 .f.st-ignored .fact .tag[data-s="ignored"]{background:var(--bd);color:var(--tx)}
 .f.st-resolved{opacity:.5;border-left-color:var(--lo)!important}
 .f.st-resolved .fact .tag[data-s="resolved"]{background:var(--lo);color:#1a1d23}
 .f.isnew{box-shadow:inset 3px 0 0 var(--med)}
 /* diff */
 .diffbox:empty{display:none}
 .diffbox{margin:8px 0 14px}
 .dinfo{font-size:12px;color:var(--mut);padding:8px 12px;background:var(--panel);
   border:1px solid var(--bd2);border-radius:var(--r6)}
 .dg{font-family:var(--fmono);font-size:12px;margin-right:8px}
 .dg.up{color:var(--hi)} .dg.dn{color:var(--lo)}
 .dgone{margin-top:8px;font:11px/1.5 var(--fmono);color:var(--ph);
   background:var(--panel);border:1px solid var(--bd2);border-radius:var(--r6);padding:8px 12px}
</style></head><body>
<div class="top">
  <div class="logo"><span class="dot"></span>STV</div>
  <span class="sub">Semgrep Security Scanner</span>
  <div class="spacer"></div>
  <span class="badge">C: D: F: G: H: I: M: W: (lecture seule)</span>
  <button type="button" id="cfgbtn" class="iconbtn" title="Parametres">&#9881;</button>
</div>
<div id="modal" class="modal"><div class="sheet">
  <div class="shead"><b>Parametres</b><span class="x" id="cfgclose">&times;</span></div>
  <div class="field">
    <div>
      <label for="cfg-roots">Emplacements autorises (une racine par ligne)</label>
      <textarea id="cfg-roots" rows="3" placeholder="F:\
W:\"></textarea>
      <div class="hint">Un scan hors de ces racines est refuse.</div>
    </div>
    <div>
      <label for="cfg-dirs">Dossiers a exclure (separes par virgule ou retour)</label>
      <textarea id="cfg-dirs" rows="3" placeholder="node_modules, .git, run"></textarea>
    </div>
    <div>
      <label for="cfg-exts">Extensions/fichiers a exclure</label>
      <textarea id="cfg-exts" rows="2" placeholder=".md, .log"></textarea>
    </div>
    <button type="button" id="cfgsave">Enregistrer</button>
    <div class="hint" id="cfgmsg"></div>
  </div>
</div></div>
<div class="app">
  <aside class="side">
    <form id="frm" class="field">
      <div>
        <label for="path">Dossier a scanner</label>
        <input type="text" id="path" placeholder="F:\monprojet" required autofocus>
      </div>
      <div>
        <label>Analyses a lancer</label>
        <label class="ck"><input type="checkbox" id="sc-semgrep" checked> Code (Semgrep)</label>
        <label class="ck"><input type="checkbox" id="sc-versions" checked> Versions des dependances</label>
        <label class="ck"><input type="checkbox" id="sc-secrets" checked> Secrets (cles, tokens)</label>
        <label class="ck"><input type="checkbox" id="sc-cve" checked> Vulnerabilites deps (CVE)</label>
        <label class="ck"><input type="checkbox" id="sc-iac" checked> Config / IaC</label>
        <label class="ck"><input type="checkbox" id="sc-license" checked> Licences</label>
        <label class="ck"><input type="checkbox" id="sc-sensitive" checked> Fichiers sensibles</label>
      </div>
      <div>
        <label for="ov-exclude">Exclure en plus (ce scan) &mdash; optionnel</label>
        <input type="text" id="ov-exclude" placeholder="run, .env, .csv">
        <div class="hint">Dossiers et extensions, en plus des exclusions globales.</div>
      </div>
      <button type="submit" id="btn">Lancer un nouveau scan</button>
      <div class="hint">Chaque scan ouvre un onglet. Ignore node_modules, .git, venv&hellip;</div>
    </form>
    <div class="tabs" id="tabs"></div>
  </aside>
  <main class="main"><div class="inner" id="views">
    <div id="welcome" class="welcome"><div class="big">&#128737;</div>
      <h2>Pret a scanner</h2><div>Entre un chemin de dossier et lance le scan.<br>
      Tu peux lancer plusieurs scans en parallele &mdash; chacun a son onglet.</div></div>
  </div></main>
</div>
<script>
const $=id=>document.getElementById(id);
const frm=$('frm'),tabsEl=$('tabs'),viewsEl=$('views'),welcome=$('welcome');
let TABS=[], active=null, seq=0;

const SCAN_IDS=['semgrep','versions','secrets','cve','iac','license','sensitive'];
function selectedScans(){return SCAN_IDS.filter(id=>{const e=$('sc-'+id);return e&&e.checked;});}
function esc(s){return (s+'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
function base(p){const s=p.replace(/[\\/]+$/,'').split(/[\\/]/);return s[s.length-1]||p;}
function fcard(r){
   const st=r.status||'open';
   const badge=r._new?'<span class="nb">NOUVEAU</span>':'';
   return '<div class="f '+r.severity+' st-'+st+'" data-key="'+esc(r.key||'')+'">'+
   '<div class="frow"><span class="sev">'+r.severity+'</span>'+badge+
   '<span class="loc">'+esc(r.file)+':<span class="ln">'+r.line+'</span></span>'+
   '<span class="fsp"></span>'+
   '<span class="fact"><a class="tag" data-s="ignored">Ignorer</a>'+
   '<a class="tag" data-s="resolved">Resolu</a>'+
   '<a class="tag" data-s="open">Rouvrir</a></span></div>'+
   '<div class="msg">'+esc(r.message)+'</div>'+
   '<div class="rid">'+esc(r.check_id)+'</div>'+
   (r.code&&r.code!=='requires login'?'<pre>'+esc(r.code)+'</pre>':'')+'</div>';}
function statCards(c){const n=c.ERROR+c.WARNING+c.INFO;return '<div class="stats">'+
   '<div class="stat c-all"><div class="n">'+n+'</div><div class="k">Total</div></div>'+
   '<div class="stat c-hi"><div class="n">'+c.ERROR+'</div><div class="k">Critiques</div></div>'+
   '<div class="stat c-med"><div class="n">'+c.WARNING+'</div><div class="k">Moyens</div></div>'+
   '<div class="stat c-lo"><div class="n">'+c.INFO+'</div><div class="k">Infos</div></div></div>';}

function tabLabel(t){
 // pendant le scan: "nom 42%", fini: "nom (n)", erreur: "nom"
 if(t.status==='run') return t.name+' '+(t.pct||0)+'%';
 if(t.status==='done') return t.name+' ('+(t.count||0)+')';
 return t.name;
}
function renderTabs(){
 // MAJ en place: on ne recree pas les noeuds a chaque tick (sinon le clic sur la
 // croix est avale car l'element disparait entre mousedown et click pendant un scan).
 const seen=new Set();
 for(const t of TABS){
   seen.add(t.id);
   let el=tabsEl.querySelector('.tab[data-id="'+t.id+'"]');
   if(!el){
     el=document.createElement('div'); el.dataset.id=t.id;
     el.innerHTML='<span class="tdot"></span><span class="tname"></span><span class="x">&times;</span>';
     el.onclick=()=>select(t.id);
     el.querySelector('.x').onclick=e=>{e.stopPropagation();closeTab(t.id);};
     tabsEl.appendChild(el);
   }
   el.className='tab'+(t.id===active?' active':'');
   el.querySelector('.tdot').className='tdot '+t.status;
   el.querySelector('.tname').textContent=tabLabel(t);
 }
 // retire les onglets disparus
 tabsEl.querySelectorAll('.tab').forEach(el=>{
   if(!seen.has(+el.dataset.id)) el.remove();
 });
}
function select(id){active=id;
 for(const t of TABS) t.view.classList.toggle('active',t.id===id);
 renderTabs();
}
async function closeTab(id){
 const t=TABS.find(x=>x.id===id); if(!t)return;
 if(t.es) t.es.close(); t.view.remove();
 if(t.scan_id){ try{ await fetch('/close/'+t.scan_id,{method:'POST'}); }catch(e){} }
 TABS=TABS.filter(x=>x.id!==id);
 if(active===id) active=TABS.length?TABS[TABS.length-1].id:null;
 if(active) select(active);
 renderTabs(); saveTabs();
 if(!TABS.length) welcome.style.display='';
}
// persiste l'ordre/selection des onglets (les donnees vivent cote serveur)
function saveTabs(){
 try{ localStorage.setItem('stv_tabs', JSON.stringify(
   {order:TABS.map(t=>t.scan_id).filter(Boolean), active:(TABS.find(t=>t.id===active)||{}).scan_id||null}
 )); }catch(e){}
}
// au chargement: recupere les jobs du serveur, reconstruit les onglets
async function restore(){
 try{ await _restore(); }
 catch(e){ console.error('restore',e); if(!TABS.length) welcome.style.display=''; }
}
async function _restore(){
 let jobs=[]; try{ jobs=await (await fetch('/jobs')).json(); }catch(e){}
 if(!Array.isArray(jobs) || !jobs.length){ welcome.style.display=''; return; }
 welcome.style.display='none';
 let pref={order:[],active:null};
 try{ pref=JSON.parse(localStorage.getItem('stv_tabs'))||pref; }catch(e){}
 // ordre: d'abord ceux memorises, puis le reste
 const byId={}; jobs.forEach(j=>byId[j.scan_id]=j);
 const ordered=[...pref.order.filter(id=>byId[id]),
   ...jobs.map(j=>j.scan_id).filter(id=>!pref.order.includes(id))];
 let activeId=null;
 for(const sid of ordered){
   const j=byId[sid];
   const tab=attach(j.scan_id, j.path, {select:false, nowire:true, scans:j.scans});
   applyState(tab, j);           // etat courant immediat
   if(j.status==='run') wire(tab); // continue a suivre les scans en cours
   if(sid===pref.active) activeId=tab.id;
 }
 select(activeId||TABS[TABS.length-1].id);
}

function newView(name){
 const v=document.createElement('div'); v.className='view';
 v.innerHTML=
  '<div class="prog on"><div class="phead"><span class="pct">0%</span>'+
   '<span class="lbl">Preparation&hellip;</span></div>'+
   '<div class="bar"><i></i></div><div class="log"></div></div>'+
  '<div class="steps"></div>'+
  '<div class="err" style="display:none"></div>'+
  '<div class="stats-wrap"></div><div class="live"></div><div class="out"></div>';
 viewsEl.appendChild(v);
 return v;
}

function norm(p){return p.replace(/[\\/]+$/,'').replace(/\\/g,'/').toLowerCase();}

// cree l'onglet + la vue pour un scan_id serveur, puis s'abonne a son etat.
function attach(scan_id, path, opts){
 opts=opts||{};
 const id=++seq;
 const view=newView(base(path));
 const tab={id,scan_id,name:base(path),path,status:'run',pct:0,count:0,view,es:null,scans:opts.scans||['semgrep']};
 TABS.push(tab);
 if(opts.select!==false) select(id); else renderTabs();
 if(opts.err){ tab.status='err'; renderTabs();
   view.querySelector('.prog').classList.remove('on');
   const ev=view.querySelector('.err'); ev.textContent='Erreur: '+opts.err;
   ev.style.display='block'; return tab; }
 if(!opts.nowire) wire(tab);
 return tab;
}

frm.addEventListener('submit',async e=>{
 e.preventDefault();
 const path=$('path').value.trim(); if(!path)return;
 const dup=TABS.find(t=>norm(t.path)===norm(path));
 if(dup){
   select(dup.id);
   if(dup.status!=='run'){
     if(!confirm('Ce dossier a deja un onglet. Relancer le scan ?')){ $('path').value=''; return; }
     await closeTab(dup.id);
   } else { $('path').value=''; return; }
 }
 welcome.style.display='none';
 const exclude=splitExclude($('ov-exclude').value);
 const scans=selectedScans();
 if(!scans.length){ alert('Coche au moins une analyse.'); return; }
 let r;
 try{ r=await fetch('/start',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({path, exclude, scans})}); }catch(x){ alert('Erreur reseau'); return; }
 const data=await r.json();
 if(!r.ok){ attach(null, path, {err:data.error||'?'}); return; }
 $('path').value=''; $('ov-exclude').value='';
 attach(data.scan_id, path, {scans});
 saveTabs();
});

const SCAN_LABELS={semgrep:'Code',versions:'Deps',secrets:'Secrets',cve:'CVE',
  iac:'IaC',license:'Licences',sensitive:'Fichiers'};
// affiche une carte de progression par scan (nom, phase, mini-barre, %)
function renderSteps(v, steps){
 const box=v.querySelector('.steps'); if(!box)return;
 const keys=Object.keys(steps);
 if(!keys.length){ box.innerHTML=''; return; }
 box.innerHTML=keys.map(k=>{
   const e=steps[k], p=e.pct||0, done=(p>=100);
   const rem=e.remaining?' · '+e.remaining+' restants':'';
   return '<div class="step'+(done?' done':'')+'">'+
     '<div class="srow"><span class="sname">'+esc(SCAN_LABELS[k]||k)+'</span>'+
     '<span class="sphase">'+esc(e.phase||'')+rem+'</span>'+
     '<span class="spct">'+p+'%</span></div>'+
     '<div class="sbar"><i style="width:'+p+'%"></i></div></div>';
 }).join('');
}

// applique un snapshot serveur a l'onglet (progression, fin, erreur)
function applyState(tab, s){
 const v=tab.view, prog=v.querySelector('.prog'),
  pbar=v.querySelector('.bar>i'), pct=v.querySelector('.pct'),
  lbl=v.querySelector('.lbl'), statsW=v.querySelector('.stats-wrap'),
  out=v.querySelector('.out'), errEl=v.querySelector('.err');
 tab.pct=s.pct||0; statsW.innerHTML=statCards(s.counts);
 if(s.status==='run'){
   pbar.style.width=s.pct+'%'; pct.textContent=s.pct+'%';
   lbl.textContent='Analyse en cours';
   renderSteps(v, s.steps||{});
   tab.status='run'; renderTabs(); return;
 }
 renderSteps(v, {});
 prog.classList.remove('on');
 if(s.status==='err'){ tab.status='err'; renderTabs();
   errEl.textContent='Erreur: '+(s.error||'?'); errEl.style.display='block';
   saveTabs(); return; }
 // done
 const res=s.results||[]; const n=res.length;
 tab.status='done'; tab.count=n; tab.results=res; renderTabs();
 const sid=tab.scan_id;
 let h='<div class="toolbar">'+
   (n?'<button type="button" class="copybtn">Copier ('+n+')</button>':'')+
   '<button type="button" class="rescanbtn copybtn">Relancer</button>'+
   (n&&sid?'<a class="copybtn dl" href="/export/'+sid+'.json" download>JSON</a>'+
     '<a class="copybtn dl" href="/export/'+sid+'.sarif" download>SARIF</a>'+
     '<a class="copybtn dl" href="/export/'+sid+'.csv" download>CSV</a>'+
     '<a class="copybtn dl" href="/export/'+sid+'.html" target="_blank">PDF/Imprimer</a>'+
     '<button type="button" class="diffbtn copybtn">Comparer au precedent</button>':'')+
   '</div><div class="diffbox"></div>';
 if(!n){ h+='<div class="empty"><div class="big">&#9989;</div>Aucune vulnerabilite trouvee.</div>'; }
 else{ for(const r of res) h+=fcard(r); }
 out.innerHTML=h;
 const cb=out.querySelector('.copybtn:not(.rescanbtn):not(.dl):not(.diffbtn)');
 if(cb) cb.onclick=()=>copyResults(tab, cb);
 const rb=out.querySelector('.rescanbtn');
 if(rb) rb.onclick=()=>rescan(tab);
 const db=out.querySelector('.diffbtn');
 if(db) db.onclick=()=>loadDiff(tab, db);
 // clic sur Ignorer/Resolu/Rouvrir
 out.querySelectorAll('.f .tag').forEach(a=>{
   a.onclick=async()=>{
     const card=a.closest('.f'); const key=card.dataset.key; const s=a.dataset.s;
     if(!key)return;
     try{ await fetch('/finding-status',{method:'POST',
       headers:{'Content-Type':'application/json'},
       body:JSON.stringify({key,state:s})}); }catch(e){ return; }
     card.classList.remove('st-open','st-ignored','st-resolved');
     card.classList.add('st-'+s);
     const r=(tab.results||[]).find(x=>x.key===key); if(r) r.status=s;
   };
 });
 saveTabs();
}

async function loadDiff(tab, btn){
 const box=tab.view.querySelector('.diffbox');
 btn.disabled=true;
 let d; try{ d=await (await fetch('/diff/'+tab.scan_id)).json(); }
 catch(e){ box.textContent='Erreur diff.'; btn.disabled=false; return; }
 btn.disabled=false;
 if(d.error){ box.innerHTML='<div class="dinfo">'+esc(d.error)+'</div>'; return; }
 const newKeys=new Set((d.new||[]).map(r=>r.key||(r.check_id+'|'+r.file+'|'+r.line)));
 // marque les cartes nouvelles
 tab.view.querySelectorAll('.f').forEach(c=>{
   if([...newKeys].some(k=>k.split('|')[0]===c.querySelector('.rid').textContent))
     c.classList.add('isnew');
 });
 box.innerHTML='<div class="dinfo"><b>Depuis le scan precedent :</b> '+
   '<span class="dg up">+'+d.new_count+' nouveaux</span> '+
   '<span class="dg dn">-'+d.gone_count+' disparus</span> '+
   '<span class="dg">'+d.same_count+' inchanges</span></div>'+
   ((d.gone||[]).length?'<div class="dgone"><b>Disparus :</b><br>'+
     d.gone.map(r=>esc(r.severity)+' '+esc(r.file)+':'+r.line+' — '+esc(r.check_id)).join('<br>')+
     '</div>':'');
}

async function rescan(tab){
 const old=tab.scan_id;
 let r;
 try{ r=await fetch('/start',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({path:tab.path,scans:tab.scans||['semgrep']})}); }catch(x){ alert('Erreur reseau'); return; }
 const data=await r.json();
 if(!r.ok){ alert('Erreur: '+(data.error||'?')); return; }
 if(old){ try{ await fetch('/close/'+old,{method:'POST'}); }catch(e){} }
 // reinitialise la vue en mode progression
 tab.scan_id=data.scan_id; tab.status='run'; tab.pct=0; tab.count=0; tab.results=[];
 const v=tab.view;
 v.querySelector('.prog').classList.add('on');
 v.querySelector('.bar>i').style.width='0%';
 v.querySelector('.pct').textContent='0%';
 v.querySelector('.lbl').textContent='Preparation…';
 v.querySelector('.err').style.display='none';
 v.querySelector('.out').innerHTML='';
 renderTabs(); wire(tab); saveTabs();
}

function wire(tab){
 if(tab.es) tab.es.close();
 const es=new EventSource('/stream/'+tab.scan_id); tab.es=es;
 es.addEventListener('state',ev=>{
   const s=JSON.parse(ev.data); applyState(tab, s);
   if(s.status!=='run') es.close();
 });
 es.onerror=()=>{ es.close();
   // job absent cote serveur (ex: conteneur relance sans reprise) -> marque perdu
   if(tab.status==='run'){ /* reconnexion auto par EventSource sinon */ } };
}

function copyResults(tab, btn){
 const rs=tab.results||[];
 const lines=rs.map(r=>'['+r.severity+'] '+r.file+':'+r.line+'\n  '+r.message+
   '\n  ('+r.check_id+')').join('\n\n');
 const txt='STV scan · '+tab.path+'\n'+rs.length+' problemes\n\n'+lines;
 const done=()=>{ const o=btn.textContent; btn.textContent='Copie !';
   setTimeout(()=>btn.textContent=o,1500); };
 if(navigator.clipboard&&navigator.clipboard.writeText){
   navigator.clipboard.writeText(txt).then(done).catch(()=>fallbackCopy(txt,done));
 } else fallbackCopy(txt,done);
}
function fallbackCopy(txt,done){
 const ta=document.createElement('textarea'); ta.value=txt;
 ta.style.position='fixed'; ta.style.opacity='0'; document.body.appendChild(ta);
 ta.select(); try{document.execCommand('copy');}catch(e){} ta.remove(); done();
}
// ---- Parametres ----
const modal=$('modal');
// separe une saisie libre en dossiers vs extensions (un token .xxx = extension)
function splitExclude(str){
 const toks=(str||'').split(/[,\n]+/).map(s=>s.trim()).filter(Boolean);
 const skip_ext=[], skip_dirs=[];
 for(const t of toks){ (t.startsWith('.')&&!t.includes('/')&&!t.includes('\\')?skip_ext:skip_dirs).push(t); }
 return {skip_dirs, skip_ext};
}
function lines(str){return (str||'').split(/[,\n]+/).map(s=>s.trim()).filter(Boolean);}
async function openCfg(){
 let c={roots:[],skip_dirs:[],skip_ext:[]};
 try{ c=await (await fetch('/config')).json(); }catch(e){}
 $('cfg-roots').value=(c.roots||[]).join('\n');
 $('cfg-dirs').value=(c.skip_dirs||[]).join(', ');
 $('cfg-exts').value=(c.skip_ext||[]).join(', ');
 $('cfgmsg').textContent='';
 modal.classList.add('on');
}
function closeCfg(){ modal.classList.remove('on'); }
$('cfgbtn').onclick=openCfg;
$('cfgclose').onclick=closeCfg;
modal.onclick=e=>{ if(e.target===modal) closeCfg(); };
$('cfgsave').onclick=async()=>{
 const body={roots:lines($('cfg-roots').value),
   skip_dirs:lines($('cfg-dirs').value), skip_ext:lines($('cfg-exts').value)};
 try{
   const r=await fetch('/config',{method:'POST',headers:{'Content-Type':'application/json'},
     body:JSON.stringify(body)});
   if(!r.ok) throw 0;
   $('cfgmsg').textContent='Enregistre.'; setTimeout(closeCfg,700);
 }catch(e){ $('cfgmsg').textContent='Echec de l\'enregistrement.'; }
};

restore();  // reconstruit les onglets/scans au chargement (F5, reouverture)
</script></body></html>
"""

if __name__ == "__main__":
    resume_jobs()  # reprend les scans non finis apres un redemarrage
    app.run(host="0.0.0.0", port=5000, threaded=True)
