"""Blueprint findings : etat (ignore/resolu), historique, diff entre runs,
export (json/sarif/csv/html) et mode CI synchrone."""
import os, json
from flask import Blueprint, request, jsonify, Response
from stv.paths import map_path, path_allowed, base_name
from stv.config import load_config
from stv.findings import diff_results
from stv.export import build_sarif, build_csv, build_html_report
from stv.jobs.store import JOBS, JLOCK, JCOND, ALL_SCANS
from stv.jobs.status import load_status, save_status, list_history, read_history
from stv.jobs.runner import new_job

bp = Blueprint("findings", __name__)


@bp.route("/finding-status", methods=["POST"])
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
    # repercute sur les jobs en memoire pour les prochains snapshots
    for j in JOBS.values():
        for r in (j.get("results") or []):
            if r.get("key") == key:
                r["status"] = state
    return jsonify({"ok": True, "key": key, "state": state})


@bp.route("/history/<scan_id>")
def history(scan_id):
    job = JOBS.get(scan_id)
    if not job:
        return jsonify({"error": "job inconnu"}), 404
    return jsonify({"path": job["path"], "runs": list_history(job["path"])})


@bp.route("/diff/<scan_id>")
def diff(scan_id):
    # compare le scan courant a un run precedent (ts en query, sinon l'avant-dernier)
    job = JOBS.get(scan_id)
    if not job or job.get("status") != "done":
        return jsonify({"error": "scan non termine"}), 400
    hist = list_history(job["path"])
    ts = request.args.get("ts", type=int)
    if not ts:
        prev_ts = [t for t in hist][:-1]   # dernier == scan courant qu'on vient de sauver
        if not prev_ts:
            return jsonify({"error": "aucun scan precedent", "runs": hist}), 200
        ts = prev_ts[-1]
    rec = read_history(job["path"], ts)
    prev = rec.get("results") if rec else []
    d = diff_results(prev, job.get("results") or [])
    d["ts"] = ts
    d["runs"] = hist
    return jsonify(d)


@bp.route("/export/<scan_id>.<fmt>")
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
        return Response(json.dumps(build_sarif(job), indent=2, ensure_ascii=False),
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=%s.sarif" % name})
    if fmt == "csv":
        return Response(build_csv(job), mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=%s.csv" % name})
    if fmt in ("html", "pdf"):
        # 'pdf' = page HTML imprimable (Ctrl+P), sans dependance
        return Response(build_html_report(job), mimetype="text/html")
    return "format inconnu (json|sarif|csv|html)", 400


@bp.route("/ci")
def ci():
    # GET /ci?path=W:\proj&scans=semgrep,secrets&fail_on=ERROR -> 200/422
    path = (request.args.get("path") or "").strip()
    if not path_allowed(path, load_config()["roots"]):
        return jsonify({"error": "emplacement non autorise"}), 403
    target = map_path(path)
    if not os.path.isdir(target):
        return jsonify({"error": "dossier introuvable"}), 400
    scans = [s for s in (request.args.get("scans", "").split(",")) if s in ALL_SCANS] or list(ALL_SCANS)
    fail_on = (request.args.get("fail_on") or "ERROR").upper()
    thresh = {"ERROR": ["ERROR"], "WARNING": ["ERROR", "WARNING"],
              "INFO": ["ERROR", "WARNING", "INFO"], "NONE": []}.get(fail_on, ["ERROR"])
    job = new_job(path, target, load_config(), scans)
    while job.get("status") == "run":     # attend la fin (synchrone pour CI)
        with JCOND:
            JCOND.wait(timeout=5)
    c = job.get("counts") or {}
    blocking = sum(c.get(s, 0) for s in thresh)
    verdict = {"path": path, "scans": scans, "fail_on": fail_on,
               "counts": c, "blocking": blocking, "passed": blocking == 0}
    with JLOCK:
        JOBS.pop(job["scan_id"], None)
    return jsonify(verdict), (200 if blocking == 0 else 422)
