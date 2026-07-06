"""Blueprint des routes de scan : liste des jobs, config, mounts, lancement,
fermeture/annulation et flux SSE de progression."""
import json
import os
from flask import Blueprint, request, jsonify, Response
from stv.paths import map_path, path_allowed
from stv.config import (load_config, save_config, normalize_config,
                        list_mounts, CONFIG_FILE)
from stv.jobs.store import JOBS, JLOCK, JCOND, ALL_SCANS, snapshot, persist
from stv.jobs.runner import new_job

bp = Blueprint("scan", __name__)


@bp.route("/jobs")
def jobs():
    with JLOCK:
        return jsonify([snapshot(j) for j in JOBS.values()])


@bp.route("/mounts")
def mounts():
    cfg = load_config()
    return jsonify({
        "mounted": list_mounts(),
        "roots": cfg["roots"],
        "configured": os.path.exists(CONFIG_FILE),
    })


@bp.route("/config", methods=["GET", "POST"])
def config():
    if request.method == "POST":
        return jsonify(save_config(request.json or {}))
    return jsonify(load_config())


@bp.route("/start", methods=["POST"])
def start():
    body = request.json or {}
    path = (body.get("path") or "").strip()
    cfg = load_config()
    if not path_allowed(path, cfg["roots"]):
        allowed = ", ".join(cfg["roots"]) or "(aucune)"
        return jsonify({"error": "Emplacement non autorise: " + path +
                        " · racines permises: " + allowed}), 403
    target = map_path(path)
    if not os.path.isdir(target):
        return jsonify({"error": "Dossier introuvable: " + path +
                        " (disques montes: C D F G H I M W)"}), 400
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


@bp.route("/close/<scan_id>", methods=["POST"])
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


@bp.route("/stream/<scan_id>")
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
