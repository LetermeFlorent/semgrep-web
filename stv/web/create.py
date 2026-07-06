"""Fabrique l'application Flask : enregistre les blueprints, la route page,
et relance les scans interrompus au demarrage."""
from flask import Flask
from stv.web.page import render_page
from stv.web.routes_scan import bp as scan_bp
from stv.web.routes_findings import bp as findings_bp
from stv.jobs.runner import resume_jobs


def create_app():
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_page()

    app.register_blueprint(scan_bp)
    app.register_blueprint(findings_bp)
    resume_jobs()   # reprend les scans non finis apres un redemarrage
    return app
