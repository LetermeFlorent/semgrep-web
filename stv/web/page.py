"""Sert la page unique de l'application (templates/index.html).
Le HTML est charge une fois puis rendu via Jinja (identique a l'ancien PAGE)."""
import os
from flask import render_template_string

_HTML_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "templates", "index.html")

with open(_HTML_PATH, encoding="utf-8") as _f:
    # l'ancien PAGE commencait par un saut de ligne (r""" suivi d'un retour) :
    # on le reproduit pour un rendu byte-identique.
    PAGE = "\n" + _f.read()


def render_page():
    return render_template_string(PAGE)
