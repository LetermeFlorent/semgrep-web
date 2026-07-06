"""Config globale persistee : racines autorisees + exclusions, plus la liste
des disques montes cote conteneur. Fonctions I/O, pas de Flask."""
import os, json, threading

SKIP_DIR = {"node_modules", ".git", "venv", ".venv", "__pycache__", "dist",
    "build", "vendor", ".next", "target", ".idea", ".vscode", "site-packages"}

CONFIG_FILE = os.environ.get("STV_CONFIG", "/state/config.json")
DEFAULT_CONFIG = {
    "roots": ["F:\\", "W:\\"],                   # liste blanche d'emplacements
    "skip_dirs": sorted(SKIP_DIR | {"run"}),     # dossiers ignores
    "skip_ext": [".md", ".log"],                 # extensions ignorees
}
_LOCK = threading.Lock()


def _clean_ext(ext):
    ext = (ext or "").strip().lower()
    if not ext:
        return None
    return ext if ext.startswith(".") else "." + ext


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
    with _LOCK:
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        tmp = CONFIG_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cfg, f, indent=2)
        os.replace(tmp, CONFIG_FILE)
    return cfg


def list_mounts():
    # lettres reellement montees dans le conteneur (dossiers sous /host)
    out = []
    try:
        for name in sorted(os.listdir("/host")):
            p = os.path.join("/host", name)
            if os.path.isdir(p) and len(name) == 1:
                out.append(name.upper() + ":\\")
    except Exception:
        pass
    return out
