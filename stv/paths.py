"""Chemins : conversion Windows->conteneur, whitelist, recensement des fichiers.
Aucune dependance Flask — testable en isolation."""
import os, hashlib

CODE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
    ".c", ".h", ".cpp", ".cc", ".cs", ".rs", ".kt", ".swift", ".scala", ".sh",
    ".bash", ".pl", ".lua", ".vue", ".html", ".yaml", ".yml", ".json", ".tf",
    ".dockerfile", ".sql", ".m", ".r"}


def map_path(path):
    # "W:\proj" -> /host/w/proj  (chaque disque monte sous /host/<lettre>)
    p = path.replace("\\", "/")
    if len(p) > 1 and p[1] == ":":
        return "/host/" + p[0].lower() + "/" + p[2:].lstrip("/")
    if not p.startswith("/host"):
        return "/host/" + p.lstrip("/")
    return p


def path_allowed(win_path, roots):
    # vrai si le chemin saisi est sous une des racines autorisees
    p = (win_path or "").replace("/", "\\").lower().rstrip("\\")
    for root in roots:
        r = root.replace("/", "\\").lower().rstrip("\\")
        if p == r or p.startswith(r + "\\"):
            return True
    return False


def list_targets(root, skip_dirs, skip_ext):
    # fichiers de code a analyser (ignore dossiers caches / exclus / extensions exclues)
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs and not d.startswith(".")]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext in skip_ext:
                continue
            if ext in CODE_EXT or name.lower() == "dockerfile":
                files.append(os.path.join(dirpath, name))
    return files


def path_slug(path):
    # identifiant stable d'un chemin (nom de dossier d'historique)
    return hashlib.sha1((path or "").encode("utf-8", "ignore")).hexdigest()[:16]


def base_name(path):
    p = (path or "").replace("\\", "/").rstrip("/")
    return p.split("/")[-1] or "scan"
