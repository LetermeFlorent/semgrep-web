"""Comparaison de versions (semver permissif)."""
import re


def parts(version):
    # extrait (major, minor, patch) en ignorant ^, ~, v, >=, espaces
    cleaned = re.sub(r"^[^0-9]*", "", (version or "").strip())
    match = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", cleaned)
    if not match:
        return None
    return tuple(int(x) if x else 0 for x in match.groups())


def parts_str(version):
    resolved = parts(version)
    return ".".join(str(x) for x in resolved) if resolved else (version or "").strip()


def is_outdated(current, latest_version):
    cur, lat = parts(current), parts(latest_version)
    if not cur or not lat:
        return False
    return cur < lat


def severity_for(current, latest_version):
    # retard de version majeure -> WARNING, sinon INFO
    cur, lat = parts(current), parts(latest_version)
    if cur and lat and lat[0] > cur[0]:
        return "WARNING"
    return "INFO"
