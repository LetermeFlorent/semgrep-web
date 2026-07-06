"""Derniere version publiee d'un paquet, par ecosysteme. Requetes reseau en
lecture seule vers les registres publics, resultats mis en cache."""
import re, json, urllib.request, urllib.parse, threading

_UA = {"User-Agent": "stv-version-scanner"}
_cache = {}                        # (ecosystem, name) -> latest version | None
_cache_lock = threading.Lock()


def _fetch_json(url, timeout=12):
    request = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def _latest_npm(name):
    return _fetch_json("https://registry.npmjs.org/%s/latest" % name).get("version")


def _latest_pypi(name):
    return _fetch_json("https://pypi.org/pypi/%s/json" % name)["info"]["version"]


def _latest_crates(name):
    crate = _fetch_json("https://crates.io/api/v1/crates/%s" % name)["crate"]
    return crate.get("max_stable_version") or crate.get("max_version")


def _latest_go(module):
    data = _fetch_json("https://proxy.golang.org/%s/@latest" % module.lower())
    return (data.get("Version") or "").lstrip("v") or None


def _latest_packagist(name):
    versions = _fetch_json("https://repo.packagist.org/p2/%s.json" % name)["packages"][name]
    for entry in versions:                    # premiere version stable
        version = entry["version"]
        if not re.search(r"(dev|alpha|beta|rc)", version, re.I):
            return version.lstrip("v")
    return versions[0]["version"].lstrip("v") if versions else None


def _latest_rubygems(name):
    return _fetch_json("https://rubygems.org/api/v1/gems/%s.json" % name).get("version")


def _latest_maven(coordinate):                # "groupId:artifactId"
    group_id, artifact_id = coordinate.split(":", 1)
    query = 'g:"%s" AND a:"%s"' % (group_id, artifact_id)
    url = "https://search.maven.org/solrsearch/select?q=%s&rows=1&wt=json" % urllib.parse.quote(query)
    docs = _fetch_json(url)["response"]["docs"]
    return docs[0].get("latestVersion") if docs else None


_REGISTRY = {"npm": _latest_npm, "pypi": _latest_pypi, "crates": _latest_crates,
    "go": _latest_go, "packagist": _latest_packagist,
    "rubygems": _latest_rubygems, "maven": _latest_maven}

# ecosysteme interne -> nom OSV.dev
OSV_ECOSYSTEM = {"npm": "npm", "pypi": "PyPI", "crates": "crates.io", "go": "Go",
    "packagist": "Packagist", "rubygems": "RubyGems", "maven": "Maven"}


def latest(ecosystem, name):
    key = (ecosystem, name)
    with _cache_lock:
        if key in _cache:
            return _cache[key]
    try:
        value = _REGISTRY[ecosystem](name)
    except Exception:
        value = None
    with _cache_lock:
        _cache[key] = value
    return value
