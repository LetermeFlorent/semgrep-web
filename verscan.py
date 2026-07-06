"""Scan des versions de dependances : detecte la techno, lit la version
utilisee, interroge le registre officiel, signale si une version plus recente existe.
Aucune ecriture disque, requetes reseau en lecture seule vers les registres publics."""
import os, re, json, urllib.request, urllib.parse, threading

UA = {"User-Agent": "stv-version-scanner"}
_CACHE = {}                    # (ecosystem, name) -> latest version (str) ou None
_CLOCK = threading.Lock()

def _get(url, timeout=12):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

def _json(url, timeout=12):
    return json.loads(_get(url, timeout))

# ---- Recuperation "derniere version" par ecosysteme ----
def _latest_npm(name):
    return _json("https://registry.npmjs.org/%s/latest" % name).get("version")

def _latest_pypi(name):
    return _json("https://pypi.org/pypi/%s/json" % name)["info"]["version"]

def _latest_crates(name):
    d = _json("https://crates.io/api/v1/crates/%s" % name)["crate"]
    return d.get("max_stable_version") or d.get("max_version")

def _latest_go(mod):
    d = _json("https://proxy.golang.org/%s/@latest" % mod.lower())
    return (d.get("Version") or "").lstrip("v") or None

def _latest_packagist(name):
    d = _json("https://repo.packagist.org/p2/%s.json" % name)
    vers = d["packages"][name]
    for v in vers:                        # premiere version stable
        ver = v["version"]
        if not re.search(r"(dev|alpha|beta|rc)", ver, re.I):
            return ver.lstrip("v")
    return vers[0]["version"].lstrip("v") if vers else None

def _latest_rubygems(name):
    return _json("https://rubygems.org/api/v1/gems/%s.json" % name).get("version")

def _latest_maven(coord):                 # coord = "groupId:artifactId"
    gid, aid = coord.split(":", 1)
    q = 'g:"%s" AND a:"%s"' % (gid, aid)
    url = "https://search.maven.org/solrsearch/select?q=%s&rows=1&wt=json" % urllib.parse.quote(q)
    docs = _json(url)["response"]["docs"]
    return docs[0].get("latestVersion") if docs else None

_REGISTRY = {
    "npm": _latest_npm, "pypi": _latest_pypi, "crates": _latest_crates,
    "go": _latest_go, "packagist": _latest_packagist,
    "rubygems": _latest_rubygems, "maven": _latest_maven,
}

def latest(ecosystem, name):
    key = (ecosystem, name)
    with _CLOCK:
        if key in _CACHE:
            return _CACHE[key]
    val = None
    try:
        val = _REGISTRY[ecosystem](name)
    except Exception:
        val = None
    with _CLOCK:
        _CACHE[key] = val
    return val

# ---- Comparaison de versions (semver permissif) ----
def _parts(v):
    v = re.sub(r"^[^0-9]*", "", (v or "").strip())      # vire ^, ~, v, >=, espaces
    m = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", v)
    if not m:
        return None
    return tuple(int(x) if x else 0 for x in m.groups())

def is_outdated(current, latest_v):
    c, l = _parts(current), _parts(latest_v)
    if not c or not l:
        return False
    return c < l

def severity_for(current, latest_v):
    # major de retard -> WARNING, mineur/patch -> INFO
    c, l = _parts(current), _parts(latest_v)
    if c and l and l[0] > c[0]:
        return "WARNING"
    return "INFO"

# ---- Parsing des manifestes -> [(ecosystem, name, version, raw_line)] ----
def _clean_ver(v):
    return (v or "").strip().strip('"').strip("'")

def parse_package_json(txt):
    out = []
    try:
        d = json.loads(txt)
    except Exception:
        return out
    for sect in ("dependencies", "devDependencies"):
        for name, ver in (d.get(sect) or {}).items():
            v = _clean_ver(ver)
            if re.match(r"[\^~]?\d", v):      # ignore les "workspace:*", "file:", git...
                out.append(("npm", name, v))
    return out

def parse_requirements(txt):
    out = []
    for line in txt.splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([0-9][\w.\-]*)", line)
        if m:
            out.append(("pypi", m.group(1), m.group(2)))
    return out

def parse_pyproject(txt):
    out = []
    # [project] dependencies = ["flask==3.1.0", ...]  ou poetry [tool.poetry.dependencies]
    for m in re.finditer(r'["\']([A-Za-z0-9_.\-]+)\s*[=><~!]=?\s*([0-9][\w.\-]*)["\']', txt):
        out.append(("pypi", m.group(1), m.group(2)))
    for m in re.finditer(r'^([A-Za-z0-9_.\-]+)\s*=\s*["\']\^?~?([0-9][\w.\-]*)["\']', txt, re.M):
        if m.group(1).lower() != "python":
            out.append(("pypi", m.group(1), m.group(2)))
    return out

def parse_cargo(txt):
    out = []
    in_deps = False
    for line in txt.splitlines():
        s = line.strip()
        if s.startswith("["):
            in_deps = "dependencies" in s
            continue
        if in_deps:
            m = re.match(r'^([A-Za-z0-9_\-]+)\s*=\s*["\']([0-9][\w.\-]*)["\']', s)      # foo = "1.2"
            if not m:
                m2 = re.match(r'^([A-Za-z0-9_\-]+)\s*=\s*\{[^}]*version\s*=\s*["\']([0-9][\w.\-]*)', s)
                m = m2
            if m:
                out.append(("crates", m.group(1), m.group(2)))
    return out

def parse_gomod(txt):
    out = []
    for m in re.finditer(r'^\s*([\w./\-]+)\s+v([0-9][\w.\-]*)', txt, re.M):
        mod = m.group(1)
        if mod not in ("go", "module", "require", "toolchain"):
            out.append(("go", mod, m.group(2)))
    return out

def parse_composer(txt):
    out = []
    try:
        d = json.loads(txt)
    except Exception:
        return out
    for sect in ("require", "require-dev"):
        for name, ver in (d.get(sect) or {}).items():
            if "/" in name and re.search(r"\d", ver):     # ignore php, ext-*
                out.append(("packagist", name, _clean_ver(ver)))
    return out

def parse_gemfile(txt):
    out = []
    for m in re.finditer(r'gem\s+["\']([\w\-]+)["\']\s*,\s*["\'][~>=\s]*([0-9][\w.\-]*)["\']', txt):
        out.append(("rubygems", m.group(1), m.group(2)))
    return out

def parse_pom(txt):
    out = []
    for m in re.finditer(r"<dependency>(.*?)</dependency>", txt, re.S):
        blk = m.group(1)
        g = re.search(r"<groupId>(.*?)</groupId>", blk)
        a = re.search(r"<artifactId>(.*?)</artifactId>", blk)
        v = re.search(r"<version>(.*?)</version>", blk)
        if g and a and v and "${" not in v.group(1):
            out.append(("maven", "%s:%s" % (g.group(1).strip(), a.group(1).strip()), v.group(1).strip()))
    return out

# nom de fichier -> parseur
PARSERS = {
    "package.json": parse_package_json,
    "requirements.txt": parse_requirements,
    "pyproject.toml": parse_pyproject,
    "cargo.toml": parse_cargo,
    "go.mod": parse_gomod,
    "composer.json": parse_composer,
    "gemfile": parse_gemfile,
    "pom.xml": parse_pom,
}

def find_manifests(root, skip_dirs):
    hits = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in skip_dirs and not d.startswith(".")]
        for fn in fns:
            p = PARSERS.get(fn.lower())
            if p:
                hits.append((os.path.join(dp, fn), p))
    return hits

# OSV.dev : ecosysteme interne -> nom ecosysteme OSV
_OSV_ECO = {"npm": "npm", "pypi": "PyPI", "crates": "crates.io",
            "go": "Go", "packagist": "Packagist", "rubygems": "RubyGems",
            "maven": "Maven"}

def _osv_query_batch(deps):
    # deps: [(eco,name,version)] -> {index: [vuln,...]} via l'API batch OSV
    queries = []
    for eco, name, ver in deps:
        osv_eco = _OSV_ECO.get(eco)
        pkg_name = name
        payload = {"version": _parts_str(ver), "package": {"name": pkg_name}}
        if osv_eco:
            payload["package"]["ecosystem"] = osv_eco
        queries.append(payload)
    body = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request("https://api.osv.dev/v1/querybatch",
                                 data=body, headers={**UA, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.loads(r.read())
    return data.get("results", [])

def _parts_str(v):
    p = _parts(v)
    return ".".join(str(x) for x in p) if p else (v or "").strip()

def scan_osv(root, skip_dirs, on_progress=None, cancelled=None):
    """CVE sans lockfile : lit les manifestes, interroge OSV.dev par lot."""
    manifests = find_manifests(root, skip_dirs)
    deps, seen = [], set()
    for path, parser in manifests:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                txt = f.read()
        except Exception:
            continue
        for eco, name, ver in parser(txt):
            k = (eco, name, ver)
            if k in seen:
                continue
            seen.add(k)
            deps.append((eco, name, ver, path))

    findings = []
    total = len(deps)
    if not total:
        if on_progress: on_progress(1, 1)
        return findings
    B = 100     # OSV batch limite
    done = 0
    for i in range(0, total, B):
        if cancelled and cancelled():
            break
        chunk = deps[i:i+B]
        try:
            res = _osv_query_batch([(e, n, v) for e, n, v, _ in chunk])
        except Exception:
            res = []
        for (eco, name, ver, path), r in zip(chunk, res):
            for vuln in (r or {}).get("vulns", []) or []:
                vid = vuln.get("id", "")
                findings.append({
                    "severity": "ERROR",
                    "file": path,
                    "line": "-",
                    "message": "%s %s : %s (%s)" % (name, ver, vid, eco),
                    "check_id": "cve.%s" % vid,
                    "code": "",
                })
        done += len(chunk)
        if on_progress:
            on_progress(done, total)
    return findings

def scan_versions(root, skip_dirs, on_progress=None, cancelled=None):
    """Retourne une liste de findings (meme forme que semgrep) pour deps obsoletes.
    on_progress(done, total) appele au fil de l'eau. cancelled() -> bool pour stopper."""
    manifests = find_manifests(root, skip_dirs)
    # (ecosystem, name, version, file) dedupliques
    deps, seen = [], set()
    for path, parser in manifests:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                txt = f.read()
        except Exception:
            continue
        for eco, name, ver in parser(txt):
            k = (eco, name, ver)
            if k in seen:
                continue
            seen.add(k)
            deps.append((eco, name, ver, path))

    findings = []
    total = len(deps)
    for i, (eco, name, ver, path) in enumerate(deps):
        if cancelled and cancelled():
            break
        if on_progress:
            on_progress(i, total)
        lat = latest(eco, name)
        if lat and is_outdated(ver, lat):
            sev = severity_for(ver, lat)
            findings.append({
                "severity": sev,
                "file": path,
                "line": "-",
                "message": "%s %s est obsolete : derniere version %s (%s)" % (name, ver, lat, eco),
                "check_id": "version.outdated.%s" % eco,
                "code": "%s: %s -> %s" % (name, ver, lat),
            })
    if on_progress:
        on_progress(total, total)
    return findings
