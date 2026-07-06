"""Lecture des manifestes de dependances -> [(ecosystem, name, version)].
Un parseur par format ; find_manifests localise les fichiers connus."""
import os, re, json


def _clean(version):
    return (version or "").strip().strip('"').strip("'")


def parse_package_json(text):
    out = []
    try:
        data = json.loads(text)
    except Exception:
        return out
    for section in ("dependencies", "devDependencies"):
        for name, version in (data.get(section) or {}).items():
            cleaned = _clean(version)
            if re.match(r"[\^~]?\d", cleaned):     # ignore workspace:*, file:, git...
                out.append(("npm", name, cleaned))
    return out


def parse_requirements(text):
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        match = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([0-9][\w.\-]*)", line)
        if match:
            out.append(("pypi", match.group(1), match.group(2)))
    return out


def parse_pyproject(text):
    out = []
    for match in re.finditer(r'["\']([A-Za-z0-9_.\-]+)\s*[=><~!]=?\s*([0-9][\w.\-]*)["\']', text):
        out.append(("pypi", match.group(1), match.group(2)))
    for match in re.finditer(r'^([A-Za-z0-9_.\-]+)\s*=\s*["\']\^?~?([0-9][\w.\-]*)["\']', text, re.M):
        if match.group(1).lower() != "python":
            out.append(("pypi", match.group(1), match.group(2)))
    return out


def parse_cargo(text):
    out, in_deps = [], False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_deps = "dependencies" in stripped
            continue
        if not in_deps:
            continue
        match = re.match(r'^([A-Za-z0-9_\-]+)\s*=\s*["\']([0-9][\w.\-]*)["\']', stripped)
        if not match:
            match = re.match(r'^([A-Za-z0-9_\-]+)\s*=\s*\{[^}]*version\s*=\s*["\']([0-9][\w.\-]*)', stripped)
        if match:
            out.append(("crates", match.group(1), match.group(2)))
    return out


def parse_gomod(text):
    out = []
    for match in re.finditer(r'^\s*([\w./\-]+)\s+v([0-9][\w.\-]*)', text, re.M):
        module = match.group(1)
        if module not in ("go", "module", "require", "toolchain"):
            out.append(("go", module, match.group(2)))
    return out


def parse_composer(text):
    out = []
    try:
        data = json.loads(text)
    except Exception:
        return out
    for section in ("require", "require-dev"):
        for name, version in (data.get(section) or {}).items():
            if "/" in name and re.search(r"\d", version):    # ignore php, ext-*
                out.append(("packagist", name, _clean(version)))
    return out


def parse_gemfile(text):
    out = []
    for match in re.finditer(r'gem\s+["\']([\w\-]+)["\']\s*,\s*["\'][~>=\s]*([0-9][\w.\-]*)["\']', text):
        out.append(("rubygems", match.group(1), match.group(2)))
    return out


def parse_pom(text):
    out = []
    for block in re.finditer(r"<dependency>(.*?)</dependency>", text, re.S):
        body = block.group(1)
        group = re.search(r"<groupId>(.*?)</groupId>", body)
        artifact = re.search(r"<artifactId>(.*?)</artifactId>", body)
        version = re.search(r"<version>(.*?)</version>", body)
        if group and artifact and version and "${" not in version.group(1):
            out.append(("maven", "%s:%s" % (group.group(1).strip(), artifact.group(1).strip()),
                        version.group(1).strip()))
    return out


PARSERS = {"package.json": parse_package_json, "requirements.txt": parse_requirements,
    "pyproject.toml": parse_pyproject, "cargo.toml": parse_cargo, "go.mod": parse_gomod,
    "composer.json": parse_composer, "gemfile": parse_gemfile, "pom.xml": parse_pom}


def find_manifests(root, skip_dirs):
    hits = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs and not d.startswith(".")]
        for name in filenames:
            parser = PARSERS.get(name.lower())
            if parser:
                hits.append((os.path.join(dirpath, name), parser))
    return hits


def collect_deps(root, skip_dirs):
    # (ecosystem, name, version, file) dedupliques sur tous les manifestes trouves
    deps, seen = [], set()
    for path, parser in find_manifests(root, skip_dirs):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                text = handle.read()
        except Exception:
            continue
        for ecosystem, name, version in parser(text):
            key = (ecosystem, name, version)
            if key in seen:
                continue
            seen.add(key)
            deps.append((ecosystem, name, version, path))
    return deps
