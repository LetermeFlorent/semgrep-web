"""Tests headless des parseurs de manifestes et du semver (aucun reseau)."""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stv.versions import parsers
from stv.versions import semver

CASES = []


def check(label, got, expected):
    CASES.append((label, got == expected, got, expected))


def run():
    check("pkg json", parsers.parse_package_json(
        '{"dependencies":{"lodash":"4.17.4"},"devDependencies":{"jest":"^29"}}'),
        [("npm", "lodash", "4.17.4"), ("npm", "jest", "^29")])
    check("requirements", parsers.parse_requirements("flask==0.5\n# c\nrequests==2.6.0"),
        [("pypi", "flask", "0.5"), ("pypi", "requests", "2.6.0")])
    # bloc require multi-lignes (format go.mod reel : module indente puis version)
    check("gomod", parsers.parse_gomod("module x\ngo 1.21\nrequire (\n\tfoo/bar v1.2.3\n)\n"),
        [("go", "foo/bar", "1.2.3")])
    check("gemfile", parsers.parse_gemfile('gem "rails", ">= 6.1.0"'),
        [("rubygems", "rails", "6.1.0")])

    check("parts", semver.parts("^1.2.3"), (1, 2, 3))
    check("parts partial", semver.parts("2"), (2, 0, 0))
    check("outdated", semver.is_outdated("1.0.0", "2.0.0"), True)
    check("not outdated", semver.is_outdated("2.0.0", "2.0.0"), False)
    check("sev major", semver.severity_for("1.0.0", "3.0.0"), "WARNING")
    check("sev minor", semver.severity_for("1.1.0", "1.2.0"), "INFO")

    failed = [c for c in CASES if not c[1]]
    for label, ok, got, exp in CASES:
        print(("  ok " if ok else "FAIL") + " " + label + ("" if ok else "  got=%r exp=%r" % (got, exp)))
    print("%d/%d verts" % (len(CASES) - len(failed), len(CASES)))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(run())
