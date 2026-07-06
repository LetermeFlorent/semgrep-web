"""Test de caracterisation : pin le comportement AVANT refactor.
Teste les fonctions pures sans Flask/Docker. Doit rester vert apres decoupage.
Lance : python -m pytest tests/ -q   (ou python tests/test_characterization.py)
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CASES = []

def check(label, got, expected):
    ok = got == expected
    CASES.append((label, ok, got, expected))
    return ok

def run():
    # import tardif : apres refactor, ces symboles viendront des nouveaux modules
    # (le test importe depuis le point d'entree public, pas les internes).
    import app_api as A

    # --- map_path : lettre Windows -> /host/<lettre> ---
    check("map_path W", A.map_path("W:\\proj\\a"), "/host/w/proj/a")
    check("map_path F slash", A.map_path("F:/x"), "/host/f/x")

    # --- path_allowed : whitelist ---
    check("allowed under root", A.path_allowed("W:\\proj\\a", ["W:\\"]), True)
    check("denied outside", A.path_allowed("C:\\x", ["W:\\", "F:\\"]), False)

    # --- finding_key : stable, insensible casse/slash ---
    r1 = {"check_id": "c.1", "file": "W:\\A\\B.py", "line": 3}
    r2 = {"check_id": "c.1", "file": "w:/a/b.py", "line": 3}
    check("finding_key stable", A.finding_key(r1), A.finding_key(r2))

    # --- dedupe : fusionne doublons, garde 1 ---
    dup = [r1, dict(r1), {"check_id": "c.2", "file": "x", "line": 1}]
    check("dedupe count", len(A.dedupe(dup)), 2)
    check("dedupe adds key", "key" in A.dedupe(dup)[0], True)

    # --- diff_results : nouveaux / disparus / communs ---
    prev = [r1]
    cur = [dict(r1), {"check_id": "c.9", "file": "y", "line": 2}]
    d = A.diff_results(prev, cur)
    check("diff new", d["new_count"], 1)
    check("diff gone", d["gone_count"], 0)
    check("diff same", d["same_count"], 1)

    # --- sarif : structure minimale ---
    job = {"path": "W:\\p", "counts": {"ERROR": 1, "WARNING": 0, "INFO": 0},
           "results": [{"check_id": "c.1", "file": "a.py", "line": "5",
                        "severity": "ERROR", "message": "m", "status": "open", "code": ""}]}
    s = A.build_sarif(job)
    check("sarif version", s["version"], "2.1.0")
    check("sarif 1 result", len(s["runs"][0]["results"]), 1)
    check("sarif level map", s["runs"][0]["results"][0]["level"], "error")

    # --- csv : header + 1 ligne ---
    csv = A.build_csv(job)
    check("csv lines", len([l for l in csv.strip().splitlines()]), 2)

    failed = [c for c in CASES if not c[1]]
    for label, ok, got, exp in CASES:
        print(("  ok " if ok else "FAIL") + " " + label + ("" if ok else "  got=%r exp=%r" % (got, exp)))
    print("%d/%d verts" % (len(CASES) - len(failed), len(CASES)))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(run())
