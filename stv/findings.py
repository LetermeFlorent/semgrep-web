"""Findings : cle stable, deduplication, diff entre deux scans.
Fonctions pures — aucune I/O, testables directement."""


def finding_key(finding):
    # cle stable pour dedup / etat / diff (insensible casse et slash)
    normalized_file = (finding.get("file") or "").replace("\\", "/").lower()
    return "%s|%s|%s" % (finding.get("check_id", ""), normalized_file, finding.get("line", ""))


def dedupe(results):
    # fusionne les doublons (meme finding remonte par plusieurs scanners)
    seen, out = set(), []
    for finding in results:
        key = finding_key(finding)
        if key in seen:
            continue
        seen.add(key)
        tagged = dict(finding)
        tagged["key"] = key
        out.append(tagged)
    return out


def diff_results(previous, current):
    # compare deux listes -> nouveaux / disparus / inchanges
    prev_keys = {finding_key(f) for f in (previous or [])}
    cur_keys = {finding_key(f) for f in (current or [])}
    new = [f for f in current if finding_key(f) not in prev_keys]
    gone = [f for f in (previous or []) if finding_key(f) not in cur_keys]
    return {"new": new, "gone": gone,
            "new_count": len(new), "gone_count": len(gone),
            "same_count": len(cur_keys & prev_keys)}
