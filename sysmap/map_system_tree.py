"""
map_system_tree.py — map a medical system's `tree` listing to LINDDUN
privacy threats, with an explanation for every mapping.

    tree > system.txt
    python3 map_system_tree.py system.txt
    python3 map_system_tree.py system.txt --components --top 25
    python3 map_system_tree.py system.txt --explain apps/registration
    python3 map_system_tree.py system.txt --json > findings.json

WHAT THIS IS NOT: a `tree` listing has nodes but no edges, so this cannot
do real LINDDUN threat elicitation, which reasons about data FLOWING across
trust boundaries. What it produces is an applicability map: which privacy
threats can attach to which components, and why. Every finding is INFERRED
FROM PATH NAMES — the tool has not read any code. Treat it as a scoping
instrument and a review queue, not as a threat model.
"""

import argparse
import json
import sys
from collections import Counter, OrderedDict, defaultdict
from pathlib import Path

from classify import Mapper
import parse_tree

BAR = "=" * 76

# Canonical LINDDUN short codes. Truncating the names instead collides:
# Non-repudiation and Non-compliance both shorten to "Non-".
CODE = {"Linkability": "L", "Identifiability": "I", "Non-repudiation": "Nr",
        "Detectability": "D", "Data Disclosure": "Dd", "Unawareness": "U",
        "Non-compliance": "Nc"}


def _noise():
    import csv as _csv
    with open(Path(__file__).resolve().parent / "path_noise.csv",
              encoding="utf-8-sig", newline="") as f:
        return {r["segment"] for r in _csv.DictReader(f)}


NOISE = _noise()


def component_of(path, depth):
    """Component name for a file, with structural segments dropped.

    Java trees bury the real component under src/main/java/org/<vendor>/
    module/, so aggregating on raw depth would group everything under one
    meaningless prefix. path_noise.csv lists the segments to skip and is
    repo-tunable.
    """
    parts = [p for p in path.split("/")[:-1] if p not in NOISE]
    return "/".join(parts[:depth]) if parts else "(root)"


def load(path_or_dash):
    if path_or_dash == "-":
        return sys.stdin.read()
    return Path(path_or_dash).read_text(encoding="utf-8", errors="replace")


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tree_file", help="output of `tree`, or - for stdin")
    ap.add_argument("--depth", type=int, default=3,
                    help="directory depth to aggregate components at (default 3)")
    ap.add_argument("--components", action="store_true",
                    help="list components rather than the summary")
    ap.add_argument("--top", type=int, default=30)
    ap.add_argument("--explain", metavar="PREFIX",
                    help="full explanation for components under PREFIX")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    entries = parse_tree.parse(load(a.tree_file))
    leaves = parse_tree.files_only(entries)
    m = Mapper()

    kept, dropped = [], Counter()
    for p in leaves:
        r = m.classify(p)
        if r["excluded"]:
            dropped[r["exclude_rule"]] += 1
        else:
            kept.append(r)

    # ---- aggregate to components ------------------------------------
    comps = OrderedDict()
    for r in kept:
        key = component_of(r["path"], a.depth)
        c = comps.setdefault(key, {
            "component": key, "files": 0, "roles": Counter(),
            "tags": Counter(), "linddun": {}, "unclassified": 0})
        c["files"] += 1
        if r["role"]:
            c["roles"][r["role"]] += 1
        else:
            c["unclassified"] += 1
        for t in r["data_tags"]:
            c["tags"][t] += 1
        for f in r["findings"]:
            c["linddun"].setdefault(f["linddun"], f)

    for c in comps.values():
        c["role"] = c["roles"].most_common(1)[0][0] if c["roles"] else None

    if a.json:
        print(json.dumps({"components": [
            {k: (dict(v) if isinstance(v, Counter) else
                 (sorted(v) if k == "linddun" else v))
             for k, v in c.items()} for c in comps.values()]}, indent=2))
        return

    # ---- explain mode ------------------------------------------------
    if a.explain:
        hits = [c for k, c in comps.items() if k.startswith(a.explain)]
        if not hits:
            raise SystemExit(f"no component matching {a.explain!r}")
        for c in hits:
            print(BAR); print(c["component"]); print(BAR)
            print(f"  files (after exclusions): {c['files']}")
            print(f"  role     : {c['role']}  "
                  f"[inferred from the path, not from code]")
            print(f"  data tags: {', '.join(c['tags']) or '(none)'}")
            if not c["linddun"]:
                print("  LINDDUN  : none — no data tag made a threat relevant")
            for cls, f in sorted(c["linddun"].items()):
                print(f"\n  >> {cls}")
                print(f"     applicable because : {f['applicability']}")
                print(f"     relevant because   : {f['relevance']}")
                print(f"     triggered by tag(s): {', '.join(f['because_of'])}")
                for lf in f["leaves"][:2]:
                    print(f"     threat tree [{lf['branch']}]")
                    print(f"       {lf['leaf']}")
                    print(f"       ({lf['source']})")
            print()
        return

    # ---- components table --------------------------------------------
    if a.components:
        ranked = sorted(comps.values(),
                        key=lambda c: (-len(c["linddun"]), -c["files"]))
        print(f"{'component':<50}{'role':<17}{'f':>4}  LINDDUN")
        print("-" * 100)
        print("  L=Linkability I=Identifiability Nr=Non-repudiation "
              "D=Detectability\n  Dd=Data Disclosure U=Unawareness "
              "Nc=Non-compliance")
        print("-" * 100)
        for c in ranked[:a.top]:
            cls = " ".join(CODE.get(x, x) for x in
                           sorted(c["linddun"])) or "-"
            print(f"{c['component'][:48]:<50}{str(c['role']):<17}"
                  f"{c['files']:>4}  {cls}")
        return

    # ---- summary -------------------------------------------------------
    print(f"entries parsed        : {len(entries):,}")
    print(f"leaf files            : {len(leaves):,}")
    print(f"excluded              : {sum(dropped.values()):,}")
    for rule, n in dropped.most_common(6):
        print(f"    {n:>6,}  {rule}")
    print(f"in scope              : {len(kept):,}")
    print(f"components (depth {a.depth}) : {len(comps):,}")

    roles = Counter(r["role"] for r in kept)
    print("\nby role (LINDDUN element type):")
    for k, n in roles.most_common():
        print(f"  {str(k):<16}{n:>6,}")

    tags = Counter(t for r in kept for t in r["data_tags"])
    print("\nby data tag:")
    for k, n in tags.most_common():
        print(f"  {k:<16}{n:>6,}")

    cls = Counter(f["linddun"] for r in kept for f in r["findings"])
    print("\nLINDDUN applicability (files):")
    for k, n in cls.most_common():
        print(f"  {k:<18}{n:>6,}")

    print(f"\nEvery finding is inferred from path names. Nothing here has "
          f"been\nconfirmed against source code.")


if __name__ == "__main__":
    main()
