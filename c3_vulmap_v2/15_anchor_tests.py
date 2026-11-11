"""
15_anchor_tests.py — regression tests for the CWE -> LINDDUN mapping.

There is no ground truth for CWE -> LINDDUN; nobody has published an
authoritative mapping, which is why this project exists. So the mapping
cannot be validated by accuracy. What CAN be checked is internal
consistency against cases where the CWE's own NAME states the privacy
effect, leaving no room for judgement: if CWE-532 "Insertion of Sensitive
Information into Log File" does not carry Data Disclosure, the mapping
disagrees with MITRE's own title and is wrong regardless of taste.

Anchors live in anchor_tests.csv so they can be argued with and extended.
Exits non-zero on failure, so this is runnable in CI.

Run:  python3 15_anchor_tests.py
      python3 15_anchor_tests.py --verbose
"""

import argparse
import csv
import sys
from pathlib import Path

from xai import Explainer

HERE = Path(__file__).resolve().parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()

    with open(HERE / "anchor_tests.csv", encoding="utf-8-sig", newline="") as f:
        anchors = list(csv.DictReader(f))

    ex = Explainer()
    failures = []
    print(f"{'CWE':<10}{'name':<52}{'expected':<18}result")
    print("-" * 100)

    for r in anchors:
        cwe = r["cwe_id"].strip().upper()
        want = r["must_include"].strip()
        e = ex.explain(cwe)
        got = set(e.final)
        ok = want in got
        if not ok:
            failures.append((cwe, r["name"], want, e))
        shown = ";".join(sorted(got)) if got else f"(none: {e.status})"
        print(f"{cwe:<10}{r['name'][:50]:<52}{want:<18}"
              f"{'PASS' if ok else 'FAIL'}")
        if a.verbose or not ok:
            print(f"{'':<10}assigned: {shown}")

    print("-" * 100)
    print(f"{len(anchors) - len(failures)} passed, {len(failures)} failed, "
          f"{len(anchors)} total")

    if failures:
        print("\nFAILURES — the mapping contradicts the CWE's own name:")
        for cwe, name, want, e in failures:
            print(f"\n  {cwe} {name}")
            print(f"    expected to include : {want}")
            print(f"    actually assigned   : "
                  f"{';'.join(sorted(e.final)) or f'(none: {e.status})'}")
            if e.status == "cwe_has_no_category":
                print(f"    -> hop-1 gap. Add it to cwe_category_additions.csv")
            elif e.status == "cwe_excluded":
                print(f"    -> on the exclusion list; remove it there first")
            else:
                print(f"    -> hop-2 issue. Fix in cwe_linddun_overrides.csv")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
