"""
14_explain_linddun.py — explain why each row carries its LINDDUN classes,
and apply the CWE-level override table (Fix B).

The LINDDUN label is a pure function of cwe_id, so the explanation is exact
and deterministic — no model, no attribution, nothing to tune. Code
evidence is reported alongside but is explicitly advisory; see xai/evidence.py.

Run:
  python 14_explain_linddun.py --cwe CWE-476
  python 14_explain_linddun.py --index 0 --json
  python 14_explain_linddun.py --code-hash 428da0ae...
  python 14_explain_linddun.py --sample 5
  python 14_explain_linddun.py --report
  python 14_explain_linddun.py --write-refined

Out (--report):        linddun_override_report.json, linddun_disagreements.csv
Out (--write-refined): corpus_final_xai.parquet  (a NEW file; the original
                       corpus_final.parquet is never modified)
"""

import argparse
import json
import sys
from collections import Counter

from xai import Explainer
from xai import paths


def _load_corpus(columns=None):
    import pandas as pd
    if not paths.CORPUS.exists():
        raise SystemExit(f"{paths.CORPUS} not found — run 06_build_splits.py")
    return pd.read_parquet(paths.CORPUS, columns=columns)


def cmd_single(ex, cwe=None, code=None, as_json=False):
    e = ex.explain(cwe, code)
    print(json.dumps(e.to_dict(), indent=2) if as_json else e.to_text())


def cmd_report(ex):
    import pandas as pd
    d = _load_corpus(["cwe_id", "code", "code_hash", "linddun_categories"])
    n = len(d)

    counts = Counter(d.cwe_id.dropna())
    rows_changed = 0
    per_cwe = []
    for cwe, k in counts.items():
        e = ex.explain(cwe)
        if e.changed:
            rows_changed += k
            per_cwe.append({
                "cwe_id": cwe, "rows": k,
                "before": ";".join(e.inherited),
                "after": ";".join(e.final),
                "confidence": e.override.confidence if e.override else "",
            })
    per_cwe.sort(key=lambda r: -r["rows"])

    print(f"{n:,} corpus rows")
    print(f"override table: {len(ex.table)} CWEs reviewed")
    print(f"CWEs whose label changes: {len(per_cwe)}")
    print(f"rows affected: {rows_changed:,} ({rows_changed/n:.1%})\n")
    print(f"{'CWE':<10}{'rows':>8}  {'before':<32} after")
    print("-" * 92)
    for r in per_cwe:
        print(f"{r['cwe_id']:<10}{r['rows']:>8,}  {r['before'][:30]:<32} "
              f"{r['after']}")

    # before/after class distribution
    def dist(which):
        c = Counter()
        for cwe, k in counts.items():
            e = ex.explain(cwe)
            for cls in (e.inherited if which == "before" else e.final):
                c[cls] += k
        return c
    before, after = dist("before"), dist("after")
    print(f"\n{'class':<18}{'before':>12}{'after':>12}{'delta':>12}")
    print("-" * 54)
    for cls in sorted(set(before) | set(after), key=lambda c: -after.get(c, 0)):
        b, a = before.get(cls, 0), after.get(cls, 0)
        print(f"{cls:<18}{b:>12,}{a:>12,}{a-b:>+12,}")

    # disagreement scan on a sample (full scan is expensive)
    sample = d[d.linddun_categories.notna()].sample(
        min(4000, int(d.linddun_categories.notna().sum())), random_state=42)
    dis = []
    for _, r in sample.iterrows():
        e = ex.explain(r.cwe_id, r.code)
        if e.disagrees:
            dis.append({"code_hash": r.code_hash, "cwe_id": r.cwe_id,
                        "asserted": ";".join(e.final),
                        "no_evidence_for": ";".join(e.unsupported)})
    rate = len(dis) / len(sample)
    print(f"\nno lexical evidence, {len(sample):,}-row sample: "
          f"{len(dis):,} ({rate:.1%})")
    print("  Counted ONLY for API-mediated classes (Identifiability, "
          "Non-repudiation,\n  Non-compliance, Unawareness). Memory-safety "
          "classes are excluded: their\n  mechanism is pointer arithmetic, "
          "not named calls, so these rules cannot\n  see them. Treat as a "
          "review queue, not a mislabel rate.")

    out = paths.OUTPUT_DIR / "linddun_override_report.json"
    with open(out, "w") as f:
        json.dump({"n_rows": n, "cwes_reviewed": len(ex.table),
                   "cwes_changed": len(per_cwe), "rows_changed": rows_changed,
                   "class_before": dict(before), "class_after": dict(after),
                   "disagreement_sample": len(sample),
                   "disagreement_rate": rate}, f, indent=2)
    print(f"\nWrote {out}")
    if dis:
        import csv as _csv
        p2 = paths.OUTPUT_DIR / "linddun_disagreements.csv"
        with open(p2, "w", newline="") as f:
            w = _csv.DictWriter(f, fieldnames=list(dis[0]))
            w.writeheader()
            w.writerows(dis)
        print(f"Wrote {p2} ({len(dis):,} rows)")


def cmd_write_refined(ex):
    d = _load_corpus()
    cache = {}

    def refined(c):
        if c not in cache:
            e = ex.explain(c)
            cache[c] = (";".join(e.final) if e.final else None,
                        e.override.rationale if e.override else None)
        return cache[c]

    vals = [refined(c) if c is not None else (None, None) for c in d.cwe_id]
    d["linddun_categories_base"] = d["linddun_categories"]
    d["linddun_categories"] = [v[0] for v in vals]
    d["linddun_primary"] = [v[0].split(";")[0] if v[0] else None
                            for v in vals]
    d["linddun_override_rationale"] = [v[1] for v in vals]

    out = paths.OUTPUT_DIR / "corpus_final_xai.parquet"
    d.to_parquet(out, index=False)
    changed = (d.linddun_categories_base.fillna("") !=
               d.linddun_categories.fillna("")).sum()
    print(f"Wrote {out}")
    print(f"  rows with a changed label: {changed:,} / {len(d):,}")
    print(f"  original corpus_final.parquet left untouched")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--cwe")
    g.add_argument("--index", type=int)
    g.add_argument("--code-hash")
    g.add_argument("--sample", type=int)
    g.add_argument("--report", action="store_true")
    g.add_argument("--write-refined", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    ex = Explainer()

    if a.report:
        return cmd_report(ex)
    if a.write_refined:
        return cmd_write_refined(ex)
    if a.cwe:
        return cmd_single(ex, a.cwe, None, a.json)

    d = _load_corpus(["cwe_id", "code", "code_hash"])
    if a.index is not None:
        if not 0 <= a.index < len(d):
            raise SystemExit(f"--index must be 0..{len(d)-1}")
        r = d.iloc[a.index]
        return cmd_single(ex, r.cwe_id, r.code, a.json)
    if a.code_hash:
        m = d[d.code_hash.str.startswith(a.code_hash)]
        if m.empty:
            raise SystemExit(f"no row with code_hash starting {a.code_hash!r}")
        r = m.iloc[0]
        return cmd_single(ex, r.cwe_id, r.code, a.json)
    if a.sample:
        for _, r in d[d.cwe_id.notna()].sample(a.sample, random_state=0).iterrows():
            cmd_single(ex, r.cwe_id, r.code, a.json)
            print()


if __name__ == "__main__":
    sys.exit(main())
