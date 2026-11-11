"""
build_cve_linddun.py — map CVE_CWE_2025_Z_liu.csv to LINDDUN privacy classes.

Takes the NVD-derived CVE corpus (280,694 rows: CVE id, CVSS v2/v3/v4,
severity, description, CWE) and attaches LINDDUN classes through the same
two-hop chain used elsewhere in this project:

    CWE -> MITRE category   (cwe_category_map.csv,     from 03c)
        -> LINDDUN class    (category_id_to_linddun.csv, from 03e)
        -> CWE-level refinement (cwe_linddun_overrides.csv, Fix B)

The chain tables are derived from the project's own source documents
("cwe_linddun_mapping main.csv" and the use/misuse case table), so reusing
them here carries no dependency on the C3-VULMAP corpus itself -- only on
the mapping, which is the reusable asset.

Unmapped rows are KEPT, with linddun_status recording why. Roughly a fifth
of this corpus is NVD-CWE-Other, a placeholder meaning "classified, but not
to a listed weakness"; dropping those silently would misrepresent coverage.

Run:  python3 build_cve_linddun.py
Out:  cve_linddun.parquet        full mapped dataset
      cve_linddun_sample.csv     2,000-row readable sample
      cve_linddun_report.json    coverage + distribution
      cve_linddun_unmapped.csv   CWEs with no LINDDUN class, by impact
"""

import json
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
SRC = PROJECT / "CVE_CWE_2025_Z_liu.csv"

sys.path.insert(0, str(PROJECT / "c3_vulmap_v2"))
from xai import Explainer                                  # noqa: E402
from xai.paths import CANONICAL_LINDDUN                    # noqa: E402

SEED = 42
VAL_FRAC, TEST_FRAC = 0.10, 0.20


def _num(x):
    try:
        v = float(x)
        return v if v == v else None
    except (TypeError, ValueError):
        return None


def main():
    if not SRC.exists():
        raise SystemExit(f"{SRC} not found")
    print(f"reading {SRC.name} ...")
    d = pd.read_csv(SRC, dtype=str, keep_default_na=False)
    n = len(d)
    print(f"{n:,} CVE rows")

    d = d.rename(columns={
        "CVE-ID": "cve_id", "CVSS-V4": "cvss_v4", "CVSS-V3": "cvss_v3",
        "CVSS-V2": "cvss_v2", "SEVERITY": "severity",
        "DESCRIPTION": "description", "CWE-ID": "cwe_id_raw"})
    d = d.drop(columns=["ID"])

    # --- clean -------------------------------------------------------
    d["cwe_id_raw"] = d.cwe_id_raw.str.strip().str.upper()
    d["cwe_valid"] = d.cwe_id_raw.str.match(r"^CWE-\d+$")
    # .where() yields NaN, not None, and NaN is truthy -- which silently
    # routed every NVD-CWE-Other row into "cwe_has_no_category" instead of
    # "no_cwe". Build the column as real None.
    d["cwe_id"] = [c if v else None
                   for c, v in zip(d.cwe_id_raw, d.cwe_valid)]
    d["severity"] = d.severity.replace({"None": None, "NONE": None})
    d["year"] = d.cve_id.str.extract(r"CVE-(\d{4})-")[0].astype("Int64")

    for c in ("cvss_v4", "cvss_v3", "cvss_v2"):
        d[c] = d[c].map(_num)

    # Coalesce to one score, newest version first, recording provenance
    # so v2 and v3 numbers are never silently treated as one scale.
    score, ver = [], []
    for v4, v3, v2 in zip(d.cvss_v4, d.cvss_v3, d.cvss_v2):
        # pd.notna, not "is not None": .map() leaves NaN in a float column
        # and NaN is not None, which would select v4 for every row.
        if pd.notna(v4):   score.append(v4); ver.append("v4")
        elif pd.notna(v3): score.append(v3); ver.append("v3")
        elif pd.notna(v2): score.append(v2); ver.append("v2")
        else:              score.append(None); ver.append(None)
    d["cvss_score"], d["cvss_version"] = score, ver

    # --- map ---------------------------------------------------------
    print("applying the LINDDUN chain ...")
    ex = Explainer()
    cache = {}

    def info(cwe):
        if cwe not in cache:
            e = ex.explain(cwe)
            cache[cwe] = {
                "status": e.status,
                "cats": ";".join(s.category_id for s in
                                 (e.chain.categories if e.chain else [])) or None,
                "cat_names": ";".join(s.category_name for s in
                                      (e.chain.categories if e.chain else [])) or None,
                "base": ";".join(e.inherited) or None,
                "final": ";".join(e.final) or None,
                "primary": e.primary,
                "override": bool(e.override and e.override.changes_label),
                "rationale": e.override.rationale if e.override else None,
                "set": set(e.final),
            }
        return cache[cwe]

    recs = [info(c) for c in d.cwe_id]
    d["linddun_status"] = [r["status"] for r in recs]
    d["cwe_category_ids"] = [r["cats"] for r in recs]
    d["cwe_categories"] = [r["cat_names"] for r in recs]
    d["linddun_categories_base"] = [r["base"] for r in recs]
    d["linddun_categories"] = [r["final"] for r in recs]
    d["linddun_primary"] = [r["primary"] for r in recs]
    d["linddun_override_applied"] = [r["override"] for r in recs]
    d["linddun_override_rationale"] = [r["rationale"] for r in recs]
    d["n_linddun"] = [len(r["set"]) for r in recs]

    # one-hot per class, for multi-label use
    for cls in CANONICAL_LINDDUN:
        col = "ld_" + cls.lower().replace(" ", "_").replace("-", "_")
        d[col] = [cls in r["set"] for r in recs]

    # --- split (stratified; CVE rows have no project/pair structure) --
    lab = d.linddun_categories.notna()
    strat = d.linddun_primary.where(lab, "__none__")
    d["_r"] = 0.0
    for key, idx in d.groupby(strat).groups.items():
        k = len(idx)
        d.loc[idx, "_r"] = pd.Series(range(k), index=idx) \
            .sample(frac=1, random_state=SEED).rank(pct=True).values
    d["split"] = pd.cut(d._r, [0, TEST_FRAC, TEST_FRAC + VAL_FRAC, 1.0],
                        labels=["test", "val", "train"], include_lowest=True)
    d = d.drop(columns=["_r", "cwe_id_raw"])

    # --- report ------------------------------------------------------
    labelled = int(lab.sum())
    status = Counter(d.linddun_status)
    cls_counts = Counter()
    for r in recs:
        for c in r["set"]:
            cls_counts[c] += 1

    print(f"\nlabelled: {labelled:,} / {n:,} ({labelled/n:.1%})")
    print("\nstatus breakdown:")
    for s, k in status.most_common():
        print(f"  {s:<26}{k:>9,}  ({k/n:5.1%})")
    print("\nLINDDUN class counts (multi-label):")
    for c, k in cls_counts.most_common():
        print(f"  {c:<20}{k:>9,}")
    print("\nsplit:")
    print(d.split.value_counts().to_string())
    print(f"\nCVSS coverage: {d.cvss_score.notna().sum():,} "
          f"({d.cvss_score.notna().mean():.1%}) — by version "
          f"{dict(Counter(v for v in d.cvss_version if isinstance(v, str)))}")

    # --- write -------------------------------------------------------
    out = HERE / "cve_linddun.parquet"
    d.to_parquet(out, index=False)
    print(f"\nWrote {out}  ({out.stat().st_size/1e6:.0f} MB, "
          f"{len(d):,} rows x {d.shape[1]} cols)")

    sample = d.sample(2000, random_state=SEED)
    sp = HERE / "cve_linddun_sample.csv"
    sample.to_csv(sp, index=False)
    print(f"Wrote {sp}")

    unmapped = (d[d.linddun_categories.isna() & d.cwe_valid]
                .groupby("cwe_id").size().sort_values(ascending=False)
                .rename("n_rows").reset_index())
    unmapped["status"] = unmapped.cwe_id.map(lambda c: info(c)["status"])
    up = HERE / "cve_linddun_unmapped.csv"
    unmapped.to_csv(up, index=False)
    print(f"Wrote {up} ({len(unmapped)} CWEs)")

    rp = HERE / "cve_linddun_report.json"
    with open(rp, "w") as f:
        json.dump({
            "source": SRC.name, "n_rows": n, "n_labelled": labelled,
            "coverage": labelled / n, "status": dict(status),
            "linddun_class_counts": dict(cls_counts),
            "cvss_coverage": float(d.cvss_score.notna().mean()),
            "cvss_by_version": {k: int(v) for k, v in
                                Counter(v for v in d.cvss_version if isinstance(v, str)).items()},
            "year_min": int(d.year.min()), "year_max": int(d.year.max()),
            "split": {k: int(v) for k, v in d.split.value_counts().items()},
            "seed": SEED,
        }, f, indent=2)
    print(f"Wrote {rp}")


if __name__ == "__main__":
    main()
