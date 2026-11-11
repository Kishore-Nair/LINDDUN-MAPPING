"""
03e_bridge_name_table_to_ids.py — produce hop 2 (category_cwe_id -> LINDDUN)
from the NAME-keyed curated table this machine actually has.

Why this exists instead of 03d_parse_usemisuse_table.py
-------------------------------------------------------
03d expects config.CWE_CATEGORY_TO_LINDDUN_TABLE to be the raw use/misuse
case transcription — columns 'Privacy Threat Types' (forward-filled) and
'CWE CATEGORY' (comma-separated numeric category ids). The file at that path
on this machine is a different artifact: the filled-in seed template that
03c_parse_cwe_categories.py emits, with columns
'category_name,linddun_category,source'.

Run against that file, 03d reads 41 rows, finds neither expected column,
and writes a header-only category_id_to_linddun.csv — 0 mappings, no error.
04_apply_linddun.py then completes with 0% LINDDUN coverage. Verified
directly, which is why this bridge is a separate script rather than an edit
to 03d: 03d stays correct for the input it documents, and the substitution
is recorded here instead of hidden in a patch.

Hop 1's output (cwe_category_map.csv) carries both category_cwe_id and
category_name, so it is the authority for the name -> id direction. The join
happens ONCE here, with every unmatched or ambiguous name printed rather
than dropped silently; downstream, 04 still joins on the numeric id exactly
as designed. This preserves the 'join on number, never on name text'
property for the pipeline — the one name-join is isolated, verified, and
reported.

Run:  python 03e_bridge_name_table_to_ids.py
Out:  category_id_to_linddun.csv   (in OUTPUT_DIR — what 04 reads for hop 2)
"""

import csv
from collections import defaultdict

import config

SEP = "=" * 72

CANONICAL_LINDDUN = {
    "Linkability", "Identifiability", "Non-repudiation", "Detectability",
    "Data Disclosure", "Unawareness", "Non-compliance",
}
CANONICAL_LOWER = {c.lower(): c for c in CANONICAL_LINDDUN}
LABEL_NORMALISE = {
    "detecting": "Detectability",
    "disclosure of information": "Data Disclosure",
    "information disclosure": "Data Disclosure",
    "non repudiation": "Non-repudiation",
    "nonrepudiation": "Non-repudiation",
    "non compliance": "Non-compliance",
    "noncompliance": "Non-compliance",
}


def head(t):
    print(f"\n{SEP}\n{t}\n{SEP}")


def main():
    outdir = config.ensure_output_dir()

    map_path = outdir / "cwe_category_map.csv"
    if not map_path.exists():
        raise SystemExit(f"{map_path} not found — run "
                         f"03c_parse_cwe_categories.py first (hop 1)")

    tbl_path = config.CWE_CATEGORY_TO_LINDDUN_TABLE
    if not tbl_path.exists():
        raise SystemExit(f"{tbl_path} does not exist.")

    head("1. LOAD HOP 1 NAME -> ID (authority: cwe_category_map.csv)")
    ids_by_name = defaultdict(set)
    name_by_id = {}
    with open(map_path, encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            cid = r["category_cwe_id"].strip().upper()
            nm = r["category_name"].strip()
            ids_by_name[nm].add(cid)
            name_by_id[cid] = nm
    print(f"{len(name_by_id)} category ids / {len(ids_by_name)} distinct "
          f"category names in hop 1")

    ambiguous = {n: s for n, s in ids_by_name.items() if len(s) > 1}
    if ambiguous:
        print(f"\nAMBIGUOUS names (one name -> several ids). Every id gets "
              f"the mapping; confirm that is intended:")
        for n, s in sorted(ambiguous.items()):
            print(f"  {n!r} -> {sorted(s)}")
    else:
        print("No ambiguous names — every category name resolves to exactly "
              "one id, so the join is unique.")

    head("2. READ THE NAME-KEYED LINDDUN TABLE")
    with open(tbl_path, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
        cols = list(rows[0].keys()) if rows else []
    print(f"{tbl_path.name}: {len(rows)} rows, columns={cols}")

    required = {"category_name", "linddun_category"}
    if not required.issubset({c.strip() for c in cols}):
        raise SystemExit(
            f"Expected columns {sorted(required)} — got {cols}. If this file "
            f"is the raw use/misuse transcription (Privacy Threat Types / "
            f"CWE CATEGORY), run 03d_parse_usemisuse_table.py instead.")

    agg = defaultdict(set)
    normalised, unrecognised, blank_ld, unmatched_names = [], [], 0, defaultdict(int)

    for i, r in enumerate(rows):
        ln = i + 2
        nm = (r.get("category_name") or "").strip()
        raw = (r.get("linddun_category") or "").strip()
        if not raw:
            blank_ld += 1
            continue
        key = raw.lower()
        if key in CANONICAL_LOWER:
            ld = CANONICAL_LOWER[key]
        elif key in LABEL_NORMALISE:
            ld = LABEL_NORMALISE[key]
            normalised.append((ln, raw, ld))
        else:
            ld = raw
            unrecognised.append((ln, raw))
        cids = ids_by_name.get(nm)
        if not cids:
            unmatched_names[nm] += 1
            continue
        for cid in cids:
            agg[cid].add(ld)

    print(f"Rows with a blank linddun_category (skipped): {blank_ld}")
    if normalised:
        print(f"\nLabel variants normalised (confirm these are correct):")
        for ln, raw, fixed in normalised:
            print(f"  line {ln}: {raw!r} -> {fixed!r}")
    if unrecognised:
        print(f"\nLabels NOT canonical and NOT a known variant (used as-is "
              f"— these will flow into the corpus verbatim, check them):")
        for ln, raw in unrecognised:
            print(f"  line {ln}: {raw!r}")

    head("3. JOIN COVERAGE")
    tbl_names = {(r.get("category_name") or "").strip() for r in rows
                 if (r.get("category_name") or "").strip()}
    hop1_names = set(ids_by_name)
    print(f"Distinct names in the LINDDUN table : {len(tbl_names)}")
    print(f"Distinct names in hop 1             : {len(hop1_names)}")
    print(f"Matched                             : "
          f"{len(tbl_names & hop1_names)}")

    if unmatched_names:
        print(f"\nIn the LINDDUN table but NOT in hop 1 — {len(unmatched_names)} "
              f"name(s), DROPPED (fix the spelling to recover these):")
        for nm, k in sorted(unmatched_names.items(), key=lambda kv: -kv[1]):
            print(f"  {nm!r} ({k} row(s))")
    else:
        print("\nEvery name in the LINDDUN table matched a hop-1 category — "
              "nothing dropped.")

    no_ld = sorted(hop1_names - tbl_names)
    if no_ld:
        print(f"\nHop-1 categories with NO LINDDUN entry — {len(no_ld)}. "
              f"Expected: LINDDUN is a privacy framework and not every MITRE "
              f"category has a privacy dimension. 04 ranks these by row "
              f"impact in unmapped_categories.csv:")
        for nm in no_ld:
            print(f"  {sorted(ids_by_name[nm])[0]:<10} {nm}")

    head("4. WRITE")
    multi = {k: v for k, v in agg.items() if len(v) > 1}
    print(f"Category ids with a LINDDUN mapping          : {len(agg)}")
    print(f"Category ids mapping to >1 LINDDUN type      : {len(multi)}")
    for cid in sorted(multi):
        print(f"  {cid:<10} {name_by_id.get(cid,'?'):<30} {sorted(agg[cid])}")

    out = outdir / "category_id_to_linddun.csv"
    n_written = 0
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["category_cwe_id", "linddun_category"])
        for cid in sorted(agg):
            for ld in sorted(agg[cid]):
                w.writerow([cid, ld])
                n_written += 1
    print(f"\nWrote {out} ({n_written} rows, {len(agg)} category ids)")


if __name__ == "__main__":
    main()
