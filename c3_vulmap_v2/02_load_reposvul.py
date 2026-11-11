"""
02_load_reposvul.py — ReposVul into the unified schema.

ADAPTED for the actual ReposVul C/C++ tar format found on disk:
  - 3 JSONL files: train_c_cpp_repository2.jsonl, test_c_cpp_repository2.jsonl,
    valid_c_cpp_repository2.jsonl
  - Each record is a FLAT object with function-level data:
      function, target (0 or 1), function_id, cve_id, commit_id, commit_date,
      project, file_name, cwe_id (list), cvss, AV, AC, PR, UI, S, C, I, A
  - This is NOT the nested details[]/function_before/function_after format
    the original loader expected. Each record is already one function.

Run:  python 02_load_reposvul.py
Out:  reposvul_rows.jsonl
"""

import json
from pathlib import Path

import config
import schema


def load_all_records(reposvul_dir):
    """Load records from all 3 split files."""
    recs = []
    patterns = ["train_c_cpp_repository2.jsonl",
                "test_c_cpp_repository2.jsonl",
                "valid_c_cpp_repository2.jsonl"]

    for pattern in patterns:
        p = reposvul_dir / pattern
        if not p.exists():
            print(f"  Warning: {p} not found, skipping")
            continue
        count = 0
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    recs.append(json.loads(line))
                    count += 1
                except Exception:
                    pass
        print(f"  {p.name}: {count:,} records")
    return recs


def extract_row(record):
    """Convert a single flat ReposVul record to a unified schema row."""
    code = record.get("function", "")
    target = record.get("target")

    if not code or len(str(code).strip()) < config.MIN_CODE_CHARS:
        return None
    if target not in (0, 1):
        return None

    project = record.get("project")
    commit_id = record.get("commit_id")
    commit_date = record.get("commit_date")
    cve_id = record.get("cve_id")
    file_name = record.get("file_name")

    # pair_id links before/after sides of the same commit
    pair_id = f"{cve_id}:{commit_id}" if (cve_id or commit_id) else None

    # cwe_id is a list in ReposVul — use first element
    cwe_raw = record.get("cwe_id")
    if isinstance(cwe_raw, list):
        primary_cwe = cwe_raw[0] if cwe_raw else None
    else:
        primary_cwe = cwe_raw

    return schema.make_row(
        code=code,
        label=target,
        source_dataset="reposvul",
        project=project,
        commit_id=commit_id,
        commit_date=commit_date,
        file_path=file_name,
        cwe_id=primary_cwe,
        is_synthetic=False,
        pair_id=pair_id,
    )


def main():
    outdir = config.ensure_output_dir()
    reposvul_dir = config.REPOSVUL_DIR

    if not reposvul_dir.exists():
        raise SystemExit(
            f"{reposvul_dir} does not exist.\n"
            f"Extract ReposVul_c_cpp.tar first:\n"
            f"  tar xf ReposVul_c_cpp.tar -C /tmp/"
        )

    print(f"Reading ReposVul from {reposvul_dir} ...")
    records = load_all_records(reposvul_dir)
    print(f"  Total: {len(records):,} raw records")

    rows = []
    skipped = 0
    for r in records:
        row = extract_row(r)
        if row is None:
            skipped += 1
        else:
            rows.append(row)

    if not rows:
        raise SystemExit(
            "Zero rows extracted. Check that the JSONL files contain "
            "'function' and 'target' fields."
        )

    print(f"  {skipped:,} skipped (empty, short, or invalid target)")
    schema.validate_rows(rows, "reposvul")

    n_vuln = sum(r["label"] for r in rows)
    print(f"\n  {n_vuln:,} vulnerable rows extracted (before dedup)")
    print(f"  Expect substantial overlap — 03_merge_and_dedupe.py resolves this")

    n_paired = sum(1 for r in rows if r["pair_id"])
    print(f"  {n_paired:,} rows carry a pair_id ({n_paired/len(rows):.1%})")

    unique_cves = len(set(r.get("pair_id", "").split(":")[0]
                          for r in rows if r.get("pair_id")))
    print(f"  {unique_cves:,} unique CVE IDs")

    out = outdir / "reposvul_rows.jsonl"
    with open(out, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
