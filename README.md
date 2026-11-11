# LINDDUN-MAPPING

Mapping code-level vulnerabilities to **LINDDUN** privacy threat categories, with
per-datapoint explanations. Final-year project (course 22AIE498).

LINDDUN categories: Linkability, Identifiability, Non-repudiation, Detectability,
Data Disclosure, Unawareness, Non-compliance.

## What this repository contains

| Path | What it is |
|---|---|
| `cve_linddun/` | **The released dataset.** Builder, dataset card, validation reports, 1 MB sample. |
| `c3_vulmap_v2/` | The numbered build pipeline, the CWE→category→LINDDUN mapping tables, and the XAI explainer. |
| `c3_vulmap_v2/xai/` | Explanation module — replays the exact provenance chain behind every label. |
| `c3_vulmap_v2_build/` | Validation and coverage reports from pipeline runs (small artifacts only). |
| `sysmap/` | Maps a medical system's architecture tree (from `tree`) onto LINDDUN threats. |
| `diary/` | Weekly project diary sheets. |
| `webpage/` | CVSS/vulnerability browser front-end. |
| `enrich_dataset.py` | NVD enrichment for CVE records. |

## How a label is decided

The mapping is a deterministic chain of lookup tables — no model, no scoring, no
thresholds. The same CWE always yields the same answer.

1. **CVE → CWE** — taken from NVD, not a project decision.
2. **CWE → MITRE category** (`cwe_category_map.csv`) — MITRE's own taxonomy. A CWE
   may belong to several categories, and a category counts as a member of itself.
   `cwe_category_additions.csv` adds memberships missing from the local extract.
3. **Exclusion check** — six MITRE-discouraged abstract CWEs contribute nothing.
   See `c3_vulmap_v2_build/excluded_abstract_cwes.csv`.
4. **Category → LINDDUN** (`category_id_to_linddun.csv`) — derived from the
   use/misuse case table. **This is the human judgement layer.**
5. **Union** across every category the CWE belongs to, then a **CWE-level override**
   (`cwe_linddun_overrides.csv`) where category inheritance is wrong.
6. **Primary label** — alphabetically first of the final set.

Explain any CWE's label:

```bash
cd c3_vulmap_v2 && python3 14_explain_linddun.py --cwe CWE-532
```

Check the mapping against known-answer anchors:

```bash
cd c3_vulmap_v2 && python3 15_anchor_tests.py
```

## Known limitations

Read these before using the dataset or quoting its numbers.

- **Step 6 is a documented defect.** `linddun_primary` is the alphabetically first
  label, not a ranking. `Data Disclosure` therefore wins every tiebreak it enters
  and `Non-compliance` never wins. Treat the multi-label set as authoritative.
- **The mapping hinges on 14 override decisions**, which move ~26.7% of labelled
  rows. Each carries a written rationale, but none is externally validated.
- **No inter-rater study yet**, so there is no agreement statistic for the
  judgement layer.
- **The local category extract has 28 categories, not the 40** the upstream release
  documents, so coverage figures here are not comparable to it.
- **The synthetic subset is 100% vulnerable** — the generator has no safe-example
  path — so report source-stratified metrics, never pooled ones.
- **Metadata alone reaches ~0.72 AUROC**, essentially the same as code length
  alone. Any model must be reported against that baseline.

## Data not in this repository

Raw corpora and large build artifacts are excluded: several exceed GitHub's 100 MB
per-file limit, and all are reproducible from the pipeline scripts.

| Not tracked | Size | Where to get it |
|---|---|---|
| `ReposVul_c_cpp.tar` | 2.9 GB | ReposVul release |
| `diversevul_20230702.json` | 703 MB | DiverseVul release |
| `CVE_CWE_2025_Z_liu.csv` | 98 MB | Liu et al. CVE/CWE export |
| `CVE_Kaggle/` | 46 MB | Kaggle CVE mirror |
| `corpus_final*.parquet` | 213 MB each | Regenerate: `c3_vulmap_v2/RUNGUIDE.md` |
| `cve_linddun.parquet` | 34 MB | Regenerate: `python3 cve_linddun/build_cve_linddun.py` |

Reference release: https://zenodo.org/records/19443251

## Attribution

`c3_vulmap_v2/` is vendored from [juxam/C3-VULMAP](https://github.com/juxam/C3-VULMAP)
(CC0 1.0), at upstream commit `eba27ba`. The XAI module, anchor tests, the
`03e` bridge script, and the override and category-addition tables are additions
made in this project.
