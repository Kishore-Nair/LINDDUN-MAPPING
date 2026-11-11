"""Locate the pipeline's tables without depending on cwd.

The numbered pipeline scripts all run from c3_vulmap_v2/ and rely on a bare
`import config`. This package can also be imported from elsewhere (a
notebook, the MPSS frontend), so it resolves paths from its own location
and only falls back to `config` if that is importable.
"""

import sys
from pathlib import Path

PKG_DIR = Path(__file__).resolve().parent
PROJECT_DIR = PKG_DIR.parent


def _output_dir():
    if str(PROJECT_DIR) not in sys.path:
        sys.path.insert(0, str(PROJECT_DIR))
    try:
        import config
        return Path(config.OUTPUT_DIR)
    except Exception:
        return PROJECT_DIR.parent / "c3_vulmap_v2_build"


OUTPUT_DIR = _output_dir()

CWE_CATEGORY_MAP = OUTPUT_DIR / "cwe_category_map.csv"
CATEGORY_LINDDUN = OUTPUT_DIR / "category_id_to_linddun.csv"
EXCLUDED_CWES = OUTPUT_DIR / "excluded_abstract_cwes.csv"
CORPUS = OUTPUT_DIR / "corpus_final.parquet"

OVERRIDES = PROJECT_DIR / "cwe_linddun_overrides.csv"
CATEGORY_ADDITIONS = PROJECT_DIR / "cwe_category_additions.csv"

CANONICAL_LINDDUN = (
    "Linkability", "Identifiability", "Non-repudiation", "Detectability",
    "Data Disclosure", "Unawareness", "Non-compliance",
)
