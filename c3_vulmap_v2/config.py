"""
config.py — every path and constant for the C3-VULMAP v2 rebuild.

Fill in the paths in Section 1, then run the scripts in numeric order — see
RUNGUIDE.md for the full sequence and what to check at each step.

Adapted for macOS setup with local data files.
"""

from pathlib import Path

# =====================================================================
# 1. PATHS — CONFIGURED FOR THIS MACHINE
# =====================================================================

# Base project directory
PROJECT_DIR = Path("/Users/kishore/Desktop/FINAL YEAR PROJ")

# DiverseVul — JSONL format, 330,492 records
# Schema: func, target, project, commit_id, cwe, hash, size, message
DIVERSEVUL_PATH = PROJECT_DIR / "diversevul_20230702.json"

# ReposVul — C/C++ split, extracted from tar
# Format: 3 JSONL files (train/test/valid), each record is a flat object
# with function-level data (function, target, cve_id, commit_id, etc.)
# NOT the nested details[] format the original loader expected.
REPOSVUL_DIR = Path("/tmp/random")  # Extracted from ReposVul_c_cpp.tar
REPOSVUL_PATH = REPOSVUL_DIR  # The loader will read all 3 JSONL files

# CWE → MITRE Category → LINDDUN mapping chain
# Hop 1: CWE_CATEGORY_RAW_PATH → parsed by 03c_parse_cwe_categories.py
# Hop 2: CWE_CATEGORY_TO_LINDDUN_TABLE → category → LINDDUN
CWE_CATEGORY_RAW_PATH = Path(__file__).parent / "cwe_linddun_mapping main.csv"
CWE_CATEGORY_TO_LINDDUN_TABLE = Path(__file__).parent / "actual mapping to linddun.csv"

# Synthetic examples directory
SYNTHETIC_DIR = PROJECT_DIR / "c3_vulmap_v2" / "synthetic_v2"

# Build output directory
OUTPUT_DIR = PROJECT_DIR / "c3_vulmap_v2_build"
FEATURES_CACHE = OUTPUT_DIR / "features_512d.npy"

# =====================================================================
# 2. DEDUPLICATION AND SPLITS
# =====================================================================

MIN_CODE_CHARS = 40
TEST_FRAC = 0.20
VAL_FRAC = 0.10
SEED = 42

NEAR_DUP_THRESHOLD = 0.70

# =====================================================================
# 3. CONTAMINATION SCREEN
# =====================================================================

import re  # noqa: E402

CONTAMINATION_PATTERNS = {
    "juliet_stonesoup": re.compile(
        r"badSink|goodSink|goodG2B|goodB2G|CWE\d{2,4}_[A-Za-z]|stonesoup", re.I),
    "toy_secret_leaky": re.compile(
        r"(?:my|super|stored|saved|admin)_?secret|secret_?(?:password|passwd)|"
        r"supersecret", re.I),
    "toy_user_leaky": re.compile(
        r"john_?doe|input_?username|input_?password|authenticate_?user\b|"
        r"my_?password", re.I),
    "self_naming_leaky": re.compile(
        r"vulnerable_?(?:function|code|buffer)|insecure_?func|bad_?buffer|"
        r"process_?sensitive", re.I),
}


# -----------------------------------------------------------------------
# Path coercion guard
for _name in ("PROJECT_DIR", "DIVERSEVUL_PATH", "REPOSVUL_DIR", "REPOSVUL_PATH",
             "CWE_CATEGORY_RAW_PATH", "CWE_CATEGORY_TO_LINDDUN_TABLE",
             "SYNTHETIC_DIR", "OUTPUT_DIR",
             "FEATURES_CACHE"):
    _val = globals().get(_name)
    if _val is not None and not isinstance(_val, Path):
        globals()[_name] = Path(_val)
del _name, _val


def ensure_output_dir():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    return OUTPUT_DIR
