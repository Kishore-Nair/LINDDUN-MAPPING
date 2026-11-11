#!/usr/bin/env python3
"""
CVE Dataset Enrichment Pipeline
================================
Merges existing CVE datasets and enriches them with data from:
  - NVD API 2.0  → CVSS v3 scores, vectors, sub-metrics, CPE, references
  - FIRST EPSS   → Exploit prediction scores
  - CISA KEV     → Known Exploited Vulnerabilities flag

Features:
  - Checkpointing: saves progress every batch so you can resume on interruption
  - Rate limiting: respects NVD API limits (configurable with/without API key)
  - Progress bar:  real-time progress tracking

Usage:
  python3 enrich_dataset.py                     # Run full pipeline
  python3 enrich_dataset.py --nvd-api-key YOUR_KEY  # With NVD API key (faster)
  python3 enrich_dataset.py --skip-nvd          # Skip NVD (if already done)
  python3 enrich_dataset.py --skip-epss         # Skip EPSS
  python3 enrich_dataset.py --skip-kev          # Skip KEV
"""

import os
import sys
import csv
import json
import time
import argparse
import urllib.request
import urllib.error
import urllib.parse
import gzip
import io
from datetime import datetime, timezone
from pathlib import Path

# ─── Configuration ───────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).parent
KAGGLE_DIR = BASE_DIR / "CVE_Kaggle"
OUTPUT_DIR = BASE_DIR / "enriched_data"
CHECKPOINT_DIR = OUTPUT_DIR / "checkpoints"

# Input files
KAGGLE_CVE = KAGGLE_DIR / "cve.csv"
KAGGLE_PRODUCTS = KAGGLE_DIR / "products.csv"
KAGGLE_VENDORS = KAGGLE_DIR / "vendors.csv"
ZLIU_CVE = BASE_DIR / "CVE_CWE_2025_Z_liu.csv"

# Output files
MERGED_CSV = OUTPUT_DIR / "01_merged_base.csv"
NVD_CHECKPOINT = CHECKPOINT_DIR / "nvd_progress.json"
NVD_DATA_DIR = CHECKPOINT_DIR / "nvd_batches"
EPSS_CSV = OUTPUT_DIR / "epss_scores.csv"
KEV_JSON = OUTPUT_DIR / "kev_catalog.json"
FINAL_CSV = OUTPUT_DIR / "custom_cve_dataset.csv"

# NVD API settings
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_BATCH_SIZE = 2000  # Max results per request
NVD_RATE_LIMIT_NO_KEY = 6.5  # seconds between requests (5 req/30s)
NVD_RATE_LIMIT_WITH_KEY = 0.65  # seconds between requests (50 req/30s)

# EPSS API
EPSS_CSV_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

# CISA KEV
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# ─── Helpers ─────────────────────────────────────────────────────────────────

def ensure_dirs():
    """Create output directories if they don't exist."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
    NVD_DATA_DIR.mkdir(parents=True, exist_ok=True)


def progress_bar(current, total, prefix="", length=40):
    """Print a simple progress bar to stdout."""
    pct = current / total if total > 0 else 1
    filled = int(length * pct)
    bar = "█" * filled + "░" * (length - filled)
    sys.stdout.write(f"\r  {prefix} |{bar}| {current}/{total} ({pct:.1%})")
    sys.stdout.flush()
    if current >= total:
        print()


def fetch_url(url, headers=None, retries=3, timeout=30):
    """Fetch a URL with retry logic."""
    req = urllib.request.Request(url)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
                # Handle gzip
                if resp.headers.get("Content-Encoding") == "gzip":
                    data = gzip.decompress(data)
                return data
        except urllib.error.HTTPError as e:
            if e.code == 403 and attempt < retries - 1:
                wait = (attempt + 1) * 30
                print(f"\n    ⚠ Rate limited (403). Waiting {wait}s...")
                time.sleep(wait)
            elif e.code == 503 and attempt < retries - 1:
                wait = (attempt + 1) * 15
                print(f"\n    ⚠ Service unavailable (503). Waiting {wait}s...")
                time.sleep(wait)
            else:
                raise
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt < retries - 1:
                wait = (attempt + 1) * 10
                print(f"\n    ⚠ Connection error: {e}. Retrying in {wait}s...")
                time.sleep(wait)
            else:
                raise

    return None


# ─── Step 1: Merge Base Datasets ────────────────────────────────────────────

def step1_merge_datasets():
    """Merge Kaggle and Z_liu datasets into a single base CSV."""
    print("\n" + "═" * 60)
    print("  STEP 1: Merging Base Datasets")
    print("═" * 60)

    if MERGED_CSV.exists():
        print(f"  ✓ Merged file already exists: {MERGED_CSV}")
        # Count rows
        with open(MERGED_CSV, "r") as f:
            row_count = sum(1 for _ in f) - 1
        print(f"    {row_count:,} records")
        return

    # ── Load Kaggle CVE data ──
    print("  Loading Kaggle cve.csv...")
    kaggle_data = {}
    with open(KAGGLE_CVE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve_id = row.get("", "").strip()
            if not cve_id.startswith("CVE-"):
                continue
            kaggle_data[cve_id] = {
                "cvss_v2_score": row.get("cvss", "").strip(),
                "cwe_code_kaggle": row.get("cwe_code", "").strip(),
                "cwe_name": row.get("cwe_name", "").strip(),
                "summary_kaggle": row.get("summary", "").strip(),
                "pub_date_kaggle": row.get("pub_date", "").strip(),
                "mod_date_kaggle": row.get("mod_date", "").strip(),
                "access_authentication": row.get("access_authentication", "").strip(),
                "access_complexity": row.get("access_complexity", "").strip(),
                "access_vector": row.get("access_vector", "").strip(),
                "impact_availability_v2": row.get("impact_availability", "").strip(),
                "impact_confidentiality_v2": row.get("impact_confidentiality", "").strip(),
                "impact_integrity_v2": row.get("impact_integrity", "").strip(),
            }
    print(f"    Loaded {len(kaggle_data):,} records from Kaggle")

    # ── Load vendor/product mappings ──
    print("  Loading vendor & product mappings...")
    vendor_map = {}
    if KAGGLE_VENDORS.exists():
        with open(KAGGLE_VENDORS, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cve_id = row.get("", "").strip()
                if cve_id:
                    vendor_map[cve_id] = row.get("vendor", "").strip()

    product_map = {}
    if KAGGLE_PRODUCTS.exists():
        with open(KAGGLE_PRODUCTS, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cve_id = row.get("cve_id", row.get("", "")).strip()
                if cve_id:
                    product_map[cve_id] = row.get("vulnerable_product", "").strip()

    print(f"    Vendors: {len(vendor_map):,} | Products: {len(product_map):,}")

    # ── Load Z_liu dataset ──
    print("  Loading CVE_CWE_2025_Z_liu.csv (this may take a moment)...")
    zliu_data = {}
    if ZLIU_CVE.exists():
        with open(ZLIU_CVE, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cve_id = row.get("CVE-ID", "").strip()
                if not cve_id.startswith("CVE-"):
                    continue
                zliu_data[cve_id] = {
                    "cvss_v2_zliu": row.get("CVSS-V2", "").strip(),
                    "cvss_v3_zliu": row.get("CVSS-V3", "").strip(),
                    "cvss_v4_zliu": row.get("CVSS-V4", "").strip(),
                    "severity_zliu": row.get("SEVERITY", "").strip(),
                    "description_zliu": row.get("DESCRIPTION", "").strip(),
                    "cwe_id_zliu": row.get("CWE-ID", "").strip(),
                }
        print(f"    Loaded {len(zliu_data):,} records from Z_liu")
    else:
        print("    ⚠ Z_liu file not found, skipping")

    # ── Merge ──
    print("  Merging datasets...")
    all_cve_ids = sorted(set(list(kaggle_data.keys()) + list(zliu_data.keys())))
    print(f"    Total unique CVEs: {len(all_cve_ids):,}")

    # Define output columns
    columns = [
        "cve_id", "published_date", "modified_date", "description",
        "vendor", "product",
        "cwe_id", "cwe_name",
        "cvss_v2_score",
        "cvss_v3_score", "cvss_v3_vector",
        "attack_vector", "attack_complexity", "privileges_required",
        "user_interaction", "scope",
        "confidentiality_impact", "integrity_impact", "availability_impact",
        "severity",
        "access_authentication_v2", "access_complexity_v2", "access_vector_v2",
        "impact_availability_v2", "impact_confidentiality_v2", "impact_integrity_v2",
        "epss_score", "epss_percentile",
        "is_kev", "kev_date_added",
        "exploit_available", "patch_available", "reference_count",
    ]

    with open(MERGED_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()

        for i, cve_id in enumerate(all_cve_ids):
            k = kaggle_data.get(cve_id, {})
            z = zliu_data.get(cve_id, {})

            # Prefer Z_liu description (more complete), fallback to Kaggle
            description = z.get("description_zliu", "") or k.get("summary_kaggle", "")

            # CWE: prefer Kaggle (has name), fallback to Z_liu
            cwe_id = k.get("cwe_code_kaggle", "") or z.get("cwe_id_zliu", "")
            cwe_name = k.get("cwe_name", "")
            # Normalize cwe_id format
            if cwe_id and not cwe_id.startswith("CWE-") and cwe_id.isdigit():
                cwe_id = f"CWE-{cwe_id}"

            # CVSS v2
            cvss_v2 = k.get("cvss_v2_score", "")
            if not cvss_v2 or cvss_v2 == "None":
                v2_z = z.get("cvss_v2_zliu", "")
                cvss_v2 = v2_z if v2_z and v2_z != "None" else ""

            # CVSS v3 (from Z_liu, often sparse — NVD will fill later)
            cvss_v3 = z.get("cvss_v3_zliu", "")
            if cvss_v3 == "None":
                cvss_v3 = ""

            # Severity
            severity = z.get("severity_zliu", "")

            row = {
                "cve_id": cve_id,
                "published_date": k.get("pub_date_kaggle", ""),
                "modified_date": k.get("mod_date_kaggle", ""),
                "description": description,
                "vendor": vendor_map.get(cve_id, ""),
                "product": product_map.get(cve_id, ""),
                "cwe_id": cwe_id,
                "cwe_name": cwe_name,
                "cvss_v2_score": cvss_v2,
                "cvss_v3_score": cvss_v3,
                "cvss_v3_vector": "",
                "attack_vector": "",
                "attack_complexity": "",
                "privileges_required": "",
                "user_interaction": "",
                "scope": "",
                "confidentiality_impact": "",
                "integrity_impact": "",
                "availability_impact": "",
                "severity": severity,
                "access_authentication_v2": k.get("access_authentication", ""),
                "access_complexity_v2": k.get("access_complexity", ""),
                "access_vector_v2": k.get("access_vector", ""),
                "impact_availability_v2": k.get("impact_availability_v2", ""),
                "impact_confidentiality_v2": k.get("impact_confidentiality_v2", ""),
                "impact_integrity_v2": k.get("impact_integrity_v2", ""),
                "epss_score": "",
                "epss_percentile": "",
                "is_kev": "",
                "kev_date_added": "",
                "exploit_available": "",
                "patch_available": "",
                "reference_count": "",
            }
            writer.writerow(row)

            if (i + 1) % 50000 == 0:
                progress_bar(i + 1, len(all_cve_ids), "Merging")

    print(f"\n  ✓ Merged dataset saved: {MERGED_CSV}")
    print(f"    {len(all_cve_ids):,} total records")


# ─── Step 2: Enrich with NVD API ────────────────────────────────────────────

def step2_enrich_nvd(api_key=None):
    """
    Pull CVSS v3 scores, vectors, sub-metrics, references, and CPE data
    from the NVD API 2.0. Uses pagination and checkpointing.
    """
    print("\n" + "═" * 60)
    print("  STEP 2: Enriching with NVD API 2.0")
    print("═" * 60)

    rate_limit = NVD_RATE_LIMIT_WITH_KEY if api_key else NVD_RATE_LIMIT_NO_KEY
    print(f"  API Key: {'Yes ✓' if api_key else 'No (slower rate limit)'}")
    print(f"  Rate limit: {rate_limit}s between requests")

    # Load checkpoint
    checkpoint = {"start_index": 0, "total_results": None, "batches_done": 0}
    if NVD_CHECKPOINT.exists():
        with open(NVD_CHECKPOINT, "r") as f:
            checkpoint = json.load(f)
        print(f"  Resuming from checkpoint: index {checkpoint['start_index']:,}")

    # First request to get total count
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    if checkpoint["total_results"] is None:
        print("  Fetching total CVE count from NVD...")
        params = urllib.parse.urlencode({
            "startIndex": 0,
            "resultsPerPage": 1,
        })
        url = f"{NVD_API_BASE}?{params}"
        data = fetch_url(url, headers=headers, timeout=60)
        if data:
            result = json.loads(data)
            checkpoint["total_results"] = result.get("totalResults", 0)
            print(f"    Total CVEs in NVD: {checkpoint['total_results']:,}")
        else:
            print("    ✗ Failed to connect to NVD API")
            return
        time.sleep(rate_limit)

    total = checkpoint["total_results"]
    start_index = checkpoint["start_index"]
    batches_done = checkpoint["batches_done"]
    total_batches = (total + NVD_BATCH_SIZE - 1) // NVD_BATCH_SIZE

    print(f"  Total batches: {total_batches:,} | Already done: {batches_done}")
    estimated_time = (total_batches - batches_done) * rate_limit / 60
    print(f"  Estimated remaining time: ~{estimated_time:.0f} minutes")
    print()

    while start_index < total:
        batch_file = NVD_DATA_DIR / f"batch_{start_index}.json"

        if batch_file.exists():
            # Batch already downloaded, skip
            start_index += NVD_BATCH_SIZE
            batches_done += 1
            continue

        params = urllib.parse.urlencode({
            "startIndex": start_index,
            "resultsPerPage": NVD_BATCH_SIZE,
        })
        url = f"{NVD_API_BASE}?{params}"

        try:
            data = fetch_url(url, headers=headers, timeout=120)
            if data is None:
                print(f"\n    ✗ Failed at index {start_index}. Saving checkpoint...")
                break

            result = json.loads(data)
            vulnerabilities = result.get("vulnerabilities", [])

            # Extract relevant fields
            batch_records = []
            for vuln in vulnerabilities:
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")

                # Metrics
                metrics = cve.get("metrics", {})
                cvss_v3_data = {}
                cvss_v2_data = {}

                # Try CVSS v3.1 first, then v3.0
                for v3_key in ["cvssMetricV31", "cvssMetricV30"]:
                    v3_list = metrics.get(v3_key, [])
                    if v3_list:
                        v3 = v3_list[0].get("cvssData", {})
                        cvss_v3_data = {
                            "cvss_v3_score": v3.get("baseScore", ""),
                            "cvss_v3_vector": v3.get("vectorString", ""),
                            "attack_vector": v3.get("attackVector", ""),
                            "attack_complexity": v3.get("attackComplexity", ""),
                            "privileges_required": v3.get("privilegesRequired", ""),
                            "user_interaction": v3.get("userInteraction", ""),
                            "scope": v3.get("scope", ""),
                            "confidentiality_impact": v3.get("confidentialityImpact", ""),
                            "integrity_impact": v3.get("integrityImpact", ""),
                            "availability_impact": v3.get("availabilityImpact", ""),
                            "severity": v3.get("baseSeverity", ""),
                        }
                        break

                # CVSS v2
                v2_list = metrics.get("cvssMetricV2", [])
                if v2_list:
                    v2 = v2_list[0].get("cvssData", {})
                    cvss_v2_data = {
                        "cvss_v2_score": v2.get("baseScore", ""),
                    }

                # Dates
                published = cve.get("published", "")
                modified = cve.get("lastModified", "")

                # Description
                desc_list = cve.get("descriptions", [])
                description = ""
                for d in desc_list:
                    if d.get("lang") == "en":
                        description = d.get("value", "")
                        break

                # CWE
                cwe_id = ""
                weaknesses = cve.get("weaknesses", [])
                for w in weaknesses:
                    for wd in w.get("description", []):
                        val = wd.get("value", "")
                        if val.startswith("CWE-"):
                            cwe_id = val
                            break
                    if cwe_id:
                        break

                # References
                refs = cve.get("references", [])
                ref_count = len(refs)
                has_exploit = any(
                    "Exploit" in (t or "")
                    for r in refs
                    for t in r.get("tags", [])
                )
                has_patch = any(
                    "Patch" in (t or "")
                    for r in refs
                    for t in r.get("tags", [])
                )

                # CPE (first match)
                cpe_uri = ""
                configs = cve.get("configurations", [])
                for config in configs:
                    for node in config.get("nodes", []):
                        for match in node.get("cpeMatch", []):
                            if match.get("vulnerable"):
                                cpe_uri = match.get("criteria", "")
                                break
                        if cpe_uri:
                            break
                    if cpe_uri:
                        break

                record = {
                    "cve_id": cve_id,
                    "published_date": published,
                    "modified_date": modified,
                    "description": description,
                    "cwe_id": cwe_id,
                    "cpe_uri": cpe_uri,
                    "ref_count": ref_count,
                    "has_exploit": has_exploit,
                    "has_patch": has_patch,
                    **cvss_v3_data,
                    **cvss_v2_data,
                }
                batch_records.append(record)

            # Save batch
            with open(batch_file, "w") as f:
                json.dump(batch_records, f)

            batches_done += 1
            start_index += NVD_BATCH_SIZE

            # Save checkpoint
            checkpoint["start_index"] = start_index
            checkpoint["batches_done"] = batches_done
            with open(NVD_CHECKPOINT, "w") as f:
                json.dump(checkpoint, f)

            progress_bar(batches_done, total_batches, "NVD API")
            time.sleep(rate_limit)

        except Exception as e:
            print(f"\n    ✗ Error at index {start_index}: {e}")
            # Save checkpoint so we can resume
            checkpoint["start_index"] = start_index
            checkpoint["batches_done"] = batches_done
            with open(NVD_CHECKPOINT, "w") as f:
                json.dump(checkpoint, f)
            print("    Checkpoint saved. Re-run the script to resume.")
            break

    print(f"\n  ✓ NVD enrichment complete. {batches_done} batches downloaded.")


# ─── Step 3: Download EPSS Scores ───────────────────────────────────────────

def step3_download_epss():
    """Download bulk EPSS scores from FIRST.org."""
    print("\n" + "═" * 60)
    print("  STEP 3: Downloading EPSS Scores")
    print("═" * 60)

    if EPSS_CSV.exists():
        with open(EPSS_CSV, "r") as f:
            row_count = sum(1 for _ in f) - 1
        print(f"  ✓ EPSS file already exists: {EPSS_CSV}")
        print(f"    {row_count:,} scores")
        return

    print(f"  Downloading from {EPSS_CSV_URL}...")
    try:
        data = fetch_url(EPSS_CSV_URL, timeout=120)
        if data is None:
            print("    ✗ Failed to download EPSS data")
            return

        # Decompress if gzipped
        try:
            decompressed = gzip.decompress(data)
        except gzip.BadGzipFile:
            decompressed = data

        text = decompressed.decode("utf-8")

        # EPSS CSV has a comment line at the top, skip it
        lines = text.strip().split("\n")
        start_idx = 0
        for i, line in enumerate(lines):
            if line.startswith("cve,") or line.startswith("cve_id,"):
                start_idx = i
                break
            elif "," in line and not line.startswith("#"):
                start_idx = i
                break

        clean_lines = lines[start_idx:]
        with open(EPSS_CSV, "w") as f:
            f.write("\n".join(clean_lines) + "\n")

        print(f"  ✓ EPSS scores saved: {EPSS_CSV}")
        print(f"    {len(clean_lines) - 1:,} scores")

    except Exception as e:
        print(f"    ✗ Error downloading EPSS: {e}")


# ─── Step 4: Download CISA KEV Catalog ──────────────────────────────────────

def step4_download_kev():
    """Download the CISA Known Exploited Vulnerabilities catalog."""
    print("\n" + "═" * 60)
    print("  STEP 4: Downloading CISA KEV Catalog")
    print("═" * 60)

    if KEV_JSON.exists():
        with open(KEV_JSON, "r") as f:
            kev = json.load(f)
        count = len(kev.get("vulnerabilities", []))
        print(f"  ✓ KEV file already exists: {KEV_JSON}")
        print(f"    {count:,} known exploited vulnerabilities")
        return

    print(f"  Downloading from CISA...")
    try:
        data = fetch_url(KEV_URL, timeout=60)
        if data is None:
            print("    ✗ Failed to download KEV catalog")
            return

        kev = json.loads(data)
        with open(KEV_JSON, "w") as f:
            json.dump(kev, f, indent=2)

        count = len(kev.get("vulnerabilities", []))
        print(f"  ✓ KEV catalog saved: {KEV_JSON}")
        print(f"    {count:,} known exploited vulnerabilities")

    except Exception as e:
        print(f"    ✗ Error downloading KEV: {e}")


# ─── Step 5: Assemble Final Dataset ─────────────────────────────────────────

def step5_assemble_final():
    """
    Merge all enrichment data into the final custom dataset CSV.
    """
    print("\n" + "═" * 60)
    print("  STEP 5: Assembling Final Custom Dataset")
    print("═" * 60)

    # ── Load NVD batch data into a lookup ──
    print("  Loading NVD enrichment data...")
    nvd_lookup = {}
    batch_files = sorted(NVD_DATA_DIR.glob("batch_*.json"))
    for bf in batch_files:
        with open(bf, "r") as f:
            records = json.load(f)
        for rec in records:
            cve_id = rec.get("cve_id", "")
            if cve_id:
                nvd_lookup[cve_id] = rec
    print(f"    Loaded {len(nvd_lookup):,} NVD records from {len(batch_files)} batches")

    # ── Load EPSS scores ──
    print("  Loading EPSS scores...")
    epss_lookup = {}
    if EPSS_CSV.exists():
        with open(EPSS_CSV, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cve_id = row.get("cve", row.get("cve_id", "")).strip()
                if cve_id:
                    epss_lookup[cve_id] = {
                        "epss_score": row.get("epss", row.get("epss_score", "")).strip(),
                        "epss_percentile": row.get("percentile", row.get("epss_percentile", "")).strip(),
                    }
    print(f"    Loaded {len(epss_lookup):,} EPSS scores")

    # ── Load KEV catalog ──
    print("  Loading KEV catalog...")
    kev_lookup = {}
    if KEV_JSON.exists():
        with open(KEV_JSON, "r") as f:
            kev = json.load(f)
        for vuln in kev.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "")
            if cve_id:
                kev_lookup[cve_id] = {
                    "date_added": vuln.get("dateAdded", ""),
                }
    print(f"    Loaded {len(kev_lookup):,} KEV entries")

    # ── Read merged base and enrich ──
    print("  Building final dataset...")

    if not MERGED_CSV.exists():
        print("    ✗ Merged base file not found. Run Step 1 first.")
        return

    columns = [
        "cve_id", "published_date", "modified_date", "description",
        "vendor", "product", "cpe_uri",
        "cwe_id", "cwe_name",
        "cvss_v2_score",
        "cvss_v3_score", "cvss_v3_vector",
        "attack_vector", "attack_complexity", "privileges_required",
        "user_interaction", "scope",
        "confidentiality_impact", "integrity_impact", "availability_impact",
        "severity",
        "access_authentication_v2", "access_complexity_v2", "access_vector_v2",
        "impact_availability_v2", "impact_confidentiality_v2", "impact_integrity_v2",
        "epss_score", "epss_percentile",
        "is_kev", "kev_date_added",
        "exploit_available", "patch_available", "reference_count",
    ]

    row_count = 0
    enriched_v3 = 0
    enriched_epss = 0
    enriched_kev = 0

    with open(MERGED_CSV, "r", encoding="utf-8") as fin, \
         open(FINAL_CSV, "w", newline="", encoding="utf-8") as fout:

        reader = csv.DictReader(fin)
        writer = csv.DictWriter(fout, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()

        for row in reader:
            cve_id = row.get("cve_id", "").strip()
            nvd = nvd_lookup.get(cve_id, {})
            epss = epss_lookup.get(cve_id, {})
            kev = kev_lookup.get(cve_id, None)

            # Enrich with NVD data (NVD takes priority for most fields)
            if nvd:
                # Dates — prefer NVD (more standardized format)
                if nvd.get("published_date"):
                    row["published_date"] = nvd["published_date"]
                if nvd.get("modified_date"):
                    row["modified_date"] = nvd["modified_date"]

                # Description — prefer NVD
                if nvd.get("description"):
                    row["description"] = nvd["description"]

                # CWE — prefer NVD if existing is empty
                if nvd.get("cwe_id") and not row.get("cwe_id"):
                    row["cwe_id"] = nvd["cwe_id"]

                # CVSS v2 — fill if missing
                if nvd.get("cvss_v2_score") and not row.get("cvss_v2_score"):
                    row["cvss_v2_score"] = nvd["cvss_v2_score"]

                # CVSS v3 — always prefer NVD
                if nvd.get("cvss_v3_score"):
                    row["cvss_v3_score"] = nvd["cvss_v3_score"]
                    row["cvss_v3_vector"] = nvd.get("cvss_v3_vector", "")
                    row["attack_vector"] = nvd.get("attack_vector", "")
                    row["attack_complexity"] = nvd.get("attack_complexity", "")
                    row["privileges_required"] = nvd.get("privileges_required", "")
                    row["user_interaction"] = nvd.get("user_interaction", "")
                    row["scope"] = nvd.get("scope", "")
                    row["confidentiality_impact"] = nvd.get("confidentiality_impact", "")
                    row["integrity_impact"] = nvd.get("integrity_impact", "")
                    row["availability_impact"] = nvd.get("availability_impact", "")
                    enriched_v3 += 1

                # Severity — prefer NVD
                if nvd.get("severity"):
                    row["severity"] = nvd["severity"]

                # CPE
                row["cpe_uri"] = nvd.get("cpe_uri", "")

                # References
                row["reference_count"] = nvd.get("ref_count", "")
                row["exploit_available"] = "TRUE" if nvd.get("has_exploit") else "FALSE"
                row["patch_available"] = "TRUE" if nvd.get("has_patch") else "FALSE"

            # Derive severity from CVSS v3 score if still missing
            if not row.get("severity") and row.get("cvss_v3_score"):
                try:
                    score = float(row["cvss_v3_score"])
                    if score == 0.0:
                        row["severity"] = "NONE"
                    elif score <= 3.9:
                        row["severity"] = "LOW"
                    elif score <= 6.9:
                        row["severity"] = "MEDIUM"
                    elif score <= 8.9:
                        row["severity"] = "HIGH"
                    else:
                        row["severity"] = "CRITICAL"
                except ValueError:
                    pass

            # Enrich with EPSS
            if epss:
                row["epss_score"] = epss.get("epss_score", "")
                row["epss_percentile"] = epss.get("epss_percentile", "")
                enriched_epss += 1

            # Enrich with KEV
            if kev is not None:
                row["is_kev"] = "TRUE"
                row["kev_date_added"] = kev.get("date_added", "")
                enriched_kev += 1
            else:
                row["is_kev"] = "FALSE"
                row["kev_date_added"] = ""

            writer.writerow(row)
            row_count += 1

            if row_count % 50000 == 0:
                progress_bar(row_count, 280000, "Assembling")

    print(f"\n  ✓ Final dataset saved: {FINAL_CSV}")
    print(f"    Total records:     {row_count:,}")
    print(f"    Enriched w/ CVSS v3: {enriched_v3:,}")
    print(f"    Enriched w/ EPSS:    {enriched_epss:,}")
    print(f"    Flagged as KEV:      {enriched_kev:,}")


# ─── Step 6: Print Summary Statistics ───────────────────────────────────────

def step6_summary():
    """Print summary statistics of the final dataset."""
    print("\n" + "═" * 60)
    print("  STEP 6: Final Dataset Summary")
    print("═" * 60)

    if not FINAL_CSV.exists():
        print("  ✗ Final dataset not found")
        return

    total = 0
    has_v3 = 0
    has_epss = 0
    has_kev = 0
    has_exploit = 0
    has_patch = 0
    severity_counts = {}
    cwe_counts = {}

    with open(FINAL_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total += 1
            if row.get("cvss_v3_score", "").strip():
                has_v3 += 1
            if row.get("epss_score", "").strip():
                has_epss += 1
            if row.get("is_kev", "").strip() == "TRUE":
                has_kev += 1
            if row.get("exploit_available", "").strip() == "TRUE":
                has_exploit += 1
            if row.get("patch_available", "").strip() == "TRUE":
                has_patch += 1

            sev = row.get("severity", "").strip() or "UNKNOWN"
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            cwe = row.get("cwe_id", "").strip()
            if cwe:
                cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1

    print(f"\n  Total Records:         {total:,}")
    print(f"  Has CVSS v3:           {has_v3:,} ({has_v3/total*100:.1f}%)")
    print(f"  Has EPSS:              {has_epss:,} ({has_epss/total*100:.1f}%)")
    print(f"  KEV flagged:           {has_kev:,}")
    print(f"  Exploit available:     {has_exploit:,}")
    print(f"  Patch available:       {has_patch:,}")

    print(f"\n  Severity Distribution:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]:
        cnt = severity_counts.get(sev, 0)
        if cnt > 0:
            bar = "█" * int(cnt / total * 50)
            print(f"    {sev:<10} {cnt:>8,}  {cnt/total*100:>5.1f}%  {bar}")

    print(f"\n  Top 10 CWE Categories:")
    top_cwe = sorted(cwe_counts.items(), key=lambda x: -x[1])[:10]
    for cwe, cnt in top_cwe:
        print(f"    {cwe:<20} {cnt:>6,}")

    print(f"\n  Output file: {FINAL_CSV}")
    file_size = FINAL_CSV.stat().st_size / (1024 * 1024)
    print(f"  File size: {file_size:.1f} MB")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CVE Dataset Enrichment Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 enrich_dataset.py                        # Full pipeline
  python3 enrich_dataset.py --nvd-api-key MY_KEY   # With API key (10x faster)
  python3 enrich_dataset.py --skip-nvd             # Skip slow NVD step
  python3 enrich_dataset.py --step 5               # Run only step 5 (assemble)
        """,
    )
    parser.add_argument("--nvd-api-key", type=str, default=None,
                        help="NVD API key for higher rate limits")
    parser.add_argument("--skip-nvd", action="store_true",
                        help="Skip NVD API enrichment (Step 2)")
    parser.add_argument("--skip-epss", action="store_true",
                        help="Skip EPSS download (Step 3)")
    parser.add_argument("--skip-kev", action="store_true",
                        help="Skip KEV download (Step 4)")
    parser.add_argument("--step", type=int, default=None,
                        help="Run only a specific step (1-6)")

    args = parser.parse_args()

    print("╔══════════════════════════════════════════════════════════╗")
    print("║       CVE Dataset Enrichment Pipeline                   ║")
    print("║       ──────────────────────────────                    ║")
    print("║  Step 1: Merge base datasets                            ║")
    print("║  Step 2: Enrich with NVD API (CVSS v3, refs, CPE)       ║")
    print("║  Step 3: Download EPSS scores                           ║")
    print("║  Step 4: Download CISA KEV catalog                      ║")
    print("║  Step 5: Assemble final custom dataset                  ║")
    print("║  Step 6: Print summary statistics                       ║")
    print("╚══════════════════════════════════════════════════════════╝")

    ensure_dirs()

    start_time = time.time()

    if args.step:
        # Run only the specified step
        step_map = {
            1: step1_merge_datasets,
            2: lambda: step2_enrich_nvd(args.nvd_api_key),
            3: step3_download_epss,
            4: step4_download_kev,
            5: step5_assemble_final,
            6: step6_summary,
        }
        if args.step in step_map:
            step_map[args.step]()
        else:
            print(f"  ✗ Invalid step: {args.step}. Choose 1-6.")
            sys.exit(1)
    else:
        # Run full pipeline
        step1_merge_datasets()

        if not args.skip_nvd:
            step2_enrich_nvd(args.nvd_api_key)
        else:
            print("\n  ⏭ Skipping NVD enrichment (--skip-nvd)")

        if not args.skip_epss:
            step3_download_epss()
        else:
            print("\n  ⏭ Skipping EPSS download (--skip-epss)")

        if not args.skip_kev:
            step4_download_kev()
        else:
            print("\n  ⏭ Skipping KEV download (--skip-kev)")

        step5_assemble_final()
        step6_summary()

    elapsed = time.time() - start_time
    print(f"\n  ⏱ Total time: {elapsed/60:.1f} minutes")
    print("  Done! 🎉\n")


if __name__ == "__main__":
    main()
