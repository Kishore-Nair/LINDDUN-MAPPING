"""Fix B — CWE-level refinement of category-inherited LINDDUN labels.

Hop 2 maps at MITRE CATEGORY level, so every member CWE inherits its
category's classes wholesale. Measured against the corpus, that collapses
35 distinct CWEs onto the single set "Data Disclosure;Linkability" —
112,688 rows, 52.8% of everything labelled — putting CWE-78 (OS command
injection) and CWE-125 (out-of-bounds read) on identical privacy semantics.

This module applies a small, human-reviewed override table on top of the
inherited label. Overrides are deliberately conservative: they REMOVE
classes the weakness does not support rather than add speculative ones,
because removing an unsupported class needs only the CWE definition while
adding one needs evidence the dataset does not carry.

Rows are also recorded when they were reviewed and left unchanged
(decision=keep), so the review is auditable as a whole rather than only
where it changed something.
"""

import csv
from dataclasses import dataclass

from . import paths


@dataclass
class Override:
    cwe_id: str
    decision: str          # "override" | "keep"
    linddun: tuple
    confidence: str
    rationale: str

    @property
    def changes_label(self):
        return self.decision == "override"


class OverrideTable:
    def __init__(self, path=None):
        self.path = path or paths.OVERRIDES
        self.by_cwe = {}
        if not self.path.exists():
            return
        with open(self.path, encoding="utf-8-sig", newline="") as f:
            for r in csv.DictReader(f):
                cwe = (r.get("cwe_id") or "").strip().upper()
                if not cwe:
                    continue
                raw = (r.get("linddun_categories") or "").strip()
                ld = tuple(sorted(
                    x.strip() for x in raw.split(";") if x.strip()))
                bad = [x for x in ld if x not in paths.CANONICAL_LINDDUN]
                if bad:
                    raise SystemExit(
                        f"{self.path}: {cwe} lists non-canonical LINDDUN "
                        f"class(es) {bad}. Allowed: "
                        f"{list(paths.CANONICAL_LINDDUN)}")
                self.by_cwe[cwe] = Override(
                    cwe_id=cwe,
                    decision=(r.get("decision") or "override").strip().lower(),
                    linddun=ld,
                    confidence=(r.get("confidence") or "").strip(),
                    rationale=(r.get("rationale") or "").strip(),
                )

    def get(self, cwe_id):
        if not cwe_id:
            return None
        return self.by_cwe.get(str(cwe_id).strip().upper())

    def apply(self, cwe_id, inherited):
        """Return (final_labels, override_or_None).

        An override never resurrects a label for a CWE the pipeline
        excluded or never categorised — those are upstream decisions, and
        silently reversing one here would hide it from 04's own reporting.
        """
        ov = self.get(cwe_id)
        if ov is None or not ov.changes_label or not inherited:
            return tuple(inherited), ov
        return ov.linddun, ov

    def __len__(self):
        return len(self.by_cwe)
