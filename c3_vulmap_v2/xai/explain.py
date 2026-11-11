"""Public API: explain why a row carries (or lacks) its LINDDUN classes."""

from dataclasses import dataclass, field

from . import chains, evidence
from .chains import (CATEGORY_UNMAPPED, EXCLUDED, MAPPED, NO_CATEGORY,
                     NO_CWE, ChainIndex)
from .overrides import OverrideTable

REASON_TEXT = {
    NO_CWE: "the row carries no CWE at all, so no chain can start",
    EXCLUDED: "the CWE is on the documented exclusion list and never "
              "contributes a category",
    NO_CATEGORY: "the CWE has no entry in the hop-1 category map",
    CATEGORY_UNMAPPED: "the CWE's categories exist but none carries a "
                       "LINDDUN class in hop 2",
}


@dataclass
class Explanation:
    cwe_id: str
    status: str
    chain: object = None
    inherited: tuple = ()
    final: tuple = ()
    override: object = None
    hits: list = field(default_factory=list)
    unsupported: list = field(default_factory=list)

    @property
    def primary(self):
        return self.final[0] if self.final else None

    @property
    def changed(self):
        return tuple(self.inherited) != tuple(self.final)

    @property
    def disagrees(self):
        """Metadata asserts a class the code shows no sign of."""
        return bool(self.final) and bool(self.unsupported)

    # -----------------------------------------------------------------
    def to_dict(self):
        return {
            "cwe_id": self.cwe_id,
            "status": self.status,
            "categories": [
                {"id": s.category_id, "name": s.category_name,
                 "linddun": list(s.linddun)}
                for s in (self.chain.categories if self.chain else [])
            ],
            "linddun_inherited": list(self.inherited),
            "linddun_final": list(self.final),
            "override": None if not self.override else {
                "decision": self.override.decision,
                "confidence": self.override.confidence,
                "rationale": self.override.rationale,
            },
            "primary": self.primary,
            "primary_rule": "alphabetical-first (not a ranking)",
            "evidence": [
                {"linddun": h.linddun, "rule": h.rule, "line": h.line_no,
                 "text": h.line, "why": h.why} for h in self.hits
            ],
            "classes_without_code_evidence": list(self.unsupported),
        }

    def to_text(self, width=74):
        L, bar = [], "-" * width
        L.append(bar)
        L.append(f"CWE: {self.cwe_id or '(none)'}")
        L.append(bar)

        if self.status != MAPPED:
            L.append(f"NO LINDDUN CLASS — {REASON_TEXT.get(self.status, '?')}")
            if self.status == EXCLUDED and self.override is None:
                L.append(f"  exclusion note: {self.chain.excluded_reason}")
            if self.status == CATEGORY_UNMAPPED and self.chain:
                for s in self.chain.categories:
                    L.append(f"  {s.category_id} {s.category_name}"
                             f" -> no LINDDUN entry")
            return "\n".join(L)

        L.append("DERIVATION (hop 1: CWE -> category, hop 2: category -> LINDDUN)")
        if self.chain.category_added:
            L.append("  ** hop-1 category supplied by "
                     "cwe_category_additions.csv, not the generated map")
        for s in self.chain.categories:
            got = ", ".join(s.linddun) if s.linddun else "(no LINDDUN entry)"
            L.append(f"  {self.cwe_id} -> {s.category_id} {s.category_name}")
            L.append(f"      -> {got}")
        L.append(f"  inherited union: {', '.join(self.inherited)}")

        if self.override is not None:
            L.append("")
            if self.override.changes_label:
                L.append(f"CWE-LEVEL OVERRIDE (confidence: "
                         f"{self.override.confidence})")
                L.append(f"  {', '.join(self.inherited)}")
                L.append(f"    -> {', '.join(self.final)}")
            else:
                L.append("REVIEWED, LEFT UNCHANGED")
            L.append(f"  {self.override.rationale}")

        L.append("")
        L.append(f"FINAL: {', '.join(self.final)}")
        L.append(f"  primary = {self.primary} "
                 f"(alphabetical first of the set, NOT a ranking)")

        L.append("")
        if self.hits:
            L.append("CODE EVIDENCE (advisory — the label came from the CWE, "
                     "not from this)")
            for h in self.hits[:12]:
                L.append(f"  [{h.linddun}] line {h.line_no}: {h.rule}")
                L.append(f"      {h.line}")
        else:
            L.append("CODE EVIDENCE: none matched")
        if self.unsupported:
            L.append(f"  ** no code evidence for: "
                     f"{', '.join(self.unsupported)} — candidate mislabel")
        return "\n".join(L)


class Explainer:
    def __init__(self):
        self.index = ChainIndex()
        self.table = OverrideTable()

    def explain(self, cwe_id, code=None):
        ch = self.index.chain(cwe_id)
        inherited = ch.linddun
        final, ov = self.table.apply(cwe_id, inherited)
        hits, missing = [], []
        if code and final:
            hits = evidence.scan(code, final)
            _, missing = evidence.supported(code, final)
        return Explanation(
            cwe_id=ch.cwe_id, status=ch.status, chain=ch,
            inherited=inherited, final=tuple(final), override=ov,
            hits=hits, unsupported=missing)

    def explain_row(self, row):
        return self.explain(row.get("cwe_id"), row.get("code"))
