"""Classify a source path into a LINDDUN DFD element role and data tags.

Two independent gates decide whether a threat is reported for a component:

  1. APPLICABILITY — the canonical LINDDUN element table (applicability.csv).
     Which threats can target an entity / process / data store / data flow
     at all. Unawareness, for instance, only attaches to data subjects.

  2. RELEVANCE — relevance.csv. Whether the data the component handles makes
     that threat meaningful here. Without this gate every component lights up
     on six of seven classes and the output says nothing.

Both tables are CSV so a reviewer can argue with them. Classification is by
path name, so every finding is INFERRED, never confirmed: a directory called
`patient` very probably handles patient data, but the tool has not read a
line of code to check.
"""

import csv
import re
from collections import OrderedDict
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _rows(name):
    with open(HERE / name, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


class Lexicon:
    def __init__(self):
        self.excludes, self.roles, self.data = [], [], []
        for r in _rows("lexicon.csv"):
            pat = re.compile(r["pattern"], re.I)
            entry = (pat, r["value"], r["note"], r["pattern"])
            {"exclude": self.excludes, "role": self.roles,
             "data": self.data}[r["kind"]].append(entry)

    def excluded(self, path):
        for pat, _, note, src in self.excludes:
            if pat.search(path):
                return src, note
        return None, None

    def role_of(self, path):
        """First matching role wins — lexicon.csv is ordered most-specific
        first, so an Odoo client is a data flow before it is a 'client'."""
        for pat, val, note, src in self.roles:
            if pat.search(path):
                return val, note, src
        return None, None, None

    def data_of(self, path):
        tags = OrderedDict()
        for pat, val, note, src in self.data:
            if pat.search(path):
                tags.setdefault(val, (note, src))
        return tags


class Mapper:
    def __init__(self):
        self.lex = Lexicon()
        self.applicable = {}
        for r in _rows("applicability.csv"):
            self.applicable.setdefault(r["role"], {})[r["linddun"]] = r["basis"]
        self.relevance = {
            r["linddun"]: (set(r["requires_any"].split(";")), r["note"])
            for r in _rows("relevance.csv")
        }
        self.leaves = {}
        for r in _rows("threat_leaves.csv"):
            self.leaves.setdefault(r["linddun"], []).append(r)

    def classify(self, path):
        src, note = self.lex.excluded(path)
        if src:
            return {"path": path, "excluded": True,
                    "exclude_rule": src, "exclude_note": note}
        role, role_note, role_src = self.lex.role_of(path)
        tags = self.lex.data_of(path)
        # "external" is a derived tag: a data flow leaving the system is what
        # makes Detectability meaningful, independent of the data it carries.
        if role == "data_flow":
            tags.setdefault("external", ("crosses a system boundary", role_src))
        findings = []
        for cls, basis in self.applicable.get(role, {}).items():
            need, why = self.relevance[cls]
            hit = need & set(tags)
            if not hit:
                continue
            findings.append({
                "linddun": cls, "applicability": basis,
                "relevance": why, "because_of": sorted(hit),
                "leaves": self.leaves.get(cls, []),
            })
        findings.sort(key=lambda f: f["linddun"])
        return {"path": path, "excluded": False, "role": role,
                "role_note": role_note, "role_rule": role_src,
                "data_tags": dict(tags), "findings": findings}
