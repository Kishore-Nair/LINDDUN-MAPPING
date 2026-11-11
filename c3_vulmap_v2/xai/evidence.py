"""Layer 2 — advisory code evidence. NOT the reason a row carries a label.

Every LINDDUN label in this corpus was derived from cwe_id alone; the code
column played no part. So nothing in this module explains why a row is
labelled the way it is — chains.py does that, exactly.

What this does instead is ask a different and genuinely open question: does
the code show anything consistent with the class the metadata assigned? The
answer is useful in two ways. Agreement is weak corroboration. DISAGREEMENT
is the valuable signal: a row whose CWE asserts Data Disclosure while the
body contains no read, copy or output primitive is a candidate mislabel,
and aggregated per CWE it shows which of the 102 chains the code does not
support.

These are hand-written patterns over C/C++ source, not a model. They are
meant to be read and argued with, which is the point -- a reviewer can
check a rule, which they cannot do with an attribution heatmap. They are
regex-level and will produce false positives on comments and strings.

Hard rule: nothing here may be written back into a label. Deriving labels
from code and then justifying them with the same patterns is circular.
"""

import re
from dataclasses import dataclass

# (class, rule name, pattern, why this is evidence for that class)
RULES = [
    ("Data Disclosure", "unbounded_copy",
     r"\b(strcpy|strcat|sprintf|vsprintf|gets)\s*\(",
     "copies without a length bound; adjacent memory can be exposed"),
    ("Data Disclosure", "sized_copy",
     r"\b(memcpy|memmove|strncpy|strncat|snprintf|bcopy)\s*\(",
     "bulk copy; discloses if the length is attacker-influenced"),
    ("Data Disclosure", "raw_read",
     r"\b(read|pread|recv|recvfrom|fread|fgets)\s*\(",
     "reads into a buffer; over-read exposes neighbouring data"),
    ("Data Disclosure", "output_sink",
     r"\b(printf|fprintf|write|send|puts|syslog)\s*\(",
     "writes data outward; a sink through which contents can escape"),

    ("Detectability", "abort_path",
     r"\b(abort|assert|BUG_ON|WARN_ON|panic|exit)\s*\(",
     "observable abort reveals internal state or existence"),
    ("Detectability", "alloc_free",
     r"\b(malloc|calloc|realloc|kmalloc|vmalloc|free|kfree)\s*\(",
     "allocation/free; exhaustion or leak is externally observable"),
    ("Detectability", "error_return",
     r"return\s+-?(E[A-Z]{2,}|ENOMEM|EINVAL|NULL)\b",
     "distinguishable error return can act as an oracle"),

    ("Identifiability", "weak_random",
     r"\b(rand|srand|random|srandom|drand48)\s*\(",
     "predictable randomness weakens tokens that stand in for identity"),
    ("Identifiability", "weak_digest",
     r"\b(MD5|SHA1|md5_|sha1_|DES_|RC4)\w*\s*\(",
     "broken digest/cipher fails to protect identifying material"),
    ("Identifiability", "credential_name",
     r"\b\w*(passwd|password|secret|token|credential|private_key)\w*\b",
     "identifier- or credential-bearing symbol in scope"),

    ("Linkability", "session_identifier",
     r"\b(session\w*|cookie\w*|uuid|uid|user_id|device_id|client_id)\b",
     "stable identifier that can correlate records to one subject"),

    ("Non-repudiation", "logging_call",
     r"\b(syslog|log_\w+|printk|audit_\w+|fprintf\s*\(\s*stderr)\s*\(?",
     "writes an audit trail the subject may not be able to repudiate"),

    ("Non-compliance", "permission_change",
     r"\b(chmod|chown|setuid|seteuid|setgid|umask|access|capable)\s*\(",
     "alters or tests privilege; policy-relevant decision point"),

    ("Unawareness", "dangerous_legacy",
     r"\b(gets|tmpnam|mktemp|alloca|system|popen)\s*\(",
     "legacy/dangerous primitive whose side effects are not evident"),
]

COMPILED = [(c, n, re.compile(p), w) for c, n, p, w in RULES]

# Classes whose MECHANISM is normally a named API call, so absence of a
# match is weak evidence of absence. Measured on a 4,000-row sample, the
# memory-safety classes are not in this set for a concrete reason: an
# out-of-bounds read in this corpus is typically pointer arithmetic or a
# macro (NXT(1), RAW, buf[i]), not memcpy, so a rule bank keyed on call
# names finds nothing in ~74% of CWE-125 bodies. Treating that silence as
# a mislabel signal would be measuring the rules, not the data.
LEXICAL_CLASSES = frozenset({
    "Identifiability", "Non-repudiation", "Non-compliance", "Unawareness",
})


@dataclass
class Hit:
    linddun: str
    rule: str
    line_no: int
    line: str
    why: str


def scan(code, classes=None, max_hits_per_rule=3):
    """Return evidence hits, optionally restricted to `classes`."""
    if not code:
        return []
    want = set(classes) if classes else None
    counts, hits = {}, []
    for i, line in enumerate(code.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "*", "/*")):
            continue
        for cls, rule, rx, why in COMPILED:
            if want is not None and cls not in want:
                continue
            if counts.get(rule, 0) >= max_hits_per_rule:
                continue
            if rx.search(line):
                counts[rule] = counts.get(rule, 0) + 1
                hits.append(Hit(cls, rule, i, stripped[:160], why))
    return hits


def supported(code, classes):
    """Which of `classes` have at least one supporting hit, and which not.

    The "missing" list is restricted to LEXICAL_CLASSES. For the others,
    silence from these rules says nothing, so reporting them as missing
    would manufacture a finding out of a known blind spot.
    """
    found = {h.linddun for h in scan(code, classes)}
    missing = (set(classes) - found) & LEXICAL_CLASSES
    return sorted(found), sorted(missing)
