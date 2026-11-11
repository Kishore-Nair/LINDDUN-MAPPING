"""Parse `tree` output into full relative paths.

`tree` draws depth with 4-character groups ("│   " or "    ") followed by a
"├── " or "└── " connector, so depth is just the connector's offset / 4.
The first line is the root and the trailing "N directories, M files" summary
is not an entry.
"""

import re

CONNECTOR = re.compile(r"[├└]── ")
SUMMARY = re.compile(r"^\s*\d[\d,]*\s+director(y|ies),\s+\d[\d,]*\s+files?\s*$")


def parse(text, keep_root=False):
    """Yield (path, depth) for every entry in a tree listing."""
    stack, root, out = {}, None, []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or SUMMARY.match(line):
            continue
        m = CONNECTOR.search(line)
        if not m:
            # Root line — only the first unindented, unconnected entry.
            if root is None and not line.startswith((" ", "│")):
                root = line.strip().rstrip("/")
            continue
        depth = m.start() // 4 + 1
        name = line[m.end():].strip()
        # A symlink arrow is annotation, not part of the name.
        name = name.split(" -> ")[0].strip()
        if not name:
            continue
        stack[depth] = name
        parts = [stack[d] for d in range(1, depth + 1) if d in stack]
        path = "/".join(parts)
        out.append((f"{root}/{path}" if keep_root and root else path, depth))
    return out


def files_only(entries):
    """Entries that no deeper entry sits under — i.e. leaves.

    `tree` does not mark directories, so a leaf is any entry that is not a
    prefix of the entry that follows it.
    """
    leaves = []
    for i, (path, depth) in enumerate(entries):
        nxt = entries[i + 1] if i + 1 < len(entries) else None
        if nxt is None or nxt[1] <= depth:
            leaves.append(path)
    return leaves
