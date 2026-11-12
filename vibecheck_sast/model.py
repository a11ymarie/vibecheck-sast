"""The Finding record every check produces, plus merging and stable ids.

Every source of findings (Semgrep rules, the secret detectors, config checks, npm audit, an
optional AI review) returns Finding objects, so everything downstream (ignores, compare, the
report, the task list, the exit-code gate) works on one shape.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field

LEVELS = ["critical", "high", "medium", "low"]
RANK = {lvl: i for i, lvl in enumerate(LEVELS)}

# Where a finding came from. "custom" rules, secrets, config checks and reviews make up the main
# report; "community" rule hits are leads; "deps" are package advisories.
SOURCES = ("custom", "community", "secrets", "config", "deps", "review")
MAIN_SOURCES = ("custom", "secrets", "config", "review")


@dataclass
class Finding:
    source: str
    rule: str
    severity: str
    title: str
    path: str | None = None          # relative to the scanned app's root
    line: int | None = None
    snippet: str = ""                # shown in the report; secrets are already masked
    message: str = ""                # what's wrong and what decides how serious it is
    confirm: str = ""                # how to tell whether it's real
    impact: str = ""                 # High / Medium / False-positive conditions
    fix: str = ""
    cwe: str = ""
    url: str = ""
    kind: str = "code"               # code | rotate | deployed | dependency
    extra: dict = field(default_factory=dict)
    # Filled in later:
    id: str = ""
    aliases: list = field(default_factory=list)
    found_by: list = field(default_factory=list)
    status: str | None = None        # with --compare: "new" or "open"
    # Text used for the id. Never written out (it can contain an unmasked secret).
    match_text: str = field(default="", repr=False)

    def where(self) -> str:
        if not self.path:
            return "(project)"
        return f"{self.path}:{self.line}" if self.line else self.path

    def to_json(self) -> dict:
        d = asdict(self)
        d.pop("match_text", None)
        return d


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def assign_ids(findings: list[Finding]) -> None:
    """Give every finding a short id that survives unrelated edits.

    The id hashes the rule, the file and the flagged code with whitespace collapsed. Line numbers
    are left out on purpose, so adding code above a finding doesn't change its id, while changing
    the flagged code does. Two identical matches in one file are told apart by their order.
    """
    seen: dict[str, int] = {}
    for f in sorted(findings, key=lambda f: (f.path or "", f.line or 0, f.rule)):
        basis = "\x1f".join([f.rule, f.path or "", _normalize(f.match_text or f.snippet or f.title)])
        digest = hashlib.sha256(basis.encode("utf-8", "ignore")).hexdigest()
        n = seen.get(digest, 0)
        seen[digest] = n + 1
        if n:
            digest = hashlib.sha256(f"{digest}/{n}".encode()).hexdigest()
        f.id = digest[:12]


# Which version of a finding to keep when several checks flag the same line: more severe first,
# then the source with the most specific write-up.
_DETAIL = {"review": 0, "custom": 1, "config": 2, "secrets": 3, "community": 4, "deps": 5}


def merge_same_line(findings: list[Finding]) -> list[Finding]:
    """Collapse findings on the same file and line into one.

    The kept finding lists every check that flagged the line in `found_by`, and the ids of the
    findings it absorbed in `aliases`, so a comparison with an earlier run still recognizes it if
    a different check ends up being the one shown.
    """
    groups: dict[tuple, list[Finding]] = {}
    order = []
    for f in findings:
        key = (f.path, f.line) if (f.path and f.line) else ("#", f.source, f.rule, f.path)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)
    out = []
    for key in order:
        group = sorted(groups[key], key=lambda f: (RANK.get(f.severity, 9), _DETAIL.get(f.source, 9)))
        keep = group[0]
        keep.found_by = sorted({g.source for g in group})
        keep.aliases = sorted({a for g in group[1:] for a in [g.id, *g.aliases]})
        out.append(keep)
    return out


def sort_key(f: Finding):
    return (RANK.get(f.severity, 9), f.path or "~", f.line or 0, f.rule)
