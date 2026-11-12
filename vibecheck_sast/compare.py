"""Compares this run with an earlier run's findings.json: what's fixed, still open, or new.

Nothing is stored between runs; the earlier file is whatever you point at (`--compare FILE`, or
`--compare last` for the newest earlier report of the same app). Findings are matched by id,
including the ids a merged finding absorbed. Only checks that ran in BOTH runs are compared, so
comparing a --quick run with a full one doesn't make every dependency look fixed or new.
"""
from __future__ import annotations

import json

from .model import RANK, Finding


def load(path: str) -> dict:
    with open(path) as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict) or "findings" not in doc or "sources" not in doc:
        raise ValueError(f"{path} isn't a findings.json from this version of vibecheck")
    return doc


def compare(current: list[Finding], sources_now: list[str], prev: dict, ignored_now: list[Finding]) -> dict:
    shared = set(sources_now) & set(prev["sources"])

    def ids(f):
        return {f["id"], *f.get("aliases", [])} if isinstance(f, dict) else {f.id, *f.aliases}

    before = [p for p in prev["findings"] if p["source"] in shared]
    before_ids = set().union(*map(ids, before)) if before else set()
    now_ids = set()
    for f in current:
        if f.source in shared:
            f.status = "open" if ids(f) & before_ids else "new"
            now_ids |= ids(f)
    ignored_ids = set().union(*map(ids, ignored_now)) if ignored_now else set()

    fixed, now_ignored = [], []
    for p in before:
        if ids(p) & now_ids:
            continue
        brief = {k: p.get(k) for k in ("id", "title", "severity", "path", "line", "rule", "source")}
        (now_ignored if ids(p) & ignored_ids else fixed).append(brief)
    fixed.sort(key=lambda p: (RANK.get(p["severity"], 9), p["path"] or "", p["line"] or 0))
    return {
        "against": prev.get("scanned_at"),
        "compared": sorted(shared),
        "not_compared": sorted((set(sources_now) | set(prev["sources"])) - shared),
        "fixed": fixed,
        "now_ignored": now_ignored,
        "open": sum(1 for f in current if f.status == "open"),
        "new": sum(1 for f in current if f.status == "new"),
    }
