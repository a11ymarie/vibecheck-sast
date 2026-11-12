"""Reads .vibecheck.yml and sets aside the findings it ignores.

  ignore_paths:
    - path: 'scripts/**'            # glob relative to the app root; ** crosses folders
      reason: One-off scripts I run by hand, never deployed.
  ignore_findings:
    - rule: vc-secret-in-url         # the rule shown on the finding
      paths: ['lib/export.ts']       # optional: only in these files
      reason: Single-use download token that expires in 5 minutes.
      until: 2027-06-30              # optional: the finding comes back after this date

Every entry needs a reason. Ignored findings aren't deleted: the report lists them, with the
entry that matched, so nothing disappears silently.
"""
from __future__ import annotations

import datetime
import fnmatch
import os
import re

import yaml

from .model import Finding


class ConfigError(ValueError):
    pass


def _glob(pattern: str):
    # fnmatch's * crosses "/"; translate so * stays within a folder and ** crosses folders.
    regex = re.escape(pattern).replace(r"\*\*/", "(?:.*/)?").replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
    return re.compile(f"^{regex}$")


def load(path: str | None):
    """Returns (rules, notes). Expired entries are dropped with a note."""
    if not path or not os.path.exists(path):
        return [], []
    try:
        with open(path) as fh:
            cfg = yaml.safe_load(fh) or {}
    except yaml.YAMLError as e:
        raise ConfigError(f"{path} isn't valid YAML: {e}")
    rules, notes = [], []
    today = datetime.date.today()
    for section in ("ignore_paths", "ignore_findings"):
        for n, entry in enumerate(cfg.get(section) or [], 1):
            entry = entry or {}
            label = f"{section} entry {n}"
            reason = " ".join(str(entry.get("reason") or "").split())
            if not reason:
                raise ConfigError(f"{os.path.basename(path)}: {label} needs a reason")
            if section == "ignore_paths":
                if not entry.get("path"):
                    raise ConfigError(f"{os.path.basename(path)}: {label} needs a path")
                rule, globs, name = None, [entry["path"]], entry["path"]
            else:
                if not entry.get("rule"):
                    raise ConfigError(f"{os.path.basename(path)}: {label} needs a rule")
                rule, globs = entry["rule"], entry.get("paths") or []
                name = rule + (f" in {', '.join(globs)}" if globs else "")
            until = entry.get("until")
            if isinstance(until, str):
                until = datetime.date.fromisoformat(until)
            if until and until < today:
                notes.append(f"The ignore for `{name}` expired on {until}; those findings are back.")
                continue
            rules.append({"name": name, "rule": rule, "globs": [_glob(g) for g in globs],
                          "reason": reason, "until": str(until) if until else None, "hits": 0})
    return rules, notes


def apply(findings: list[Finding], rules: list[dict]):
    """Split findings into (kept, ignored). Ignored ones carry the matching entry in .extra."""
    kept, ignored = [], []
    for f in findings:
        hit = None
        for r in rules:
            if r["rule"] and r["rule"] != f.rule:
                continue
            if r["globs"] and not (f.path and any(g.match(f.path) for g in r["globs"])):
                continue
            hit = r
            break
        if hit:
            hit["hits"] += 1
            f.extra = dict(f.extra, ignored_by=hit["name"], reason=hit["reason"], until=hit["until"])
            ignored.append(f)
        else:
            kept.append(f)
    return kept, ignored
