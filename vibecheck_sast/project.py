"""Per-project settings from .vibecheck.yml (in the scanned app's root). Every key is optional:

  rules:                       # your own Semgrep rules: files or folders, relative to this file
    - .vibecheck/rules/
  secrets:                     # your own secret formats (Python regular expressions)
    - id: acme-api-token
      title: Acme internal API token
      pattern: 'acme_(live|test)_[A-Za-z0-9]{32}'
      severity: high           # optional: critical | high | medium | low (default high)
  severity:                    # raise or lower any rule for this project
    vc-token-in-localstorage: high
  community: false             # skip Semgrep's community rules (default: on for full scans)
  ignore_paths: [...]          # see ignores.py
  ignore_findings: [...]

Everything is checked before the scan starts, so a typo fails fast with a clear message.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

import yaml

from . import ignores
from .model import LEVELS
from .secrets import Detector

KNOWN_KEYS = {"rules", "secrets", "severity", "community", "ignore_paths", "ignore_findings"}


class ConfigError(ValueError):
    pass


@dataclass
class Project:
    path: str | None = None
    ignores: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    rule_paths: list = field(default_factory=list)
    secret_detectors: list = field(default_factory=list)
    severity: dict = field(default_factory=dict)
    community: bool = True


def load(path: str | None) -> Project:
    if not path or not os.path.exists(path):
        return Project()
    name = os.path.basename(path)
    try:
        with open(path) as fh:
            cfg = yaml.safe_load(fh) or {}
    except yaml.YAMLError as e:
        raise ConfigError(f"{name} isn't valid YAML: {e}")
    if not isinstance(cfg, dict):
        raise ConfigError(f"{name} should be a set of keys like `rules:` and `ignore_findings:`")
    unknown = set(cfg) - KNOWN_KEYS
    if unknown:
        raise ConfigError(f"{name}: unknown key(s) {', '.join(sorted(unknown))}. "
                          f"Known keys: {', '.join(sorted(KNOWN_KEYS))}")

    p = Project(path=path)
    try:
        p.ignores, p.notes = ignores.parse(cfg, name)
    except ignores.ConfigError as e:
        raise ConfigError(str(e))

    base = os.path.dirname(os.path.abspath(path))
    for entry in cfg.get("rules") or []:
        full = os.path.abspath(os.path.join(base, os.path.expanduser(str(entry))))
        if not os.path.exists(full):
            raise ConfigError(f"{name}: rules entry `{entry}` doesn't exist (looked for {full})")
        p.rule_paths.append(full)

    for n, s in enumerate(cfg.get("secrets") or [], 1):
        s = s or {}
        rid, pattern = s.get("id"), s.get("pattern")
        if not rid or not pattern:
            raise ConfigError(f"{name}: secrets entry {n} needs an id and a pattern")
        level = s.get("severity", "high")
        if level not in LEVELS:
            raise ConfigError(f"{name}: secrets entry `{rid}` has severity `{level}`; use one of {', '.join(LEVELS)}")
        try:
            rx = re.compile(pattern)
        except re.error as e:
            raise ConfigError(f"{name}: secrets entry `{rid}` has an invalid pattern: {e}")
        p.secret_detectors.append(Detector(rid, s.get("title") or rid.replace("-", " ").capitalize(), level, rx))

    for rule, level in (cfg.get("severity") or {}).items():
        if level not in LEVELS:
            raise ConfigError(f"{name}: severity for `{rule}` is `{level}`; use one of {', '.join(LEVELS)}")
        p.severity[str(rule)] = level

    p.community = bool(cfg.get("community", True))
    return p
