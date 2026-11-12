"""Dependency advisories from `npm audit`, one finding per vulnerable package.

Each finding says whether the package ships with the app (a production dependency) or is only a
build/test tool, whether the app depends on it directly, and what npm says it takes to fix it.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

from .model import Finding

NPM_LEVEL = {"critical": "critical", "high": "high", "moderate": "medium", "low": "low", "info": "low"}


def _dev_flags(app: str) -> dict:
    """package name -> True if every copy of it in the lockfile is dev-only."""
    try:
        with open(os.path.join(app, "package-lock.json")) as fh:
            packages = json.load(fh).get("packages", {})
    except (OSError, ValueError):
        return {}
    flags: dict[str, bool] = {}
    for key, info in packages.items():
        if "node_modules/" not in key:
            continue
        name = key.rsplit("node_modules/", 1)[1]
        flags[name] = flags.get(name, True) and bool(info.get("dev") or info.get("devOptional"))
    return flags


def scan(app: str, raw_dir: str) -> tuple[list[Finding], list[str]]:
    if not os.path.exists(os.path.join(app, "package-lock.json")):
        others = [f for f in ("pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb")
                  if os.path.exists(os.path.join(app, f))]
        if others:
            return [], [f"Dependencies weren't checked: found {others[0]}, but only npm's "
                        "package-lock.json is supported so far. Run that package manager's own audit."]
        if os.path.exists(os.path.join(app, "package.json")):
            return [], ["Dependencies weren't checked: there's no package-lock.json "
                        "(run `npm install` to create one)."]
        return [], []
    if not shutil.which("npm"):
        return [], ["Dependencies weren't checked: npm isn't installed."]

    proc = subprocess.run(["npm", "audit", "--json", "--package-lock-only"], cwd=app,
                          capture_output=True, text=True)
    with open(os.path.join(raw_dir, "npm-audit.json"), "w") as fh:
        fh.write(proc.stdout)
    try:
        audit = json.loads(proc.stdout)
    except ValueError:
        return [], ["Dependencies weren't checked: npm audit didn't return results (offline?)."]
    if "vulnerabilities" not in audit:
        msg = (audit.get("error") or {}).get("summary") or "unexpected output"
        return [], [f"Dependencies weren't checked: npm audit said: {msg}"]

    dev = _dev_flags(app)
    out = []
    for name, v in sorted(audit["vulnerabilities"].items()):
        level = NPM_LEVEL.get(v.get("severity"), "medium")
        advisories = [a for a in v.get("via", []) if isinstance(a, dict)]
        through = sorted({a for a in v.get("via", []) if isinstance(a, str)})
        scope = "dev only" if dev.get(name) else "ships with the app"
        relation = "direct dependency" if v.get("isDirect") else "pulled in by another package"
        lines = [f"`{name}` ({v.get('range', '?')}) — {scope}, {relation}."]
        for a in advisories[:4]:
            lines.append(f"- {a.get('title', 'advisory')} ({a.get('severity', '?')}): {a.get('url', '')}")
        if through:
            lines.append(f"- Vulnerable because of: {', '.join(through)}")
        fa = v.get("fixAvailable")
        if fa is True:
            fix = "`npm audit fix` can update it without breaking changes."
        elif isinstance(fa, dict):
            fix = (f"Fixed by upgrading `{fa.get('name')}` to {fa.get('version')}"
                   + (" — a major version, so check its changelog for breaking changes before upgrading."
                      if fa.get("isSemVerMajor") else "; `npm audit fix` can do it."))
        else:
            fix = "No fixed version yet. Consider replacing the package or limiting how it's used."
        out.append(Finding(
            source="deps", rule=name, severity=level, title=f"Vulnerable package: {name}",
            path="package-lock.json", message="\n".join(lines), fix=fix,
            confirm="Run `npm ls " + name + "` to see why it's installed, then check whether your "
                    "code uses the affected feature (see the advisory).",
            impact="Matters most for packages that ship with the app; dev-only tools only run on "
                   "your machine and in CI.",
            url=advisories[0].get("url", "") if advisories else "", kind="dependency",
            extra={"scope": "dev" if dev.get(name) else "prod", "direct": bool(v.get("isDirect")),
                   "major_fix": bool(isinstance(fa, dict) and fa.get("isSemVerMajor"))},
            match_text=name))
    return out, []
