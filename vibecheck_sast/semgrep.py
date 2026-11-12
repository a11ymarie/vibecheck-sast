"""Runs Semgrep: our own rules, plus a pinned set of Semgrep's community rules.

Both rule sets run in ONE Semgrep invocation, so files are parsed once. The community rules are
licensed separately (Semgrep Rules License), so they aren't shipped in this repo: the first full
scan downloads them from a pinned commit and keeps them in rules/community/ (gitignored).
"""
from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import urllib.request

from . import guidance
from .model import Finding

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OWN_RULES = os.path.join(ROOT, "rules", "vibecheck-rules.yaml")
COMMUNITY_DIR = os.path.join(ROOT, "rules", "community")

# Pinned so results only change when this line does. Bump deliberately.
COMMUNITY_COMMIT = "16b9e6d45f10649f6a531ec4838ed9924372c3bc"
COMMUNITY_URL = "https://codeload.github.com/semgrep/semgrep-rules/tar.gz/{commit}"
# Only security rules for the languages these apps are written in.
COMMUNITY_LANGS = ("javascript", "typescript", "html", "dockerfile")

OWN_PREFIX = "vc-"

SKIP_DIRS = ["node_modules", ".git", ".next", ".nuxt", ".output", ".vercel", ".turbo",
             ".svelte-kit", ".expo", "build", "dist", "out", "coverage", "storybook-static",
             "ios", "android", "vendor", "vibecheck-report", ".vibecheck"]
SKIP_FILES = ["*.min.js", "*.bundle.js", "*.map", "*.test.*", "*.spec.*", "__tests__", "__mocks__"]

SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


class ScanError(RuntimeError):
    pass


def community_ready() -> bool:
    try:
        with open(os.path.join(COMMUNITY_DIR, ".commit")) as fh:
            return fh.read().strip() == COMMUNITY_COMMIT
    except OSError:
        return False


def _from_tarball():
    """Yield (path inside the repo, bytes) from the pinned commit's tarball."""
    url = COMMUNITY_URL.format(commit=COMMUNITY_COMMIT)
    with urllib.request.urlopen(url, timeout=120) as resp:
        data = resp.read()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for member in tar.getmembers():
            if member.isfile():
                rel = member.name.split("/", 1)[1] if "/" in member.name else member.name
                with tar.extractfile(member) as fh:
                    yield rel, fh.read()


def _from_git():
    """Fallback for networks that block GitHub's download host: a shallow git fetch."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        git = lambda *a: subprocess.run(["git", "-C", tmp, *a], check=True, capture_output=True)
        git("init", "-q")
        git("fetch", "-q", "--depth", "1", "https://github.com/semgrep/semgrep-rules.git", COMMUNITY_COMMIT)
        git("checkout", "-q", "FETCH_HEAD")
        for here, dirs, files in os.walk(tmp):
            dirs[:] = [d for d in dirs if d != ".git"]
            for name in files:
                full = os.path.join(here, name)
                with open(full, "rb") as fh:
                    yield os.path.relpath(full, tmp), fh.read()


def _wanted(rel: str) -> bool:
    parts = rel.split("/")
    # Never trust paths from a downloaded archive: no absolute paths, no "..", no empty parts.
    if rel.startswith("/") or "\\" in rel or any(p in ("", ".", "..") for p in parts):
        return False
    name = parts[-1]
    return (len(parts) > 2 and parts[0] in COMMUNITY_LANGS and "security" in parts
            and name.endswith((".yaml", ".yml")) and ".test." not in name and ".fixed." not in name)


def fetch_community(log=print) -> int:
    """Download the pinned community rules. Returns how many rule files were kept."""
    log(f"Downloading Semgrep community rules ({COMMUNITY_COMMIT[:10]}, one time)...")
    tmp = COMMUNITY_DIR + ".partial"
    errors = []
    for source in (_from_tarball, _from_git):
        shutil.rmtree(tmp, ignore_errors=True)
        kept = 0
        try:
            for rel, data in source():
                if not (_wanted(rel) or rel == "LICENSE"):
                    continue
                dest = os.path.realpath(os.path.join(tmp, rel))
                if not dest.startswith(os.path.realpath(tmp) + os.sep):
                    continue
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "wb") as out:
                    out.write(data)
                kept += rel != "LICENSE"
        except (OSError, subprocess.CalledProcessError, tarfile.TarError) as e:
            errors.append(str(e))
            continue
        with open(os.path.join(tmp, ".commit"), "w") as fh:
            fh.write(COMMUNITY_COMMIT + "\n")
        shutil.rmtree(COMMUNITY_DIR, ignore_errors=True)
        os.replace(tmp, COMMUNITY_DIR)
        return kept
    shutil.rmtree(tmp, ignore_errors=True)
    raise ScanError("couldn't download the community rules (" + "; ".join(errors)
                    + "). Check your connection, or use --quick, which doesn't need them.")


def _rule_files(path: str):
    if os.path.isdir(path):
        for here, _dirs, files in os.walk(path):
            for name in sorted(files):
                # Skip test targets that sit next to rules (e.g. my-rule.test.yaml is fine to skip).
                if name.endswith((".yaml", ".yml")) and ".test." not in name:
                    yield os.path.join(here, name)
    else:
        yield path


def _load_rules(paths) -> dict:
    """Rule id -> rule, for vibecheck's own rules and any project rules."""
    import yaml
    out = {}
    for path in paths:
        for f in _rule_files(path):
            try:
                with open(f) as fh:
                    doc = yaml.safe_load(fh) or {}
            except (OSError, yaml.YAMLError) as e:
                raise ScanError(f"couldn't read rule file {f}: {e}")
            for r in doc.get("rules", []) if isinstance(doc, dict) else []:
                if isinstance(r, dict) and r.get("id"):
                    out[r["id"]] = r
    return out


def _read_lines(app, path, start, end):
    try:
        with open(os.path.join(app, path), errors="ignore") as fh:
            lines = fh.readlines()
        return "".join(lines[start - 1:end]).strip()
    except OSError:
        return ""


def run(app: str, raw_dir: str, community: bool, project_rules=()) -> tuple[list[Finding], list[str]]:
    """Scan `app`. Returns findings and notes about files Semgrep couldn't fully read.

    Raises ScanError if Semgrep fails: a scan that didn't run must never look like a clean one.
    """
    if not shutil.which("semgrep"):
        raise ScanError("semgrep isn't installed. Run: pip install -r requirements.txt")
    out = os.path.join(raw_dir, "semgrep.json")
    cmd = ["semgrep", "scan", "--json", "--output", out, "--metrics", "off", "--quiet",
           "--timeout", "10", "--max-target-bytes", "2000000", "--config", OWN_RULES]
    if community:
        cmd += ["--config", COMMUNITY_DIR]
    for path in project_rules:
        cmd += ["--config", path]
    for pat in SKIP_DIRS + SKIP_FILES:
        cmd += ["--exclude", pat]
    cmd.append(".")
    env = dict(os.environ, SEMGREP_ENABLE_VERSION_CHECK="0", SEMGREP_SEND_METRICS="off")
    proc = subprocess.run(cmd, cwd=app, env=env, capture_output=True, text=True)
    with open(os.path.join(raw_dir, "semgrep.log"), "w") as fh:
        fh.write(proc.stderr)
    # Semgrep exits 0 when the scan completed (findings or not); anything else is a failure.
    if proc.returncode != 0:
        hint = (" If you just added or changed a project rule, check it with: semgrep --test "
                "--config <rule file> <test file>") if project_rules else ""
        raise ScanError(f"Semgrep failed (exit {proc.returncode}); see {raw_dir}/semgrep.log.{hint}")
    try:
        with open(out) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        raise ScanError(f"Semgrep produced no readable results; see {raw_dir}/semgrep.log")

    own = _load_rules([OWN_RULES])
    mine = _load_rules(project_rules)
    findings = []
    for r in data.get("results", []):
        rule = r["check_id"].rsplit(".", 1)[-1]
        path = r["path"][2:] if r["path"].startswith("./") else r["path"]
        start, end = r["start"]["line"], r["end"]["line"]
        code = _read_lines(app, path, start, end)
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        first_line = code.splitlines()[0].strip()[:160] if code else ""
        if rule.startswith(OWN_PREFIX) and rule in own:
            m = own[rule].get("metadata", {})
            findings.append(Finding(
                source="custom", rule=rule, severity=m.get("level", "medium"), title=m["title"],
                path=path, line=start, snippet=first_line, message=extra.get("message", "").strip(),
                confirm=m.get("confirm", ""), impact=m.get("impact", ""), fix=m.get("fix", ""),
                cwe=m.get("cwe", ""), kind=m.get("kind", "code"), match_text=code))
        elif rule in mine:
            # A project rule: use its metadata if it has vibecheck's fields, sensible defaults if not.
            m = mine[rule].get("metadata", {}) or {}
            level = m.get("level") or SEMGREP_SEVERITY.get(mine[rule].get("severity", "WARNING"), "medium")
            cwe = m.get("cwe", "")
            cwe = cwe[0] if isinstance(cwe, list) and cwe else cwe
            findings.append(Finding(
                source="custom", rule=rule, severity=level,
                title=m.get("title") or rule.replace("-", " ").replace("_", " ").capitalize(),
                path=path, line=start, snippet=first_line, message=extra.get("message", "").strip(),
                confirm=m.get("confirm", ""), impact=m.get("impact", ""), fix=m.get("fix", ""),
                cwe=cwe, kind=m.get("kind", "code"), extra={"project_rule": True}, match_text=code))
        else:
            cls = guidance.for_cwe(meta.get("cwe"))
            cwe = meta.get("cwe")
            cwe = cwe[0] if isinstance(cwe, list) and cwe else (cwe or "")
            refs = meta.get("references") or []
            findings.append(Finding(
                source="community", rule=rule,
                severity=SEMGREP_SEVERITY.get(extra.get("severity", "WARNING"), "medium"),
                title=f"{cls['name']}: {rule.replace('-', ' ')}", path=path, line=start,
                snippet=first_line, message=extra.get("message", "").strip(),
                confirm=cls["confirm"], impact=cls["impact"], fix=cls["fix"], cwe=cwe,
                url=refs[0] if refs else "", match_text=code))

    notes = []
    skipped = {e.get("path") for e in data.get("errors", []) if e.get("path")}
    if skipped:
        notes.append(f"Semgrep couldn't fully read {len(skipped)} file(s), usually syntax it doesn't "
                     f"support yet; they were partly skipped. Details: {raw_dir}/semgrep.json")
    return findings, notes
