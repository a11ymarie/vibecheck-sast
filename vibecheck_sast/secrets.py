"""Finds credentials committed to an app's files.

Each detector is a provider-specific pattern plus an optional check that decides whether a match
really is a secret (and how serious). In a git repository, files git ignores are skipped: an
ignored .env.local is exactly where secrets belong. Matched values are masked before anything is
written out, so a report never re-leaks the secret it found.
"""
from __future__ import annotations

import base64
import json
import math
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Callable, Optional

from .model import Finding

ROTATE = ("Rotate it in the provider's dashboard first: it's exposed for as long as the old "
          "value works, and deleting it from the file doesn't remove it from git history. Then "
          "load the new value from a server-side environment variable.")

NOT_SECRET_WORDS = re.compile(
    r"(?i)example|sample|dummy|placeholder|changeme|change_me|your[-_ ]|<.+>|xxxx|\*\*\*|"
    r"\$\{|process\.env|import\.meta\.env|fake|mock|redacted|todo|lorem|test[-_]?key")

SKIP_DIRS = {"node_modules", ".git", ".next", ".nuxt", ".output", ".vercel", ".turbo",
             ".svelte-kit", ".expo", "build", "dist", "out", "coverage", "ios", "android",
             "vendor", "vibecheck-report", ".vibecheck"}
SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".zip",
                 ".gz", ".woff", ".woff2", ".ttf", ".otf", ".mp3", ".mp4", ".mov", ".map",
                 ".lock", ".lockb", "package-lock.json", ".min.js")
MAX_FILE = 2_000_000


@dataclass
class Detector:
    rule: str
    title: str
    severity: str
    pattern: re.Pattern
    group: int = 0                                   # which capture group is the secret
    judge: Optional[Callable[[str, str], Optional[tuple]]] = None   # (value, line) -> override or None to drop
    note: str = ROTATE


def entropy(s: str) -> float:
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values()) if s else 0.0


def judge_jwt(value, line):
    """Supabase API keys are JWTs. The anon key is public by design; service_role is not."""
    try:
        seg = value.split(".")[1]
        role = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))).get("role")
    except Exception:
        role = None
    if role == "anon":
        return None
    if role == "service_role":
        return ("supabase-service-role-key", "Supabase service role key", "critical",
                "This key skips Row Level Security: whoever has it can read and change every row "
                "in every table. " + ROTATE + " Only server code may use it.")
    return ()


def judge_google(value, line):
    if re.search(r"(?i)firebase|apiKey\s*[:=]", line):
        return ("firebase-web-api-key", "Firebase web API key", "low",
                "Firebase web API keys are public by design: they identify your project and "
                "aren't what protects your data. Security Rules do, so check those (and restrict "
                "the key to your domains in Google Cloud Console).")
    return ()


def judge_generic(value, line):
    if re.fullmatch(r"[A-Z0-9_.-]+", value) or entropy(value) < 3.5 or value.isalpha():
        return None
    return ()


DETECTORS = [
    Detector("openai-key", "OpenAI API key", "high",
             re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b")),
    Detector("anthropic-key", "Anthropic API key", "high",
             re.compile(r"\bsk-ant-(?:api|admin)\d\d-[A-Za-z0-9_-]{20,}")),
    Detector("groq-key", "Groq API key", "high", re.compile(r"\bgsk_[A-Za-z0-9]{40,}")),
    Detector("supabase-secret-key", "Supabase secret key", "critical",
             re.compile(r"\bsb_secret_[A-Za-z0-9_-]{20,}")),
    Detector("jwt", "Hard-coded JWT", "medium",
             re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), judge=judge_jwt),
    Detector("stripe-live-key", "Stripe or Clerk live secret key", "high",
             re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}")),
    Detector("stripe-test-key", "Stripe or Clerk test secret key", "medium",
             re.compile(r"\bsk_test_[A-Za-z0-9]{16,}")),
    Detector("aws-access-key", "AWS access key ID", "high", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    Detector("github-token", "GitHub token", "high",
             re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})")),
    Detector("slack-token", "Slack token", "high", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    Detector("google-api-key", "Google API key", "high", re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b"),
             judge=judge_google),
    Detector("private-key", "Private key", "high",
             re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")),
    Detector("npm-token", "npm access token", "high",
             re.compile(r"\bnpm_[A-Za-z0-9]{36}\b|_authToken\s*=\s*([^\s$][^\s]{15,})"), group=0),
    Detector("db-url-password", "Database URL with a password", "high",
             re.compile(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?)://[^\s:/@'\"]+:"
                        r"([^\s@'\"]{6,})@([^\s/:'\"]+)"), group=1),
    Detector("hardcoded-secret", "Hard-coded secret", "medium",
             re.compile(r"(?i)\b[\w-]*(?:secret|password|passwd|api[_-]?key|access[_-]?token|"
                        r"auth[_-]?token|private[_-]?key)[\w-]*['\"]?\s*[:=]\s*['\"]([^'\"\s]{12,})['\"]"),
             group=1, judge=judge_generic),
]

LOCAL_HOSTS = re.compile(r"^(localhost|127\.0\.0\.1|0\.0\.0\.0|db|postgres|mysql|mongo|redis|host\.docker\.internal)$")


def mask(text: str, secret: str) -> str:
    shown = secret[:4] if len(secret) > 10 else ""
    return text.replace(secret, f"{shown}…[redacted]")


def _git_ignored(app: str, rels: list[str]) -> set[str]:
    try:
        inside = subprocess.run(["git", "-C", app, "rev-parse", "--is-inside-work-tree"],
                                capture_output=True, text=True)
        if inside.returncode != 0:
            return set()
        res = subprocess.run(["git", "-C", app, "check-ignore", "--stdin"],
                             input="\n".join(rels), capture_output=True, text=True)
        return set(res.stdout.splitlines())
    except OSError:
        return set()


def _files(app: str):
    for here, dirs, files in os.walk(app):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            if name.endswith(SKIP_SUFFIXES) or re.search(r"\.(test|spec|stories)\.", name):
                continue
            full = os.path.join(here, name)
            try:
                if os.path.getsize(full) <= MAX_FILE:
                    yield full, os.path.relpath(full, app)
            except OSError:
                pass


def scan(app: str, extra: list[Detector] | None = None) -> list[Finding]:
    files = list(_files(app))
    ignored = _git_ignored(app, [rel for _, rel in files])
    found = []
    for full, rel in files:
        if rel in ignored:
            continue
        try:
            with open(full, errors="ignore") as fh:
                lines = fh.read().splitlines()
        except OSError:
            continue
        for n, line in enumerate(lines, 1):
            if len(line) > 3000:
                continue
            for d in [*(extra or []), *DETECTORS]:
                m = d.pattern.search(line)
                if not m:
                    continue
                value = m.group(d.group) if d.group and m.lastindex else m.group(0)
                if d.rule == "npm-token" and m.lastindex:
                    value = m.group(1)
                if NOT_SECRET_WORDS.search(value):
                    continue
                if d.rule == "db-url-password" and LOCAL_HOSTS.match(m.group(2)):
                    continue
                rule, title, sev, note = d.rule, d.title, d.severity, d.note
                if d.judge:
                    verdict = d.judge(value, line)
                    if verdict is None:
                        continue
                    if verdict:
                        rule, title, sev, note = verdict
                found.append(Finding(
                    source="secrets", rule=rule, severity=sev, title=title, path=rel, line=n,
                    snippet=mask(line.strip(), value)[:160],
                    message=f"A {title.lower()} appears to be written into a file git will commit.",
                    confirm="Check that the value is a real, current credential and not a "
                            "placeholder; `git log -p -- <file>` shows when it was added and "
                            "whether it was pushed.",
                    impact="High if it's real and was ever pushed or deployed. False positive if "
                           "it's a placeholder or a deliberately public value.",
                    fix=note, cwe="CWE-798", kind="rotate" if sev != "low" else "code",
                    match_text=f"{rule}:{value}"))
                break
    return found
