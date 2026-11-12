"""Configuration checks for mistakes that are common in AI-built apps and aren't code patterns:

  public-env-secret-name      a secret-looking variable with a NEXT_PUBLIC_ / VITE_ / EXPO_PUBLIC_ /
                              REACT_APP_ / PUBLIC_ prefix, which bundlers ship to the browser
  env-file-not-gitignored     a .env file with values that git doesn't ignore (or already tracks)
  supabase-table-without-rls  a table created in SQL migrations with no ENABLE ROW LEVEL SECURITY
  supabase-rls-disabled       a migration that turns Row Level Security off
  supabase-permissive-policy  a write policy with USING (true) / WITH CHECK (true)
  firebase-rules-open         Firestore/Storage rules with `if true`, or test-mode date rules
  firebase-rules-any-user     Firestore/Storage rules where any signed-in user can read/write all
  firebase-rtdb-rules-open    Realtime Database rules with ".read"/".write": true
"""
from __future__ import annotations

import os
import re
import subprocess

from .model import Finding

SKIP_DIRS = {"node_modules", ".git", "build", "dist", "out", "coverage", "storybook-static",
             ".expo", "ios", "android", ".next", ".nuxt", ".output", ".vercel", ".turbo",
             ".svelte-kit", ".cache", "vendor", "vibecheck-report", ".vibecheck"}
TEXT_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro", ".json",
            ".yml", ".yaml", ".toml", ".md", ".sql", ".rules", ".html", ".sh", ".txt", ""}
MAX_BYTES = 1_500_000
KIND = {"public-env-secret-name": "rotate", "env-file-not-gitignored": "rotate",
        "supabase-table-without-rls": "deployed", "supabase-rls-disabled": "deployed",
        "supabase-permissive-policy": "deployed", "firebase-rules-open": "deployed",
        "firebase-rules-any-user": "deployed", "firebase-rtdb-rules-open": "deployed"}

CHECKS = {
    "public-env-secret-name": dict(
        severity="high", cwe="CWE-200: Exposure of Sensitive Information", owasp="A05:2021 Security Misconfiguration",
        title="Secret in a browser-exposed environment variable",
        message=("Variables starting with NEXT_PUBLIC_, VITE_, EXPO_PUBLIC_, REACT_APP_ or PUBLIC_ are "
                 "copied into the JavaScript your users download. This variable's name says it holds a "
                 "secret (a service role key, an AI provider key, a database URL, a password). Anyone "
                 "can read it from the browser, even if the .env file itself is never committed."),
        validation=("Static: find where the variable is set (.env.local, your host's environment "
                    "settings) and what it holds. Runtime (Web): open the deployed site, devtools > "
                    "Sources, and search the loaded JavaScript for the first few characters of the value."),
        impact=("High: the value is a real secret key or password. False positive: the value is public "
                "by design (e.g. a Supabase anon/publishable key or a Stripe publishable key) and only "
                "the name is misleading; rename it."),
        remediation=("Rename it without the public prefix so only server code can read it, and move "
                     "the code that uses it into a server route or server action. Rotate the value, "
                     "since every deployed build so far has shipped it.")),
    "env-file-not-gitignored": dict(
        severity="high", cwe="CWE-538: Insertion of Sensitive Information into Externally-Accessible File",
        owasp="A05:2021 Security Misconfiguration",
        title=".env file is not ignored by git",
        message=("This .env file contains values, and git will commit it (or already has). Anyone with "
                 "access to the repository, or to a public fork of it, gets every value inside."),
        validation=("Static: run git check-ignore -v <file> (no output means it is NOT ignored) and "
                    "git log --oneline -- <file> (any output means it was committed)."),
        impact=("High: it holds real keys and has been committed or pushed. Medium: not committed yet. "
                "False positive: it only holds non-secret settings."),
        remediation=("Add .env* (with !.env.example if you keep a template) to .gitignore. If it was "
                     "ever committed, run git rm --cached <file> and rotate every secret in it; "
                     "removing it later does not remove it from history.")),
    "supabase-table-without-rls": dict(
        severity="high", cwe="CWE-284: Improper Access Control", owasp="A01:2021 Broken Access Control",
        title="Supabase table created without Row Level Security",
        message=("This table is created in a SQL migration, but no migration enables Row Level Security "
                 "on it. Without RLS, anyone with your public anon key, which is in your front-end code "
                 "by design, can read and change every row through the Supabase API."),
        validation=("Static: search your migrations for ALTER TABLE <name> ENABLE ROW LEVEL SECURITY. "
                    "RLS can also be turned on in the dashboard, so check there: Table Editor shows "
                    "'RLS disabled' on unprotected tables, and the Security Advisor lists them. "
                    "Runtime (Web): with only the anon key, run supabase.from('<table>').select('*') "
                    "from a browser console and check whether rows come back."),
        impact=("High: the table holds user data and RLS is off. False positive: RLS is enabled in the "
                "dashboard or a later migration under another name, or the table is not exposed through "
                "the API (e.g. in a private schema)."),
        remediation=("Add ALTER TABLE <name> ENABLE ROW LEVEL SECURITY; and policies that limit rows "
                     "to their owner, e.g. USING (auth.uid() = user_id).")),
    "supabase-rls-disabled": dict(
        severity="high", cwe="CWE-284: Improper Access Control", owasp="A01:2021 Broken Access Control",
        title="Row Level Security turned off",
        message=("A migration disables Row Level Security on a table, so the anon key in your front end "
                 "can read and write all of its rows."),
        validation="Static: confirm no later migration re-enables it, and check the table in the dashboard.",
        impact="High: the table holds user data. False positive: a later migration re-enables RLS.",
        remediation="Remove the DISABLE statement and add ENABLE ROW LEVEL SECURITY with owner-scoped policies."),
    "supabase-permissive-policy": dict(
        severity="medium", cwe="CWE-284: Improper Access Control", owasp="A01:2021 Broken Access Control",
        title="Supabase write policy allows everyone",
        message=("An RLS policy for writes uses USING (true) or WITH CHECK (true), which turns RLS on "
                 "but lets any caller (often including anonymous users) insert, update or delete rows."),
        validation=("Static: read the policy's command (ALL/INSERT/UPDATE/DELETE) and roles (TO anon, "
                    "authenticated). Runtime (Web): as a different user, try to update a row you don't own."),
        impact=("High: anyone can change or delete other users' rows. Medium: limited to signed-in users. "
                "False positive: the table is intentionally world-writable (e.g. an anonymous feedback form "
                "with insert only)."),
        remediation="Replace true with an ownership check, e.g. USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id)."),
    "firebase-rules-open": dict(
        severity="critical", cwe="CWE-284: Improper Access Control", owasp="A01:2021 Broken Access Control",
        title="Firebase Security Rules allow public access",
        message=("These Security Rules let anyone read or write without signing in: either `if true`, or "
                 "the 'test mode' date rule, which leaves the database open to the internet until the "
                 "date passes (and then breaks the app)."),
        validation=("Static: check whether these are the rules actually deployed: Firebase console > "
                    "Firestore (or Storage) > Rules. Runtime (Web): use the Rules Playground in the "
                    "console to simulate an unauthenticated read of a user document."),
        impact="Critical: user data in this database can be read or wiped by anyone. False positive: the rules file isn't deployed.",
        remediation=("Write rules per collection that check request.auth.uid against the document "
                     "owner, e.g. allow read, write: if request.auth != null && request.auth.uid == userId;")),
    "firebase-rules-any-user": dict(
        severity="medium", cwe="CWE-284: Improper Access Control", owasp="A01:2021 Broken Access Control",
        title="Firebase Security Rules allow any signed-in user",
        message=("These rules only check that someone is signed in, not who. If sign-up is open, anyone "
                 "can create an account and then read or change every other user's data."),
        validation="Static: check which paths the rule covers (a wildcard match like /{document=**} covers everything).",
        impact="High: it covers user documents and sign-up is open. False positive: the data is meant to be shared by all users.",
        remediation="Compare request.auth.uid to the document's owner field or path segment instead of only checking request.auth != null."),
    "firebase-rtdb-rules-open": dict(
        severity="critical", cwe="CWE-284: Improper Access Control", owasp="A01:2021 Broken Access Control",
        title="Firebase Realtime Database rules allow public access",
        message="\".read\" or \".write\" is set to true, so anyone can read or write that part of the database without signing in.",
        validation="Static: confirm these rules are deployed (Firebase console > Realtime Database > Rules).",
        impact="Critical: user data is publicly readable or writable. False positive: it covers intentionally public data only.",
        remediation="Use auth-based rules, e.g. \".read\": \"auth != null && auth.uid === $uid\" under a users/$uid node."),
}

PUBLIC_SECRET = re.compile(
    r"\b(?:NEXT_PUBLIC|VITE|EXPO_PUBLIC|REACT_APP|NUXT_PUBLIC|GATSBY|PUBLIC)_[A-Z0-9_]*?"
    r"(?:SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|OPENAI|ANTHROPIC|CLAUDE|GEMINI|GROQ|MISTRAL|"
    r"REPLICATE|DATABASE_URL|DB_URL|POSTGRES|RESEND|SENDGRID|TWILIO|STRIPE_SECRET)[A-Z0-9_]*\b")
ENV_FILE = re.compile(r"^\.env(\..+)?$")
ENV_TEMPLATE = re.compile(r"\.(example|sample|template|defaults?|dist)$")
ENV_VALUE = re.compile(r"^\s*(export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*['\"]?[^'\"\s#]")
CREATE_TABLE = re.compile(r'(?i)\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?(?:"?(\w+)"?\.)?"?(\w+)"?')
ENABLE_RLS = re.compile(r'(?i)\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?:"?\w+"?\.)?"?(\w+)"?\s+enable\s+row\s+level\s+security')
DISABLE_RLS = re.compile(r'(?i)\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?:"?\w+"?\.)?"?(\w+)"?\s+disable\s+row\s+level\s+security')
POLICY = re.compile(r"(?is)\bcreate\s+policy\b.*?;")
FB_OPEN = re.compile(r"\ballow\s+[a-z, ]+\s*:\s*if\s+true\s*;|request\.time\s*<\s*timestamp\.date\s*\(")
FB_ANY_USER = re.compile(r"\ballow\s+[a-z, ]+\s*:\s*if\s+request\.auth\s*!=\s*null\s*;")
RTDB_OPEN = re.compile(r'"\.(read|write)"\s*:\s*(true|"true")')




def _walk(root):
    for here, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            full = os.path.join(here, name)
            try:
                if os.path.getsize(full) <= MAX_BYTES:
                    yield full, os.path.relpath(full, root), name
            except OSError:
                pass


def _lines(path):
    try:
        with open(path, errors="ignore") as fh:
            return fh.readlines()
    except OSError:
        return []


def _git(root, *args, stdin=None):
    try:
        return subprocess.run(["git", "-C", root, *args], input=stdin, capture_output=True, text=True)
    except OSError:
        return None


def _line_of(text, offset):
    return text.count("\n", 0, offset) + 1


def scan(root: str) -> list[Finding]:
    out: list[Finding] = []

    def add(check, rel, line, snippet):
        c = CHECKS[check]
        snippet = " ".join(snippet.split())[:160]
        out.append(Finding(source="config", rule=check, severity=c["severity"], title=c["title"],
                           path=rel, line=line, snippet=snippet, message=c["message"],
                           confirm=c["validation"], impact=c["impact"], fix=c["remediation"],
                           cwe=c["cwe"], kind=KIND[check], match_text=snippet))

    r = _git(root, "rev-parse", "--is-inside-work-tree")
    in_git = r is not None and r.returncode == 0
    env_files, sql_files, seen_public = [], [], set()

    for full, rel, name in _walk(root):
        ext = os.path.splitext(name)[1].lower()
        is_env = bool(ENV_FILE.match(name))
        if is_env:
            env_files.append((full, rel, name))
        if ext == ".sql":
            sql_files.append((full, rel))
        if not (is_env or ext in TEXT_EXT):
            continue
        lines = _lines(full)
        for i, line in enumerate(lines, 1):
            for m in PUBLIC_SECRET.finditer(line):
                if (rel, m.group(0)) in seen_public:
                    continue
                seen_public.add((rel, m.group(0)))
                # On an env-file line, show the name but never the value.
                shown = line.split("=", 1)[0] + "=…[redacted]" if is_env and "=" in line else line
                add("public-env-secret-name", rel, i, shown)
        if ext == ".rules":
            for i, line in enumerate(lines, 1):
                if FB_OPEN.search(line):
                    add("firebase-rules-open", rel, i, line)
                elif FB_ANY_USER.search(line):
                    add("firebase-rules-any-user", rel, i, line)
        if name == "database.rules.json":
            for i, line in enumerate(lines, 1):
                if RTDB_OPEN.search(line):
                    add("firebase-rtdb-rules-open", rel, i, line)

    if in_git:
        candidates = [(full, rel) for full, rel, name in env_files if not ENV_TEMPLATE.search(name)
                      and any(ENV_VALUE.match(l) for l in _lines(full))]
        if candidates:
            r = _git(root, "check-ignore", "--stdin", stdin="\n".join(rel for _, rel in candidates))
            ignored = set(r.stdout.splitlines()) if r else set()
            for full, rel in candidates:
                t = _git(root, "ls-files", "--error-unmatch", rel)
                tracked = t is not None and t.returncode == 0
                if tracked or rel not in ignored:
                    add("env-file-not-gitignored", rel, None,
                        f"{rel} ({'already tracked by git' if tracked else 'not in .gitignore'})")

    created, enabled = [], set()
    for full, rel in sorted(sql_files):
        text = "".join(_lines(full))
        for m in CREATE_TABLE.finditer(text):
            schema, table = (m.group(1) or "public").lower(), m.group(2).lower()
            if schema == "public":
                created.append((table, rel, _line_of(text, m.start()), m.group(0)))
        enabled |= {m.group(1).lower() for m in ENABLE_RLS.finditer(text)}
        for m in DISABLE_RLS.finditer(text):
            add("supabase-rls-disabled", rel, _line_of(text, m.start()), m.group(0))
        for m in POLICY.finditer(text):
            stmt = m.group(0)
            if re.search(r"(?i)\bfor\s+(all|insert|update|delete)\b", stmt) and \
                    re.search(r"(?i)\b(using|with\s+check)\s*\(\s*true\s*\)", stmt):
                add("supabase-permissive-policy", rel, _line_of(text, m.start()), stmt)
    for table, rel, line, snippet in created:
        if table not in enabled:
            add("supabase-table-without-rls", rel, line, snippet)
    return out
