"""vibecheck test-rules: check project rules against annotated example files.

  vibecheck test-rules <rules file or folder> [more rules...] <tests folder>

Test files use Semgrep's comment annotations: a `ruleid: <rule>` comment means that rule must
match the next code line; `ok: <rule>` means it must not. Unlike `semgrep --test`, this runs the
rules the way a real scan does, from the tests folder as the project root, so rules limited with
`paths:` (e.g. only /app/api/**) are tested with their scoping applied: lay the tests folder out
like your app.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict

ANNOTATION = re.compile(r"(?:^|\s)(?://|#|--|/\*|\{/\*)\s*(ruleid|ok|todoruleid|todook):\s*([\w\-., ]+)")
COMMENT_ONLY = re.compile(r"^\s*(//|#|--|/\*|\*|\{/\*)")


def expectations(root):
    """{(path, line, rule): 'ruleid'|'ok'} from annotations, with path relative to root."""
    exp = {}
    for here, _dirs, files in os.walk(root):
        for name in files:
            full = os.path.join(here, name)
            rel = os.path.relpath(full, root)
            try:
                with open(full, errors="ignore") as fh:
                    lines = fh.read().splitlines()
            except OSError:
                continue
            for i, line in enumerate(lines):
                m = ANNOTATION.search(line)
                if not m or m.group(1).startswith("todo"):
                    continue
                target = i + 1
                while target < len(lines) and (not lines[target].strip() or COMMENT_ONLY.match(lines[target])):
                    target += 1
                for rule in re.split(r"[,\s]+", m.group(2).strip()):
                    if rule:
                        exp[(rel, target + 1, rule)] = m.group(1)
    return exp


def main(argv):
    if len(argv) < 2 or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv[:1] in (["-h"], ["--help"]) else 2
    *rule_paths, tests = argv
    for p in rule_paths + [tests]:
        if not os.path.exists(p):
            print(f"vibecheck test-rules: no such file or folder: {p}", file=sys.stderr)
            return 2
    if not shutil.which("semgrep"):
        print("vibecheck test-rules: semgrep isn't installed (pip install -r requirements.txt)", file=sys.stderr)
        return 2
    tests = os.path.abspath(tests)
    root = tests if os.path.isdir(tests) else os.path.dirname(tests)
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "out.json")
        cmd = ["semgrep", "scan", "--json", "--output", out, "--metrics", "off", "--quiet",
               "--no-git-ignore", "--x-ignore-semgrepignore-files"]
        for p in rule_paths:
            cmd += ["--config", os.path.abspath(p)]
        cmd.append(".")
        env = dict(os.environ, SEMGREP_ENABLE_VERSION_CHECK="0")
        proc = subprocess.run(cmd, cwd=root, env=env, capture_output=True, text=True)
        if proc.returncode != 0 or not os.path.exists(out):
            print(proc.stderr.strip()[-2000:], file=sys.stderr)
            print("vibecheck test-rules: Semgrep couldn't run these rules (see the error above).", file=sys.stderr)
            return 2
        with open(out) as fh:
            data = json.load(fh)

    exp = expectations(root)
    rules_tested = {r for (_p, _l, r) in exp}
    got = set()
    for r in data.get("results", []):
        rule = r["check_id"].rsplit(".", 1)[-1]
        path = r["path"][2:] if r["path"].startswith("./") else r["path"]
        got.add((path, r["start"]["line"], rule))

    problems = defaultdict(list)
    for (path, line, rule), kind in sorted(exp.items()):
        if kind == "ruleid" and (path, line, rule) not in got:
            problems[rule].append(f"missed: {path}:{line} should match")
        if kind == "ok" and (path, line, rule) in got:
            problems[rule].append(f"false positive: {path}:{line} should not match")
    for (path, line, rule) in sorted(got):
        if rule in rules_tested and (path, line, rule) not in exp:
            problems[rule].append(f"unexpected match: {path}:{line} (add a ruleid: or fix the rule)")
    untested = sorted({r for (_p, _l, r) in got} - rules_tested)

    for rule in sorted(rules_tested):
        n = sum(1 for k in exp if k[2] == rule)
        if problems[rule]:
            print(f"✖ {rule}")
            for p in problems[rule]:
                print(f"    {p}")
        else:
            print(f"✓ {rule} ({n} cases)")
    for rule in untested:
        print(f"? {rule}: matched something but has no test annotations")
    failed = sum(1 for r in rules_tested if problems[r])
    print(f"\n{len(rules_tested) - failed}/{len(rules_tested)} rules passed")
    return 1 if failed else 0
