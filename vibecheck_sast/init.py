#!/usr/bin/env python3
"""vibecheck init: set vibecheck up in a project, asking before each change.

Usage: vibecheck init [--yes | --all | --dry-run] [--only a,b,...] <path-to-app>

  --yes      accept the suggested answer for every step (shown as [Y/n] or [y/N])
  --all      say yes to every step
  --dry-run  show what would change, change nothing
  --only     limit to some steps: gitignore, config, rules, claude, agents, cursor, scripts, hook,
             action

Every step only adds: existing files are never overwritten. Sections it adds to CLAUDE.md and
AGENTS.md sit between vibecheck markers, so running init again updates them in place.
"""
import json, os, re, stat, subprocess, sys

SCANNER = os.path.abspath(sys.argv[1])
INTEGRATIONS = os.path.join(SCANNER, "integrations")
START, END = "<!-- vibecheck:start -->", "<!-- vibecheck:end -->"
STEPS = ["gitignore", "config", "rules", "claude", "agents", "cursor", "scripts", "hook", "action"]

args = sys.argv[2:]
mode, only, app = "ask", None, None
i = 0
while i < len(args):
    a = args[i]
    if a in ("--yes", "-y"):
        mode = "yes"
    elif a == "--all":
        mode = "all"
    elif a == "--dry-run":
        mode = "dry"
    elif a == "--only":
        i += 1
        only = set(args[i].split(",")) if i < len(args) else set()
        bad = only - set(STEPS)
        if bad:
            sys.exit(f"unknown step(s): {', '.join(sorted(bad))}. Steps: {', '.join(STEPS)}")
    elif a in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)
    elif a.startswith("-"):
        sys.exit(f"unknown option: {a}\n{__doc__}")
    elif app is None:
        app = a
    else:
        sys.exit("only one app path at a time")
    i += 1
if not app:
    sys.exit(__doc__)
APP = os.path.abspath(app)
if not os.path.isdir(APP):
    sys.exit(f"no such folder: {app}")
if APP == SCANNER or APP.startswith(SCANNER + os.sep):
    sys.exit("point init at your app's folder, not at the vibecheck-sast folder")
if mode == "ask" and not sys.stdin.isatty():
    print("Not running in an interactive terminal, so nothing will be changed. Showing the plan;"
          " re-run with --yes (suggested answers) or --all to apply it.\n")
    mode = "dry"

# Paths written into files that get committed use the scanner's location RELATIVE to the app
# (no personal absolute paths), overridable per machine with $VIBECHECK_HOME.
REL = os.path.relpath(SCANNER, APP)
VC = f'"${{VIBECHECK_HOME:-{REL}}}/vibecheck"'
changed, skipped = [], []


def p(*parts):
    return os.path.join(APP, *parts)


def read(path):
    try:
        with open(path) as fh:
            return fh.read()
    except OSError:
        return None


def write(path, text, executable=False):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)
    if executable:
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    changed.append(os.path.relpath(path, APP))


def ask(step, question, default):
    if only is not None and step not in only:
        return False
    hint = "[Y/n]" if default else "[y/N]"
    if mode == "dry":
        print(f"• {question} {hint}")
        return False
    if mode == "all":
        print(f"• {question} yes")
        return True
    if mode == "yes":
        print(f"• {question} {'yes' if default else 'no'}")
        return default
    while True:
        ans = input(f"• {question} {hint} ").strip().lower()
        if not ans:
            return default
        if ans in ("y", "yes", "n", "no"):
            return ans.startswith("y")


def workflow():
    with open(os.path.join(INTEGRATIONS, "workflow.md")) as fh:
        return fh.read().replace("{{VC}}", VC)


def always_rule(pointer):
    return f"""## Security check (vibecheck)

- When you finish a feature or fix, run `{VC} --quick --compare last .` from the project root.
  Fix any critical or high finding marked 🆕 (new): your change introduced it. Mention older
  findings to the person, but don't start fixing them unless asked.
- Never put API keys or other secrets in client-side code, or in `NEXT_PUBLIC_`, `VITE_`,
  `EXPO_PUBLIC_` or `REACT_APP_` variables: those ship to every visitor's browser.
- Never add entries to `.vibecheck.yml` to hide a finding without asking.
- {pointer}
"""


def upsert_section(path, body):
    """Add or replace the vibecheck section between markers, keeping everything else."""
    block = f"{START}\n{body.rstrip()}\n{END}\n"
    text = read(path)
    if text is None:
        write(path, block)
    elif START in text and END in text:
        new = re.sub(re.escape(START) + r".*?" + re.escape(END) + r"\n?", block, text, flags=re.S)
        if new != text:
            write(path, new)
        else:
            skipped.append(f"{os.path.relpath(path, APP)} (already up to date)")
    else:
        write(path, text.rstrip("\n") + "\n\n" + block)


def scanner_repo():
    try:
        url = subprocess.run(["git", "-C", SCANNER, "remote", "get-url", "origin"],
                             capture_output=True, text=True).stdout.strip()
    except OSError:
        url = ""
    m = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?$", url)
    return m.group(1) if m else None


is_git = os.path.isdir(p(".git"))
pkg_path = p("package.json")
print(f"Setting up vibecheck in {APP}")
print(f"Scanner: {SCANNER} (referenced as {VC})\n")

# 1. .gitignore -------------------------------------------------------------------------------
wanted = [".env", ".env.*", "!.env.example", "vibecheck-report/"]
gi = read(p(".gitignore")) or ""
have = {l.strip() for l in gi.splitlines()}
missing = [w for w in wanted if w not in have]
if missing and ask("gitignore", f".gitignore: add {', '.join(missing)}?", True):
    write(p(".gitignore"), gi.rstrip("\n") + ("\n\n" if gi.strip() else "") +
          "# vibecheck: keep secrets and scan reports out of git\n" + "\n".join(missing) + "\n")

# 2. .vibecheck.yml ---------------------------------------------------------------------------
if not os.path.exists(p(".vibecheck.yml")) and \
        ask("config", "Create .vibecheck.yml (an empty, commented ignore file)?", True):
    write(p(".vibecheck.yml"), """\
# vibecheck settings for this project. Every key is optional; see docs/customizing.md in
# vibecheck-sast for the full guide.
#
# rules:                         # your own Semgrep rules (files or folders, relative to this file)
#   - .vibecheck/rules/
#
# secrets:                       # your own secret formats (regular expressions)
#   - id: myapp-service-token
#     pattern: '\\bmyapp_svc_[A-Za-z0-9]{32}\\b'
#
# severity:                      # raise or lower a rule for this project
#   vc-open-redirect: low
#
# ignore_paths:                  # every ignore needs a reason; ignored findings stay in the report
#   - path: 'scripts/**'
#     reason: One-off scripts I run by hand. Never deployed.
#
# ignore_findings:
#   - rule: vc-secret-in-url
#     paths: ['lib/export.ts']          # optional: only in these files
#     reason: Single-use download token that expires in 5 minutes.
#     until: 2027-06-30                 # optional: the finding comes back after this date
""")

# 2b. Starter project rule ----------------------------------------------------------------------
starter_dir = p(".vibecheck", "rules")
if not os.path.exists(starter_dir) and ask(
        "rules", "Create .vibecheck/rules/ with a starter rule (every API route must check who's calling)?", False):
    src = os.path.join(SCANNER, "examples", "custom-rules", "rules")
    for here, _dirs, files in os.walk(src):
        for name in files:
            rel = os.path.relpath(os.path.join(here, name), src)
            with open(os.path.join(here, name)) as fh:
                text = fh.read()
            if "myapp-admin-client" in text:      # only the require-auth starter and its tests
                continue
            write(os.path.join(starter_dir, rel), text)
    cfg_path = p(".vibecheck.yml")
    cfg_text = read(cfg_path) or ""
    if not re.search(r"^rules:", cfg_text, re.M):
        write(cfg_path, "rules:\n  - .vibecheck/rules/\n\n" + cfg_text)
    print("  Edit .vibecheck/rules/require-auth.yaml to use your auth helper's name, then test it:\n"
          f"  {VC} test-rules .vibecheck/rules .vibecheck/rules/tests")

# 3. Claude Code ------------------------------------------------------------------------------
if ask("claude", "Claude Code: add the /vibecheck skill (.claude/skills) and a short rule in CLAUDE.md?", True):
    skill = p(".claude", "skills", "vibecheck", "SKILL.md")
    body = ("---\nname: vibecheck\ndescription: Security scan and fix loop. Runs the vibecheck "
            "scanner on this project, confirms each finding, fixes the real ones one at a time, "
            "re-checks after every fix, and reports what still needs a person (like rotating "
            "leaked keys). Use when asked for a security check, security scan, or to fix "
            "security issues.\n---\n\n" + workflow())
    if read(skill) != body:
        write(skill, body)
    upsert_section(p("CLAUDE.md"), always_rule("For a full security pass, use the `/vibecheck` skill."))

# 4. AGENTS.md (Codex, Copilot coding agent, Gemini CLI, Windsurf and others) ------------------
if ask("agents", "AGENTS.md (Codex, Copilot, Gemini CLI and others): add the vibecheck section?",
       os.path.exists(p("AGENTS.md"))):
    upsert_section(p("AGENTS.md"), always_rule(
        "When asked for a security check or to fix security issues, follow the workflow below.")
        + "\n" + re.sub(r"^# ", "### ", workflow(), flags=re.M).replace("\n## ", "\n#### "))

# 5. Cursor -----------------------------------------------------------------------------------
cursor_rule = p(".cursor", "rules", "vibecheck.mdc")
if not os.path.exists(cursor_rule) and ask(
        "cursor", "Cursor: add .cursor/rules/vibecheck.mdc?", os.path.isdir(p(".cursor"))):
    write(cursor_rule, "---\ndescription: Security scan and fix loop with vibecheck. Use when "
          "asked for a security check or to fix security issues, and when finishing a feature.\n"
          "alwaysApply: false\n---\n\n" + always_rule("For a full security pass, follow the "
          "workflow below.") + "\n" + workflow())

# 6. package.json scripts ---------------------------------------------------------------------
pkg_text = read(pkg_path)
if pkg_text is not None:
    try:
        pkg = json.loads(pkg_text)
    except ValueError:
        pkg = None
        skipped.append("package.json (couldn't parse it)")
    if pkg is not None:
        scripts = pkg.get("scripts") or {}
        add = {k: v for k, v in {"security": f"{VC} --fail-on high --compare last .",
                                 "security:quick": f"{VC} --quick --compare last ."}.items()
               if k not in scripts}
        if add and ask("scripts", f"package.json: add {' and '.join(add)} scripts?", True):
            pkg["scripts"] = {**scripts, **add}
            indent = len(m.group(1)) if (m := re.search(r'\n( +)"', pkg_text)) else 2
            write(pkg_path, json.dumps(pkg, indent=indent, ensure_ascii=False) + "\n")

# 7. pre-commit hook (local only, never committed) --------------------------------------------
if is_git:
    hook = p(".git", "hooks", "pre-commit")
    existing = read(hook)
    if existing is not None and "vibecheck" not in existing:
        skipped.append(".git/hooks/pre-commit (you already have one; add this line to it: "
                       f"{VC} --quick --fail-on secrets .)")
    elif existing is None and ask(
            "hook", "Git pre-commit hook: block commits that expose keys or have critical findings?", True):
        write(hook, f"""#!/usr/bin/env bash
# vibecheck pre-commit hook (added by vibecheck init). Blocks the commit if the quick scan finds
# exposed keys or critical problems. Skip once with: git commit --no-verify
cd "$(git rev-parse --show-toplevel)" || exit 0
VC="{SCANNER}/vibecheck"
[ -x "$VC" ] || {{ echo "vibecheck not found at $VC; skipping the security check." >&2; exit 0; }}
"$VC" --quick --fail-on secrets . || {{
  echo; echo "Commit blocked by vibecheck: fix the findings above (see fix-tasks.md), or skip once with git commit --no-verify."
  exit 1
}}
""", executable=True)

# 8. GitHub Action ----------------------------------------------------------------------------
action_path = p(".github", "workflows", "vibecheck.yml")
if not os.path.exists(action_path) and ask(
        "action", "GitHub Action: scan every push and pull request, fail on high or critical?",
        os.path.isdir(p(".github"))):
    repo = scanner_repo()
    with open(os.path.join(INTEGRATIONS, "github-action.yml")) as fh:
        text = fh.read().replace("{{SCANNER_REPO}}", repo or "YOUR-GITHUB-USER/vibecheck-sast")
    write(action_path, text)
    if not repo:
        print("  ⚠️  Couldn't tell where vibecheck-sast lives on GitHub: edit `repository:` in "
              ".github/workflows/vibecheck.yml.")

# Done ----------------------------------------------------------------------------------------
print()
if mode == "dry":
    print("Dry run: nothing was changed.")
    sys.exit(0)
if changed:
    print("Changed:")
    for c in changed:
        print(f"  + {c}")
for s in skipped:
    print(f"  - skipped {s}")
if not changed and not skipped:
    print("Nothing to change.")
print(f"""
Next:
  • Scan now:              {VC} .
  • In Claude Code, type:  /vibecheck   (or ask your assistant for a security check)
  • Review these changes with `git diff` before committing them.""")
if REL.startswith(".."):
    print(f"  • The files above find the scanner at {REL} relative to this project. On another "
          "machine, set VIBECHECK_HOME to wherever vibecheck-sast is cloned.")
