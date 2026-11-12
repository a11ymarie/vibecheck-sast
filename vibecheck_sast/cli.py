"""vibecheck: an ad-hoc security scan for apps you're building.

  vibecheck <app>                        full scan, writes a report
  vibecheck --quick <app>                fast: skip community rules and the dependency audit
  vibecheck --compare last <app>         show what's fixed, still open or new since the last scan
  vibecheck --fail-on high <app>         exit 1 if anything high or critical is found
  vibecheck init <app>                   set it up in a project (asks before each change)
  vibecheck test-rules <rules> <tests>   test your own rules (see docs/customizing.md)

Exit codes: 0 done (and passed --fail-on), 1 --fail-on threshold hit, 2 the scan failed.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from datetime import datetime

from . import compare as comparing
from . import configcheck, deps, ignores, project, report, secrets, semgrep, tasks
from .model import LEVELS, RANK, assign_ids, merge_same_line, sort_key

VERSION = "1.0.0"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS = os.path.join(ROOT, "vibecheck-report")
ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}


def fail(msg: str):
    print(f"vibecheck: {msg}", file=sys.stderr)
    sys.exit(2)


def parse(argv):
    p = argparse.ArgumentParser(prog="vibecheck", description=__doc__.split("\n\n")[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__.split("\n\n", 1)[1])
    p.add_argument("app", help="path to the app's folder")
    p.add_argument("--quick", action="store_true",
                   help="own rules, secrets and config checks only (seconds)")
    p.add_argument("--compare", metavar="FILE",
                   help='an earlier findings.json, or "last" for the newest earlier report of this app')
    p.add_argument("--fail-on", choices=LEVELS + ["secrets"],
                   help='exit 1 at this level or above; "secrets" = exposed keys and critical findings only')
    p.add_argument("--out", metavar="DIR", help="report folder (default: vibecheck-report/<app>-<time>)")
    p.add_argument("--config", metavar="FILE", help="ignore file (default: <app>/.vibecheck.yml)")
    p.add_argument("--counts-only", action="store_true",
                   help="terminal output without finding titles or paths (for public CI logs)")
    p.add_argument("--version", action="version", version=f"vibecheck-sast {VERSION}")
    return p.parse_args(argv)


def previous_report(name: str, exclude: str):
    candidates = sorted(glob.glob(os.path.join(REPORTS, f"{name}-*", "findings.json")),
                        key=os.path.getmtime, reverse=True)
    for c in candidates:
        if os.path.dirname(os.path.abspath(c)) != exclude:
            return c
    return None


def step(label, fn):
    print(f"  {label:<22}", end="", flush=True)
    try:
        result = fn()
    except Exception:
        print("FAILED")
        raise
    print("done")
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["test-rules"]:
        from . import ruletest
        return ruletest.main(argv[1:])
    if argv[:1] == ["init"]:
        init = os.path.join(os.path.dirname(os.path.abspath(__file__)), "init.py")
        os.execv(sys.executable, [sys.executable, init, ROOT, *argv[1:]])
    a = parse(argv)

    app = os.path.abspath(a.app)
    if not os.path.isdir(app):
        fail(f"no such folder: {a.app}")
    name = os.path.basename(app)
    cfg = a.config or (os.path.join(app, ".vibecheck.yml") if os.path.exists(os.path.join(app, ".vibecheck.yml")) else None)
    if a.config and not os.path.exists(a.config):
        fail(f"no such config file: {a.config}")

    try:
        proj = project.load(cfg)
    except project.ConfigError as e:
        fail(str(e))
    rules = proj.ignores
    community = not a.quick and proj.community

    now = datetime.now()
    out = os.path.abspath(a.out or os.path.join(REPORTS, f"{name}-{now:%Y%m%d-%H%M%S}"))
    if os.path.isdir(out) and os.listdir(out) and not os.path.exists(os.path.join(out, "findings.json")):
        fail(f"{out} already has other files in it; pick another --out")
    if out == app or out.startswith(app + os.sep):
        print("note: the report is inside the app folder. Keep it out of git: secrets are masked, "
              "but it describes weaknesses in your app.", file=sys.stderr)
    raw = os.path.join(out, "raw")
    os.makedirs(raw, exist_ok=True)

    prev_path, notes = None, list(proj.notes)
    if not a.quick and not proj.community:
        notes.append("Community rules are turned off in .vibecheck.yml (`community: false`).")
    if a.compare == "last":
        prev_path = previous_report(name, out)
        if not prev_path:
            notes.append(f"--compare last: there's no earlier report for {name} yet.")
    elif a.compare:
        prev_path = os.path.abspath(a.compare)
        if not os.path.exists(prev_path):
            fail(f"no such file to compare with: {a.compare}")


    print(f"vibecheck: scanning {app}" + (" (quick)" if a.quick else ""))
    found = []
    try:
        if community and not semgrep.community_ready():
            semgrep.fetch_community(log=lambda m: print("  " + m))
        label = "Code rules" + (f" (+{len(proj.rule_paths)} project)" if proj.rule_paths else "")
        sg, sg_notes = step(label, lambda: semgrep.run(app, raw, community=community,
                                                        project_rules=proj.rule_paths))
        found += sg
        notes += sg_notes
        found += step("Secrets", lambda: secrets.scan(app, proj.secret_detectors))
        found += step("Configuration", lambda: configcheck.scan(app))
        if not a.quick:
            dep, dep_notes = step("Dependencies", lambda: deps.scan(app, raw))
            found += dep
            notes += dep_notes
    except semgrep.ScanError as e:
        fail(f"{e}\nThe scan didn't finish, so no report was written.")

    sources = ["custom", "secrets", "config"] + (["community"] if community else []) + \
              ([] if a.quick else ["deps"])
    for f in found:
        if f.rule in proj.severity:
            f.extra = dict(f.extra, severity_was=f.severity)
            f.severity = proj.severity[f.rule]
    assign_ids(found)
    kept, ignored = ignores.apply(found, rules)
    unused = [r["name"] for r in rules if r["hits"] == 0]
    if unused:
        notes.append("Ignore entries that matched nothing (safe to remove): " + ", ".join(f"`{u}`" for u in unused))
    findings = sorted(merge_same_line(kept), key=sort_key)

    cmp = None
    if prev_path:
        try:
            cmp = comparing.compare(findings, sources, comparing.load(prev_path), ignored)
            cmp["file"] = prev_path
        except (OSError, ValueError) as e:
            notes.append(f"Couldn't compare with {prev_path}: {e}")

    scanned_at = now.isoformat(timespec="seconds")
    with open(os.path.join(out, "findings.json"), "w") as fh:
        json.dump({"tool": "vibecheck-sast", "version": VERSION, "app": name, "app_path": app,
                   "scanned_at": scanned_at, "quick": a.quick, "sources": sources, "notes": notes,
                   "compare": cmp, "findings": [f.to_json() for f in findings],
                   "ignored": [f.to_json() for f in ignored]}, fh, indent=2)
    report.write(os.path.join(out, "report.md"), app_name=name, scanned_at=scanned_at, quick=a.quick,
                 findings=findings, ignored=ignored, notes=notes, cmp=cmp)
    exe = os.path.join(ROOT, "vibecheck")
    tasks.write(os.path.join(out, "fix-tasks.md"), findings, name,
                recheck=[exe, "--quick", "--compare", os.path.join(out, "findings.json"), app],
                full_check=[exe, "--compare", os.path.join(out, "findings.json"), app])

    # ---- terminal summary ----
    main_ = [f for f in findings if f.source in ("custom", "secrets", "config")]
    deps_ = [f for f in findings if f.source == "deps"]
    leads = [f for f in findings if f.source == "community"]
    counts = {lvl: sum(1 for f in main_ if f.severity == lvl) for lvl in LEVELS}
    print("\n" + "  ".join(f"{ICON[l]} {counts[l]} {l}" for l in LEVELS)
          + (f"   (+{len(deps_)} vulnerable package{'s' if len(deps_) != 1 else ''}, "
             f"{len(leads)} lead{'s' if len(leads) != 1 else ''})" if not a.quick else ""))
    if cmp:
        new_leads = sum(1 for f in leads if f.status == "new")
        print(f"Since {str(cmp['against']).replace('T', ' ')[:16]}: ✅ {len(cmp['fixed'])} fixed, "
              f"⏳ {cmp['open']} still open, 🆕 {cmp['new']} new"
              + (f" ({new_leads} of them community-rule leads)" if new_leads else ""))
    if not a.counts_only:
        urgent = [f for f in main_ if f.severity in ("critical", "high")]
        if cmp:
            for p in cmp["fixed"]:
                print(f"  ✅ Fixed: {p['title']} (id {p['id']})")
            for f in main_ + deps_:
                if f.status == "new":
                    print(f"  🆕 New: {f.title} — {f.where()} (id {f.id})")
        if urgent:
            print("Fix first:")
            for f in urgent[:8]:
                print(f"  {ICON[f.severity]} {f.title} — {f.where()}")
            if len(urgent) > 8:
                print(f"  … {len(urgent) - 8} more in the report")
        for n in notes:
            print(f"  ⚠️  {n}")
    print(f"Report:    {os.path.join(out, 'report.md')}")
    print(f"Fix tasks: {os.path.join(out, 'fix-tasks.md')}")

    if a.fail_on:
        if a.fail_on == "secrets":
            hits = [f for f in main_ if f.kind == "rotate" or f.severity == "critical"]
            what = "exposed keys or critical findings"
        else:
            limit = RANK[a.fail_on]
            hits = [f for f in main_ if RANK[f.severity] <= limit] + \
                   [f for f in deps_ if RANK[f.severity] <= limit and f.extra.get("scope") != "dev"]
            what = f"findings at {a.fail_on} or above"
        if hits:
            print(f"\nFailed --fail-on {a.fail_on}: {len(hits)} {what}.")
            return 1
        print(f"\nPassed --fail-on {a.fail_on}: no {what}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
