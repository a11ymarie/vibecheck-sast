"""Writes report.md, the human-readable report."""
from __future__ import annotations

from collections import defaultdict

from .model import LEVELS, RANK, Finding, sort_key

ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}


def _anchor(f: Finding) -> str:
    return f"finding-{f.id}"


def write(path: str, *, app_name: str, scanned_at: str, quick: bool, findings: list[Finding],
          ignored: list[Finding], notes: list[str], cmp: dict | None):
    main = sorted([f for f in findings if f.source in ("custom", "secrets", "config")], key=sort_key)
    deps = sorted([f for f in findings if f.source == "deps"],
                  key=lambda f: (RANK[f.severity], f.extra.get("scope") == "dev", f.rule))
    leads = [f for f in findings if f.source == "community"]
    shipped_bad = [d for d in deps if d.extra.get("scope") != "dev" and d.severity in ("critical", "high")]
    count = {lvl: sum(1 for f in main if f.severity == lvl) for lvl in LEVELS}
    new = " 🆕"

    L = [f"# Security report: {app_name}", "",
         f"*{scanned_at.replace('T', ' ')} · {'quick scan' if quick else 'full scan'} · vibecheck-sast*", "",
         "| " + " | ".join(f"{ICON[l]} {l.capitalize()}" for l in LEVELS) + " |",
         "| --- | --- | --- | --- |",
         "| " + " | ".join(str(count[l]) for l in LEVELS) + " |", ""]
    extras = []
    if deps:
        extras.append(f"{len(deps)} vulnerable package{'s' if len(deps) != 1 else ''} "
                      f"({len(shipped_bad)} critical or high that ship with the app)")
    if leads:
        extras.append(f"{len(leads)} community-rule lead{'s' if len(leads) != 1 else ''}")
    if ignored:
        extras.append(f"{len(ignored)} ignored by `.vibecheck.yml`")
    if extras:
        L += ["Also: " + " · ".join(extras) + ".", ""]
    L += ["> Confirm each finding before fixing it: a scanner finds patterns, not proof. For an exposed "
          "key, **rotate it first** in the provider's dashboard. `fix-tasks.md` next to this report "
          "has the same findings as a step-by-step list for you or your AI assistant "
          "(in Claude Code: `/vibecheck`).", ""]

    if cmp:
        L += [f"## Changes since {str(cmp['against']).replace('T', ' ')[:16]}", "",
              f"✅ **{len(cmp['fixed'])} fixed** · ⏳ {cmp['open']} still open · 🆕 {cmp['new']} new"
              + (f" ({sum(1 for f in leads if f.status == 'new')} of them community-rule leads)"
                 if any(f.status == "new" for f in leads) else ""), ""]
        if cmp["not_compared"]:
            L += [f"Not compared (only one of the two scans ran them): {', '.join(cmp['not_compared'])}.", ""]
        for p in cmp["fixed"]:
            where = (p["path"] or "") + (f":{p['line']}" if p.get("line") else "")
            L.append(f"- ✅ {p['title']} — `{where}` (id `{p['id']}`)")
        for p in cmp["now_ignored"]:
            L.append(f"- 🙈 Now ignored, not fixed: {p['title']} — `{p['path']}`")
        if cmp["fixed"] or cmp["now_ignored"]:
            L.append("")
        if cmp["new"]:
            L += [f"New findings are marked{new} below. Right after a fix, that usually means the fix "
                  "introduced them.", ""]

    urgent = [f for f in main if f.severity in ("critical", "high")]
    if urgent or shipped_bad:
        L += ["## Start here", ""]
        for f in urgent:
            L.append(f"1. {ICON[f.severity]} [{f.title}](#{_anchor(f)}) — `{f.where()}`"
                     + (new if f.status == "new" else ""))
        if shipped_bad:
            L.append(f"1. 🟠 Update {len(shipped_bad)} vulnerable package(s) that ship with the app "
                     "([list](#vulnerable-packages))")
        L.append("")
    elif not main:
        L += ["No code or configuration findings. A good baseline, not a guarantee: see "
              "[what this scan can't see](#what-this-scan-cant-see).", ""]

    if main:
        L += ["## Findings", ""]
    for f in main:
        L += [f'<a id="{_anchor(f)}"></a>', "",
              f"### {ICON[f.severity]} {f.title}" + (new if f.status == "new" else ""), "",
              f"`{f.where()}` · rule `{f.rule}` · id `{f.id}`"
              + (f" · {f.cwe}" if f.cwe else "")
              + (f" · also flagged by {', '.join(s for s in f.found_by if s != f.source)}"
                 if len(f.found_by) > 1 else ""), ""]
        if f.snippet:
            L += ["```", f.snippet, "```", ""]
        if f.message:
            L += [f.message.strip(), ""]
        if f.impact:
            L += [f"**How serious:** {f.impact.strip()}", ""]
        if f.confirm:
            L += [f"**Confirm it:** {f.confirm.strip()}", ""]
        if f.fix:
            L += [f"**Fix:** {f.fix.strip()}", ""]

    if deps:
        L += ['<a id="vulnerable-packages"></a>', "", f"## Vulnerable packages ({len(deps)})", "",
              "From `npm audit`. Packages that ship with the app matter most; dev-only tools run on "
              "your machine and in CI. `npm ls <package>` shows why something is installed.", "",
              "| Package | Severity | Ships with app | Direct | Fix |", "| --- | --- | --- | --- | --- |"]
        for d in deps:
            name = f"[{d.rule}]({d.url})" if d.url else d.rule
            fix = "major upgrade" if d.extra.get("major_fix") else \
                  ("`npm audit fix`" if "npm audit fix" in d.fix else "no fix yet")
            L.append(f"| {name}{new if d.status == 'new' else ''} | {d.severity} | "
                     f"{'no' if d.extra.get('scope') == 'dev' else 'yes'} | "
                     f"{'yes' if d.extra.get('direct') else 'no'} | {fix} |")
        L.append("")

    if leads:
        L += [f"## Community-rule leads ({len(leads)})", "",
              "Broader patterns from Semgrep's community rules. Worth a look, but more likely to be "
              "false positives than the findings above.", ""]
        groups = defaultdict(list)
        for f in leads:
            groups[f.rule].append(f)
        for rule, items in sorted(groups.items(), key=lambda kv: (RANK[kv[1][0].severity], kv[0])):
            first = items[0]
            spots = ", ".join(f"`{i.where()}`" for i in items[:5]) + \
                    (f" and {len(items) - 5} more" if len(items) > 5 else "")
            L += [f"- **{first.title}** ({first.severity}, {len(items)}×): {spots}",
                  f"  - {first.message.splitlines()[0][:220] if first.message else ''}",
                  f"  - Fix: {first.fix}"]
        L.append("")

    if ignored:
        L += ["## Ignored by .vibecheck.yml", "", "| Finding | Where | Reason | Until |",
              "| --- | --- | --- | --- |"]
        for f in sorted(ignored, key=sort_key):
            L.append(f"| {f.title} | `{f.where()}` | {f.extra.get('reason')} | {f.extra.get('until') or '—'} |")
        L.append("")

    L += ['<a id="what-this-scan-cant-see"></a>', "", "## What this scan can't see", ""]
    L += [f"- ⚠️ {n}" for n in notes]
    L += ["- **Whether each user can only reach their own data.** That's the most common serious bug "
          "in real apps, and reading code can't settle it. Log in as two different users and try to "
          "view or change the other one's records.",
          "- **Settings that live only in a dashboard:** Supabase RLS toggled in the UI, Firebase rules "
          "deployed from the console, environment variables on your host.",
          "- **Anything outside this folder**, and languages other than JavaScript/TypeScript for the "
          "code rules."]
    with open(path, "w") as fh:
        fh.write("\n".join(L) + "\n")
