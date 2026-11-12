"""Writes fix-tasks.md: one self-contained task per finding, in order, for a person or an AI
coding assistant to work through, each with a re-check command that proves it's done."""
from __future__ import annotations

import re
import shlex

from .model import Finding, RANK, sort_key

ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}

NEEDS_PERSON = ("**Needs a person:** this credential has to be revoked or rotated in the provider's "
                "dashboard. An assistant can do the code side (move it to a server-only environment "
                "variable, take it out of client code, fix `.gitignore`), but must say which key to "
                "rotate and where, and must never print the value. Leave the task open until the "
                "rotation is confirmed.")
DEPLOYED = {
    "firebase": ("**Also check what's live:** the fix changes the rules file in the repo, not what's "
                 "deployed. Deploy it (e.g. `firebase deploy --only firestore:rules`) and confirm in "
                 "the Firebase console. Deploying is for the person to do or approve."),
    "supabase": ("**Also check what's live:** the fix changes the migration, not the database. Apply "
                 "it (e.g. `supabase db push`) and confirm in the Supabase dashboard (Table Editor "
                 "shows RLS status; Advisors lists open tables). Applying it is for the person to do "
                 "or approve."),
}


def _not_a_problem_if(impact: str):
    m = re.search(r"False positive(?: if)?:?\s*(.+?)(?:\n|$)", impact or "")
    return m.group(1).strip() if m else None


def write(path: str, findings: list[Finding], app_name: str, recheck: list[str], full_check: list[str]):
    q = lambda argv: " ".join(shlex.quote(a) for a in argv)
    main = sorted([f for f in findings if f.source in ("custom", "secrets", "config")], key=sort_key)
    deps = [f for f in findings if f.source == "deps" and f.severity in ("critical", "high")
            and f.extra.get("scope") != "dev"]

    L = [f"# Fix tasks: {app_name}", "",
         "Work top to bottom, one task at a time.", "",
         "## How to work this list", "",
         "1. **Confirm before changing code** with the task's *Confirm it's real* steps. If it isn't "
         "a real problem here, say why and move on; don't change code just to silence a scanner.",
         "2. **Make the smallest fix** that follows *Fix*, in the project's existing style. Run the "
         "project's own lint, type check or tests afterwards if it has them.",
         "3. **Re-check** with the command below. The task's `id` should appear under **Fixed**. "
         "Anything listed as **New** was introduced by the change: deal with it before moving on.",
         "4. **Tasks marked *Needs a person*** can't be finished in code: report them back instead "
         "of marking them done.",
         "5. **Don't add entries to `.vibecheck.yml`** to hide a finding unless the person agrees.",
         "6. **Never print or copy secret values** into chat, commits, logs or new files.", "",
         "Re-check after a fix (seconds):", "", "```bash", q(recheck), "```", "",
         "Full re-check when the list is done (adds dependencies and community rules):", "",
         "```bash", q(full_check), "```", ""]
    if not main and not deps:
        L += ["**No tasks.** Nothing that needs fixing was found.", ""]

    n = 0
    deps_written = False
    for f in main + [None]:
        if deps and not deps_written and (f is None or RANK[f.severity] > RANK["high"]):
            deps_written = True
            n += 1
            names = ", ".join(f"`{d.rule}`" for d in deps)
            L += [f"## Task {n} · 🟠 high · Update vulnerable packages that ship with the app", "",
                  "- **id:** `dependencies`", f"- **Packages:** {names}", "",
                  "**Fix:** run `npm audit fix` (never `--force`), then the project's build and tests. "
                  "Packages that need a major-version upgrade are listed in the report; ask before "
                  "upgrading those, since they can break the app.", "",
                  "**Done when:** the full re-check no longer lists these packages.", ""]
        if f is None:
            break
        n += 1
        new = " · 🆕 new since the compared run" if f.status == "new" else ""
        L += [f"## Task {n} · {ICON[f.severity]} {f.severity} · {f.title}", "",
              f"- **id:** `{f.id}`{new}", f"- **Where:** `{f.where()}`", f"- **Rule:** `{f.rule}`", ""]
        if f.kind == "rotate":
            L += [NEEDS_PERSON, ""]
        elif f.kind == "deployed":
            L += [DEPLOYED["firebase" if "firebase" in f.rule else "supabase"], ""]
        if f.snippet:
            L += [f"Flagged: `{f.snippet}`", ""]
        if f.message:
            L += ["**What's wrong:** " + f.message.strip(), ""]
        if f.confirm:
            L += ["**Confirm it's real:** " + f.confirm.strip(), ""]
        fp = _not_a_problem_if(f.impact)
        if fp:
            L += [f"**Not a problem if:** {fp}", ""]
        if f.fix:
            L += ["**Fix:** " + f.fix.strip(), ""]
        done = {"rotate": ", and the person has confirmed the rotation",
                "deployed": ", and the deployed setting matches"}.get(f.kind, "")
        L += [f"**Done when:** the re-check lists `{f.id}` under Fixed{done}.", ""]

    leads = sum(1 for f in findings if f.source == "community")
    if leads:
        L += ["---", "",
              f"Not tasks: {leads} community-rule hits and any dev-only or lower-severity package "
              "advisories. They're in the report as leads to review once these tasks are done.", ""]
    with open(path, "w") as fh:
        fh.write("\n".join(L))
    return n
