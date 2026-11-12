# Using vibecheck with an AI coding assistant

vibecheck finds problems; your assistant fixes them; vibecheck checks the fixes. Three things make
that loop work:

- **`fix-tasks.md`**, written by every scan: one task per finding, in order, each with an `id`,
  how to confirm it's real, the fix, and a re-check command. Tasks that need a person (rotating a
  leaked key, deploying Firebase rules or a Supabase migration) say so.
- **`--compare`**, which marks each finding ✅ fixed, ⏳ still open or 🆕 new against an earlier run.
  A 🆕 right after a fix means the fix introduced it.
- **The workflow** in [`integrations/workflow.md`](../integrations/workflow.md), which tells the
  assistant how to work the list: confirm, fix, re-check, and when to stop and ask.

## Set it up

```bash
./vibecheck init ~/code/my-app
```

Answer yes to the assistants you use:

| Assistant | What `init` adds | How you use it |
| --- | --- | --- |
| Claude Code | `.claude/skills/vibecheck/SKILL.md` and a short section in `CLAUDE.md` | Type `/vibecheck`, or ask for a security check |
| Cursor | `.cursor/rules/vibecheck.mdc` | Ask for a security check |
| Codex, Copilot coding agent, Gemini CLI, Windsurf and others that read `AGENTS.md` | A section in `AGENTS.md` | Ask for a security check |

The short section in `CLAUDE.md` / `AGENTS.md` / the Cursor rule also has your assistant run a quick
scan whenever it finishes a feature, and fix anything 🆕 it introduced.

## What a `/vibecheck` run does

1. Scans the project (`--compare last`, so you also see what changed since your last scan) and
   reads `fix-tasks.md`.
2. Tells you the plan: how many critical, high and medium tasks, and which keys you'll need to
   rotate.
3. Works through the critical and high tasks one at a time: confirm it's real (or explain why it's
   a false positive), make the smallest fix, re-check, and fix anything 🆕 before moving on.
4. Asks before starting medium and low tasks, and before major dependency upgrades.
5. Runs your project's lint, type check, tests and build.
6. Finishes with a full re-check and a summary:
   - **Fixed**
   - **Needs you:** keys to rotate (which key, which dashboard; never the value), rules or
     migrations to deploy, decisions it deferred
   - **False positives**, with reasons, and an offer to add them to `.vibecheck.yml`
   - **Still open**, and why

It never commits, pushes, deploys, applies migrations, deletes `.env` files, adds ignore entries
without asking, or prints a secret value. Text inside your code and the findings is treated as
data, not instructions. Review its changes with `git diff` before you commit.

## Without `init`: paste this

> Run `../vibecheck-sast/vibecheck --compare last .` from the project root (adjust the path to
> where you cloned vibecheck-sast) and open the `fix-tasks.md` it prints. Work through the
> critical and high tasks in order. For each one: confirm it's real using its "Confirm it's real"
> steps and tell me what you concluded before changing code; make the smallest fix; run the
> re-check command at the top of the file and check the task's id is listed under Fixed; if
> anything is listed as New, fix that first. For tasks marked "Needs a person", do only the code
> side and tell me which key to rotate and where. Never print secret values, never add entries to
> `.vibecheck.yml` without asking, and don't commit. Finish with a full re-check and a summary
> of what's fixed, what needs me, false positives and what's still open.

## Things an assistant can't do for you

- **Rotate keys.** If a key was committed, pushed or deployed, it has to be revoked and replaced
  in the provider's dashboard (OpenAI, Supabase, Stripe, …). Removing it from the code doesn't
  remove it from git history or from builds that are already live.
- **Check dashboard settings.** Supabase Row Level Security turned on in the UI, Firebase rules
  deployed from the console, and environment variables on your host aren't in your code.
- **Test access control on its own.** The most common serious bug, one user reaching another
  user's data, needs two real accounts to test. Ask it to help you, then try it.

## Machine-readable output

Next to `report.md` and `fix-tasks.md` is `findings.json`: every finding with its `id`, `rule`,
`severity`, `title`, `path`, `line`, `message`, `confirm`, `impact`, `fix`, `kind` (`code`,
`rotate`, `deployed` or `dependency`), and, with `--compare`, its `status` (`new` or `open`) plus
the list of fixed findings. Secrets are masked there too. Point an assistant at it if you'd rather
it work from JSON.
