# Example: a real `/vibecheck` run

An actual run of the `/vibecheck` Claude Code skill on a practice copy of
[`examples/demo-app`](../examples/demo-app), made with `./demo.sh --playground`. Nothing was edited
by hand. Nobody was there to answer questions, so the skill's rules limited it to the critical and
high findings.

```bash
./demo.sh --playground ../vibecheck-playground
./vibecheck init --only claude ../vibecheck-playground
cd ../vibecheck-playground
claude -p "/vibecheck  Nobody is available to answer questions during this run." \
  --allowedTools "Bash,Read,Edit,Write,Glob,Grep,Skill" --permission-mode acceptEdits
```

## Before and after

A full scan of the untouched copy, then a full scan after the run, compared:

```
🔴 0 critical  🟠 0 high  🟡 9 medium  ⚪ 0 low   (+13 vulnerable packages, 3 leads)
Since 2026-11-12 00:28: ✅ 17 fixed, ⏳ 23 still open, 🆕 2 new (2 of them community-rule leads)
```

Before: 2 critical and 15 high. After: none. The 9 medium findings were left for approval, as the
workflow says, and the dependency upgrades need a decision (see below). The 2 new items are
low-confidence community-rule leads on the rewritten file route, which Claude reviewed and
explained as false positives without hiding them.

```
 .gitignore                                 |  2 +
 app/api/chat/route.ts                      | new: server-side proxy for the AI call
 app/api/files/route.ts                     |  7 +-
 app/api/notes/route.ts                     |  2 +-
 app/api/preview/route.ts                   | 80 ++++++-
 app/chat/page.tsx                          | 13 +-
 firestore.rules                            |  6 +-
 lib/accounts.ts                            | 16 +-
 lib/auth.ts                                | 16 +-
 lib/supabase-admin.ts                      |  4 +-
 server/worker.js                           | 51 ++++-
 supabase/migrations/0002_invoices_rls.sql  | new: RLS for the invoices table
```

## What the fixes look like

The token secret now fails fast, and tokens are verified instead of decoded:

```diff
-const TOKEN_SECRET = process.env.TOKEN_SECRET || 'demo-app-token-secret'
+if (!process.env.TOKEN_SECRET) throw new Error('TOKEN_SECRET is not set')
...
-  const claims = jwt.decode(req.headers.get('authorization') ?? '') as {sub?: string} | null
+    const claims = jwt.verify(token, TOKEN_SECRET, {algorithms: ['HS256']}) as {sub?: string}
```

The unprotected table got Row Level Security in a new migration, scoped to project owners:

```sql
alter table public.invoices enable row level security;

create policy "project owners can read invoices" on public.invoices
  for select to authenticated
  using (exists (select 1 from public.projects p
                 where p.id = invoices.project_id and p.owner = auth.uid()));
```

The OpenAI call moved into a server route, passwords moved from SHA-256 to salted scrypt, the
`eval` became a small arithmetic parser, the shell command runs without a shell, both SQL queries
use parameters, TLS checks are back on, and Firestore's test-mode rules became deny-all (the app
has no Firestore code).

## The loop caught a bad fix

Claude's first fix for the link-preview SSRF checked the URL's address and *then* fetched it. That
leaves a DNS-rebinding gap: the name can resolve to a safe address for the check and an internal
one for the request. The re-check flagged the rewritten route as 🆕, and Claude rewrote it to
block internal addresses at connection time, with no redirects, a timeout and a size limit, then
tested it against localhost, `::1` and `169.254.169.254`. That's the scan → fix → re-check loop
doing its job.

## What it handed back

From Claude's summary:

> **Needs you**
> - **Rotate keys.** The Supabase service role key (Supabase dashboard → Project Settings → API)
>   and the OpenAI key (OpenAI dashboard → API keys). Both were in browser-exposed variables, so
>   any build that shipped them leaked them. Also rename these variables in your hosting
>   provider's environment settings.
> - **Deploy.** `firebase deploy --only firestore:rules` and `supabase db push` for the new
>   migration. I didn't run either.
> - **Upgrade dependencies.** `npm audit fix` changed nothing because every version is pinned
>   exactly. Most fixes stay within the same major version (next 13.4.0 → 13.5.11, express
>   4.17.1 → 4.22.3, axios 0.21.1 → 0.21.4, lodash 4.17.20 → 4.18.1); jsonwebtoken 8 → 9 is a
>   major upgrade and needs a decision.
>
> **Still open:** 9 medium findings waiting for your go-ahead.
>
> None of the scanned code or comments contained instructions aimed at me.

It didn't print a secret, commit, deploy, use `--force`, or add ignore entries.

## What a reviewer would still ask for

The new `/api/chat` route keeps the OpenAI key on the server, but it has no authentication or
rate limit, so anyone could still spend the credits through it. No scanner will flag that: it's a
logic problem, not a pattern. That's why the report and the skill both end by telling you to test
access control yourself.
