# demo-app

A deliberately insecure app for trying vibecheck-sast. **It doesn't run and must never be
deployed.** It looks like a typical AI-built project: a Next.js app with Supabase, Prisma and
OpenAI, a small Express worker, Supabase migrations and Firebase rules, with common mistakes
planted throughout:

| Check | Planted mistakes |
| --- | --- |
| Rules | OpenAI key in the browser, hard-coded token secret, Prisma and `pg` SQL built from strings, Supabase filter injection, request body saved as-is, link-preview SSRF, file path from the URL, open redirect after login, unsanitized HTML, unverified JWT, refresh token in `localStorage`, `Math.random()` reset codes, SHA-256 password hashing, shell command and `eval` from input, TLS checks off, credentialed CORS from anywhere, token in a URL |
| Configuration | Service role key in a `NEXT_PUBLIC_` variable, a table without Row Level Security, an update policy open to everyone, Firestore "test mode" rules, and (added by `demo.sh`) an `.env.local` that git doesn't ignore |
| Secrets | A hard-coded API secret in `server/worker.js`, plus keys that `demo.sh` writes into `.env.local` at run time |
| Dependencies | Old versions of `next`, `axios`, `jsonwebtoken`, `lodash` and `express` |

`.vibecheck.yml` shows how to ignore a finding with a reason. Every credential here, and every
one `demo.sh` generates, is made up and was never valid anywhere.
