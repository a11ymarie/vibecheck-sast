# Fix tasks: demo-app

Work top to bottom, one task at a time.

## How to work this list

1. **Confirm before changing code** with the task's *Confirm it's real* steps. If it isn't a real problem here, say why and move on; don't change code just to silence a scanner.
2. **Make the smallest fix** that follows *Fix*, in the project's existing style. Run the project's own lint, type check or tests afterwards if it has them.
3. **Re-check** with the command below. The task's `id` should appear under **Fixed**. Anything listed as **New** was introduced by the change: deal with it before moving on.
4. **Tasks marked *Needs a person*** can't be finished in code: report them back instead of marking them done.
5. **Don't add entries to `.vibecheck.yml`** to hide a finding unless the person agrees.
6. **Never print or copy secret values** into chat, commits, logs or new files.

Re-check after a fix (seconds):

```bash
vibecheck-sast/vibecheck --quick --compare vibecheck-sast/vibecheck-report/demo-app-20261112-090000/findings.json ~/code/demo-app
```

Full re-check when the list is done (adds dependencies and community rules):

```bash
vibecheck-sast/vibecheck --compare vibecheck-sast/vibecheck-report/demo-app-20261112-090000/findings.json ~/code/demo-app
```

## Task 1 · 🔴 critical · Supabase service role key

- **id:** `91fc269bfaa2`
- **Where:** `.env.local:2`
- **Rule:** `supabase-service-role-key`

**Needs a person:** this credential has to be revoked or rotated in the provider's dashboard. An assistant can do the code side (move it to a server-only environment variable, take it out of client code, fix `.gitignore`), but must say which key to rotate and where, and must never print the value. Leave the task open until the rotation is confirmed.

Flagged: `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJh…[redacted]`

**What's wrong:** A supabase service role key appears to be written into a file git will commit.

**Confirm it's real:** Check that the value is a real, current credential and not a placeholder; `git log -p -- <file>` shows when it was added and whether it was pushed.

**Not a problem if:** it's a placeholder or a deliberately public value.

**Fix:** This key skips Row Level Security: whoever has it can read and change every row in every table. Rotate it in the provider's dashboard first: it's exposed for as long as the old value works, and deleting it from the file doesn't remove it from git history. Then load the new value from a server-side environment variable. Only server code may use it.

**Done when:** the re-check lists `91fc269bfaa2` under Fixed, and the person has confirmed the rotation.

## Task 2 · 🔴 critical · Firebase Security Rules allow public access

- **id:** `2559f0b926b7`
- **Where:** `firestore.rules:6`
- **Rule:** `firebase-rules-open`

**Also check what's live:** the fix changes the rules file in the repo, not what's deployed. Deploy it (e.g. `firebase deploy --only firestore:rules`) and confirm in the Firebase console. Deploying is for the person to do or approve.

Flagged: `allow read, write: if request.time < timestamp.date(2027, 6, 1);`

**What's wrong:** These Security Rules let anyone read or write without signing in: either `if true`, or the 'test mode' date rule, which leaves the database open to the internet until the date passes (and then breaks the app).

**Confirm it's real:** Static: check whether these are the rules actually deployed: Firebase console > Firestore (or Storage) > Rules. Runtime (Web): use the Rules Playground in the console to simulate an unauthenticated read of a user document.

**Not a problem if:** the rules file isn't deployed.

**Fix:** Write rules per collection that check request.auth.uid against the document owner, e.g. allow read, write: if request.auth != null && request.auth.uid == userId;

**Done when:** the re-check lists `2559f0b926b7` under Fixed, and the deployed setting matches.

## Task 3 · 🟠 high · .env file is not ignored by git

- **id:** `85d502101118`
- **Where:** `.env.local`
- **Rule:** `env-file-not-gitignored`

**Needs a person:** this credential has to be revoked or rotated in the provider's dashboard. An assistant can do the code side (move it to a server-only environment variable, take it out of client code, fix `.gitignore`), but must say which key to rotate and where, and must never print the value. Leave the task open until the rotation is confirmed.

Flagged: `.env.local (not in .gitignore)`

**What's wrong:** This .env file contains values, and git will commit it (or already has). Anyone with access to the repository, or to a public fork of it, gets every value inside.

**Confirm it's real:** Static: run git check-ignore -v <file> (no output means it is NOT ignored) and git log --oneline -- <file> (any output means it was committed).

**Not a problem if:** it only holds non-secret settings.

**Fix:** Add .env* (with !.env.example if you keep a template) to .gitignore. If it was ever committed, run git rm --cached <file> and rotate every secret in it; removing it later does not remove it from history.

**Done when:** the re-check lists `85d502101118` under Fixed, and the person has confirmed the rotation.

## Task 4 · 🟠 high · Secret in a browser-exposed environment variable

- **id:** `e700d2d1d114`
- **Where:** `.env.local:3`
- **Rule:** `public-env-secret-name`

**Needs a person:** this credential has to be revoked or rotated in the provider's dashboard. An assistant can do the code side (move it to a server-only environment variable, take it out of client code, fix `.gitignore`), but must say which key to rotate and where, and must never print the value. Leave the task open until the rotation is confirmed.

Flagged: `NEXT_PUBLIC_OPENAI_API_KEY=…[redacted]`

**What's wrong:** Variables starting with NEXT_PUBLIC_, VITE_, EXPO_PUBLIC_, REACT_APP_ or PUBLIC_ are copied into the JavaScript your users download. This variable's name says it holds a secret (a service role key, an AI provider key, a database URL, a password). Anyone can read it from the browser, even if the .env file itself is never committed.

**Confirm it's real:** Static: find where the variable is set (.env.local, your host's environment settings) and what it holds. Runtime (Web): open the deployed site, devtools > Sources, and search the loaded JavaScript for the first few characters of the value.

**Not a problem if:** the value is public by design (e.g. a Supabase anon/publishable key or a Stripe publishable key) and only the name is misleading; rename it.

**Fix:** Rename it without the public prefix so only server code can read it, and move the code that uses it into a server route or server action. Rotate the value, since every deployed build so far has shipped it.

**Done when:** the re-check lists `e700d2d1d114` under Fixed, and the person has confirmed the rotation.

## Task 5 · 🟠 high · File path built from request input (path traversal)

- **id:** `603533d3558b`
- **Where:** `app/api/files/route.ts:7`
- **Rule:** `vc-path-from-request`

Flagged: `const data = await readFile(path.join(process.cwd(), 'uploads', name!))`

**What's wrong:** A file path is built from request input, so a value like ../../.env can read or overwrite files outside the folder you meant (path traversal).

**Confirm it's real:** Locally, send a value containing ../ and see whether a file outside the intended folder is read or written.

**Not a problem if:** the value is checked against an allow-list or reduced to a plain file name first.

**Fix:** Use path.basename() on the value or map an id to a file name yourself, then check that the resolved path still starts with the intended folder.

**Done when:** the re-check lists `603533d3558b` under Fixed.

## Task 6 · 🟠 high · SQL built from strings (SQL injection)

- **id:** `17a2653e938e`
- **Where:** `app/api/notes/route.ts:9`
- **Rule:** `vc-sql-from-strings`

Flagged: `const notes = await prisma.$queryRawUnsafe(`SELECT * FROM "Note" WHERE tag = '${tag}'`)`

**What's wrong:** A SQL query is built by inserting values into the query text. If any of those values can come from a request, someone can change the query (SQL injection) and read or delete data.

**Confirm it's real:** Trace each inserted value back to its source. On a local or staging database only, send a value containing a single quote and see whether the query errors or behaves differently.

**Not a problem if:** every inserted value is a constant or a validated number.

**Fix:** Use placeholders and pass values separately, e.g. db.query('... WHERE id = $1', [id]), or your query builder's parameter API.

**Done when:** the re-check lists `17a2653e938e` under Fixed.

## Task 7 · 🟠 high · Server fetches a URL from the request (SSRF)

- **id:** `c1d3ae42bf8d`
- **Where:** `app/api/preview/route.ts:5`
- **Rule:** `vc-server-fetches-user-url`

Flagged: `const page = await fetch(target!)`

**What's wrong:** Your server fetches a URL that comes from the request. Someone can point it at internal addresses (http://169.254.169.254 for cloud credentials, localhost services) and read the responses (server-side request forgery).

**Confirm it's real:** Locally, send http://127.0.0.1:<some port> or http://169.254.169.254/ as the URL and see whether the server makes the request.

**Not a problem if:** the URL is checked against a fixed list of hosts first.

**Fix:** Allow only specific hosts, and reject private, loopback and link-local addresses after resolving the hostname.

**Done when:** the re-check lists `c1d3ae42bf8d` under Fixed.

## Task 8 · 🟠 high · AI API key exposed in the browser

- **id:** `2bc32f2e15fc`
- **Where:** `app/chat/page.tsx:6`
- **Rule:** `vc-ai-key-in-browser`

**Needs a person:** this credential has to be revoked or rotated in the provider's dashboard. An assistant can do the code side (move it to a server-only environment variable, take it out of client code, fix `.gitignore`), but must say which key to rotate and where, and must never print the value. Leave the task open until the rotation is confirmed.

Flagged: `const openai = new OpenAI({apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY, dangerouslyAllowBrowser: true})`

**What's wrong:** An AI SDK client is created with dangerouslyAllowBrowser: true, so its API key is sent to the browser, where anyone can copy it from devtools and spend your credits.

**Confirm it's real:** Check that this file runs in the browser (a "use client" component, a Vite/React SPA, an Expo app) and that the apiKey is a real provider key. In the running app, open devtools > Network, use the AI feature, and look for requests going straight to the provider.

**Not a problem if:** the code only ever runs server-side.

**Fix:** Move the AI call into a server route or server action that reads the key from a server-only environment variable, call that route from the page, and rotate the key.

**Done when:** the re-check lists `2bc32f2e15fc` under Fixed, and the person has confirmed the rotation.

## Task 9 · 🟠 high · Password hashed with a fast hash

- **id:** `d7f24c89a70c`
- **Where:** `lib/accounts.ts:10`
- **Rule:** `vc-fast-hash-for-password`

Flagged: `crypto.createHash('sha256').update(password).digest('hex')`

**What's wrong:** A password is hashed with a fast hash (MD5, SHA-1, SHA-256...). Fast hashes can be guessed billions of times per second, so a leaked database gives up most passwords quickly.

**Confirm it's real:** Check that the hashed value is a user's password (not a checksum or cache key).

**Not a problem if:** a non-password value with a password-like name.

**Fix:** Use bcrypt, scrypt or argon2 (e.g. await bcrypt.hash(password, 12)), or let your auth provider (Supabase Auth, Clerk, Auth.js) handle passwords.

**Done when:** the re-check lists `d7f24c89a70c` under Fixed.

## Task 10 · 🟠 high · Hard-coded secret or secret fallback

- **id:** `c001796e75a0`
- **Where:** `lib/auth.ts:4`
- **Rule:** `vc-secret-fallback`

Flagged: `const TOKEN_SECRET = process.env.TOKEN_SECRET || 'demo-app-token-secret'`

**What's wrong:** A secret has a hard-coded value: either a fallback such as process.env.JWT_SECRET || '...', or a literal passed to jwt.sign / jwt.verify. If the environment variable is ever missing (a typo, a new preview deployment), the app quietly uses a value anyone with the code knows, and for a signing secret that means anyone can forge a login.

**Confirm it's real:** Find what the value protects (token signing, encryption, an API). Then run the app locally with the variable unset: if it still starts and logins work, production would too.

**Not a problem if:** the value isn't secret, or it's test-only code.

**Fix:** Remove the fallback and stop at startup when the variable is missing, e.g. if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET is not set'). Rotate the value if it was ever used in production.

**Done when:** the re-check lists `c001796e75a0` under Fixed.

## Task 11 · 🟠 high · JWT read without checking its signature

- **id:** `8499583a74ba`
- **Where:** `lib/auth.ts:9`
- **Rule:** `vc-jwt-not-verified`

Flagged: `const claims = jwt.decode(req.headers.get('authorization') ?? '') as {sub?: string} | null`

**What's wrong:** jwt.decode reads a token's claims without checking its signature, so anyone can make a token with any user id or role. That's only safe if the token was verified earlier on the same request.

**Confirm it's real:** Check whether jwt.verify (or your auth library) runs on the same token before this. On a local copy, send a token with an edited payload and a wrong signature.

**Not a problem if:** the token was verified earlier on the same request.

**Fix:** Use jwt.verify(token, secret, { algorithms: ['HS256'] }) (or your auth provider's SDK) and use the claims it returns.

**Done when:** the re-check lists `8499583a74ba` under Fixed.

## Task 12 · 🟠 high · Secret in a browser-exposed environment variable

- **id:** `fed49e705cec`
- **Where:** `lib/supabase-admin.ts:6`
- **Rule:** `public-env-secret-name`

**Needs a person:** this credential has to be revoked or rotated in the provider's dashboard. An assistant can do the code side (move it to a server-only environment variable, take it out of client code, fix `.gitignore`), but must say which key to rotate and where, and must never print the value. Leave the task open until the rotation is confirmed.

Flagged: `process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!,`

**What's wrong:** Variables starting with NEXT_PUBLIC_, VITE_, EXPO_PUBLIC_, REACT_APP_ or PUBLIC_ are copied into the JavaScript your users download. This variable's name says it holds a secret (a service role key, an AI provider key, a database URL, a password). Anyone can read it from the browser, even if the .env file itself is never committed.

**Confirm it's real:** Static: find where the variable is set (.env.local, your host's environment settings) and what it holds. Runtime (Web): open the deployed site, devtools > Sources, and search the loaded JavaScript for the first few characters of the value.

**Not a problem if:** the value is public by design (e.g. a Supabase anon/publishable key or a Stripe publishable key) and only the name is misleading; rename it.

**Fix:** Rename it without the public prefix so only server code can read it, and move the code that uses it into a server route or server action. Rotate the value, since every deployed build so far has shipped it.

**Done when:** the re-check lists `fed49e705cec` under Fixed, and the person has confirmed the rotation.

## Task 13 · 🟠 high · TLS certificate checking turned off

- **id:** `0cdb062b2bf3`
- **Where:** `server/worker.js:12`
- **Rule:** `vc-tls-check-off`

Flagged: `const pool = new Pool({connectionString: process.env.DATABASE_URL, ssl: {rejectUnauthorized: false}})`

**What's wrong:** TLS certificate checking is turned off, so anyone on the network path can impersonate the server this code talks to and read or change the traffic, including credentials.

**Confirm it's real:** Check whether this code runs in production and what it connects to (database, payment provider, internal API).

**Fix:** Remove the override. For a database with a private certificate authority, pass its CA certificate (ssl: { ca: ... }) instead of disabling checks.

**Done when:** the re-check lists `0cdb062b2bf3` under Fixed.

## Task 14 · 🟠 high · SQL built from strings (SQL injection)

- **id:** `5e4b745d3a4f`
- **Where:** `server/worker.js:18`
- **Rule:** `vc-sql-from-strings`

Flagged: `const {rows} = await pool.query(`SELECT id, name FROM projects WHERE owner = '${req.query.owner}'`)`

**What's wrong:** A SQL query is built by inserting values into the query text. If any of those values can come from a request, someone can change the query (SQL injection) and read or delete data.

**Confirm it's real:** Trace each inserted value back to its source. On a local or staging database only, send a value containing a single quote and see whether the query errors or behaves differently.

**Not a problem if:** every inserted value is a constant or a validated number.

**Fix:** Use placeholders and pass values separately, e.g. db.query('... WHERE id = $1', [id]), or your query builder's parameter API.

**Done when:** the re-check lists `5e4b745d3a4f` under Fixed.

## Task 15 · 🟠 high · Shell command built from strings (command injection)

- **id:** `b84e0a8466e8`
- **Where:** `server/worker.js:23`
- **Rule:** `vc-shell-command-from-input`

Flagged: `exec(`convert uploads/${req.body.file} -resize 200x200 thumbs/${req.body.file}`, err =>`

**What's wrong:** A shell command is built by inserting values into the command string. A value containing characters like ; or $( ) can run extra commands on your server.

**Confirm it's real:** Trace the inserted values to their source. Locally, pass a value such as "x; id" and see whether the extra command runs.

**Not a problem if:** all inserted values are constants.

**Fix:** Use execFile/spawn with an argument array (no shell), and validate the values against an allow-list.

**Done when:** the re-check lists `b84e0a8466e8` under Fixed.

## Task 16 · 🟠 high · Code run from a string (eval)

- **id:** `12cbadfc63a0`
- **Where:** `server/worker.js:28`
- **Rule:** `vc-dynamic-code`

Flagged: `res.json({result: eval(req.body.expression)})`

**What's wrong:** Code is built and run at runtime with eval or new Function. If any part of it can come from a request, someone can run their own code on your server or in your users' browsers.

**Confirm it's real:** Find where the evaluated string comes from. If any of it is user input, it's real.

**Not a problem if:** the string is a constant.

**Fix:** Don't evaluate strings. Parse data with JSON.parse, or map allowed operations to functions in a lookup table.

**Done when:** the re-check lists `12cbadfc63a0` under Fixed.

## Task 17 · 🟠 high · Supabase table created without Row Level Security

- **id:** `3bf64adc0494`
- **Where:** `supabase/migrations/0001_init.sql:15`
- **Rule:** `supabase-table-without-rls`

**Also check what's live:** the fix changes the migration, not the database. Apply it (e.g. `supabase db push`) and confirm in the Supabase dashboard (Table Editor shows RLS status; Advisors lists open tables). Applying it is for the person to do or approve.

Flagged: `create table public.invoices`

**What's wrong:** This table is created in a SQL migration, but no migration enables Row Level Security on it. Without RLS, anyone with your public anon key, which is in your front-end code by design, can read and change every row through the Supabase API.

**Confirm it's real:** Static: search your migrations for ALTER TABLE <name> ENABLE ROW LEVEL SECURITY. RLS can also be turned on in the dashboard, so check there: Table Editor shows 'RLS disabled' on unprotected tables, and the Security Advisor lists them. Runtime (Web): with only the anon key, run supabase.from('<table>').select('*') from a browser console and check whether rows come back.

**Not a problem if:** RLS is enabled in the dashboard or a later migration under another name, or the table is not exposed through the API (e.g. in a private schema).

**Fix:** Add ALTER TABLE <name> ENABLE ROW LEVEL SECURITY; and policies that limit rows to their owner, e.g. USING (auth.uid() = user_id).

**Done when:** the re-check lists `3bf64adc0494` under Fixed, and the deployed setting matches.

## Task 18 · 🟠 high · Update vulnerable packages that ship with the app

- **id:** `dependencies`
- **Packages:** `next`, `axios`, `body-parser`, `express`, `jsonwebtoken`, `lodash`, `path-to-regexp`, `postcss`, `qs`, `zod`

**Fix:** run `npm audit fix` (never `--force`), then the project's build and tests. Packages that need a major-version upgrade are listed in the report; ask before upgrading those, since they can break the app.

**Done when:** the full re-check no longer lists these packages.

## Task 19 · 🟡 medium · Request body saved to the database as-is (mass assignment)

- **id:** `97d2988a1035`
- **Where:** `app/api/notes/route.ts:15`
- **Rule:** `vc-mass-assignment`

Flagged: `const note = await prisma.note.update({where: {id: changes.id}, data: changes})`

**What's wrong:** The whole request body is written to the database. A user can add fields you didn't intend to accept, such as role: "admin", credits, or another user's id.

**Confirm it's real:** Look at the table or model: if it has columns users must not set themselves (role, is_admin, plan, owner id, balance), send one of them in the request and see if it sticks.

**Not a problem if:** the body is validated with a strict schema first.

**Fix:** Pick the allowed fields explicitly ({ name, bio }) or validate with a schema (e.g. zod) that rejects unknown keys.

**Done when:** the re-check lists `97d2988a1035` under Fixed.

## Task 20 · 🟡 medium · Redirect target taken from the request (open redirect)

- **id:** `b42cf54b7666`
- **Where:** `app/auth/callback/route.ts:6`
- **Rule:** `vc-open-redirect`

Flagged: `return NextResponse.redirect(back ?? '/')`

**What's wrong:** Users are redirected to an address taken from the request, so a link to your site can send people to any other site, which makes phishing links look trustworthy.

**Confirm it's real:** Open the route with the parameter set to https://example.org and see whether the browser ends up there.

**Not a problem if:** the value is checked against known paths first.

**Fix:** Only redirect to relative paths starting with a single "/", or to a fixed list of destinations.

**Done when:** the re-check lists `b42cf54b7666` under Fixed.

## Task 21 · 🟡 medium · HTML inserted without sanitizing (XSS)

- **id:** `625869f93dba`
- **Where:** `components/Bio.tsx:6`
- **Rule:** `vc-unsanitized-html`

Flagged: `<div dangerouslySetInnerHTML={{__html: profile.bioHtml}} />`

**What's wrong:** HTML is inserted into the page with dangerouslySetInnerHTML without being sanitized. If the content can come from a user, it can run scripts in other users' browsers (XSS).

**Confirm it's real:** Find where the HTML comes from. If a user can write it (bio, comment, message), save <img src=x onerror=alert(1)> locally and view it.

**Not a problem if:** the HTML is your own static content.

**Fix:** Render it as text, or sanitize it first: dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}.

**Done when:** the re-check lists `625869f93dba` under Fixed.

## Task 22 · 🟡 medium · Guessable token made with Math.random()

- **id:** `82a2373cfc4b`
- **Where:** `lib/accounts.ts:5`
- **Rule:** `vc-predictable-token`

Flagged: `const resetCode = Math.random().toString(36).slice(2, 10)`

**What's wrong:** Math.random() is used to make a token or code. It isn't designed to be unpredictable, so reset links, invite codes or one-time passwords made this way can be guessed.

**Confirm it's real:** Check what the value is used for. Password reset, login, invite, verification and API tokens matter; UI ids and animations don't.

**Not a problem if:** it's not security related.

**Fix:** Use crypto.randomUUID() or crypto.randomBytes(32).toString('hex') (Node), or crypto.getRandomValues() in the browser.

**Done when:** the re-check lists `82a2373cfc4b` under Fixed.

## Task 23 · 🟡 medium · Login token stored in localStorage

- **id:** `25398cca6202`
- **Where:** `lib/session.ts:4`
- **Rule:** `vc-token-in-localstorage`

Flagged: `localStorage.setItem('refresh_token', session.refresh_token)`

**What's wrong:** A login or session token is stored in localStorage, where any script on the page can read it. One cross-site scripting bug, or one compromised npm package, is enough to steal it.

**Confirm it's real:** Check what's stored: open devtools > Application > Local Storage after logging in. A refresh token or long-lived token matters most.

**Not a problem if:** a non-secret value with a token-like name.

**Fix:** Keep the session in an httpOnly, Secure, SameSite cookie set by your server (Supabase and most auth libraries support this), and don't store tokens in localStorage.

**Done when:** the re-check lists `25398cca6202` under Fixed.

## Task 24 · 🟡 medium · Supabase filter built from input

- **id:** `14a62c2faa07`
- **Where:** `lib/supabase-admin.ts:10`
- **Rule:** `vc-supabase-filter-injection`

Flagged: `supabaseAdmin.from('projects').select('*').or(`name.ilike.%${term}%,summary.ilike.%${term}%`)`

**What's wrong:** A Supabase .or() filter is built with string interpolation. Filter strings are a small query language, so a value containing a comma or parenthesis can add conditions, for example widening a search to rows the user shouldn't see.

**Confirm it's real:** Trace the interpolated value to its source, and check which client runs the query: one made with the service role key skips Row Level Security. In the app, try a search value like x,id.gt.0 and see whether extra rows come back.

**Not a problem if:** the value is constant or strictly validated.

**Fix:** Use the typed filter methods (.ilike('title', `%${q}%`), .eq('id', id)) instead of a raw filter string, or strip , ( ) and " from the value first.

**Done when:** the re-check lists `14a62c2faa07` under Fixed.

## Task 25 · 🟡 medium · CORS lets any website make logged-in requests

- **id:** `b849e98797f0`
- **Where:** `server/worker.js:10`
- **Rule:** `vc-cors-any-origin-with-cookies`

Flagged: `app.use(cors({origin: true, credentials: true}))`

**What's wrong:** CORS reflects any website's origin and allows credentials, so any site a logged-in user visits can call your API as that user and read the responses.

**Confirm it's real:** Check whether the API uses cookie sessions. Run curl -si -H 'Origin: https://example.org' against an API route and look for that origin echoed back with Access-Control-Allow-Credentials: true.

**Not a problem if:** a fully public API with no cookies.

**Fix:** Set origin to your own front-end URLs, e.g. origin: ['https://yourapp.com'].

**Done when:** the re-check lists `b849e98797f0` under Fixed.

## Task 26 · 🟡 medium · Hard-coded secret

- **id:** `c0c13f90f0bd`
- **Where:** `server/worker.js:15`
- **Rule:** `hardcoded-secret`

**Needs a person:** this credential has to be revoked or rotated in the provider's dashboard. An assistant can do the code side (move it to a server-only environment variable, take it out of client code, fix `.gitignore`), but must say which key to rotate and where, and must never print the value. Leave the task open until the rotation is confirmed.

Flagged: `const billing = {accountId: 'acct_demo', apiSecret: 'Zt7w…[redacted]'}`

**What's wrong:** A hard-coded secret appears to be written into a file git will commit.

**Confirm it's real:** Check that the value is a real, current credential and not a placeholder; `git log -p -- <file>` shows when it was added and whether it was pushed.

**Not a problem if:** it's a placeholder or a deliberately public value.

**Fix:** Rotate it in the provider's dashboard first: it's exposed for as long as the old value works, and deleting it from the file doesn't remove it from git history. Then load the new value from a server-side environment variable.

**Done when:** the re-check lists `c0c13f90f0bd` under Fixed, and the person has confirmed the rotation.

## Task 27 · 🟡 medium · Supabase write policy allows everyone

- **id:** `db0f88dee46e`
- **Where:** `supabase/migrations/0001_init.sql:11`
- **Rule:** `supabase-permissive-policy`

**Also check what's live:** the fix changes the migration, not the database. Apply it (e.g. `supabase db push`) and confirm in the Supabase dashboard (Table Editor shows RLS status; Advisors lists open tables). Applying it is for the person to do or approve.

Flagged: `create policy "projects are editable" on public.projects for update using (true);`

**What's wrong:** An RLS policy for writes uses USING (true) or WITH CHECK (true), which turns RLS on but lets any caller (often including anonymous users) insert, update or delete rows.

**Confirm it's real:** Static: read the policy's command (ALL/INSERT/UPDATE/DELETE) and roles (TO anon, authenticated). Runtime (Web): as a different user, try to update a row you don't own.

**Not a problem if:** the table is intentionally world-writable (e.g. an anonymous feedback form with insert only).

**Fix:** Replace true with an ownership check, e.g. USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id).

**Done when:** the re-check lists `db0f88dee46e` under Fixed, and the deployed setting matches.

---

Not tasks: 1 community-rule hits and any dev-only or lower-severity package advisories. They're in the report as leads to review once these tasks are done.
