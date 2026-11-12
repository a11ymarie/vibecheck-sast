# Security report: demo-app

*2026-11-12 01:00:59 · full scan · vibecheck-sast*

| 🔴 Critical | 🟠 High | 🟡 Medium | ⚪ Low |
| --- | --- | --- | --- |
| 2 | 15 | 9 | 0 |

Also: 13 vulnerable packages (10 critical or high that ship with the app) · 1 community-rule lead · 1 ignored by `.vibecheck.yml`.

> Confirm each finding before fixing it: a scanner finds patterns, not proof. For an exposed key, **rotate it first** in the provider's dashboard. `fix-tasks.md` next to this report has the same findings as a step-by-step list for you or your AI assistant (in Claude Code: `/vibecheck`).

## Start here

1. 🔴 [Supabase service role key](#finding-91fc269bfaa2) — `.env.local:2`
1. 🔴 [Firebase Security Rules allow public access](#finding-2559f0b926b7) — `firestore.rules:6`
1. 🟠 [.env file is not ignored by git](#finding-85d502101118) — `.env.local`
1. 🟠 [Secret in a browser-exposed environment variable](#finding-e700d2d1d114) — `.env.local:3`
1. 🟠 [File path built from request input (path traversal)](#finding-603533d3558b) — `app/api/files/route.ts:7`
1. 🟠 [SQL built from strings (SQL injection)](#finding-17a2653e938e) — `app/api/notes/route.ts:9`
1. 🟠 [Server fetches a URL from the request (SSRF)](#finding-c1d3ae42bf8d) — `app/api/preview/route.ts:5`
1. 🟠 [AI API key exposed in the browser](#finding-2bc32f2e15fc) — `app/chat/page.tsx:6`
1. 🟠 [Password hashed with a fast hash](#finding-d7f24c89a70c) — `lib/accounts.ts:10`
1. 🟠 [Hard-coded secret or secret fallback](#finding-c001796e75a0) — `lib/auth.ts:4`
1. 🟠 [JWT read without checking its signature](#finding-8499583a74ba) — `lib/auth.ts:9`
1. 🟠 [Secret in a browser-exposed environment variable](#finding-fed49e705cec) — `lib/supabase-admin.ts:6`
1. 🟠 [TLS certificate checking turned off](#finding-0cdb062b2bf3) — `server/worker.js:12`
1. 🟠 [SQL built from strings (SQL injection)](#finding-5e4b745d3a4f) — `server/worker.js:18`
1. 🟠 [Shell command built from strings (command injection)](#finding-b84e0a8466e8) — `server/worker.js:23`
1. 🟠 [Code run from a string (eval)](#finding-12cbadfc63a0) — `server/worker.js:28`
1. 🟠 [Supabase table created without Row Level Security](#finding-3bf64adc0494) — `supabase/migrations/0001_init.sql:15`
1. 🟠 Update 10 vulnerable package(s) that ship with the app ([list](#vulnerable-packages))

## Findings

<a id="finding-91fc269bfaa2"></a>

### 🔴 Supabase service role key

`.env.local:2` · rule `supabase-service-role-key` · id `91fc269bfaa2` · CWE-798 · also flagged by config

```
NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJh…[redacted]
```

A supabase service role key appears to be written into a file git will commit.

**How serious:** High if it's real and was ever pushed or deployed. False positive if it's a placeholder or a deliberately public value.

**Confirm it:** Check that the value is a real, current credential and not a placeholder; `git log -p -- <file>` shows when it was added and whether it was pushed.

**Fix:** This key skips Row Level Security: whoever has it can read and change every row in every table. Rotate it in the provider's dashboard first: it's exposed for as long as the old value works, and deleting it from the file doesn't remove it from git history. Then load the new value from a server-side environment variable. Only server code may use it.

<a id="finding-2559f0b926b7"></a>

### 🔴 Firebase Security Rules allow public access

`firestore.rules:6` · rule `firebase-rules-open` · id `2559f0b926b7` · CWE-284: Improper Access Control

```
allow read, write: if request.time < timestamp.date(2027, 6, 1);
```

These Security Rules let anyone read or write without signing in: either `if true`, or the 'test mode' date rule, which leaves the database open to the internet until the date passes (and then breaks the app).

**How serious:** Critical: user data in this database can be read or wiped by anyone. False positive: the rules file isn't deployed.

**Confirm it:** Static: check whether these are the rules actually deployed: Firebase console > Firestore (or Storage) > Rules. Runtime (Web): use the Rules Playground in the console to simulate an unauthenticated read of a user document.

**Fix:** Write rules per collection that check request.auth.uid against the document owner, e.g. allow read, write: if request.auth != null && request.auth.uid == userId;

<a id="finding-85d502101118"></a>

### 🟠 .env file is not ignored by git

`.env.local` · rule `env-file-not-gitignored` · id `85d502101118` · CWE-538: Insertion of Sensitive Information into Externally-Accessible File

```
.env.local (not in .gitignore)
```

This .env file contains values, and git will commit it (or already has). Anyone with access to the repository, or to a public fork of it, gets every value inside.

**How serious:** High: it holds real keys and has been committed or pushed. Medium: not committed yet. False positive: it only holds non-secret settings.

**Confirm it:** Static: run git check-ignore -v <file> (no output means it is NOT ignored) and git log --oneline -- <file> (any output means it was committed).

**Fix:** Add .env* (with !.env.example if you keep a template) to .gitignore. If it was ever committed, run git rm --cached <file> and rotate every secret in it; removing it later does not remove it from history.

<a id="finding-e700d2d1d114"></a>

### 🟠 Secret in a browser-exposed environment variable

`.env.local:3` · rule `public-env-secret-name` · id `e700d2d1d114` · CWE-200: Exposure of Sensitive Information · also flagged by secrets

```
NEXT_PUBLIC_OPENAI_API_KEY=…[redacted]
```

Variables starting with NEXT_PUBLIC_, VITE_, EXPO_PUBLIC_, REACT_APP_ or PUBLIC_ are copied into the JavaScript your users download. This variable's name says it holds a secret (a service role key, an AI provider key, a database URL, a password). Anyone can read it from the browser, even if the .env file itself is never committed.

**How serious:** High: the value is a real secret key or password. False positive: the value is public by design (e.g. a Supabase anon/publishable key or a Stripe publishable key) and only the name is misleading; rename it.

**Confirm it:** Static: find where the variable is set (.env.local, your host's environment settings) and what it holds. Runtime (Web): open the deployed site, devtools > Sources, and search the loaded JavaScript for the first few characters of the value.

**Fix:** Rename it without the public prefix so only server code can read it, and move the code that uses it into a server route or server action. Rotate the value, since every deployed build so far has shipped it.

<a id="finding-603533d3558b"></a>

### 🟠 File path built from request input (path traversal)

`app/api/files/route.ts:7` · rule `vc-path-from-request` · id `603533d3558b` · CWE-22: Path Traversal · also flagged by community

```
const data = await readFile(path.join(process.cwd(), 'uploads', name!))
```

A file path is built from request input, so a value like ../../.env can read or overwrite files outside the folder you meant (path traversal).

**How serious:** High: it reads or writes files with the value. False positive: the value is checked against an allow-list or reduced to a plain file name first.

**Confirm it:** Locally, send a value containing ../ and see whether a file outside the intended folder is read or written.

**Fix:** Use path.basename() on the value or map an id to a file name yourself, then check that the resolved path still starts with the intended folder.

<a id="finding-17a2653e938e"></a>

### 🟠 SQL built from strings (SQL injection)

`app/api/notes/route.ts:9` · rule `vc-sql-from-strings` · id `17a2653e938e` · CWE-89: SQL Injection

```
const notes = await prisma.$queryRawUnsafe(`SELECT * FROM "Note" WHERE tag = '${tag}'`)
```

A SQL query is built by inserting values into the query text. If any of those values can come from a request, someone can change the query (SQL injection) and read or delete data.

**How serious:** High: request input reaches the query. Medium: only admin input or stored data does. False positive: every inserted value is a constant or a validated number.

**Confirm it:** Trace each inserted value back to its source. On a local or staging database only, send a value containing a single quote and see whether the query errors or behaves differently.

**Fix:** Use placeholders and pass values separately, e.g. db.query('... WHERE id = $1', [id]), or your query builder's parameter API.

<a id="finding-c1d3ae42bf8d"></a>

### 🟠 Server fetches a URL from the request (SSRF)

`app/api/preview/route.ts:5` · rule `vc-server-fetches-user-url` · id `c1d3ae42bf8d` · CWE-918: Server-Side Request Forgery

```
const page = await fetch(target!)
```

Your server fetches a URL that comes from the request. Someone can point it at internal addresses (http://169.254.169.254 for cloud credentials, localhost services) and read the responses (server-side request forgery).

**How serious:** High: on servers or containers that can reach internal services or cloud metadata. Medium: on isolated serverless functions. False positive: the URL is checked against a fixed list of hosts first.

**Confirm it:** Locally, send http://127.0.0.1:<some port> or http://169.254.169.254/ as the URL and see whether the server makes the request.

**Fix:** Allow only specific hosts, and reject private, loopback and link-local addresses after resolving the hostname.

<a id="finding-2bc32f2e15fc"></a>

### 🟠 AI API key exposed in the browser

`app/chat/page.tsx:6` · rule `vc-ai-key-in-browser` · id `2bc32f2e15fc` · CWE-522: Insufficiently Protected Credentials · also flagged by config

```
const openai = new OpenAI({apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY, dangerouslyAllowBrowser: true})
```

An AI SDK client is created with dangerouslyAllowBrowser: true, so its API key is sent to the browser, where anyone can copy it from devtools and spend your credits.

**How serious:** High: a real provider key reaches the browser. Medium: it's a short-lived per-user token your server issued. False positive: the code only ever runs server-side.

**Confirm it:** Check that this file runs in the browser (a "use client" component, a Vite/React SPA, an Expo app) and that the apiKey is a real provider key. In the running app, open devtools > Network, use the AI feature, and look for requests going straight to the provider.

**Fix:** Move the AI call into a server route or server action that reads the key from a server-only environment variable, call that route from the page, and rotate the key.

<a id="finding-d7f24c89a70c"></a>

### 🟠 Password hashed with a fast hash

`lib/accounts.ts:10` · rule `vc-fast-hash-for-password` · id `d7f24c89a70c` · CWE-916: Use of Password Hash With Insufficient Computational Effort

```
crypto.createHash('sha256').update(password).digest('hex')
```

A password is hashed with a fast hash (MD5, SHA-1, SHA-256...). Fast hashes can be guessed billions of times per second, so a leaked database gives up most passwords quickly.

**How serious:** High: stored user passwords. False positive: a non-password value with a password-like name.

**Confirm it:** Check that the hashed value is a user's password (not a checksum or cache key).

**Fix:** Use bcrypt, scrypt or argon2 (e.g. await bcrypt.hash(password, 12)), or let your auth provider (Supabase Auth, Clerk, Auth.js) handle passwords.

<a id="finding-c001796e75a0"></a>

### 🟠 Hard-coded secret or secret fallback

`lib/auth.ts:4` · rule `vc-secret-fallback` · id `c001796e75a0` · CWE-798: Use of Hard-coded Credentials

```
const TOKEN_SECRET = process.env.TOKEN_SECRET || 'demo-app-token-secret'
```

A secret has a hard-coded value: either a fallback such as process.env.JWT_SECRET || '...', or a literal passed to jwt.sign / jwt.verify. If the environment variable is ever missing (a typo, a new preview deployment), the app quietly uses a value anyone with the code knows, and for a signing secret that means anyone can forge a login.

**How serious:** High: it signs or encrypts sessions, or the repo is or was public. Medium: production always sets the variable. False positive: the value isn't secret, or it's test-only code.

**Confirm it:** Find what the value protects (token signing, encryption, an API). Then run the app locally with the variable unset: if it still starts and logins work, production would too.

**Fix:** Remove the fallback and stop at startup when the variable is missing, e.g. if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET is not set'). Rotate the value if it was ever used in production.

<a id="finding-8499583a74ba"></a>

### 🟠 JWT read without checking its signature

`lib/auth.ts:9` · rule `vc-jwt-not-verified` · id `8499583a74ba` · CWE-347: Improper Verification of Cryptographic Signature

```
const claims = jwt.decode(req.headers.get('authorization') ?? '') as {sub?: string} | null
```

jwt.decode reads a token's claims without checking its signature, so anyone can make a token with any user id or role. That's only safe if the token was verified earlier on the same request.

**How serious:** High: the claims decide who the user is or what they can do. Medium: they're only displayed. False positive: the token was verified earlier on the same request.

**Confirm it:** Check whether jwt.verify (or your auth library) runs on the same token before this. On a local copy, send a token with an edited payload and a wrong signature.

**Fix:** Use jwt.verify(token, secret, { algorithms: ['HS256'] }) (or your auth provider's SDK) and use the claims it returns.

<a id="finding-fed49e705cec"></a>

### 🟠 Secret in a browser-exposed environment variable

`lib/supabase-admin.ts:6` · rule `public-env-secret-name` · id `fed49e705cec` · CWE-200: Exposure of Sensitive Information

```
process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!,
```

Variables starting with NEXT_PUBLIC_, VITE_, EXPO_PUBLIC_, REACT_APP_ or PUBLIC_ are copied into the JavaScript your users download. This variable's name says it holds a secret (a service role key, an AI provider key, a database URL, a password). Anyone can read it from the browser, even if the .env file itself is never committed.

**How serious:** High: the value is a real secret key or password. False positive: the value is public by design (e.g. a Supabase anon/publishable key or a Stripe publishable key) and only the name is misleading; rename it.

**Confirm it:** Static: find where the variable is set (.env.local, your host's environment settings) and what it holds. Runtime (Web): open the deployed site, devtools > Sources, and search the loaded JavaScript for the first few characters of the value.

**Fix:** Rename it without the public prefix so only server code can read it, and move the code that uses it into a server route or server action. Rotate the value, since every deployed build so far has shipped it.

<a id="finding-0cdb062b2bf3"></a>

### 🟠 TLS certificate checking turned off

`server/worker.js:12` · rule `vc-tls-check-off` · id `0cdb062b2bf3` · CWE-295: Improper Certificate Validation

```
const pool = new Pool({connectionString: process.env.DATABASE_URL, ssl: {rejectUnauthorized: false}})
```

TLS certificate checking is turned off, so anyone on the network path can impersonate the server this code talks to and read or change the traffic, including credentials.

**How serious:** High: production traffic with credentials or user data. Low: local development only.

**Confirm it:** Check whether this code runs in production and what it connects to (database, payment provider, internal API).

**Fix:** Remove the override. For a database with a private certificate authority, pass its CA certificate (ssl: { ca: ... }) instead of disabling checks.

<a id="finding-5e4b745d3a4f"></a>

### 🟠 SQL built from strings (SQL injection)

`server/worker.js:18` · rule `vc-sql-from-strings` · id `5e4b745d3a4f` · CWE-89: SQL Injection · also flagged by community

```
const {rows} = await pool.query(`SELECT id, name FROM projects WHERE owner = '${req.query.owner}'`)
```

A SQL query is built by inserting values into the query text. If any of those values can come from a request, someone can change the query (SQL injection) and read or delete data.

**How serious:** High: request input reaches the query. Medium: only admin input or stored data does. False positive: every inserted value is a constant or a validated number.

**Confirm it:** Trace each inserted value back to its source. On a local or staging database only, send a value containing a single quote and see whether the query errors or behaves differently.

**Fix:** Use placeholders and pass values separately, e.g. db.query('... WHERE id = $1', [id]), or your query builder's parameter API.

<a id="finding-b84e0a8466e8"></a>

### 🟠 Shell command built from strings (command injection)

`server/worker.js:23` · rule `vc-shell-command-from-input` · id `b84e0a8466e8` · CWE-78: OS Command Injection · also flagged by community

```
exec(`convert uploads/${req.body.file} -resize 200x200 thumbs/${req.body.file}`, err =>
```

A shell command is built by inserting values into the command string. A value containing characters like ; or $( ) can run extra commands on your server.

**How serious:** High: request input reaches the command. Medium: only trusted configuration does. False positive: all inserted values are constants.

**Confirm it:** Trace the inserted values to their source. Locally, pass a value such as "x; id" and see whether the extra command runs.

**Fix:** Use execFile/spawn with an argument array (no shell), and validate the values against an allow-list.

<a id="finding-12cbadfc63a0"></a>

### 🟠 Code run from a string (eval)

`server/worker.js:28` · rule `vc-dynamic-code` · id `12cbadfc63a0` · CWE-95: Eval Injection · also flagged by community

```
res.json({result: eval(req.body.expression)})
```

Code is built and run at runtime with eval or new Function. If any part of it can come from a request, someone can run their own code on your server or in your users' browsers.

**How serious:** High: user input reaches it. Medium: only trusted data does. False positive: the string is a constant.

**Confirm it:** Find where the evaluated string comes from. If any of it is user input, it's real.

**Fix:** Don't evaluate strings. Parse data with JSON.parse, or map allowed operations to functions in a lookup table.

<a id="finding-3bf64adc0494"></a>

### 🟠 Supabase table created without Row Level Security

`supabase/migrations/0001_init.sql:15` · rule `supabase-table-without-rls` · id `3bf64adc0494` · CWE-284: Improper Access Control

```
create table public.invoices
```

This table is created in a SQL migration, but no migration enables Row Level Security on it. Without RLS, anyone with your public anon key, which is in your front-end code by design, can read and change every row through the Supabase API.

**How serious:** High: the table holds user data and RLS is off. False positive: RLS is enabled in the dashboard or a later migration under another name, or the table is not exposed through the API (e.g. in a private schema).

**Confirm it:** Static: search your migrations for ALTER TABLE <name> ENABLE ROW LEVEL SECURITY. RLS can also be turned on in the dashboard, so check there: Table Editor shows 'RLS disabled' on unprotected tables, and the Security Advisor lists them. Runtime (Web): with only the anon key, run supabase.from('<table>').select('*') from a browser console and check whether rows come back.

**Fix:** Add ALTER TABLE <name> ENABLE ROW LEVEL SECURITY; and policies that limit rows to their owner, e.g. USING (auth.uid() = user_id).

<a id="finding-97d2988a1035"></a>

### 🟡 Request body saved to the database as-is (mass assignment)

`app/api/notes/route.ts:15` · rule `vc-mass-assignment` · id `97d2988a1035` · CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes

```
const note = await prisma.note.update({where: {id: changes.id}, data: changes})
```

The whole request body is written to the database. A user can add fields you didn't intend to accept, such as role: "admin", credits, or another user's id.

**How serious:** High: the record has permission, billing or ownership fields. Medium: only harmless fields exist today. False positive: the body is validated with a strict schema first.

**Confirm it:** Look at the table or model: if it has columns users must not set themselves (role, is_admin, plan, owner id, balance), send one of them in the request and see if it sticks.

**Fix:** Pick the allowed fields explicitly ({ name, bio }) or validate with a schema (e.g. zod) that rejects unknown keys.

<a id="finding-b42cf54b7666"></a>

### 🟡 Redirect target taken from the request (open redirect)

`app/auth/callback/route.ts:6` · rule `vc-open-redirect` · id `b42cf54b7666` · CWE-601: Open Redirect

```
return NextResponse.redirect(back ?? '/')
```

Users are redirected to an address taken from the request, so a link to your site can send people to any other site, which makes phishing links look trustworthy.

**How serious:** High: part of a login flow that passes tokens along. Medium: elsewhere. False positive: the value is checked against known paths first.

**Confirm it:** Open the route with the parameter set to https://example.org and see whether the browser ends up there.

**Fix:** Only redirect to relative paths starting with a single "/", or to a fixed list of destinations.

<a id="finding-625869f93dba"></a>

### 🟡 HTML inserted without sanitizing (XSS)

`components/Bio.tsx:6` · rule `vc-unsanitized-html` · id `625869f93dba` · CWE-79: Cross-site Scripting

```
<div dangerouslySetInnerHTML={{__html: profile.bioHtml}} />
```

HTML is inserted into the page with dangerouslySetInnerHTML without being sanitized. If the content can come from a user, it can run scripts in other users' browsers (XSS).

**How serious:** High: other users see content one user wrote. Medium: only the author sees it. False positive: the HTML is your own static content.

**Confirm it:** Find where the HTML comes from. If a user can write it (bio, comment, message), save <img src=x onerror=alert(1)> locally and view it.

**Fix:** Render it as text, or sanitize it first: dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}.

<a id="finding-82a2373cfc4b"></a>

### 🟡 Guessable token made with Math.random()

`lib/accounts.ts:5` · rule `vc-predictable-token` · id `82a2373cfc4b` · CWE-338: Use of Cryptographically Weak PRNG

```
const resetCode = Math.random().toString(36).slice(2, 10)
```

Math.random() is used to make a token or code. It isn't designed to be unpredictable, so reset links, invite codes or one-time passwords made this way can be guessed.

**How serious:** High: it grants access (reset link, login code). False positive: it's not security related.

**Confirm it:** Check what the value is used for. Password reset, login, invite, verification and API tokens matter; UI ids and animations don't.

**Fix:** Use crypto.randomUUID() or crypto.randomBytes(32).toString('hex') (Node), or crypto.getRandomValues() in the browser.

<a id="finding-25398cca6202"></a>

### 🟡 Login token stored in localStorage

`lib/session.ts:4` · rule `vc-token-in-localstorage` · id `25398cca6202` · CWE-922: Insecure Storage of Sensitive Information

```
localStorage.setItem('refresh_token', session.refresh_token)
```

A login or session token is stored in localStorage, where any script on the page can read it. One cross-site scripting bug, or one compromised npm package, is enough to steal it.

**How serious:** High: a refresh or long-lived token. Medium: a short-lived access token. False positive: a non-secret value with a token-like name.

**Confirm it:** Check what's stored: open devtools > Application > Local Storage after logging in. A refresh token or long-lived token matters most.

**Fix:** Keep the session in an httpOnly, Secure, SameSite cookie set by your server (Supabase and most auth libraries support this), and don't store tokens in localStorage.

<a id="finding-14a62c2faa07"></a>

### 🟡 Supabase filter built from input

`lib/supabase-admin.ts:10` · rule `vc-supabase-filter-injection` · id `14a62c2faa07` · CWE-943: Improper Neutralization of Special Elements in Data Query Logic

```
supabaseAdmin.from('projects').select('*').or(`name.ilike.%${term}%,summary.ilike.%${term}%`)
```

A Supabase .or() filter is built with string interpolation. Filter strings are a small query language, so a value containing a comma or parenthesis can add conditions, for example widening a search to rows the user shouldn't see.

**How serious:** High: user input reaches it and the client uses the service role key, or the table has no RLS. Medium: RLS limits rows to the current user. False positive: the value is constant or strictly validated.

**Confirm it:** Trace the interpolated value to its source, and check which client runs the query: one made with the service role key skips Row Level Security. In the app, try a search value like x,id.gt.0 and see whether extra rows come back.

**Fix:** Use the typed filter methods (.ilike('title', `%${q}%`), .eq('id', id)) instead of a raw filter string, or strip , ( ) and " from the value first.

<a id="finding-b849e98797f0"></a>

### 🟡 CORS lets any website make logged-in requests

`server/worker.js:10` · rule `vc-cors-any-origin-with-cookies` · id `b849e98797f0` · CWE-942: Permissive Cross-domain Policy

```
app.use(cors({origin: true, credentials: true}))
```

CORS reflects any website's origin and allows credentials, so any site a logged-in user visits can call your API as that user and read the responses.

**How serious:** High: cookie sessions and user data. Medium: header-based auth with some cookie routes. False positive: a fully public API with no cookies.

**Confirm it:** Check whether the API uses cookie sessions. Run curl -si -H 'Origin: https://example.org' against an API route and look for that origin echoed back with Access-Control-Allow-Credentials: true.

**Fix:** Set origin to your own front-end URLs, e.g. origin: ['https://yourapp.com'].

<a id="finding-c0c13f90f0bd"></a>

### 🟡 Hard-coded secret

`server/worker.js:15` · rule `hardcoded-secret` · id `c0c13f90f0bd` · CWE-798

```
const billing = {accountId: 'acct_demo', apiSecret: 'Zt7w…[redacted]'}
```

A hard-coded secret appears to be written into a file git will commit.

**How serious:** High if it's real and was ever pushed or deployed. False positive if it's a placeholder or a deliberately public value.

**Confirm it:** Check that the value is a real, current credential and not a placeholder; `git log -p -- <file>` shows when it was added and whether it was pushed.

**Fix:** Rotate it in the provider's dashboard first: it's exposed for as long as the old value works, and deleting it from the file doesn't remove it from git history. Then load the new value from a server-side environment variable.

<a id="finding-db0f88dee46e"></a>

### 🟡 Supabase write policy allows everyone

`supabase/migrations/0001_init.sql:11` · rule `supabase-permissive-policy` · id `db0f88dee46e` · CWE-284: Improper Access Control

```
create policy "projects are editable" on public.projects for update using (true);
```

An RLS policy for writes uses USING (true) or WITH CHECK (true), which turns RLS on but lets any caller (often including anonymous users) insert, update or delete rows.

**How serious:** High: anyone can change or delete other users' rows. Medium: limited to signed-in users. False positive: the table is intentionally world-writable (e.g. an anonymous feedback form with insert only).

**Confirm it:** Static: read the policy's command (ALL/INSERT/UPDATE/DELETE) and roles (TO anon, authenticated). Runtime (Web): as a different user, try to update a row you don't own.

**Fix:** Replace true with an ownership check, e.g. USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id).

<a id="vulnerable-packages"></a>

## Vulnerable packages (13)

From `npm audit`. Packages that ship with the app matter most; dev-only tools run on your machine and in CI. `npm ls <package>` shows why something is installed.

| Package | Severity | Ships with app | Direct | Fix |
| --- | --- | --- | --- | --- |
| [next](https://github.com/advisories/GHSA-c59h-r6p8-q9wc) | critical | yes | yes | `npm audit fix` |
| [axios](https://github.com/advisories/GHSA-wf5p-g6vw-rhxx) | high | yes | yes | `npm audit fix` |
| [body-parser](https://github.com/advisories/GHSA-qwcr-r2fm-qrc7) | high | yes | no | `npm audit fix` |
| [express](https://github.com/advisories/GHSA-qw6h-vgh9-j6wx) | high | yes | yes | `npm audit fix` |
| [jsonwebtoken](https://github.com/advisories/GHSA-8cf7-32gw-wr33) | high | yes | yes | major upgrade |
| [lodash](https://github.com/advisories/GHSA-35jh-r3h4-6jhm) | high | yes | yes | `npm audit fix` |
| [path-to-regexp](https://github.com/advisories/GHSA-9wv6-86v2-598j) | high | yes | no | `npm audit fix` |
| [postcss](https://github.com/advisories/GHSA-7fh5-64p2-3v2j) | high | yes | no | `npm audit fix` |
| [qs](https://github.com/advisories/GHSA-hrpp-h998-j3pp) | high | yes | no | `npm audit fix` |
| [zod](https://github.com/advisories/GHSA-m95q-7qp3-xv42) | high | yes | no | `npm audit fix` |
| [cookie](https://github.com/advisories/GHSA-pxg6-pf52-xh8x) | low | yes | no | `npm audit fix` |
| [send](https://github.com/advisories/GHSA-m6fv-jmcg-4jfg) | low | yes | no | `npm audit fix` |
| [serve-static](https://github.com/advisories/GHSA-cm22-4g7w-348p) | low | yes | no | `npm audit fix` |

## Community-rule leads (1)

Broader patterns from Semgrep's community rules. Worth a look, but more likely to be false positives than the findings above.

- **Authentication or authorization weakness: express check csurf middleware usage** (low, 1×): `server/worker.js:8`
  - A CSRF middleware was not detected in your express application. Ensure you are either using one such as `csurf` or `csrf` (see rule references) and/or you are properly doing CSRF validation in your routes with a token or
  - Fix: Verify tokens with a pinned algorithm, check the current user's permission on every request, and use your framework's CSRF protection for cookie sessions.

## Ignored by .vibecheck.yml

| Finding | Where | Reason | Until |
| --- | --- | --- | --- |
| Token or key in a URL | `server/worker.js:32` | Example of a scoped ignore: pretend the export link uses a single-use download token that expires in five minutes, not a session token. Only this file is ignored; the rule still runs everywhere else. | 2027-06-30 |

<a id="what-this-scan-cant-see"></a>

## What this scan can't see

- **Whether each user can only reach their own data.** That's the most common serious bug in real apps, and reading code can't settle it. Log in as two different users and try to view or change the other one's records.
- **Settings that live only in a dashboard:** Supabase RLS toggled in the UI, Firebase rules deployed from the console, environment variables on your host.
- **Anything outside this folder**, and languages other than JavaScript/TypeScript for the code rules.
