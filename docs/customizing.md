# Customizing vibecheck

Out of the box, vibecheck is a general security scanner for JavaScript/TypeScript apps:

| Layer | What it is |
| --- | --- |
| **vibecheck rules** | 18 [Semgrep](https://semgrep.dev) rules for the mistakes common in AI-built apps (`rules/vibecheck-rules.yaml`) |
| **Community rules** | Semgrep's own community security rules, pinned, reported as leads |
| **Secret detection** | Provider key formats (OpenAI, Anthropic, Stripe, Supabase, AWS, GitHub…), masked in output |
| **Configuration checks** | `.env` files, Supabase migrations and RLS, Firebase rules, browser-exposed env vars |
| **Dependency audit** | `npm audit`, labeled by whether each package ships with the app |

A general scanner can't know your app's conventions: what your auth helper is called, which
folders are public on purpose, which internal function runs raw SQL, what your company's tokens
look like. This guide shows how to teach it, from simple settings to your own rules.

**Three levels, from least to most effort:**

1. **Settings** in `.vibecheck.yml`: ignore findings, change severities, add your own secret
   formats, turn community rules off. No code.
2. **Your own rules** in your project, listed in `.vibecheck.yml`. They run in the same scan and
   show up in the report, fix tasks, `--compare` and `--fail-on` like built-in ones.
3. **A fork** of vibecheck-sast, to change the defaults for every project you scan.

Most people only need 1 and 2. Working examples of everything here are in
[`examples/custom-rules/`](../examples/custom-rules).

---

## 1. Settings: `.vibecheck.yml`

Put a `.vibecheck.yml` in your app's root (`./vibecheck init` can create one). Every key is
optional:

```yaml
# Your own Semgrep rules: files or folders, relative to this file.
rules:
  - .vibecheck/rules/

# Your own secret formats (Python regular expressions). Matches are masked in reports.
secrets:
  - id: myapp-service-token
    title: MyApp internal service token
    pattern: '\bmyapp_svc_[A-Za-z0-9]{32}\b'
    severity: high                    # critical | high | medium | low (default: high)

# Raise or lower any rule's severity for this project (built-in or your own).
severity:
  vc-token-in-localstorage: high
  vc-open-redirect: low

# Semgrep's community rules run in full scans by default. false = only vibecheck's rules + yours.
community: false

# Skip whole folders. Every entry needs a reason.
ignore_paths:
  - path: 'scripts/**'                # * stays inside a folder, ** crosses folders
    reason: One-off scripts I run by hand. Never deployed.

# Hide specific findings. Every entry needs a reason; ignored findings stay listed in the report.
ignore_findings:
  - rule: vc-secret-in-url            # the rule shown on the finding
    paths: ['lib/export.ts']          # optional: only in these files
    reason: Single-use download token that expires in 5 minutes.
    until: 2027-06-30                 # optional: the finding comes back after this date
```

The file is checked before the scan starts. A typo, an unknown key, a bad severity, an invalid
regular expression or a missing rules folder stops the scan with a message saying exactly what to
fix.

**Ignore or change severity?** Ignore a finding when it's a false positive or an accepted risk
in one place. Change a rule's severity when the rule is right but your project weighs it
differently everywhere. To turn a rule off entirely, ignore it without `paths` (with a reason).

---

## 2. Your own rules

Project rules are ordinary [Semgrep rules](https://semgrep.dev/docs/writing-rules/overview) with
a few optional extra fields that make findings as useful as the built-in ones. Keep them in your
app, usually in `.vibecheck/rules/`, and list that folder under `rules:` in `.vibecheck.yml`.
Anything inside `.vibecheck/` is never scanned as app code, so rule tests there won't show up as
findings.

**The fastest start:** `./vibecheck init <app>` and answer yes to *"Create .vibecheck/rules/ with a
starter rule"*. You get a working rule, its tests, and the `rules:` entry. Or copy rules from
[`examples/custom-rules/rules/`](../examples/custom-rules/rules).

### Anatomy of a rule

```yaml
rules:
  - id: myapp-route-without-auth          # your own prefix; vc- is reserved for built-ins
    languages: [typescript, javascript]
    severity: ERROR                       # Semgrep's own: ERROR / WARNING / INFO
    message: >-                           # What's wrong and why it matters. Shown in the report.
      This API route never calls requireUser(), so anyone can call it without logging in.
    paths:                                # optional: limit where the rule runs
      include: ["app/api/**/route.ts"]
      exclude: ["app/api/public/**"]
    metadata:                             # optional, but makes the report and fix tasks useful
      title: API route doesn't check who's calling       # finding title
      level: high                         # critical | high | medium | low (overrides severity)
      confirm: Call the route while logged out; a 401 means it's fine.
      impact: >-                          # put "False positive:" conditions here: they become
        High: it returns user data.       # "Not a problem if" in fix-tasks.md
        False positive: the route is public on purpose.
      fix: Start the handler with const user = await requireUser(req).
      cwe: "CWE-862: Missing Authorization"
      kind: code                          # or "rotate" if a finding means a credential leaked
    patterns:                             # what to match (see the recipes below)
      - pattern: |
          export async function $METHOD(...) { ... }
      - metavariable-regex:
          metavariable: $METHOD
          regex: ^(GET|POST|PUT|PATCH|DELETE)$
      - pattern-not: |
          export async function $METHOD(...) {
            ...
            <... requireUser(...) ...>;
            ...
          }
```

Without the `metadata` fields a rule still works: the title comes from its id and the level from
`severity`. With them, findings get a real title, "how serious", "confirm it" and "fix" sections,
and a proper task in `fix-tasks.md`.

### Pattern basics

Semgrep patterns look like the code they match, with a few wildcards:

| Syntax | Means | Example |
| --- | --- | --- |
| `...` | any arguments, statements or fields | `fetch(...)`, `{ ... }` |
| `$NAME` | any single expression, captured by name | `$DB.query($SQL)` |
| `<... X ...>` | any expression or statement containing X | `<... requireUser(...) ...>` |
| `"..."` | any string literal | `eval("...")` |
| `pattern-not` | exclude matches that also look like this | the "has requireUser" case above |
| `pattern-inside` | only match inside this context | inside a function that reads the body |
| `metavariable-regex` | constrain a captured `$NAME` by regex | `$METHOD` is GET/POST/… |

[Semgrep's playground](https://semgrep.dev/playground) is the quickest way to try a pattern
against a snippet. The full syntax is in
[Semgrep's docs](https://semgrep.dev/docs/writing-rules/pattern-syntax).

### Recipes

Each one is a complete, tested rule in [`examples/custom-rules/rules/`](../examples/custom-rules/rules).

**Require a check everywhere** ([`require-auth.yaml`](../examples/custom-rules/rules/require-auth.yaml)).
Every API route handler must call your auth helper, except folders that are public on purpose. The
shape: match the thing (`export async function GET(...)`), then `pattern-not` the version that does
it properly. This is the single most valuable project rule, because "does every route check who's
calling?" is the bug general scanners can't catch.

**Allow something only in certain folders** ([`admin-client.yaml`](../examples/custom-rules/rules/admin-client.yaml)).
Only admin code may import the service-role database client. The shape: match the import, and use
`paths: exclude` for the places it's allowed.

**Don't pass X to Y** ([`no-logging-request-body.yaml`](../examples/custom-rules/rules/no-logging-request-body.yaml)).
Never log whole request bodies. The shape: `pattern-either` over the calls (`console.$LOG(...,
$REQ.body, ...)`), plus `pattern-inside` to also catch `const body = await req.json()` followed by
`console.log(body)`.

**Follow request input to your own risky function** ([`internal-sql-helper.yaml`](../examples/custom-rules/rules/internal-sql-helper.yaml)).
`mode: taint` follows values from *sources* (request query, body, `searchParams.get`) through
variables and string building to a *sink* (here, the SQL argument of a `runReport()` helper),
unless a *sanitizer* (`allowColumn()`) was applied on the way. Use taint mode whenever "where did
this value come from?" matters; it's far more precise than matching the call alone.

### Limiting where a rule runs

```yaml
paths:
  include: ["app/api/**/route.ts", "server/**"]
  exclude: ["app/api/public/**", "**/*.test.ts"]
```

Patterns are relative to the app's root. **Don't start them with `/`**: Semgrep treats a leading
slash differently than you might expect, and the rule quietly stops matching.

### Test your rules

Write example files with comments saying what should and shouldn't match. A `ruleid:` comment means
the rule must match the next code line; `ok:` means it must not:

```ts
// ruleid: myapp-route-without-auth
export async function GET(req: Request) {
  return Response.json(await db.notes.findMany())
}

// ok: myapp-route-without-auth
export async function POST(req: Request) {
  const user = await requireUser(req)
  ...
}
```

**Lay the test folder out like your app**, so rules with `paths:` apply: a test for a rule limited
to `app/api/**/route.ts` goes in `tests/app/api/<something>/route.ts`. Then:

```bash
./vibecheck test-rules .vibecheck/rules .vibecheck/rules/tests
```
```
✓ myapp-route-without-auth (4 cases)
✖ myapp-logs-request-body
    missed: app/api/reports/route.ts:24 should match

1/2 rules passed
```

`test-rules` runs your rules exactly the way a scan does, `paths:` scoping included, which
`semgrep --test` doesn't. Write at least one `ruleid:` and one `ok:` case per rule, and add an `ok:`
case every time you fix a false positive, so it stays fixed.

Then scan for real and check the findings read well in `report.md`:

```bash
./vibecheck --quick ~/code/my-app
```

### Tips for good rules

- **Aim for few false positives.** A rule that's wrong half the time gets ignored. Narrow it with
  `paths`, `pattern-not` and `metavariable-regex` until the hits are worth reading.
- **Write the message for the person fixing it,** not for a security team: what's wrong, why it
  matters here, and what decides whether it's serious.
- **Keep ids stable.** They appear in `.vibecheck.yml` ignores and in finding ids that `--compare`
  uses; renaming a rule makes its findings look fixed and new.
- **Use your own prefix** (`myapp-`, `acme-`). `vc-` is reserved for the built-in rules.

### Sharing rules across projects

`rules:` entries can point anywhere, for example a shared folder or a git submodule:

```yaml
rules:
  - .vibecheck/rules/               # this app's own rules
  - ../company-rules/web/           # rules shared by every app
```

### Have your AI assistant write a rule

> Write a Semgrep rule for this project in `.vibecheck/rules/<name>.yaml` that flags <the
> mistake>, with vibecheck's metadata fields (title, level, confirm, impact, fix, cwe); see
> examples/custom-rules/rules/ in vibecheck-sast for the format. Add test cases in
> `.vibecheck/rules/tests/`, laid out like the app, with `// ruleid:` and `// ok:` comments,
> including at least one realistic false positive. Run
> `<path-to>/vibecheck test-rules .vibecheck/rules .vibecheck/rules/tests` and iterate until it
> passes, then run `<path-to>/vibecheck --quick .` and show me what it finds.

---

## 3. Fork it: change the defaults

For changes every project you scan should get, fork vibecheck-sast and edit:

| To change | Edit |
| --- | --- |
| Built-in rules | `rules/vibecheck-rules.yaml` and its tests in `rules/tests/vibecheck-rules.tsx` |
| Guidance shown for community-rule hits | `vibecheck_sast/guidance.py` (by vulnerability class / CWE) |
| Which community rules are downloaded, and the pinned version | `COMMUNITY_LANGS` and `COMMUNITY_COMMIT` in `vibecheck_sast/semgrep.py` |
| Built-in secret formats | `DETECTORS` in `vibecheck_sast/secrets.py` |
| Configuration checks (env, Supabase, Firebase) | `vibecheck_sast/configcheck.py` |
| Folders never scanned | `SKIP_DIRS` in `semgrep.py`, `secrets.py` and `configcheck.py` |
| Semgrep version | `requirements.txt` |

Then run the full test suite before using your fork:

```bash
semgrep --test --config rules/vibecheck-rules.yaml rules/tests/vibecheck-rules.tsx
./vibecheck test-rules examples/custom-rules/rules examples/custom-rules/rules/tests
python3 -m unittest discover tests
./demo.sh
```

Pinned versions are deliberate: an upgrade can change results, which shows up in `--compare` as
findings that look fixed or new. Bump them on purpose, and re-run the demo to see what changed.

If a rule you wrote would help everyone, consider opening a pull request.
