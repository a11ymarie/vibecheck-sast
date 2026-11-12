# Example: customizing vibecheck for one project

A starter kit for the [customization guide](../../docs/customizing.md):

- **`.vibecheck.yml`**: every per-project setting: your own rules, your own secret formats,
  severity changes, community rules on or off, and ignores.
- **`rules/require-auth.yaml`**: every Next.js API route must call `requireUser()` (except ones
  under `app/api/public/` and `app/api/webhooks/`). A general scanner can't know your app's auth
  helper; a project rule can.
- **`rules/admin-client.yaml`**: only admin code may import the service-role Supabase client.
- **`rules/tests/`**: example files laid out like an app, with `ruleid:` / `ok:` comments.

Test the rules:

```bash
./vibecheck test-rules examples/custom-rules/rules examples/custom-rules/rules/tests
```
