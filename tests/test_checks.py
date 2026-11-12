#!/usr/bin/env python3
"""Tests for the secret detectors (vibecheck_sast/secrets.py) and config checks (configcheck.py).

Run: python3 -m unittest discover tests

Every key-shaped value is assembled at run time from parts, so this file never contains a string
that a secret scanner (or GitHub push protection) would flag.
"""
import base64, json, os, subprocess, sys, tempfile, textwrap, unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from vibecheck_sast import configcheck, secrets  # noqa: E402


def jwt(role):
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return b({"alg": "HS256"}) + "." + b({"iss": "supabase", "role": role}) + "." + "c2lnbmF0dXJlTm90UmVhbDEyMzQ1Njc4"


OPENAI = "sk-" + "proj-" + "q7Lm2Vx9Rt4Kp8Wz3Bn6Yc1Hd5Gs0Fa"
ANTHROPIC = "sk-" + "ant-api03-" + "Zr8Kq2Lp5Vn9Xw3Ty7Bm1Hc4Jd6Fs0Ga"
GROQ = "gsk" + "_" + "Rq7Lm2Vx9Rt4Kp8Wz3Bn6Yc1Hd5Gs0FaQ7Lm2Vx9R"
SB_SECRET = "sb_" + "secret_" + "Rq7Lm2Vx9Rt4Kp8Wz3Bn6Yc1H"
FIREBASE = "AI" + "za" + "SyD3mQ7Lm2Vx9Rt4Kp8Wz3Bn6Yc1Hd5Gs0F"


def write(root, rel, text):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(textwrap.dedent(text))


def run(module, root):
    """Findings as dicts with the field names these tests use."""
    mod = {"secrets": secrets, "config": configcheck}[module]
    return [{"rule": f.rule, "check": f.rule, "severity": f.severity, "path": f.path,
             "line": f.line, "snippet": f.snippet} for f in mod.scan(root)]


def git_init(root, ignore=""):
    subprocess.run(["git", "init", "-q", root], check=True)
    write(root, ".gitignore", ignore)


class SecretSweep(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def rules(self):
        return {(r["path"], r["rule"]): r for r in run("secrets", self.root)}

    def test_provider_keys_found_and_masked(self):
        write(self.root, "lib/keys.ts", f"""\
            const a = '{OPENAI}'
            const b = '{ANTHROPIC}'
            const c = '{GROQ}'
            const d = '{SB_SECRET}'
            """)
        found = self.rules()
        for rule in ("openai-key", "anthropic-key", "groq-key", "supabase-secret-key"):
            self.assertIn(("lib/keys.ts", rule), found)
        for r in found.values():
            for secret in (OPENAI, ANTHROPIC, GROQ, SB_SECRET):
                self.assertNotIn(secret, r["snippet"], "secret must be masked in the output")

    def test_supabase_jwt_roles(self):
        write(self.root, "lib/supabase.ts", f"const anon = '{jwt('anon')}'\nconst admin = '{jwt('service_role')}'\n")
        found = run("secrets", self.root)
        self.assertEqual([(r["rule"], r["severity"], r["line"]) for r in found],
                         [("supabase-service-role-key", "critical", 2)])

    def test_firebase_web_key_is_low(self):
        write(self.root, "lib/firebase.ts", f"export const firebaseConfig = {{ apiKey: '{FIREBASE}' }}\n")
        r = self.rules()[("lib/firebase.ts", "firebase-web-api-key")]
        self.assertEqual(r["severity"], "low")

    def test_database_url(self):
        write(self.root, "db.ts", "const a = 'postgres://app:Hx9qLm2Vz7@db.myapp.io:5432/app'\n"
                                  "const b = 'postgres://app:localpass99@localhost:5432/app'\n")
        found = run("secrets", self.root)
        self.assertEqual([(r["rule"], r["line"]) for r in found], [("db-url-password", 1)])

    def test_gitignored_files_skipped(self):
        git_init(self.root, ".env.local\n")
        write(self.root, ".env.local", f"OPENAI_API_KEY={OPENAI}\n")
        write(self.root, "lib/ai.ts", f"const k = '{OPENAI}'\n")
        self.assertEqual({p for p, _ in self.rules()}, {"lib/ai.ts"})


class ConfigChecks(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def checks(self):
        return sorted((r["check"], r["path"], r["line"]) for r in run("config", self.root))

    def test_public_env_secret_names(self):
        write(self.root, "lib/a.ts", "createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)\n"
                                     "const k = import.meta.env.VITE_OPENAI_API_KEY\n"
                                     "const ok = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY\n")
        write(self.root, ".env.local", "NEXT_PUBLIC_STRIPE_SECRET_KEY=abc123secretvalue\n")
        found = run("config", self.root)
        self.assertEqual(sorted((r["path"], r["line"]) for r in found),
                         [(".env.local", 1), ("lib/a.ts", 1), ("lib/a.ts", 2)])
        env = next(r for r in found if r["path"] == ".env.local")
        self.assertNotIn("abc123secretvalue", env["snippet"])

    def test_env_file_not_gitignored(self):
        git_init(self.root, "node_modules/\n.env.production\n")
        write(self.root, ".env.local", "API_KEY=abc\n")
        write(self.root, ".env.production", "API_KEY=abc\n")
        write(self.root, ".env.example", "API_KEY=abc\n")
        write(self.root, ".env.empty", "# nothing set\nAPI_KEY=\n")
        self.assertEqual(self.checks(), [("env-file-not-gitignored", ".env.local", None)])

    def test_supabase_migrations(self):
        write(self.root, "supabase/migrations/1.sql", """\
            create table public.profiles (id uuid primary key);
            create table if not exists "notes" (id bigint);
            create table private.audit (id bigint);
            alter table public.profiles enable row level security;
            create policy "p1" on public.profiles for update using (true);
            create policy "p2" on public.profiles for select using (true);
            """)
        write(self.root, "supabase/migrations/2.sql", "alter table public.profiles disable row level security;\n")
        self.assertEqual(self.checks(), [
            ("supabase-permissive-policy", "supabase/migrations/1.sql", 5),
            ("supabase-rls-disabled", "supabase/migrations/2.sql", 1),
            ("supabase-table-without-rls", "supabase/migrations/1.sql", 2),
        ])

    def test_firebase_rules(self):
        write(self.root, "firestore.rules", """\
            match /a/{id} { allow read, write: if true; }
            match /b/{id} { allow read, write: if request.time < timestamp.date(2027, 1, 1); }
            match /c/{id} { allow read: if request.auth != null; }
            match /d/{id} { allow read: if request.auth.uid == id; }
            """)
        write(self.root, "database.rules.json", '{"rules": {".read": true, ".write": "auth != null"}}\n')
        self.assertEqual(self.checks(), [
            ("firebase-rtdb-rules-open", "database.rules.json", 1),
            ("firebase-rules-any-user", "firestore.rules", 3),
            ("firebase-rules-open", "firestore.rules", 1),
            ("firebase-rules-open", "firestore.rules", 2),
        ])


if __name__ == "__main__":
    unittest.main()
