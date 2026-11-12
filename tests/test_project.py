#!/usr/bin/env python3
"""Tests for project settings in .vibecheck.yml: own rules, own secret formats, severity changes,
community on/off, validation errors, and `vibecheck test-rules`."""
import json, os, shutil, subprocess, tempfile, textwrap, unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
VC = os.path.join(ROOT, "vibecheck")
EXAMPLE_RULES = os.path.join(ROOT, "examples", "custom-rules", "rules")


def run(*args):
    return subprocess.run(args, capture_output=True, text=True, stdin=subprocess.DEVNULL)


def write(root, rel, text):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(textwrap.dedent(text))


@unittest.skipUnless(shutil.which("semgrep"), "semgrep not installed")
class ProjectSettings(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.app = os.path.join(self.tmp, "app")
        shutil.copytree(EXAMPLE_RULES, os.path.join(self.app, ".vibecheck", "rules"))
        write(self.app, "app/api/notes/route.ts", "export async function GET(req: Request) {\n  return Response.json([])\n}\n")
        write(self.app, "app/api/health/route.ts", "export async function GET() {\n  return Response.json({ok: true})\n}\n")
        token = "myapp_svc_" + "Qx7Lm2Vz9Rt4Kp8Wn3Bd6Yc1Hf5Gs0Ja"
        write(self.app, "lib/x.ts", f"export const t = '{token}'\n"
                                    "export const save = (s: any) => localStorage.setItem('auth_token', s)\n")
        self.token = token

    def config(self, text):
        write(self.app, ".vibecheck.yml", text)

    def scan(self):
        out = os.path.join(self.tmp, f"r{len(os.listdir(self.tmp))}")
        r = run(VC, "--quick", "--out", out, self.app)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        with open(os.path.join(out, "findings.json")) as fh:
            doc = json.load(fh)
        with open(os.path.join(out, "report.md")) as fh:
            return doc, fh.read()

    def test_all_settings_together(self):
        self.config("""\
            rules: [.vibecheck/rules/]
            secrets:
              - id: myapp-service-token
                title: MyApp internal service token
                pattern: '\\bmyapp_svc_[A-Za-z0-9]{32}\\b'
            severity:
              vc-token-in-localstorage: high
            ignore_findings:
              - rule: myapp-route-without-auth
                paths: ['app/api/health/route.ts']
                reason: Uptime check.
            """)
        doc, report = self.scan()
        by_rule = {f["rule"]: f for f in doc["findings"]}
        self.assertEqual(by_rule["myapp-route-without-auth"]["title"], "API route doesn't check who's calling")
        self.assertEqual(by_rule["myapp-route-without-auth"]["path"], "app/api/notes/route.ts")
        self.assertEqual(by_rule["myapp-service-token"]["severity"], "high")
        self.assertEqual(by_rule["vc-token-in-localstorage"]["severity"], "high")
        self.assertIn("was medium", report)
        self.assertIn("project rule", report)
        self.assertNotIn(self.token, report + json.dumps(doc))
        self.assertEqual([f["path"] for f in doc["ignored"]], ["app/api/health/route.ts"])
        # The rules' own test files under .vibecheck/ are never scanned as app code.
        self.assertFalse(any(".vibecheck" in (f["path"] or "") for f in doc["findings"]))

    def test_without_settings_project_rules_dont_run(self):
        doc, _ = self.scan()
        self.assertNotIn("myapp-route-without-auth", {f["rule"] for f in doc["findings"]})

    def test_bad_settings_fail_before_scanning(self):
        cases = {
            "colour: blue": "unknown key",
            "severity: {vc-open-redirect: urgent}": "use one of",
            "secrets: [{id: x, pattern: '([a-z'}]": "invalid pattern",
            "rules: [nope/]": "doesn't exist",
            "ignore_findings: [{rule: x}]": "needs a reason",
        }
        for text, expected in cases.items():
            self.config(text + "\n")
            out = os.path.join(self.tmp, "never")
            r = run(VC, "--quick", "--out", out, self.app)
            self.assertEqual(r.returncode, 2, text)
            self.assertIn(expected, r.stderr, text)
            self.assertFalse(os.path.exists(out), "a failed config must not leave a report folder")


@unittest.skipUnless(shutil.which("semgrep"), "semgrep not installed")
class TestRules(unittest.TestCase):
    def test_examples_pass(self):
        r = run(VC, "test-rules", EXAMPLE_RULES, os.path.join(EXAMPLE_RULES, "tests"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("4/4 rules passed", r.stdout)

    def test_a_broken_expectation_fails(self):
        tmp = tempfile.mkdtemp()
        shutil.copytree(EXAMPLE_RULES, os.path.join(tmp, "rules"))
        route = os.path.join(tmp, "rules", "tests", "app", "api", "notes", "route.ts")
        with open(route) as fh:
            text = fh.read()
        with open(route, "w") as fh:          # claim the protected POST should be flagged
            fh.write(text.replace("// ok: myapp-route-without-auth\nexport async function POST",
                                  "// ruleid: myapp-route-without-auth\nexport async function POST"))
        r = run(VC, "test-rules", os.path.join(tmp, "rules"), os.path.join(tmp, "rules", "tests"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("missed", r.stdout)


if __name__ == "__main__":
    unittest.main()
