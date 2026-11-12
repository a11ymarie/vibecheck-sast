#!/usr/bin/env python3
"""Tests for ids, merging, --compare, fix-tasks.md, the --fail-on gate, and `vibecheck init`.

Run: python3 -m unittest discover tests   (the end-to-end tests need semgrep installed)
"""
import json, os, shutil, subprocess, sys, tempfile, unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
VC = os.path.join(ROOT, "vibecheck")
sys.path.insert(0, ROOT)
from vibecheck_sast import compare  # noqa: E402
from vibecheck_sast.model import Finding, assign_ids, merge_same_line  # noqa: E402


def F(rule, path="a.js", line=1, source="custom", sev="high", text=None):
    return Finding(source=source, rule=rule, severity=sev, title=rule, path=path, line=line,
                   match_text=text or rule)


class Ids(unittest.TestCase):
    def test_ids_ignore_line_numbers_but_not_code(self):
        a, b, c = F("r", line=3, text="eval(x)"), F("r", line=30, text="eval(x)"), F("r", text="eval(y)")
        for f in (a, b, c):
            assign_ids([f])
        self.assertEqual(a.id, b.id)
        self.assertNotEqual(a.id, c.id)

    def test_merge_keeps_most_severe_and_records_aliases(self):
        low, high = F("x", sev="low", source="community"), F("y", sev="high")
        assign_ids([low, high])
        [kept] = merge_same_line([low, high])
        self.assertEqual((kept.rule, kept.found_by, kept.aliases), ("y", ["community", "custom"], [low.id]))


class Compare(unittest.TestCase):
    def prev(self, findings, sources=("custom", "secrets")):
        return {"sources": list(sources), "scanned_at": "2026-11-01T10:00:00",
                "findings": [f.to_json() for f in findings]}

    def test_fixed_open_new(self):
        a, b, s = F("a"), F("b"), F("s", source="secrets")
        assign_ids([a, b, s])
        now_b, now_c = F("b"), F("c")
        assign_ids([now_b, now_c])
        cmp = compare.compare([now_b, now_c], ["custom", "secrets"], self.prev([a, b, s]), [])
        self.assertEqual(sorted(x["rule"] for x in cmp["fixed"]), ["a", "s"])
        self.assertEqual((cmp["open"], cmp["new"], now_b.status, now_c.status), (1, 1, "open", "new"))

    def test_only_sources_both_runs_had(self):
        a, dep = F("a"), F("lodash", source="deps", path="package-lock.json", line=None)
        assign_ids([a, dep])
        cmp = compare.compare([dep], ["custom", "deps"], self.prev([a], ["custom"]), [])
        self.assertIsNone(dep.status)
        self.assertEqual(([x["rule"] for x in cmp["fixed"]], cmp["not_compared"]), (["a"], ["deps"]))

    def test_alias_keeps_identity(self):
        shown, hidden = F("openai-key", source="secrets", text="k"), F("public-env-secret-name", source="config", text="k2")
        assign_ids([shown, hidden])
        [merged] = merge_same_line([shown, hidden])
        now = F("public-env-secret-name", source="config", text="k2")
        assign_ids([now])
        cmp = compare.compare([now], ["secrets", "config"], self.prev([merged], ["secrets", "config"]), [])
        self.assertEqual((now.status, cmp["fixed"]), ("open", []))

    def test_ignored_is_not_fixed(self):
        a = F("a")
        assign_ids([a])
        again = F("a")
        assign_ids([again])
        cmp = compare.compare([], ["custom"], self.prev([a], ["custom"]), [again])
        self.assertEqual((cmp["fixed"], len(cmp["now_ignored"])), ([], 1))


def run(*args, **kw):
    return subprocess.run(args, capture_output=True, text=True, stdin=subprocess.DEVNULL, **kw)


@unittest.skipUnless(shutil.which("semgrep"), "semgrep not installed")
class FixLoop(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.app = os.path.join(self.tmp, "loopapp")
        os.makedirs(self.app)
        self.write("app.post('/run', (req, res) => res.json(eval(req.body.code)))\n")

    def write(self, text):
        with open(os.path.join(self.app, "server.js"), "w") as fh:
            fh.write(text)

    def scan(self, *extra):
        out = os.path.join(self.tmp, f"run{len(os.listdir(self.tmp))}")
        r = run(VC, "--quick", "--out", out, *extra, self.app)
        self.assertIn(r.returncode, (0, 1), r.stdout + r.stderr)
        with open(os.path.join(out, "findings.json")) as fh:
            return out, r, json.load(fh)

    def test_fix_then_compare(self):
        out1, _, doc1 = self.scan()
        [task] = [f for f in doc1["findings"] if f["rule"] == "vc-dynamic-code"]
        with open(os.path.join(out1, "fix-tasks.md")) as fh:
            tasks = fh.read()
        self.assertIn(f"`{task['id']}`", tasks)
        self.assertIn("--compare", tasks)
        self.write("app.post('/run', (req, res) => res.json(JSON.parse(req.body.code)))\n"
                   "const key = process.env.API_SECRET || 'fallback-secret-value'\n")
        _, r, doc2 = self.scan("--compare", os.path.join(out1, "findings.json"))
        self.assertEqual([x["id"] for x in doc2["compare"]["fixed"]], [task["id"]])
        self.assertEqual(doc2["compare"]["new"], 1)
        self.assertIn("1 fixed", r.stdout)
        self.assertIn("🆕 New: Hard-coded secret or secret fallback", r.stdout)

    def test_gate_levels_and_counts_only(self):
        self.assertEqual(self.scan("--fail-on", "secrets")[1].returncode, 0)   # eval isn't a secret
        _, r, _ = self.scan("--fail-on", "high", "--counts-only")
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("server.js", r.stdout)

    def test_failed_semgrep_means_no_report(self):
        fake = os.path.join(self.tmp, "bin")
        os.makedirs(fake)
        with open(os.path.join(fake, "semgrep"), "w") as fh:
            fh.write("#!/bin/sh\nexit 7\n")
        os.chmod(os.path.join(fake, "semgrep"), 0o755)
        out = os.path.join(self.tmp, "broken")
        r = run(VC, "--quick", "--out", out, self.app, env=dict(os.environ, PATH=fake + os.pathsep + os.environ["PATH"]))
        self.assertEqual(r.returncode, 2)
        self.assertFalse(os.path.exists(os.path.join(out, "report.md")))


class Init(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.app = os.path.join(self.tmp, "myapp")
        os.makedirs(os.path.join(self.app, ".cursor", "rules"))
        run("git", "init", "-q", self.app)
        self.put("package.json", '{\n    "name": "myapp",\n    "scripts": {"security": "my own"}\n}\n')
        self.put(".cursor/rules/vibecheck.mdc", "mine")
        self.put("CLAUDE.md", "# Notes\nKeep this.\n")

    def put(self, rel, text):
        with open(os.path.join(self.app, rel), "w") as fh:
            fh.write(text)

    def read(self, rel):
        with open(os.path.join(self.app, rel)) as fh:
            return fh.read()

    def test_non_interactive_changes_nothing(self):
        r = run(VC, "init", self.app)
        self.assertIn("Dry run", r.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.app, ".vibecheck.yml")))

    def test_all_is_additive_and_idempotent(self):
        r = run(VC, "init", "--all", self.app)
        self.assertEqual(r.returncode, 0, r.stderr)
        pkg = json.loads(self.read("package.json"))
        self.assertEqual(pkg["scripts"]["security"], "my own")
        self.assertIn("--quick --compare last", pkg["scripts"]["security:quick"])
        self.assertEqual(self.read(".cursor/rules/vibecheck.mdc"), "mine")
        self.assertTrue(self.read("CLAUDE.md").startswith("# Notes\nKeep this.\n"))
        skill = self.read(".claude/skills/vibecheck/SKILL.md")
        self.assertIn("name: vibecheck", skill)
        self.assertIn("vibecheck:start", self.read("AGENTS.md"))
        self.assertTrue(os.access(os.path.join(self.app, ".git", "hooks", "pre-commit"), os.X_OK))
        self.assertIn("repository:", self.read(".github/workflows/vibecheck.yml"))
        for text in (self.read("CLAUDE.md"), skill, json.dumps(pkg)):
            self.assertNotIn("${VIBECHECK_HOME:-/", text, "committed files must use a relative path")
        before = {p: self.read(p) for p in ("CLAUDE.md", "AGENTS.md", ".gitignore", "package.json")}
        run(VC, "init", "--all", self.app)
        self.assertEqual(before, {p: self.read(p) for p in before})


if __name__ == "__main__":
    unittest.main()
