# Security policy

vibecheck-sast is a security tool, so problems in it matter. Thanks for reporting them privately.

## Reporting a vulnerability

Please **don't open a public issue**. Use GitHub's private reporting instead: go to this repo's
**Security** tab and choose **Report a vulnerability**. Include what you found, how to reproduce
it, and what an attacker could do with it.

Don't include real secrets in a report. If your report involves a credential, rotate it first.

This is a personal project maintained in spare time: expect an acknowledgement within a week and
a fix or a plan as soon as practical. Fixes go into the next release, with credit if you'd like it.

## What counts

In scope, for example:

- Scanning a folder makes vibecheck run code, write outside its report folder, or reach the
  network beyond downloading the pinned community rules (e.g. a crafted file, config or rule).
- A secret ends up unmasked in `report.md`, `fix-tasks.md`, `findings.json` or terminal output.
- `vibecheck init`, the GitHub Action template or the pre-commit hook it installs does something
  unsafe in the project it's set up in (e.g. exposes a token or the report on a public repo).
- The `/vibecheck` assistant workflow can be steered by text in the scanned code into an unsafe
  action (printing secrets, committing, deploying, editing ignore entries without asking).

Not security vulnerabilities (open a normal issue instead):

- Anything in `examples/` or `rules/tests/`: that code is **deliberately insecure** so the scanner
  has something to find, and its credentials are made up.
- A rule that misses something (false negative) or flags something harmless (false positive).
  Those are very welcome as issues, ideally with a small code sample.

## Supported versions

Only the latest release gets fixes.
