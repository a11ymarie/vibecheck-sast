#!/usr/bin/env bash
# Scans examples/demo-app and refreshes docs/sample-report.md and docs/sample-fix-tasks.md.
#
#   ./demo.sh                      # full demo scan into demo-output/ (gitignored)
#   ./demo.sh --playground [DIR]   # make a standalone practice copy to try `vibecheck init` and
#                                  # /vibecheck on (default: ../vibecheck-playground)
#
# The demo app is set up the way a real project often looks: a git repo whose .gitignore forgot
# .env.local, and an .env.local with keys in it. The (fake) keys are assembled here at run time,
# so this repo never contains a string that looks like a real credential.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "${1:-}" = "--playground" ]; then
  APP="${2:-$ROOT/../vibecheck-playground}"
  [ ! -e "$APP" ] || { echo "demo: $APP already exists; remove it or pick another folder." >&2; exit 2; }
  mkdir -p "$APP"; APP="$(cd "$APP" && pwd)"; PLAYGROUND=1
else
  WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
  APP="$WORK/demo-app"; mkdir -p "$APP"; PLAYGROUND=0
fi
cp -R "$ROOT/examples/demo-app/." "$APP"

python3 - "$APP/.env.local" <<'PY'
import base64, json, sys
enc = lambda d: base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).decode().rstrip("=")
service_role = ".".join([enc({"alg": "HS256", "typ": "JWT"}),
                         enc({"iss": "supabase", "ref": "demoapp", "role": "service_role", "iat": 1730000000}),
                         "ZGVtby1zaWduYXR1cmUtbm90LXJlYWwtYXQtYWxsLTAx"])
openai = "sk-" + "proj-" + "Hq4Vn8Tz2Ly6Rc9Wm3Kp7Bd5Gx1Sf0Ja"
with open(sys.argv[1], "w") as fh:
    fh.write("NEXT_PUBLIC_SUPABASE_URL=https://demoapp.supabase.co\n"
             f"NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY={service_role}\n"
             f"NEXT_PUBLIC_OPENAI_API_KEY={openai}\n")
PY
printf 'node_modules/\n.next/\n' > "$APP/.gitignore"      # forgot .env.local
git -C "$APP" init -q

if [ "$PLAYGROUND" = 1 ]; then
  git -C "$APP" add -A -- . ':!.env.local'
  git -C "$APP" -c user.name=vibecheck -c user.email=vibecheck@example.invalid \
    commit -qm "Practice app: starting point" --no-verify
  cat <<MSG
Practice app ready: $APP
(the deliberately insecure demo app, fake keys only, in its own git repo)

  ./vibecheck init "$APP"     set it up (asks before each change)
  cd "$APP" && claude         then type /vibecheck
  git diff                    review what changed

To start over, delete the folder and run ./demo.sh --playground again.
MSG
  exit 0
fi

rm -rf "$ROOT/demo-output"
set +e
"$ROOT/vibecheck" --out "$ROOT/demo-output" --fail-on high "$APP"
rc=$?
set -e
[ "$rc" = 1 ] || { echo "demo: expected --fail-on high to exit 1, got $rc" >&2; exit 1; }

# Publish copies with machine-specific paths swapped for placeholders.
for f in report fix-tasks; do
  sed -e "s|$ROOT/demo-output|vibecheck-sast/vibecheck-report/demo-app-20261112-090000|g" \
      -e "s|$ROOT|vibecheck-sast|g" -e "s|$WORK|~/code|g" \
      "$ROOT/demo-output/$f.md" > "$ROOT/docs/sample-$f.md"
done
echo; echo "Refreshed docs/sample-report.md and docs/sample-fix-tasks.md"
