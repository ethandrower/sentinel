#!/usr/bin/env bash
# ABOUTME: Installs sentinel onto the OpenClaw gateway and registers its cron entry.
# ABOUTME: Idempotent — safe to re-run after editing checks.yaml.
set -euo pipefail

HOST="${SENTINEL_HOST:?set SENTINEL_HOST=user@monitor-box}"
# Home-relative on purpose: scp does NOT expand $HOME in a remote path, so an
# absolute path has to be resolved locally first. Relative paths land in $HOME.
DEST_REL="${SENTINEL_DEST:-sentinel}"
INTERVAL="${SENTINEL_INTERVAL:-*/5}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Installing sentinel to ${HOST}:~/${DEST_REL}"

ssh -o BatchMode=yes "$HOST" "mkdir -p ~/${DEST_REL}"
scp -q -o BatchMode=yes \
    "$HERE/sentinel.py" "$HERE/checks.yaml" "$HERE/test_sentinel.py" \
    "$HOST:${DEST_REL}/"
ssh -o BatchMode=yes "$HOST" "chmod +x ~/${DEST_REL}/sentinel.py"

echo "==> Running unit tests remotely"
ssh -o BatchMode=yes "$HOST" "cd ~/${DEST_REL} && python3 test_sentinel.py | tail -2"

echo "==> Live dry-run (no state written, no Slack posted)"
ssh -o BatchMode=yes "$HOST" "cd ~/${DEST_REL} && python3 sentinel.py --dry-run" || true

echo
echo "==> Registering cron (${INTERVAL} * * * *)"
# Replace any prior sentinel line, keep every other entry untouched.
# $HOME and $tmp are escaped so they expand on the remote side, not here.
ssh -o BatchMode=yes "$HOST" "
  set -e
  tmp=\$(mktemp)
  crontab -l 2>/dev/null | grep -v 'sentinel.py' > \"\$tmp\" || true
  echo '${INTERVAL} * * * * . \$HOME/.sentinel.env 2>/dev/null; cd \$HOME/${DEST_REL} && /usr/bin/python3 \$HOME/${DEST_REL}/sentinel.py --quiet >> \$HOME/${DEST_REL}/sentinel.log 2>&1' >> \"\$tmp\"
  crontab \"\$tmp\"
  rm -f \"\$tmp\"
  echo '--- crontab now ---'
  crontab -l | grep sentinel
"

cat <<'NOTE'

==> Done.

Credentials live in ~/.sentinel.env on the gateway (chmod 600), NOT in git —
checks.yaml is committed to a GitHub repo, so a webhook there would be public.
The cron line sources that file before each run:

    export SENTINEL_SLACK_WEBHOOK="https://hooks.slack.com/services/..."
    export SENTINEL_HEARTBEAT_URL="https://hc-ping.com/<uuid>"

Remaining manual steps:

  1. Heartbeat — create a free check at healthchecks.io and set
     SENTINEL_HEARTBEAT_URL. Without it, nothing notices if the gateway
     itself dies, which is the one failure sentinel cannot self-report.

  2. Redis / Postgres — they are not on the prod web host. Find the host
     behind REDIS_URL and DATABASE_URL, then uncomment section 4 of
     checks.yaml.

NOTE
