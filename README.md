# Sentinel

A small external monitor. One cron script, ~450 lines of Python, stdlib +
PyYAML. It probes your servers over HTTP, ICMP and SSH and posts to Slack only
when something *changes*.

No agents to install on the machines you watch. No time-series database. No
SaaS bill. If your estate is a handful of boxes and you mostly need to know
when one of them stops working, this is probably the right size of tool.

## The one idea

**Run the monitor somewhere that isn't the thing it monitors.**

Most small setups grow monitoring inside the application — a cron job in the
app, a periodic task on the queue worker. That works until the interesting
failure happens. When the database dies, the periodic task that would have
told you also dies. When the host reboots, so does its alarm. You get silence,
and in that arrangement **silence is indistinguishable from health**.

Sentinel runs on a separate box that holds SSH access to the others. It can
watch all of them, and none of them can silence it. The one thing it cannot
report is its own death, which is what `heartbeat_url` is for.

## Checks

| type | proves | key options |
|---|---|---|
| `http` | responds, fast enough, valid TLS | `expect_status`, `body_contains`, `max_latency_ms`, `tls_min_days` |
| `ping` | host is up at all | `count` |
| `tcp` | a port is open | `host`, `port` |
| `ssh` | anything expressible as a command | `max_value`, `min_value`, `output_matches` |
| `disk` | mount below N% | `path`, `max_percent` |
| `memory` | RAM below N% | `max_percent` |
| `docker` | containers running and not `unhealthy` | `containers` |
| `log` | error pattern under N matches in M minutes | `pattern`, `since_minutes`, `max_matches` |
| `deadman` | a file was touched recently | `path`, `max_age_minutes` |

TLS expiry rides along with the HTTPS check, so there's no separate cert
monitor to forget about.

`disk`, `memory`, `docker`, `log` and `deadman` are sugar over `ssh` — they
build a command, run it, and compare. Anything they can't express, `ssh` with
`max_value` / `output_matches` can.

### Check datastores over SSH, not TCP

A TCP probe of Redis or Postgres from your monitoring box only passes if the
port is reachable from there — which usually means exposed more widely than
you want. Running `redis-cli ping` *inside* the host over SSH proves health
without requiring exposure.

## Noise control

This is what decides whether anyone still reads the channel in a month.

- **Damping** — `failures_before_alert: 2` means a check must fail twice in a
  row before Slack hears about it. One blip stays quiet.
- **State-change only** — a host down for six hours produces *one* alert, not
  seventy-two.
- **Recovery notices** — and only if a failure was actually announced, so a
  silent blip doesn't produce a cheerful "recovered!" for something nobody
  knew was broken.
- **Severity** — `critical` vs `warn`, rendered as separate sections.
- **One message per run** — ten simultaneous failures are one Slack post.

## Usage

```bash
./sentinel.py                   # normal cron mode
./sentinel.py --dry-run         # run everything, print, touch nothing
./sentinel.py --only web-prod   # one check
./sentinel.py --list            # what's configured
./sentinel.py --quiet           # print only failures (what cron uses)
```

Exit code is `1` if anything is failing, `0` if all clear.

## Setup

Requires Python 3.8+ and PyYAML on the monitoring box, and key-based SSH from
it to whatever you want to check.

```bash
cp checks.example.yaml checks.yaml   # then edit: your hosts, your URLs
SENTINEL_HOST=user@monitor-box ./install.sh
```

`install.sh` copies the files, runs the tests remotely, does a live dry-run,
and registers a `*/5` cron entry — replacing any prior sentinel line and
leaving your other entries alone. Re-run it after editing `checks.yaml`.

### Credentials

Put them in `~/.sentinel.env` on the monitoring box, `chmod 600`. The cron
line sources it. **Don't put the webhook in `checks.yaml`** — that file is
meant to be committed, and `.gitignore` excludes it here for exactly that
reason.

```bash
export SENTINEL_SLACK_WEBHOOK="https://hooks.slack.com/services/..."
export SENTINEL_HEARTBEAT_URL="https://hc-ping.com/<uuid>"
```

### Your config is private

`checks.yaml` describes your infrastructure — addresses, what runs where,
which box reaches which. That's a useful map for an attacker. Keep it in a
private repo or on the box; this repo ships `checks.example.yaml` with
placeholders and gitignores the real thing.

## Watching the watcher

`heartbeat_url` is pinged at the end of every completed run. Point it at a
free dead-man's-switch service (healthchecks.io and others). If the monitoring
box dies, or sentinel crashes, or cron stops, the ping stops arriving and you
get told. Without it, sentinel has the exact flaw it exists to fix.

## Tests

```bash
python3 test_sentinel.py
```

30 assertions over the alert state machine — damping, dedupe, recovery,
flapping, isolation, timestamp stability, state persistence, corrupt-state
recovery, and shell quoting. No network, no SSH.

## A bug worth remembering

The first version of the `log` check piped its source straight into
`grep -Ec ... || true`. When the container name was wrong, `docker logs`
failed, `|| true` swallowed it, and the check reported **"0 errors —
healthy."**

A monitor that reports health because it failed to look is worse than no
monitor, because you stop checking manually. The source now runs separately
with its exit code tested, and a missing source fails loudly.

If you add a check type, apply the same test: **make the thing it watches
disappear, and confirm the check goes red rather than green.**

## License

MIT.
