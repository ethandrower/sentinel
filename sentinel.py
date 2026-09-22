#!/usr/bin/env python3
# ABOUTME: Lean external monitor — runs on the OpenClaw box, probes the estate over
# ABOUTME: HTTP/TCP/ICMP/SSH, and alerts to Slack only on state changes.
"""Sentinel — one cron script that watches the whole estate from outside it.

Runs where nothing it monitors runs, so a dead Redis, a full disk or a rebooted
Dokku host cannot silence its own alarm. Alerts fire on state *change* (new
failure / recovery) after N consecutive failures, so a single blip stays quiet.

    ./sentinel.py                 # run every check, alert on transitions
    ./sentinel.py --dry-run       # run everything, print, never touch Slack/state
    ./sentinel.py --only web-app  # run one check by name
    ./sentinel.py --list          # show configured checks
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import yaml

DEFAULT_CONFIG = Path(__file__).with_name("checks.yaml")
DEFAULT_STATE = Path(os.environ.get("SENTINEL_STATE", "~/.sentinel/state.json")).expanduser()
SSH_OPTS = [
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "ConnectTimeout=8",
]


def _stamp():
    """UTC timestamp for log lines. A log that cannot say *when* cannot explain anything."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _one_line(text):
    """Collapse a detail to a single line.

    ssh reports some failures on two lines — "Connection timed out during banner
    exchange", then "Connection to <host> port 22 timed out". Printed as-is the
    second line lands in the log bare, with no check name and no status, and
    reads as noise from nowhere.
    """
    return " · ".join(p.strip() for p in str(text or "").splitlines() if p.strip())


def failure_key(detail):
    """What a failure *is*, with the parts that drift from run to run removed.

    "6 matches ... above threshold 5" and "7 matches ... above threshold 5" are
    the same problem, and so are "91% RAM" and "93% RAM". Re-alerting on every
    wobble in a count would be noise of its own. Checks that can say precisely
    what is broken (the docker check names the containers) supply their own key.
    """
    return re.sub(r"\d+(?:\.\d+)?", "#", detail or "")


class Result:
    """Outcome of one check. `ok` drives alerting; `detail` is the human line.

    `key` is the failure's stable identity, used to notice when an
    already-failing check starts failing *differently*. `reason` is set by
    `reconcile` to say why a failure is being announced.
    """

    __slots__ = ("name", "ok", "detail", "severity", "latency_ms", "key", "reason")

    def __init__(self, name, ok, detail, severity="critical", latency_ms=None, key=None):
        self.name = name
        self.ok = ok
        self.detail = _one_line(detail)
        self.severity = severity
        self.latency_ms = latency_ms
        self.key = key if key is not None else failure_key(self.detail)
        self.reason = "new"


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Assert the status the server actually returned, not the one it lands on."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _tls_days_left(host, port=443, timeout=8):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            not_after = tls.getpeercert()["notAfter"]
    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    return (expiry - datetime.now(timezone.utc)).days


def check_http(cfg):
    url = cfg["url"]
    expect = cfg.get("expect_status", [200])
    if isinstance(expect, int):
        expect = [expect]
    timeout = cfg.get("timeout", 15)

    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(
        url, headers={"User-Agent": "sentinel/1.0"}, method=cfg.get("method", "GET")
    )

    started = time.monotonic()
    try:
        resp = opener.open(req, timeout=timeout)
        status, body = resp.status, resp.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read(65536).decode("utf-8", "replace")
    except Exception as e:
        return False, f"unreachable: {type(e).__name__}: {e}", None
    latency_ms = int((time.monotonic() - started) * 1000)

    if status not in expect:
        return False, f"HTTP {status} (expected {'/'.join(map(str, expect))})", latency_ms

    needle = cfg.get("body_contains")
    if needle and needle not in body:
        return False, f"HTTP {status} but body missing {needle!r}", latency_ms

    max_latency = cfg.get("max_latency_ms")
    if max_latency and latency_ms > max_latency:
        return False, f"HTTP {status} but slow: {latency_ms}ms > {max_latency}ms", latency_ms

    # TLS expiry rides along with the HTTPS check — no extra monitor to forget.
    min_days = cfg.get("tls_min_days")
    if min_days and url.startswith("https://"):
        try:
            days = _tls_days_left(urlparse(url).hostname)
            if days < min_days:
                return False, f"HTTP {status} but TLS expires in {days}d (< {min_days}d)", latency_ms
        except Exception as e:
            return False, f"HTTP {status} but TLS check failed: {e}", latency_ms

    return True, f"HTTP {status} in {latency_ms}ms", latency_ms


def check_json(cfg):
    """GET a JSON health endpoint and fail on exactly the problems it names.

    The endpoint does the judging — "this queue has not moved in 15 minutes",
    "the broker is evicting keys" — and returns them as a list (`field`,
    default "failing"). An empty list is healthy. The failure key is the set of
    names with numbers stripped, so a second queue going stale inside an
    already-failing check re-alerts as "changed", while a count creeping from
    +3 to +7 evictions does not.

    A bearer token, when needed, is read from the environment variable named
    by `bearer_env`: secrets never go in checks.yaml. A missing variable is a
    failure, not an unauthenticated request — a monitor that silently stops
    authenticating would read every 401 as the app being down.
    """
    url, field = cfg["url"], cfg.get("field", "failing")
    headers = {"User-Agent": "sentinel/1.0", "Accept": "application/json"}
    token_env = cfg.get("bearer_env")
    if token_env:
        token = os.environ.get(token_env, "")
        if not token:
            return False, f"{token_env} is not set; cannot authenticate", None, "json:no-token"
        headers["Authorization"] = f"Bearer {token}"

    opener = urllib.request.build_opener(_NoRedirect)
    started = time.monotonic()
    try:
        resp = opener.open(urllib.request.Request(url, headers=headers), timeout=cfg.get("timeout", 15))
        status, body = resp.status, resp.read(262144)
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}", None, f"json:http-{e.code}"
    except Exception as e:
        return False, f"unreachable: {type(e).__name__}: {e}", None, "json:unreachable"
    latency_ms = int((time.monotonic() - started) * 1000)

    try:
        items = json.loads(body).get(field)
    except (ValueError, AttributeError):
        return False, f"HTTP {status} but the response is not a JSON object", latency_ms, "json:not-json"
    if not isinstance(items, list):
        return False, f"HTTP {status} but no {field!r} list in the response", latency_ms, "json:shape"
    if items:
        names = [str(item) for item in items]
        key = "json:" + ",".join(sorted(failure_key(name) for name in names))
        return False, "; ".join(names)[:250], latency_ms, key
    return True, f"HTTP {status}, nothing failing, in {latency_ms}ms", latency_ms


def check_tcp(cfg):
    host, port = cfg["host"], int(cfg["port"])
    timeout = cfg.get("timeout", 8)
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except Exception as e:
        return False, f"{host}:{port} closed: {type(e).__name__}", None
    latency_ms = int((time.monotonic() - started) * 1000)
    return True, f"{host}:{port} open in {latency_ms}ms", latency_ms


def check_ping(cfg):
    host = cfg["host"]
    count = str(cfg.get("count", 2))
    proc = subprocess.run(
        ["ping", "-c", count, "-W", "3", host],
        capture_output=True, text=True, timeout=cfg.get("timeout", 20),
    )
    if proc.returncode != 0:
        return False, f"{host} unreachable (ICMP)", None
    m = re.search(r"= [\d.]+/([\d.]+)/", proc.stdout)
    avg = f" avg {float(m.group(1)):.0f}ms" if m else ""
    return True, f"{host} reachable{avg}", None


def _ssh(cfg, command, timeout=None):
    """Run a command on a remote host. Returns (exit_code, stdout, stderr)."""
    target = f"{cfg.get('user', 'root')}@{cfg['host']}"
    proc = subprocess.run(
        ["ssh", *SSH_OPTS, target, command],
        capture_output=True, text=True, timeout=timeout or cfg.get("timeout", 30),
    )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def check_ssh(cfg):
    try:
        rc, out, err = _ssh(cfg, cfg["command"])
    except subprocess.TimeoutExpired:
        return False, f"ssh {cfg['host']} timed out", None
    except Exception as e:
        return False, f"ssh {cfg['host']} failed: {type(e).__name__}: {e}", None

    if rc != cfg.get("expect_exit", 0):
        return False, f"exit {rc}: {(err or out)[:200]}", None

    pattern = cfg.get("output_matches")
    if pattern and not re.search(pattern, out):
        return False, f"output {out[:120]!r} does not match /{pattern}/", None

    # Numeric comparison — the disk/memory/queue-depth workhorse.
    for bound, exceeded, word in (
        ("max_value", lambda v, t: v > t, "above"),
        ("min_value", lambda v, t: v < t, "below"),
    ):
        threshold = cfg.get(bound)
        if threshold is None:
            continue
        m = re.search(r"-?\d+(?:\.\d+)?", out)
        if not m:
            return False, f"expected a number, got {out[:120]!r}", None
        value = float(m.group())
        unit = cfg.get("unit", "")
        if exceeded(value, float(threshold)):
            return False, f"{value:g}{unit} is {word} threshold {threshold:g}", None
        return True, f"{value:g}{unit}", None

    return True, (out[:160] or "ok"), None


def check_disk(cfg):
    """Sugar over ssh: percent-used of a mount point."""
    path = cfg.get("path", "/")
    return check_ssh({
        **cfg,
        "command": f"df --output=pcent {_shq(path)} | tail -1 | tr -dc '0-9'",
        "max_value": cfg.get("max_percent", 85),
        "unit": "% used",
    })


def check_memory(cfg):
    """Sugar over ssh: percent of RAM in use."""
    return check_ssh({
        **cfg,
        "command": "free | awk '/^Mem:/ {printf \"%.0f\", ($2-$7)/$2*100}'",
        "max_value": cfg.get("max_percent", 90),
        "unit": "% RAM",
    })


def check_docker(cfg):
    """Sugar over ssh: named containers must be running, and healthy if they declare a healthcheck."""
    names = cfg.get("containers") or [cfg["container"]]
    pattern = "|".join(re.escape(n) for n in names)
    cmd = (
        "docker ps -a --format '{{.Names}}\\t{{.State}}\\t{{.Status}}' "
        f"| grep -E {_shq('^(' + pattern + ')')} || true"
    )
    try:
        rc, out, err = _ssh(cfg, cmd)
    except subprocess.TimeoutExpired:
        return False, f"ssh {cfg['host']} timed out", None
    except Exception as e:
        return False, f"ssh {cfg['host']} failed: {type(e).__name__}", None
    if rc != 0:
        return False, f"docker ps failed: {(err or out)[:200]}", None
    if not out:
        return False, f"no container matching {names}", None

    bad, bad_names, seen = [], [], set()
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        name, state, status = parts[0], parts[1], parts[2]
        if ".upcoming-" in name:
            # dokku names the container for an in-flight deploy
            # `<app>.<proc>.<n>.upcoming-<id>`, and a deploy that fails leaves
            # it behind, exited, indefinitely. It is not a process the app
            # runs. Counting it made this check fail continuously — and because
            # alerts fire on transitions, a check that is always failing never
            # transitions, so it silently absorbed a real OOM-killed worker.
            continue
        seen.add(name)
        if state != "running" or "unhealthy" in status.lower():
            bad.append(f"{name}={state}/{status}")
            # The key omits the status text on purpose: "Exited (1) 13 hours
            # ago" becomes "About an hour ago" and then "2 days ago", and a key
            # that drifts would re-alert on the passage of time.
            bad_names.append(f"{name}={state}")
    missing = [n for n in names if not any(s.startswith(n) for s in seen)]
    if missing:
        bad.append(f"missing={','.join(missing)}")
        bad_names.append(f"missing={','.join(sorted(missing))}")
    if bad:
        return False, "; ".join(bad)[:250], None, "docker:" + ",".join(sorted(bad_names))
    return True, f"{len(seen)} container(s) running", None


def check_log(cfg):
    """Sugar over ssh: count matches of a pattern in recent output; alert past a threshold.

    The log source is run *separately* from the grep and its exit code checked.
    Piping straight into `grep -c ... || true` would turn a missing container or
    an unreadable journal into a confident "0 errors" — a monitor reporting
    health because it failed to look is worse than no monitor at all.
    """
    minutes = cfg.get("since_minutes", 15)
    pattern = cfg["pattern"]
    if "command" in cfg:
        source = cfg["command"]
    elif "container" in cfg:
        source = f"docker logs --since {minutes}m {_shq(cfg['container'])} 2>&1"
    else:
        source = f"journalctl --since {_shq(str(minutes) + ' min ago')} --no-pager"
    # grep exits 1 on zero matches, which is the healthy case — so `|| true`
    # belongs on the grep, never on the source.
    command = (
        f"_out=$({source}) || {{ echo LOG_SOURCE_UNAVAILABLE; exit 9; }}; "
        f"printf '%s' \"$_out\" | grep -Ec {_shq(pattern)} || true"
    )
    return check_ssh({
        **cfg,
        "command": command,
        "max_value": cfg.get("max_matches", 0),
        "unit": f" matches of /{pattern}/ in {minutes}m",
    })


def check_deadman(cfg):
    """Assert a heartbeat file was touched recently — catches jobs that stop running."""
    path = _shq(cfg["path"])
    cmd = f"echo $(( ($(date +%s) - $(stat -c %Y {path} 2>/dev/null || echo 0)) / 60 ))"
    return check_ssh({
        **cfg,
        "command": cmd,
        "max_value": cfg.get("max_age_minutes", 60),
        "unit": "min since last run",
    })


def _shq(s):
    """Single-quote a string for safe interpolation into a remote shell command."""
    return "'" + str(s).replace("'", "'\\''") + "'"


CHECKERS = {
    "http": check_http, "json": check_json, "tcp": check_tcp, "ping": check_ping, "ssh": check_ssh,
    "disk": check_disk, "memory": check_memory, "docker": check_docker,
    "log": check_log, "deadman": check_deadman,
}


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------

def run_check(cfg):
    name = cfg.get("name", cfg.get("type", "unnamed"))
    severity = cfg.get("severity", "critical")
    checker = CHECKERS.get(cfg.get("type"))
    if checker is None:
        return Result(name, False, f"unknown check type {cfg.get('type')!r}", "warn")
    key = None
    try:
        # Checkers return (ok, detail, latency) and may add a fourth element: a
        # stable key for the failure, when they can name what broke precisely.
        outcome = checker(cfg)
        ok, detail, latency = outcome[0], outcome[1], outcome[2]
        if len(outcome) > 3:
            key = outcome[3]
    except subprocess.TimeoutExpired:
        ok, detail, latency = False, "check timed out", None
    except Exception as e:  # a broken check must not abort the whole run
        ok, detail, latency = False, f"check error: {type(e).__name__}: {e}", None
    return Result(name, ok, detail, severity, latency, key=key)


def load_state(path):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(path, state):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True))
    tmp.replace(path)  # atomic — a killed run never leaves truncated state


def reconcile(results, state, threshold_default, clear_default=2):
    """Fold results into state. Returns (newly_failing, recovered) for alerting.

    Only transitions are returned, so a host that has been down for six hours
    produces one alert, not seventy-two.

    Recovery is damped the same way failure is. A check that has alerted must
    come back clean `clear_after` times before it is called recovered, because a
    measurement that sits on its threshold — 6 errors, then 5, then 6 — crosses
    it every few minutes, and announcing each crossing produces a stream of
    alternating "warning" and "recovered" posts that say nothing and train
    everyone to ignore the channel. Until it clears, the check stays in its
    alerting state, so the next failure is not a new alert either.
    """
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    newly_failing, recovered = [], []

    for r in results:
        prev = state.get(r.name, {"status": "ok", "consecutive_fail": 0})
        was_alerting = prev.get("alerting", False)
        threshold = prev.get("threshold", threshold_default)

        clear_after = prev.get("clear_after", clear_default)

        if r.ok:
            clean = prev.get("consecutive_ok", 0) + 1
            if was_alerting and clean < clear_after:
                # Clean, but not yet clean enough to say so. Hold the alerting
                # state: this is the run that would otherwise announce a
                # recovery the next run takes back.
                state[r.name] = {
                    **prev, "status": "ok", "consecutive_fail": 0, "consecutive_ok": clean,
                    "alerting": True, "last_detail": r.detail,
                    "threshold": threshold, "clear_after": clear_after,
                }
                continue
            if was_alerting:
                recovered.append((r, prev.get("since")))
            state[r.name] = {
                "status": "ok", "consecutive_fail": 0, "consecutive_ok": clean, "alerting": False,
                "since": prev.get("since", now) if prev.get("status") == "ok" else now,
                "last_detail": r.detail, "threshold": threshold, "clear_after": clear_after,
            }
        else:
            fails = prev.get("consecutive_fail", 0) + 1
            # Damping: stay quiet until the failure repeats, so one blip is not a
            # page. It gates *entering* an episode, not continuing one — a check
            # that is already alerting and fails again mid-recovery stays in the
            # same episode, or a measurement crossing its threshold would drop
            # out of alerting and re-announce itself on the way back up.
            alerting = was_alerting or fails >= threshold
            if alerting and not was_alerting:
                newly_failing.append(r)
            elif alerting and was_alerting:
                if "key" not in prev:
                    # State written by a version that did not record what a
                    # failure *was*. Re-announce it once rather than assume it
                    # is unchanged: assuming so is exactly how an OOM-killed
                    # production worker went unreported for thirteen hours
                    # inside a check that was already failing for another reason.
                    r.reason = "ongoing"
                    newly_failing.append(r)
                elif prev["key"] != r.key:
                    # Still failing, but failing *differently* — a second
                    # container down, a new error. Alerting only on ok->fail
                    # would stay silent here, which is the gap that hid the
                    # worker above.
                    r.reason = "changed"
                    newly_failing.append(r)
            state[r.name] = {
                "status": "fail", "consecutive_fail": fails, "consecutive_ok": 0,
                "alerting": alerting,
                "since": prev.get("since", now) if prev.get("status") == "fail" else now,
                "last_detail": r.detail, "threshold": threshold, "key": r.key,
                "clear_after": clear_after,
            }

    return newly_failing, recovered


# --------------------------------------------------------------------------
# Alerting
# --------------------------------------------------------------------------

def post_slack(webhook, text):
    payload = json.dumps({"text": text}).encode()
    req = urllib.request.Request(
        webhook, data=payload, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status == 200
    except Exception as e:
        print(f"{_stamp()}  [sentinel] slack post failed: {e}", file=sys.stderr)
        return False


_REASON_TAG = {
    "changed": " _(changed — was already failing, now failing differently)_",
    "ongoing": " _(already failing; re-announced once after an upgrade)_",
}


def _alert_line(r):
    return f"• *{r.name}* — {r.detail}{_REASON_TAG.get(r.reason, '')}"


def format_alert(newly_failing, recovered, hostname):
    lines = []
    crit = [r for r in newly_failing if r.severity == "critical"]
    warn = [r for r in newly_failing if r.severity != "critical"]

    if crit:
        lines.append(f":rotating_light: *{len(crit)} CRITICAL* — production check failing")
        lines += [_alert_line(r) for r in crit]
    if warn:
        if lines:
            lines.append("")
        lines.append(f":warning: *{len(warn)} warning*")
        lines += [_alert_line(r) for r in warn]
    if recovered:
        if lines:
            lines.append("")
        lines.append(f":white_check_mark: *{len(recovered)} recovered*")
        for r, since in recovered:
            downtime = ""
            if since:
                try:
                    delta = datetime.now(timezone.utc) - datetime.fromisoformat(since)
                    downtime = f" (down {int(delta.total_seconds() // 60)}m)"
                except ValueError:
                    pass
            lines.append(f"• *{r.name}* — {r.detail}{downtime}")

    lines.append(f"\n_sentinel on {hostname} · {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}_")
    return "\n".join(lines)


def heartbeat(url):
    """Ping an external dead-man's switch so a dead sentinel is itself noticed."""
    if not url:
        return
    try:
        urllib.request.urlopen(url, timeout=10).read()
    except Exception as e:
        print(f"{_stamp()}  [sentinel] heartbeat failed: {e}", file=sys.stderr)


# --------------------------------------------------------------------------

#: Cron fires every few minutes and never exactly on the second, so a check
#: due "every 60 minutes" would otherwise slip to every 65.
_DUE_SLACK_SECONDS = 60


def is_due(cfg, prev, now=None):
    """Whether a check with `every_minutes` should run on this invocation.

    Most checks run every time. Some cost real money or real load — a canary
    that performs live scrapes through a paid proxy — and belong on a slower
    clock than the one cron gives sentinel. Their last run is kept in the state
    file, so the cadence survives across invocations without a second cron line.
    """
    every = cfg.get("every_minutes")
    if not every:
        return True
    last = prev.get("last_run")
    if not last:
        return True
    try:
        last_at = datetime.fromisoformat(last)
    except ValueError:
        return True
    now = now or datetime.now(timezone.utc)
    return (now - last_at).total_seconds() >= every * 60 - _DUE_SLACK_SECONDS


def print_status(state_path):
    """What is failing right now, read from the state file.

    With --quiet the log records only changes, so "is anything still broken?"
    is answered here rather than by scrolling back through repeats.
    """
    state = load_state(state_path)
    if not state:
        print("no state yet — sentinel has not completed a run")
        return 0
    failing = {n: s for n, s in state.items() if s.get("status") == "fail"}
    if not failing:
        print(f"all {len(state)} checks passing")
        return 0
    print(f"{len(failing)} of {len(state)} checks failing:\n")
    for name, s in sorted(failing.items(), key=lambda kv: kv[1].get("since", "")):
        flag = "ALERTED" if s.get("alerting") else "damped "
        print(f"  {flag}  {name:<28} since {s.get('since', '?')}  ({s.get('consecutive_fail', 0)} runs)")
        print(f"           {s.get('last_detail', '')}")
    return 1


def main():
    ap = argparse.ArgumentParser(description="Lean estate monitor.")
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    ap.add_argument("--state", type=Path, default=DEFAULT_STATE)
    ap.add_argument("--dry-run", action="store_true", help="print results; never alert or write state")
    ap.add_argument("--only", metavar="NAME", help="run a single check by name")
    ap.add_argument("--list", action="store_true", help="list configured checks and exit")
    ap.add_argument(
        "--quiet", action="store_true",
        help="log only changes: new failures, changed failures and recoveries",
    )
    ap.add_argument(
        "--status", action="store_true",
        help="show what is failing now, from the state file, and exit",
    )
    args = ap.parse_args()

    if args.status:
        return print_status(args.state)

    cfg = yaml.safe_load(args.config.read_text()) or {}
    checks = cfg.get("checks", [])
    settings = cfg.get("settings", {})

    if args.list:
        for c in checks:
            print(f"{c.get('severity', 'critical'):>8}  {c.get('type', '?'):<8}  {c.get('name')}")
        return 0

    if args.only:
        checks = [c for c in checks if c.get("name") == args.only]
        if not checks:
            print(f"no check named {args.only!r}", file=sys.stderr)
            return 2

    state = {} if args.dry_run else load_state(args.state)
    if not (args.only or args.dry_run):
        checks = [c for c in checks if is_due(c, state.get(c.get("name"), {}))]

    workers = min(settings.get("parallelism", 8), max(len(checks), 1))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(run_check, checks))

    failing = [r for r in results if not r.ok]

    # Interactive and dry runs print every check, so a person running it by
    # hand sees the whole picture.
    if args.dry_run or not args.quiet:
        for r in results:
            print(f"{_stamp()}  {'ok  ' if r.ok else 'FAIL'}  {r.name:<28} {r.detail}")

    if args.dry_run:
        print(f"{_stamp()}  [dry-run] {len(failing)}/{len(results)} failing; state and Slack untouched")
        return 1 if failing else 0

    newly_failing, recovered = reconcile(
        results,
        state,
        settings.get("failures_before_alert", 2),
        settings.get("clear_after", 2),
    )
    ran_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for r in results:
        state.setdefault(r.name, {})["last_run"] = ran_at
    save_state(args.state, state)

    if args.quiet:
        # The cron log records *changes* — the same things Slack is told. A
        # check that has been failing for a day belongs in the state file (see
        # --status), not repeated every five minutes: that repetition is what
        # buried an OOM-killed production worker under 260 identical lines.
        for r in newly_failing:
            tag = {"changed": "CHANGED  ", "ongoing": "ONGOING  "}.get(r.reason, "FAIL     ")
            print(f"{_stamp()}  {tag} {r.name:<28} {r.detail}")
        for r, _since in recovered:
            print(f"{_stamp()}  RECOVERED {r.name:<28} {r.detail}")
        if newly_failing or recovered:
            print(f"{_stamp()}  run: {len(results)} checks, {len(failing)} failing")

    if newly_failing or recovered:
        webhook = os.environ.get("SENTINEL_SLACK_WEBHOOK") or settings.get("slack_webhook")
        text = format_alert(newly_failing, recovered, socket.gethostname())
        if webhook:
            post_slack(webhook, text)
        else:
            print(
                f"{_stamp()}  [sentinel] no webhook configured; alert follows:\n" + text,
                file=sys.stderr,
            )

    # Heartbeat last and only on a completed run, so a crashed sentinel trips the switch.
    heartbeat(os.environ.get("SENTINEL_HEARTBEAT_URL") or settings.get("heartbeat_url"))
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
