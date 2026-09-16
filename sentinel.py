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


class Result:
    """Outcome of one check. `ok` drives alerting; `detail` is the human line."""

    __slots__ = ("name", "ok", "detail", "severity", "latency_ms")

    def __init__(self, name, ok, detail, severity="critical", latency_ms=None):
        self.name = name
        self.ok = ok
        self.detail = detail
        self.severity = severity
        self.latency_ms = latency_ms


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

    bad, seen = [], set()
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        name, state, status = parts[0], parts[1], parts[2]
        seen.add(name)
        if state != "running" or "unhealthy" in status.lower():
            bad.append(f"{name}={state}/{status}")
    missing = [n for n in names if not any(s.startswith(n) for s in seen)]
    if missing:
        bad.append(f"missing={','.join(missing)}")
    if bad:
        return False, "; ".join(bad)[:250], None
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
    "http": check_http, "tcp": check_tcp, "ping": check_ping, "ssh": check_ssh,
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
    try:
        ok, detail, latency = checker(cfg)
    except subprocess.TimeoutExpired:
        ok, detail, latency = False, "check timed out", None
    except Exception as e:  # a broken check must not abort the whole run
        ok, detail, latency = False, f"check error: {type(e).__name__}: {e}", None
    return Result(name, ok, detail, severity, latency)


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


def reconcile(results, state, threshold_default):
    """Fold results into state. Returns (newly_failing, recovered) for alerting.

    Only transitions are returned, so a host that has been down for six hours
    produces one alert, not seventy-two.
    """
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    newly_failing, recovered = [], []

    for r in results:
        prev = state.get(r.name, {"status": "ok", "consecutive_fail": 0})
        was_alerting = prev.get("alerting", False)
        threshold = prev.get("threshold", threshold_default)

        if r.ok:
            if was_alerting:
                recovered.append((r, prev.get("since")))
            state[r.name] = {
                "status": "ok", "consecutive_fail": 0, "alerting": False,
                "since": prev.get("since", now) if prev.get("status") == "ok" else now,
                "last_detail": r.detail, "threshold": threshold,
            }
        else:
            fails = prev.get("consecutive_fail", 0) + 1
            # Damping: stay quiet until the failure repeats, so one blip is not a page.
            alerting = fails >= threshold
            if alerting and not was_alerting:
                newly_failing.append(r)
            state[r.name] = {
                "status": "fail", "consecutive_fail": fails, "alerting": alerting,
                "since": prev.get("since", now) if prev.get("status") == "fail" else now,
                "last_detail": r.detail, "threshold": threshold,
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
        print(f"[sentinel] slack post failed: {e}", file=sys.stderr)
        return False


def format_alert(newly_failing, recovered, hostname):
    lines = []
    crit = [r for r in newly_failing if r.severity == "critical"]
    warn = [r for r in newly_failing if r.severity != "critical"]

    if crit:
        lines.append(f":rotating_light: *{len(crit)} CRITICAL* — production check failing")
        lines += [f"• *{r.name}* — {r.detail}" for r in crit]
    if warn:
        if lines:
            lines.append("")
        lines.append(f":warning: *{len(warn)} warning*")
        lines += [f"• *{r.name}* — {r.detail}" for r in warn]
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
        print(f"[sentinel] heartbeat failed: {e}", file=sys.stderr)


# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Lean estate monitor.")
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    ap.add_argument("--state", type=Path, default=DEFAULT_STATE)
    ap.add_argument("--dry-run", action="store_true", help="print results; never alert or write state")
    ap.add_argument("--only", metavar="NAME", help="run a single check by name")
    ap.add_argument("--list", action="store_true", help="list configured checks and exit")
    ap.add_argument("--quiet", action="store_true", help="print only failures")
    args = ap.parse_args()

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

    workers = min(settings.get("parallelism", 8), max(len(checks), 1))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(run_check, checks))

    for r in results:
        if r.ok and args.quiet:
            continue
        print(f"{'ok  ' if r.ok else 'FAIL'}  {r.name:<28} {r.detail}")

    failing = [r for r in results if not r.ok]

    if args.dry_run:
        print(f"\n[dry-run] {len(failing)}/{len(results)} failing; state and Slack untouched")
        return 1 if failing else 0

    state = load_state(args.state)
    newly_failing, recovered = reconcile(results, state, settings.get("failures_before_alert", 2))
    save_state(args.state, state)

    if newly_failing or recovered:
        webhook = os.environ.get("SENTINEL_SLACK_WEBHOOK") or settings.get("slack_webhook")
        text = format_alert(newly_failing, recovered, socket.gethostname())
        if webhook:
            post_slack(webhook, text)
        else:
            print("[sentinel] no webhook configured; alert follows:\n" + text, file=sys.stderr)

    # Heartbeat last and only on a completed run, so a crashed sentinel trips the switch.
    heartbeat(os.environ.get("SENTINEL_HEARTBEAT_URL") or settings.get("heartbeat_url"))
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
