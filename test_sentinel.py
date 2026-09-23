#!/usr/bin/env python3
# ABOUTME: Tests for sentinel's alert state machine and shell quoting.
# ABOUTME: Pure-logic only — no network, no SSH; run with `python3 -m pytest` or directly.
"""Run: python3 test_sentinel.py   (or pytest, if available)"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import sentinel  # noqa: E402
from sentinel import Result, _shq, format_alert, load_state, reconcile, save_state  # noqa: E402

FAILURES = []


def check(label, cond):
    if cond:
        print(f"  ok    {label}")
    else:
        print(f"  FAIL  {label}")
        FAILURES.append(label)


def ok(name):
    return Result(name, True, "HTTP 200 in 90ms")


def bad(name, severity="critical"):
    return Result(name, False, "unreachable", severity)


def test_damping_suppresses_a_single_blip():
    print("damping: one failure is not an alert")
    state = {}
    newly, rec = reconcile([bad("web")], state, threshold_default=2)
    check("first failure alerts nobody", newly == [] and rec == [])
    check("but it is recorded", state["web"]["consecutive_fail"] == 1)
    check("and is not yet alerting", state["web"]["alerting"] is False)


def test_second_failure_alerts_once_then_stays_quiet():
    print("dedupe: alert fires once, not every run")
    state = {}
    reconcile([bad("web")], state, 2)
    newly, _ = reconcile([bad("web")], state, 2)
    check("second consecutive failure alerts", [r.name for r in newly] == ["web"])

    newly, _ = reconcile([bad("web")], state, 2)
    check("third failure is silent (already alerting)", newly == [])
    newly, _ = reconcile([bad("web")], state, 2)
    check("fourth failure is still silent", newly == [])
    check("fail count keeps climbing", state["web"]["consecutive_fail"] == 4)


def test_recovery_alerts_only_if_we_had_alerted():
    print("recovery: only announced if a failure was announced")
    state = {}
    reconcile([bad("web")], state, 2)
    reconcile([bad("web")], state, 2)          # now alerting
    newly, rec = reconcile([ok("web")], state, 2)
    check("one clean run is not yet a recovery", rec == [])
    newly, rec = reconcile([ok("web")], state, 2)
    check("recovery is announced once it holds", [r.name for r, _ in rec] == ["web"])
    check("state is clean", state["web"]["status"] == "ok")
    check("counter reset", state["web"]["consecutive_fail"] == 0)

    # A blip that never alerted must not produce a recovery message.
    state2 = {}
    reconcile([bad("db")], state2, 2)          # 1 failure, below threshold
    newly, rec = reconcile([ok("db")], state2, 2)
    check("silent blip produces no recovery noise", rec == [] and newly == [])


def test_flapping_does_not_spam():
    print("flapping: alternating up/down stays quiet under threshold 2")
    state = {}
    alerts = 0
    for i in range(6):
        newly, rec = reconcile([bad("x") if i % 2 == 0 else ok("x")], state, 2)
        alerts += len(newly) + len(rec)
    check("no alert from pure flapping", alerts == 0)


def test_independent_checks_do_not_interfere():
    print("isolation: checks track state separately")
    state = {}
    reconcile([bad("a"), ok("b")], state, 2)
    newly, _ = reconcile([bad("a"), ok("b")], state, 2)
    check("only the failing check alerts", [r.name for r in newly] == ["a"])
    check("healthy check untouched", state["b"]["status"] == "ok")


def test_since_timestamp_is_stable_across_runs():
    print("since: failure start time does not drift")
    state = {}
    reconcile([bad("web")], state, 2)
    first_since = state["web"]["since"]
    reconcile([bad("web")], state, 2)
    reconcile([bad("web")], state, 2)
    check("since pinned to first failure", state["web"]["since"] == first_since)


def test_format_alert_separates_severities():
    print("formatting: critical and warn are visually separated")
    text = format_alert([bad("web"), bad("disk", "warn")], [], "monitor-host")
    check("critical section present", "1 CRITICAL" in text)
    check("warn section present", "1 warning" in text)
    check("names included", "web" in text and "disk" in text)
    check("host attributed", "monitor-host" in text)

    rtext = format_alert([], [(ok("web"), None)], "monitor-host")
    check("recovery rendered", "recovered" in rtext)


def test_shell_quoting_blocks_injection():
    print("quoting: config values cannot break out of the remote shell")
    check("single quotes escaped", _shq("it's") == "'it'\\''s'")
    nasty = _shq("; rm -rf /")
    check("semicolon is inert inside quotes", nasty.startswith("'") and nasty.endswith("'"))
    check("no bare semicolon escape", "'; rm" not in nasty[1:-1] or nasty.count("'") == 2)


def test_state_roundtrip_is_atomic_and_lossless():
    print("state: persists and reloads")
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "nested" / "state.json"
        state = {}
        reconcile([bad("web"), ok("db")], state, 2)
        save_state(p, state)
        check("parent dirs created", p.exists())
        check("roundtrips exactly", load_state(p) == state)
        check("valid json on disk", isinstance(json.loads(p.read_text()), dict))
        check("no temp file left behind", not p.with_suffix(".tmp").exists())

    check("missing file yields empty state", load_state(Path("/nonexistent/x.json")) == {})


def test_corrupt_state_does_not_crash():
    print("state: corrupt file degrades gracefully")
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write("{ this is not json")
        path = Path(f.name)
    check("corrupt state reads as empty", load_state(path) == {})
    path.unlink()


# --------------------------------------------------------------------------
# Log noise and masked outages
#
# The first production deployment wrote the same two failures every five
# minutes for days, and one of them was a false positive — an abandoned dokku
# deploy container. Because alerts fire on transitions, that always-failing
# check never transitioned again, so when a real worker was OOM-killed inside
# it, nothing was announced. These tests hold the fixes.
# --------------------------------------------------------------------------


def test_multiline_detail_becomes_one_line():
    print("detail: ssh's two-line errors do not leak a bare line into the log")
    r = Result("disk", False, "exit 255: Connection timed out during banner exchange\n"
                              "Connection to 1.2.3.4 port 22 timed out")
    check("no newline survives", "\n" not in r.detail)
    check("both halves kept", "banner exchange" in r.detail and "port 22 timed out" in r.detail)


def test_numbers_do_not_change_a_failures_identity():
    print("identity: a wobbling count is the same failure, not a new one")
    a = Result("errs", False, "6 matches of /Traceback/ in 30m is above threshold 5")
    b = Result("errs", False, "7 matches of /Traceback/ in 30m is above threshold 5")
    check("same key despite different counts", a.key == b.key)
    state = {}
    reconcile([a], state, 2)
    reconcile([a], state, 2)                          # now alerting
    newly, _ = reconcile([b], state, 2)
    check("count wobble does not re-alert", newly == [])


def test_a_failing_check_that_fails_differently_realerts():
    print("changed: a new failure inside an already-failing check is announced")
    state = {}
    first = Result("procs", False, "worker_ai=exited", key="docker:worker_ai=exited")
    reconcile([first], state, 2)
    reconcile([first], state, 2)                      # alerting on worker_ai
    worse = Result("procs", False, "worker_ai=exited; worker1=exited",
                   key="docker:worker1=exited,worker_ai=exited")
    newly, _ = reconcile([worse], state, 2)
    check("the new failure alerts", [r.name for r in newly] == ["procs"])
    check("and is labelled as a change", bool(newly) and newly[0].reason == "changed")
    newly, _ = reconcile([worse], state, 2)
    check("then goes quiet again", newly == [])


def test_state_from_an_older_version_is_reannounced_once():
    print("upgrade: a failure recorded without a key is re-announced exactly once")
    state = {"procs": {"status": "fail", "consecutive_fail": 40, "alerting": True,
                       "since": "2026-09-17T17:00:00+00:00", "last_detail": "x",
                       "threshold": 2}}
    r = Result("procs", False, "worker1=exited", key="docker:worker1=exited")
    newly, _ = reconcile([r], state, 2)
    check("re-announced after upgrade", [x.name for x in newly] == ["procs"])
    check("labelled ongoing", bool(newly) and newly[0].reason == "ongoing")
    newly, _ = reconcile([r], state, 2)
    check("but only once", newly == [])


def _docker(lines):
    """check_docker against canned `docker ps -a` output — no SSH."""
    real = sentinel._ssh
    sentinel._ssh = lambda cfg, cmd, timeout=None: (0, "\n".join(lines), "")
    try:
        return sentinel.check_docker(
            {"host": "h", "containers": ["app.web", "app.worker1", "app.worker_ai"]}
        )
    finally:
        sentinel._ssh = real


def test_docker_ignores_abandoned_dokku_deploy_containers():
    print("docker: a failed deploy's .upcoming- container is not an outage")
    out = _docker([
        "app.web.1\trunning\tUp 22 hours",
        "app.worker1.1\trunning\tUp 22 hours",
        "app.worker_ai.1\trunning\tUp 22 hours",
        "app.worker_ai.1.upcoming-3712\texited\tExited (127) 22 hours ago",
    ])
    check("all real processes running -> ok", out[0] is True)


def test_docker_still_catches_a_real_dead_worker():
    print("docker: ignoring deploy leftovers must not hide a real exit")
    out = _docker([
        "app.web.1\trunning\tUp 22 hours",
        "app.worker1.1\texited\tExited (1) 13 hours ago",
        "app.worker_ai.1\trunning\tUp 22 hours",
        "app.worker_ai.1.upcoming-3712\texited\tExited (127) 22 hours ago",
    ])
    check("dead worker fails the check", out[0] is False)
    check("names the dead worker", "app.worker1.1" in out[1])
    check("does not blame the deploy leftover", "upcoming" not in out[1])


def test_docker_key_does_not_drift_with_elapsed_time():
    print("docker: 'About an hour ago' becoming '13 hours ago' is not a new failure")
    a = _docker(["app.web.1\trunning\tUp", "app.worker1.1\texited\tExited (1) About an hour ago",
                 "app.worker_ai.1\trunning\tUp"])
    b = _docker(["app.web.1\trunning\tUp", "app.worker1.1\texited\tExited (1) 13 hours ago",
                 "app.worker_ai.1\trunning\tUp"])
    check("same key as time passes", a[3] == b[3])


def test_format_alert_says_why_a_failure_is_announced():
    print("formatting: changed and re-announced failures are labelled")
    r = Result("procs", False, "worker1=exited")
    r.reason = "changed"
    check("changed is labelled", "changed" in format_alert([r], [], "h"))
    r.reason = "ongoing"
    check("ongoing is labelled", "re-announced" in format_alert([r], [], "h"))


def test_a_measurement_sitting_on_its_threshold_alerts_once():
    print("flapping: 6 errors, then 5, then 6 is one alert, not a stream")
    # The real case: a log check counting 4-6 matches against a threshold of 5
    # produced alternating "warning" and "recovered" posts every ~35 minutes.
    state = {}
    alerts = 0
    recoveries = 0
    for value in [6, 6, 5, 6, 5, 6, 6, 5, 6]:      # above, below, above ...
        result = Result("errs", value <= 5, f"{value} matches of /Traceback/ in 30m", "warn")
        newly, rec = reconcile([result], state, 2)
        alerts += len(newly)
        recoveries += len(rec)
    check("one alert for the whole episode", alerts == 1)
    check("and no recovery while it keeps crossing back", recoveries == 0)

    # It still recovers once the thing actually stops.
    for _ in range(3):
        newly, rec = reconcile([Result("errs", True, "2 matches of /Traceback/ in 30m")], state, 2)
        recoveries += len(rec)
    check("recovery announced when it really clears", recoveries == 1)


def test_a_real_outage_still_recovers_promptly():
    print("recovery: damping costs one run, not an hour")
    state = {}
    reconcile([bad("web")], state, 2)
    reconcile([bad("web")], state, 2)
    reconcile([ok("web")], state, 2)
    newly, rec = reconcile([ok("web")], state, 2)
    check("announced on the second clean run", [r.name for r, _ in rec] == ["web"])


def test_status_reports_what_is_failing_now():
    print("status: --status reads the state file, since the log no longer repeats")
    import contextlib
    import io

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "state.json"
        state = {}
        reconcile([bad("web"), ok("db")], state, 2)
        reconcile([bad("web"), ok("db")], state, 2)
        save_state(p, state)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = sentinel.print_status(p)
        check("exit 1 while something fails", code == 1)
        check("names the failing check", "web" in buf.getvalue())
        check("does not list the healthy one", "  db " not in buf.getvalue())


# --------------------------------------------------------------------------
# json checks: an endpoint names what is wrong; sentinel alerts on exactly that
# --------------------------------------------------------------------------


def _serve(body, status=200):
    """A throwaway local HTTP server returning `body`; records the last request's headers."""
    import http.server
    import threading

    seen = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            seen["auth"] = self.headers.get("Authorization")
            payload = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}/health", seen


def _json(body, status=200, **cfg):
    server, url, seen = _serve(body, status)
    try:
        return sentinel.check_json({"url": url, **cfg}), seen
    finally:
        server.shutdown()


def test_json_nothing_failing_is_healthy():
    print("json: an empty failing list is healthy")
    (outcome, _) = _json({"failing": [], "queues": []})
    check("ok", outcome[0] is True)


def test_json_names_exactly_what_is_failing():
    print("json: the detail is the endpoint's own words")
    (outcome, _) = _json({"failing": ["reports=stale"]})
    check("fails", outcome[0] is False)
    check("detail names the queue", outcome[1] == "reports=stale")


def test_json_key_ignores_counts_but_not_new_problems():
    print("json: +3 -> +7 evictions is the same problem; a second queue is a new one")
    (a, _) = _json({"failing": ["broker.evictions=+3"]})
    (b, _) = _json({"failing": ["broker.evictions=+7"]})
    (c, _) = _json({"failing": ["broker.evictions=+7", "reports=stale"]})
    check("count change keeps the key", a[3] == b[3])
    check("a new problem changes the key", b[3] != c[3])


def test_json_sends_the_bearer_from_the_environment():
    print("json: the token comes from an env var, never the config file")
    import os

    os.environ["SENTINEL_TEST_TOKEN"] = "s3cret"
    try:
        (outcome, seen) = _json({"failing": []}, bearer_env="SENTINEL_TEST_TOKEN")
    finally:
        del os.environ["SENTINEL_TEST_TOKEN"]
    check("authenticated", seen.get("auth") == "Bearer s3cret")
    check("ok", outcome[0] is True)


def test_json_missing_token_is_a_failure_not_an_anonymous_request():
    print("json: a missing token fails loudly instead of reading 401s as an outage")
    (outcome, seen) = _json({"failing": []}, bearer_env="SENTINEL_DOES_NOT_EXIST")
    check("fails", outcome[0] is False)
    check("says why", "SENTINEL_DOES_NOT_EXIST is not set" in outcome[1])
    check("never sent the request", "auth" not in seen)


def test_json_http_error_fails():
    print("json: a 5xx means the app itself is down")
    (outcome, _) = _json({"failing": []}, status=503)
    check("fails", outcome[0] is False and outcome[1] == "HTTP 503")


def test_json_unreadable_or_wrong_shape_fails():
    print("json: an answer sentinel cannot read is never treated as healthy")
    (not_json, _) = _json(b"<html>login</html>")
    (no_field, _) = _json({"status": "ok"})
    check("non-JSON fails", not_json[0] is False)
    check("missing field fails", no_field[0] is False and "no 'failing' list" in no_field[1])


# --------------------------------------------------------------------------
# every_minutes: some checks belong on a slower clock than cron's
# --------------------------------------------------------------------------


def test_checks_without_a_cadence_always_run():
    print("cadence: a plain check runs on every invocation")
    check("no every_minutes -> due", sentinel.is_due({"name": "web"}, {"last_run": "2026-09-22T12:00:00+00:00"}))


def test_an_hourly_check_waits_for_its_hour():
    print("cadence: an hourly canary runs once an hour, not every five minutes")
    from datetime import datetime, timedelta, timezone

    last = datetime(2026, 9, 22, 12, 0, 3, tzinfo=timezone.utc)
    prev = {"last_run": last.isoformat()}
    cfg = {"name": "canary", "every_minutes": 60}
    check("never run -> due", sentinel.is_due(cfg, {}))
    check("5 minutes later -> not due", not sentinel.is_due(cfg, prev, last + timedelta(minutes=5)))
    check("55 minutes later -> not due", not sentinel.is_due(cfg, prev, last + timedelta(minutes=55)))
    # Cron fires a few seconds either side of the minute; without slack an
    # hourly check would slip to every 65 minutes.
    check("59m58s later -> due", sentinel.is_due(cfg, prev, last + timedelta(minutes=59, seconds=58)))


def test_an_unreadable_last_run_does_not_silence_a_check():
    print("cadence: a corrupt timestamp runs the check rather than skipping it forever")
    check("bad timestamp -> due", sentinel.is_due({"every_minutes": 60}, {"last_run": "yesterday"}))


# --------------------------------------------------------------------------
# Slack threads: one per incident, changes and the recovery inside it
# --------------------------------------------------------------------------


def _fake_slack(ok=True):
    """A local stand-in for chat.postMessage; records every post."""
    import http.server
    import threading

    posts = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            posts.append({**body, "auth": self.headers.get("Authorization")})
            reply = {"ok": True, "ts": f"1000.{len(posts)}"} if ok else {"ok": False, "error": "not_in_channel"}
            payload = json.dumps(reply).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    sentinel.SLACK_API = f"http://127.0.0.1:{server.server_port}/chat.postMessage"
    return server, posts


def _cycle(results, state):
    """One sentinel run's alerting half, as main() does it."""
    threads = {n: e.get("thread_ts") for n, e in state.items() if e.get("thread_ts")}
    newly, rec = reconcile(results, state, 2)
    events = sentinel.build_events(newly, rec, state, "monitor-host")
    return events, sentinel.announce_threaded(events, state, threads, "xoxb-test", "C0ALERTS")


def test_an_incident_is_one_thread():
    print("threads: fail opens a thread; changed and recovered reply inside it")
    server, posts = _fake_slack()
    try:
        state = {}
        _cycle([Result("procs", False, "a=exited", key="docker:a")], state)      # damped
        _cycle([Result("procs", False, "a=exited", key="docker:a")], state)      # FAIL
        _cycle([Result("procs", False, "a=exited; b=exited", key="docker:a,b")], state)  # CHANGED
        _cycle([ok("procs")], state)                                               # clean, held
        _cycle([ok("procs")], state)                                               # RECOVERED
    finally:
        server.shutdown()
    check("three posts: fail, changed, recovered", len(posts) == 3)
    check("the failure opens the thread", "thread_ts" not in posts[0])
    check("the change replies in it", posts[1].get("thread_ts") == "1000.1")
    check("the recovery replies in it", posts[2].get("thread_ts") == "1000.1")
    check("posted as the bot", posts[0]["auth"] == "Bearer xoxb-test" and posts[0]["channel"] == "C0ALERTS")
    check("the thread is forgotten once recovered", "thread_ts" not in state["procs"])


def test_an_alert_says_what_where_and_for_how_long():
    print("wording: a check name is an identifier, not an explanation")
    from datetime import datetime, timedelta, timezone

    since = (datetime.now(timezone.utc) - timedelta(minutes=6)).isoformat(timespec="seconds")
    line = sentinel._event_line({
        "check": "queues-prod", "target": "cloud.citemed.com", "event": "fail",
        "severity": "critical", "since": since,
        "detail": "'prod_ai' queue (AI extraction) has had no worker for 5 min",
    })
    check("names the system, not just the check", "cloud.citemed.com" in line)
    # sentinel's clock (6 min) would contradict the endpoint's own (5 min).
    check("no duration of sentinel's own", "(for " not in line and "6 min" not in line)
    check("carries the endpoint's own words", "no worker for 5 min" in line)

    recovered = sentinel._event_line({
        "check": "queues-prod", "target": "cloud.citemed.com", "event": "recovered",
        "severity": "critical", "since": since, "detail": "nothing failing",
    })
    check("recovery says how long the alert was open",
          recovered == ":white_check_mark: *queues-prod* on `cloud.citemed.com` recovered"
                       " — alert open 6 min — nothing failing")

    brief = sentinel._event_line({
        "check": "queues-prod", "target": "cloud.citemed.com", "event": "recovered",
        "severity": "critical", "detail": "nothing failing",
        "since": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })
    check("under a minute", "recovered — alert open less than a minute — nothing failing" in brief)


def test_a_check_target_is_the_system_it_watches():
    print("wording: the target comes from the check's url or host")
    check("url -> hostname", sentinel.check_target({"url": "https://cloud.citemed.com/x"}) == "cloud.citemed.com")
    check("host as given", sentinel.check_target({"host": "64.227.24.99"}) == "64.227.24.99")
    check("neither -> empty", sentinel.check_target({}) == "")


def test_a_check_can_post_to_its_own_channel():
    print("threads: production pages the room that fixes it; staging goes to notifications")
    server, posts = _fake_slack()
    try:
        state = {}
        results = [bad("web-prod"), bad("web-staging")]
        threads = {}
        reconcile(results, state, 2)
        newly, rec = reconcile(results, state, 2)
        events = sentinel.build_events(newly, rec, state, "monitor-host")
        sentinel.announce_threaded(
            events, state, threads, "xoxb-test", "C0DEV", {"web-staging": "C0NOTIFY"}
        )
    finally:
        server.shutdown()
    where = {p["text"].split("*")[1]: p["channel"] for p in posts}
    check("production to the default channel", where["web-prod"] == "C0DEV")
    check("staging to its own", where["web-staging"] == "C0NOTIFY")


def test_the_next_incident_gets_a_new_thread():
    print("threads: a later failure of the same check starts fresh")
    server, posts = _fake_slack()
    try:
        state = {}
        for results in ([bad("web")], [bad("web")], [ok("web")], [ok("web")], [bad("web")], [bad("web")]):
            _cycle(results, state)
    finally:
        server.shutdown()
    check("fail, recovered, fail", len(posts) == 3)
    check("second incident is a new top-level post", "thread_ts" not in posts[2])
    check("and has its own thread", state["web"]["thread_ts"] == "1000.3")


def test_a_refused_bot_post_is_handed_back_for_the_fallback():
    print("threads: if Slack refuses the bot, the alert is returned undelivered, not lost")
    server, _ = _fake_slack(ok=False)
    try:
        state = {}
        _cycle([bad("web")], state)
        _, undelivered = _cycle([bad("web")], state)
    finally:
        server.shutdown()
    check("returned for the webhook fallback", [e["check"] for e in undelivered] == ["web"])


def test_each_event_records_the_channel_and_thread_it_was_posted_in():
    print("events: an event says where it landed, so whoever picks it up can reply there")
    posted = []

    def fake_post(token, channel, text, thread_ts=None, broadcast=False):
        posted.append(thread_ts)
        return f"2000.{len(posted)}"

    real_post = sentinel.post_slack_bot
    sentinel.post_slack_bot = fake_post
    try:
        state, all_events = {}, []
        for results in ([bad("web")], [bad("web")], [ok("web")], [ok("web")]):
            events, _ = _cycle(results, state)
            all_events += events
    finally:
        sentinel.post_slack_bot = real_post
    fail, recovered = all_events
    check("the failure carries its channel", fail["channel"] == "C0ALERTS")
    check("and the thread it opened", fail["thread_ts"] == "2000.1")
    check("the recovery carries the same thread", recovered["thread_ts"] == "2000.1")
    check("and the same channel", recovered["channel"] == "C0ALERTS")


def test_events_share_one_incident_id_and_are_appended():
    print("events: fail, changed and recovered belong to one incident; the log only grows")
    server, _ = _fake_slack()
    try:
        state, all_events = {}, []
        for results in (
            [Result("q", False, "x=stale", key="json:x")],
            [Result("q", False, "x=stale", key="json:x")],
            [Result("q", False, "x=stale; y=stale", key="json:x,y")],
            [ok("q")],
            [ok("q")],
        ):
            events, _ = _cycle(results, state)
            all_events += events
    finally:
        server.shutdown()
    check("three transitions", [e["event"] for e in all_events] == ["fail", "changed", "recovered"])
    check("one incident id", len({e["incident"] for e in all_events}) == 1)
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "events.jsonl"
        sentinel.append_events(path, all_events[:2])
        sentinel.append_events(path, all_events[2:])
        lines = path.read_text().splitlines()
    check("appended, never rewritten", len(lines) == 3 and json.loads(lines[2])["event"] == "recovered")


# --------------------------------------------------------------------------
# Reminders: an incident that stays down keeps saying so
# --------------------------------------------------------------------------


SCHEDULE = [60, 240, 1440]


def _open_incident(name="web", minutes_ago=0):
    """State for a check that has alerted, with its incident begun `minutes_ago`."""
    from datetime import datetime, timedelta, timezone

    state = {}
    reconcile([bad(name)], state, 2)
    reconcile([bad(name)], state, 2)                  # alerting
    start = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    state[name]["since"] = start.isoformat(timespec="seconds")
    return state, start


def _remind_at(state, start, minutes, name="web", schedule=SCHEDULE):
    """Run reconcile and the reminder pass as if `minutes` into the incident."""
    from datetime import timedelta

    results = [bad(name)]
    reconcile(results, state, 2)
    return sentinel.due_reminders(results, state, schedule, now=start + timedelta(minutes=minutes))


def test_no_reminder_before_the_first_hour():
    print("reminders: an incident under an hour old stays quiet")
    state, start = _open_incident()
    check("nothing at 5 min", _remind_at(state, start, 5) == [])
    check("nothing at 59 min", _remind_at(state, start, 59) == [])
    check("no count recorded", state["web"].get("reminders", 0) == 0)


def test_one_reminder_at_an_hour_and_not_again():
    print("reminders: exactly one at 60 min, none on the next run")
    state, start = _open_incident()
    due = _remind_at(state, start, 61)
    check("one reminder at 61 min", [r.name for r in due] == ["web"])
    check("count stored in the check's state", state["web"]["reminders"] == 1)
    check("none on the next run", _remind_at(state, start, 66) == [])
    check("none at 239 min", _remind_at(state, start, 239) == [])


def test_second_reminder_at_four_hours():
    print("reminders: the second fires at 240 min")
    state, start = _open_incident()
    _remind_at(state, start, 61)
    check("second at 241 min", [r.name for r in _remind_at(state, start, 241)] == ["web"])
    check("count is 2", state["web"]["reminders"] == 2)


def test_reminders_repeat_every_day_after_the_last_point():
    print("reminders: after 1440 min, one every 1440 min")
    state, start = _open_incident()
    fired = []
    for minutes in range(0, 5 * 1440 + 1, 5):         # five days of five-minute runs
        if _remind_at(state, start, minutes):
            fired.append(minutes)
    check("fires at 60, 240, then every 1440", fired == [60, 240, 1440, 2880, 4320, 5760, 7200])


def test_a_late_run_sends_one_reminder_not_a_burst():
    print("reminders: a monitor that missed several points catches up with one post")
    state, start = _open_incident()
    check("one at 25 hours", len(_remind_at(state, start, 25 * 60)) == 1)
    check("count jumps past every missed point", state["web"]["reminders"] == 3)
    check("and the next run is quiet", _remind_at(state, start, 25 * 60 + 5) == [])


def test_no_reminder_once_recovered_and_count_resets():
    print("reminders: a recovered incident is silent; the next one starts from zero")
    from datetime import datetime, timedelta, timezone

    state, start = _open_incident()
    _remind_at(state, start, 61)
    reconcile([ok("web")], state, 2)                  # clean, held
    check("none while the recovery is held", sentinel.due_reminders(
        [ok("web")], state, SCHEDULE, now=start + timedelta(minutes=300)) == [])
    reconcile([ok("web")], state, 2)                  # recovered
    check("count gone with the incident", "reminders" not in state["web"])
    check("none once recovered", sentinel.due_reminders(
        [ok("web")], state, SCHEDULE, now=start + timedelta(minutes=300)) == [])

    reconcile([bad("web")], state, 2)
    reconcile([bad("web")], state, 2)                 # a new incident
    new_start = datetime.fromisoformat(state["web"]["since"])
    check("new incident quiet under an hour", sentinel.due_reminders(
        [bad("web")], state, SCHEDULE, now=new_start + timedelta(minutes=30)) == [])
    check("and reminded afresh at an hour", len(sentinel.due_reminders(
        [bad("web")], state, SCHEDULE, now=new_start + timedelta(minutes=61))) == 1)
    check("counting from one", state["web"]["reminders"] == 1)


def test_a_damped_failure_is_never_reminded():
    print("reminders: a failure that never alerted has nothing to remind about")
    from datetime import datetime, timedelta, timezone

    state = {}
    reconcile([bad("web")], state, 3)
    state["web"]["since"] = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
    check("not alerting -> no reminder", sentinel.due_reminders([bad("web")], state, SCHEDULE) == [])


def test_empty_or_null_schedule_disables_reminders():
    print("reminders: remind_after_minutes: [] or null turns them off")
    state, start = _open_incident(minutes_ago=3000)
    check("[] disables", sentinel.due_reminders([bad("web")], state, []) == [])
    check("null disables", sentinel.due_reminders([bad("web")], state, None) == [])
    check("the default would have fired", len(sentinel.due_reminders([bad("web")], state, SCHEDULE)) == 1)


def test_a_check_with_an_event_this_run_waits_for_the_next():
    print("reminders: a check that just posted a change is not also reminded")
    state, _ = _open_incident(minutes_ago=90)
    check("skipped", sentinel.due_reminders([bad("web")], state, SCHEDULE, skip={"web"}) == [])
    check("count untouched", state["web"].get("reminders", 0) == 0)


def test_a_reminder_event_belongs_to_its_incident():
    print("reminders: the event carries the incident id, detail, since and target")
    state, _ = _open_incident(minutes_ago=241)
    due = sentinel.due_reminders([bad("web")], state, SCHEDULE)
    events = sentinel.build_reminder_events(due, state, "monitor-host", {"web": "app.example.com"})
    e = events[0] if events else {}
    check("type reminder", e.get("event") == "reminder")
    check("same incident id as the fail", e.get("incident") == f"web@{state['web']['since']}")
    check("current detail", e.get("detail") == "unreachable")
    check("since and target", e.get("since") == state["web"]["since"] and e.get("target") == "app.example.com")


def test_reminder_wording_says_still_failing():
    print("reminders: the line says it is still failing, with the check's own detail")
    from datetime import datetime, timedelta, timezone

    since = (datetime.now(timezone.utc) - timedelta(hours=4)).isoformat(timespec="seconds")
    line = sentinel._event_line({
        "check": "procs", "target": "app.example.com", "event": "reminder",
        "severity": "critical", "since": since, "detail": "worker1=exited",
    })
    check("exact wording",
          line == ":hourglass: *procs* on `app.example.com` is still failing: worker1=exited")


def test_a_reminder_replies_in_the_thread_and_is_broadcast():
    print("reminders: posted in the incident's thread, and shown in the channel too")
    server, posts = _fake_slack()
    try:
        state = {}
        _cycle([bad("web")], state)
        _cycle([bad("web")], state)                  # FAIL opens thread 1000.1
        from datetime import datetime, timedelta, timezone
        state["web"]["since"] = (datetime.now(timezone.utc) - timedelta(minutes=61)).isoformat()
        threads = {n: e.get("thread_ts") for n, e in state.items() if e.get("thread_ts")}
        results = [bad("web")]
        reconcile(results, state, 2)
        due = sentinel.due_reminders(results, state, SCHEDULE)
        events = sentinel.build_reminder_events(due, state, "monitor-host")
        undelivered = sentinel.announce_threaded(events, state, threads, "xoxb-test", "C0ALERTS")
    finally:
        server.shutdown()
    check("two posts: fail, reminder", len(posts) == 2)
    check("reminder replies in the thread", posts[1].get("thread_ts") == "1000.1")
    check("and is broadcast", posts[1].get("reply_broadcast") is True)
    check("the failure itself was not broadcast", "reply_broadcast" not in posts[0])
    check("delivered", undelivered == [])
    check("event records channel and thread", events[0]["channel"] == "C0ALERTS"
          and events[0]["thread_ts"] == "1000.1")


def test_changed_and_recovered_are_not_broadcast():
    print("reminders: CHANGED and RECOVERED stay inside the thread")
    server, posts = _fake_slack()
    try:
        state = {}
        _cycle([Result("p", False, "a", key="k:a")], state)
        _cycle([Result("p", False, "a", key="k:a")], state)
        _cycle([Result("p", False, "a; b", key="k:a,b")], state)
        _cycle([ok("p")], state)
        _cycle([ok("p")], state)
    finally:
        server.shutdown()
    check("three posts", len(posts) == 3)
    check("none broadcast", not any(p.get("reply_broadcast") for p in posts))


def test_a_reminder_without_a_thread_is_a_top_level_post():
    print("reminders: an incident with no thread gets its reminder at the top level")
    server, posts = _fake_slack()
    try:
        state, _ = _open_incident(minutes_ago=61)    # alerted via webhook: no thread_ts
        due = sentinel.due_reminders([bad("web")], state, SCHEDULE)
        events = sentinel.build_reminder_events(due, state, "monitor-host")
        sentinel.announce_threaded(events, state, {}, "xoxb-test", "C0ALERTS")
    finally:
        server.shutdown()
    check("one post", len(posts) == 1)
    check("top level", "thread_ts" not in posts[0])
    check("not broadcast (nothing to broadcast from)", "reply_broadcast" not in posts[0])


def test_the_webhook_fallback_carries_reminders():
    print("reminders: without a bot token the webhook post still says it")
    state, _ = _open_incident(minutes_ago=61)
    due = sentinel.due_reminders([bad("web")], state, SCHEDULE)
    events = sentinel.build_reminder_events(due, state, "monitor-host")
    text = format_alert([], [], "monitor-host", events)
    check("reminder rendered", "still failing" in text and "*web*" in text)
    check("undelivered reminders render too", "still failing" in sentinel._event_line(events[0]))


# --------------------------------------------------------------------------
# The event hook: hand an incident to something that can act on it
# --------------------------------------------------------------------------


def test_the_hook_receives_each_event_as_json():
    print("hook: one run per event, the event on stdin")
    import time

    with tempfile.TemporaryDirectory() as d:
        seen = Path(d) / "seen"
        seen.mkdir()
        script = Path(d) / "hook.sh"
        # One file per run: the hook is started twice, concurrently.
        script.write_text(f'#!/bin/sh\ncat > "{seen}/$$.json"\n')
        script.chmod(0o755)
        events = [
            {"check": "web", "event": "fail", "incident": "web@t0"},
            {"check": "db", "event": "recovered", "incident": "db@t1"},
        ]
        check("both started", sentinel.run_event_hook([str(script)], events) == 2)
        for _ in range(50):  # it is deliberately not waited for
            files = list(seen.glob("*.json"))
            if len(files) == 2 and all(f.read_text().strip() for f in files):
                break
            time.sleep(0.1)
        delivered = [json.loads(f.read_text()) for f in seen.glob("*.json")]
    check("each event delivered whole", {e["check"] for e in delivered} == {"web", "db"})
    check("and delivered as the event, not a summary", {e["event"] for e in delivered} == {"fail", "recovered"})


def test_a_broken_hook_does_not_stop_a_run():
    print("hook: a hook that cannot start is logged, never raised")
    check("no exception, nothing started", sentinel.run_event_hook(["/does/not/exist"], [{"a": 1}]) == 0)


def test_no_events_means_no_hook_run():
    print("hook: a quiet run wakes nobody")
    check("not started", sentinel.run_event_hook(["/bin/true"], []) == 0)


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {FAILURES}")
        sys.exit(1)
    print("all tests passed")
