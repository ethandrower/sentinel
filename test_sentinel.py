#!/usr/bin/env python3
# ABOUTME: Tests for sentinel's alert state machine and shell quoting.
# ABOUTME: Pure-logic only — no network, no SSH; run with `python3 -m pytest` or directly.
"""Run: python3 test_sentinel.py   (or pytest, if available)"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

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
    check("recovery is announced", [r.name for r, _ in rec] == ["web"])
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


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {FAILURES}")
        sys.exit(1)
    print("all tests passed")
