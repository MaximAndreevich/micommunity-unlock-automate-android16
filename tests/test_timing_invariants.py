"""Timing invariants: whatever was measured and whatever the options, the tap never
reaches the device (and so the server) before target + MIN_ARRIVAL_MS.

The checks below recompute the bounds from the measurement itself instead of trusting
TimingPlan, so a wrong compensation_ms / send_time cannot hide behind its own numbers.
"""

import itertools
from datetime import datetime, timedelta, timezone

import pytest

from fakes import T0, FakeDevice, a, measurement, ms, run_with

INJECT = [[1.0], [53.04, 66.58, 79.56], [69.999, 70.5], [120.9, 125, 140],
          [100, 110, 120, 400], [900.5, 910]]
ROUND_TRIP = {"auto": lambda inject: None,                       # inject + 50 ms
              "tight": lambda inject: [min(inject) + 1, max(inject) + 60]}
ADB = [None, [4, 5], [60, 64]]
NET = [None, [40.7, 55]]
TARGETS = [T0, T0 + timedelta(microseconds=456)]                 # sub-millisecond target
ARGS = [[], ["--adaptive-margin-ms", "0"], ["--adaptive-margin-ms", "49"],
        ["--adaptive-margin-ms", "300"], ["--timing", "fixed"],
        ["--timing", "fixed", "--margin-ms", "0"], ["--margin-ms", "20"],
        ["--margin-ms", "400"]]


def proven_delay_ms(plan, measured):
    """Send -> arrival delay the measurement proves (0 unless the plan compensates)."""
    if plan.mode != "adaptive":
        return 0.0
    return measured.inject.min + (measured.net.min / 2 if measured.net else 0.0)


def assert_timing_invariants(plan, send, target, measured, args):
    proven = proven_delay_ms(plan, measured)
    # no false start: even the fastest measured delivery arrives after target + 50 ms
    assert send + timedelta(milliseconds=proven) >= target + ms(a.MIN_ARRIVAL_MS)
    # the compensation is whole ms, never more than proven, wasting less than 1 ms
    assert isinstance(plan.compensation_ms, int)
    assert 0 <= plan.compensation_ms <= proven
    if plan.mode == "adaptive":
        assert proven - plan.compensation_ms < 1
        # the device part of a tap fits into its round-trip minus the way there and back
        adb = measured.adb_rtt.min / 2 if measured.adb_rtt else 0.0
        assert measured.inject.min <= measured.round_trip.min - adb
    else:
        assert plan.compensation_ms == 0
    # send time and the bound it promises agree with the plan
    assert send == plan.send_time(target) == target + ms(plan.margin_ms - plan.compensation_ms)
    assert plan.earliest_arrival(target) == target + ms(plan.margin_ms)
    assert send >= target - ms(plan.compensation_ms)
    assert plan.margin_ms >= a.MIN_ARRIVAL_MS
    assert_margin_rule(plan, measured, args)


def assert_margin_rule(plan, measured, args):
    if plan.source == "guard fallback":
        assert (plan.mode, plan.margin_ms) == ("fixed", a.DEFAULT_MARGIN_MS)
    elif plan.mode == "fixed":
        assert plan.margin_ms == args.margin_ms
    else:
        wide = measured.inject.p95 - measured.inject.min > a.WIDE_SPREAD_MS
        expected = max(args.adaptive_margin_ms, a.WIDE_SPREAD_MARGIN_MS if wide else 0)
        assert plan.margin_ms == expected


def planned(argv, measured, target=T0):
    args = a.build_parser().parse_args(argv)
    plan, send = a.checked_send_time(a.plan_timing(args, measured, "test"), target)
    return args, plan, send


@pytest.mark.parametrize("argv", ARGS, ids=" ".join)
@pytest.mark.parametrize("inject", INJECT, ids=str)
def test_no_false_start_for_any_measurement_and_options(argv, inject):
    for rt, adb, net, target in itertools.product(ROUND_TRIP, ADB, NET, TARGETS):
        measured = measurement(inject, ROUND_TRIP[rt](inject), adb, net)
        args, plan, send = planned(argv, measured, target)
        case = f"round_trip={rt} adb={adb} net={net} target={target} -> {plan}"
        try:
            assert_timing_invariants(plan, send, target, measured, args)
        except AssertionError as exc:
            raise AssertionError(case) from exc


@pytest.mark.parametrize("argv", ARGS, ids=" ".join)
def test_no_false_start_without_a_measurement(argv):
    args, plan, send = planned(argv, None)
    assert plan.mode == "fixed"
    assert_timing_invariants(plan, send, T0, None, args)


def test_longer_delay_never_sends_later():
    sends = [planned([], measurement([d, d + 10]))[2] for d in range(0, 400, 7)]
    assert sends == sorted(sends, reverse=True)


@pytest.mark.parametrize("inject", INJECT, ids=str)
def test_adaptive_never_sends_later_than_fixed(inject):
    for adb, net in itertools.product(ADB, NET):
        adaptive = planned([], measurement(inject, None, adb, net))[2]
        assert adaptive <= planned(["--timing", "fixed"], None)[2]


def test_guard_is_idempotent():
    for argv, inject in itertools.product(ARGS, INJECT):
        _, plan, send = planned(argv, measurement(inject))
        assert a.checked_send_time(plan, T0) == (plan, send)


def test_send_time_does_not_depend_on_the_target_time_zone():
    measured = measurement([53.04, 66.58])
    cst = T0.astimezone(timezone(a.BEIJING_OFFSET))
    assert planned([], measured, cst)[2] == planned([], measured, T0)[2]


# ------------------------------------------------------------------- end to end
# The fake phone injects every tap `inject_ms` after the command starts, in virtual
# time; the real tap must land no earlier than target + margin.

@pytest.mark.parametrize("timing", [[], ["--timing", "fixed"]], ids=["adaptive", "fixed"])
@pytest.mark.parametrize("inject_ms, tap_rt_ms", [(5, 60), (70, 120), (140, 250),
                                                  ([90, 70, 130, 75], 200)],
                         ids=["fast", "typical", "slow", "jitter"])
def test_real_tap_is_injected_after_target_plus_margin(monkeypatch, inject_ms, tap_rt_ms,
                                                       timing):
    plans = []
    real_log_plan = a.log_plan

    def spy(plan, target_utc, send_utc, *rest):
        plans.append((plan, target_utc, send_utc))
        return real_log_plan(plan, target_utc, send_utc, *rest)
    monkeypatch.setattr(a, "log_plan", spy)
    dev = FakeDevice(inject_ms=inject_ms, tap_rt_ms=tap_rt_ms)
    assert run_with(monkeypatch, dev, ["--test-in", "150"] + timing) == a.EXIT_OK

    [(plan, target, send)] = plans
    [injected] = [datetime.fromtimestamp(t, timezone.utc)
                  for cmd, t in dev.injections if cmd in dev.taps]
    assert plan.mode == ("fixed" if timing else "adaptive")
    assert injected >= target + ms(plan.margin_ms) >= target + ms(a.MIN_ARRIVAL_MS)
    slowest = max(inject_ms) if isinstance(inject_ms, list) else inject_ms
    assert injected - send <= ms(slowest + 20)       # + the virtual cost of the clock calls
