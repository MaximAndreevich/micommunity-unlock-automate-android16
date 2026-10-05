"""Timing invariants: whatever was measured and whatever the options, the tap never
reaches the device (and so the server) before target + MIN_ARRIVAL_MS.

The checks (fakes.assert_timing_invariants) recompute the bounds from the measurement
itself instead of trusting TimingPlan, so a wrong compensation_ms / send_time cannot hide
behind its own numbers.
"""

import itertools
from datetime import datetime, timedelta, timezone

import pytest

from fakes import T0, FakeDevice, a, assert_timing_invariants, measurement, ms, planned, run_with

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

def real_run(monkeypatch, dev, argv):
    """A non-dry run; returns the plan, the target, the send moment and the injection."""
    plans = []
    real_log_plan = a.log_plan

    def spy(plan, target_utc, send_utc, *rest):
        plans.append((plan, target_utc, send_utc))
        return real_log_plan(plan, target_utc, send_utc, *rest)
    monkeypatch.setattr(a, "log_plan", spy)
    assert run_with(monkeypatch, dev, ["--test-in", "150"] + argv) == a.EXIT_OK
    [(plan, target, send)] = plans
    [injected] = [datetime.fromtimestamp(t, timezone.utc)
                  for cmd, t in dev.injections if cmd in dev.taps]
    return plan, target, send, injected


@pytest.mark.parametrize("timing", [[], ["--timing", "fixed"]], ids=["adaptive", "fixed"])
@pytest.mark.parametrize("inject_ms, tap_rt_ms", [(5, 60), (70, 120), (140, 250),
                                                  ([90, 70, 130, 75], 200)],
                         ids=["fast", "typical", "slow", "jitter"])
def test_real_tap_is_injected_after_target_plus_margin(monkeypatch, inject_ms, tap_rt_ms,
                                                       timing):
    dev = FakeDevice(inject_ms=inject_ms, tap_rt_ms=tap_rt_ms)
    plan, target, send, injected = real_run(monkeypatch, dev, timing)
    assert plan.mode == ("fixed" if timing else "adaptive")
    assert injected >= target + ms(plan.margin_ms) >= target + ms(a.MIN_ARRIVAL_MS)
    slowest = max(inject_ms) if isinstance(inject_ms, list) else inject_ms
    assert injected - send <= ms(slowest + 20)       # + the virtual cost of the clock calls


# The real tap does not have to be as slow as the probes: on the phone one run measured
# min 40 ms, another 53 ms. Here the probes see 53-80 ms (the samples of a real run) and
# the real tap is faster than all of them. Only the margin covers that, so the tap no
# longer lands after target + margin - but up to `margin` ms faster it is still after
# the target.
PROBES_MS = [66.38, 76.38, 63.02, 79.0, 64.44, 53.04, 63.94, 65.94, 73.48, 66.58,
             73.24, 76.31, 72.76, 66.69, 53.06, 64.38, 74.93, 72.9, 79.56, 64.11]


@pytest.mark.parametrize("real_ms", [53.04, 40, 20, 3.5])
def test_real_tap_faster_than_the_probes_still_lands_after_the_target(monkeypatch, real_ms):
    dev = FakeDevice(inject_ms=PROBES_MS, tap_rt_ms=130, real_tap_inject_ms=real_ms)
    plan, target, _, injected = real_run(monkeypatch, dev, [])
    assert (plan.mode, plan.compensation_ms, plan.margin_ms) == ("adaptive", 53, 50)
    assert injected >= target
    # the margin is used up by exactly the difference (+ a few ms of virtual clock calls)
    expected = target + ms(plan.margin_ms - (min(PROBES_MS) - real_ms))
    assert expected <= injected <= expected + ms(5)


def test_real_tap_faster_than_the_probes_by_more_than_the_margin_is_early(monkeypatch):
    """The limit of the model, not a wish: nothing but the margin covers a real tap that
    is faster than every probe, so 130 ms faster with a 50 ms margin is a false start."""
    dev = FakeDevice(inject_ms=[150, 160, 170], tap_rt_ms=250, real_tap_inject_ms=20)
    plan, target, _, injected = real_run(monkeypatch, dev, [])
    assert (plan.compensation_ms, plan.margin_ms) == (149, 50)     # 150 - the resolution
    assert injected < target - ms(70)
