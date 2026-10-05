"""Property-based timing tests (hypothesis): random measurements, options and targets
instead of a hand-picked grid. Each property is one reason the tap cannot be early."""

from datetime import datetime, timedelta, timezone

import pytest
from hypothesis import HealthCheck, assume, example, given, settings
from hypothesis import strategies as st

from fakes import (FakeDevice, a, assert_timing_invariants, measurement, ms,
                   planned, run_with)

delays = st.floats(min_value=0, max_value=5000, allow_nan=False, allow_infinity=False)
samples = st.lists(delays, min_size=1, max_size=30)


def option_lists(margins):
    return st.one_of(
        st.just(()),                                             # the defaults
        st.tuples(st.just("--adaptive-margin-ms"), margins, st.just("--margin-ms"), margins),
        st.tuples(st.just("--timing"), st.just("fixed"), st.just("--margin-ms"), margins),
    ).map(list)


options = option_lists(st.integers(min_value=0, max_value=2000).map(str))
# margins the guard accepts: below MIN_ARRIVAL_MS it replaces the plan with the fixed one
guarded_options = option_lists(st.integers(min_value=a.MIN_ARRIVAL_MS, max_value=2000).map(str))
targets = st.builds(
    lambda moment, offset_min: moment.replace(tzinfo=timezone.utc).astimezone(
        timezone(timedelta(minutes=offset_min))),
    st.datetimes(min_value=datetime(2020, 1, 1), max_value=datetime(2040, 1, 1)),
    st.integers(min_value=-12 * 60, max_value=14 * 60))


@st.composite
def measurements(draw):
    """inject + round_trip (sometimes implausibly short) + optional adb / ping RTT."""
    inject = draw(samples)
    round_trip = draw(st.one_of(
        st.none(),                                               # inject + 50 ms
        st.lists(st.floats(min_value=0.1, max_value=6000), min_size=1, max_size=30)))
    adb = draw(st.one_of(st.none(), st.lists(st.floats(min_value=0.1, max_value=500),
                                             min_size=1, max_size=5)))
    net = draw(st.one_of(st.none(), st.lists(st.floats(min_value=0.1, max_value=1000),
                                             min_size=1, max_size=10)))
    return measurement(inject, round_trip, adb, net)


# ------------------------------------------------------------------- the plan

@given(measured=measurements(), argv=options, target=targets)
@example(measured=measurement([53.996]), argv=[], target=datetime(2026, 10, 6, 16,
                                                                  tzinfo=timezone.utc))
def test_no_false_start(measured, argv, target):
    args, plan, send = planned(argv, measured, target)
    assert_timing_invariants(plan, send, target, measured, args)


@given(measured=measurements(), argv=options, data=st.data())
def test_order_of_the_samples_does_not_matter(measured, argv, data):
    shuffled = measurement(data.draw(st.permutations(measured.inject.samples)),
                           data.draw(st.permutations(measured.round_trip.samples)),
                           measured.adb_rtt and measured.adb_rtt.samples,
                           measured.net and measured.net.samples)
    _, plan, send = planned(argv, measured)
    _, plan2, send2 = planned(argv, shuffled)
    assert (plan2.mode, plan2.margin_ms, plan2.compensation_ms, send2) \
        == (plan.mode, plan.margin_ms, plan.compensation_ms, send)


@given(measured=measurements(), argv=options, target=targets, other=targets)
def test_offset_from_the_target_does_not_depend_on_the_target(measured, argv, target, other):
    _, _, send = planned(argv, measured, target)
    _, _, send2 = planned(argv, measured, other)
    assert send - target == send2 - other


@given(inject=samples, extra=delays, argv=guarded_options)
def test_a_slower_sample_never_raises_the_compensation(inject, extra, argv):
    """Only the fastest sample is compensated: adding a slower one changes nothing."""
    assume(extra >= min(inject))
    round_trip = [max(inject + [extra]) + 50]                  # the same for both
    _, plan, _ = planned(argv, measurement(inject, round_trip))
    _, plan2, _ = planned(argv, measurement(inject + [extra], round_trip))
    assert plan2.compensation_ms == plan.compensation_ms


@given(inject=samples, faster=delays, argv=guarded_options)
def test_a_faster_sample_never_sends_earlier(inject, faster, argv):
    """A faster tap seen once lowers the compensation: the plan only gets later."""
    assume(faster < min(inject))
    round_trip = [max(inject) + 50]
    _, plan, send = planned(argv, measurement(inject, round_trip))
    _, plan2, send2 = planned(argv, measurement(inject + [faster], round_trip))
    assert plan2.compensation_ms <= plan.compensation_ms
    if plan2.margin_ms == plan.margin_ms:
        assert send2 >= send


# ------------------------------------------------------------------- the measurement
# A simulated probe sequence on the device clock, in integer nanoseconds so that the
# printed start and the logcat line are exact strings. A float of an epoch time holds
# ~0.24 us: parsing the two times and subtracting them errs by at most ~0.25 us (FLOAT_MS).

SEC = 10**9
FLOAT_MS = 0.0003


@st.composite
def probe_runs(draw):
    resolution_digits = draw(st.sampled_from([6, 9]))      # $EPOCHREALTIME / date +%s.%N
    start = draw(st.integers(min_value=1_700_000_000 * SEC, max_value=1_900_000_000 * SEC))
    taps = []
    for _ in range(draw(st.integers(min_value=1, max_value=25))):
        # true delay in ns; real ones are 30+ ms, and one under 1 ms + the resolution may
        # come out negative and be dropped (safe, but it would shift the pairing below)
        delay = draw(st.integers(min_value=2 * 10**6, max_value=1500 * 10**6))
        # the command runs at least 1 ms after the injection (the JVM shuts down); an exact
        # tie of the delay and the round-trip would depend on float rounding
        duration = delay + draw(st.integers(min_value=10**6, max_value=1000 * 10**6))
        overhead = draw(st.integers(min_value=0, max_value=300 * 10**6))  # PC <-> device
        taps.append({"start": start, "delay": delay, "round_trip_ms": (duration + overhead) / 1e6,
                     "printed": draw(st.booleans()) or not taps,    # lost start line
                     "logged": draw(st.booleans())})                # lost logcat line
        # the next command starts after this one returned and the PROBE_GAP_SEC sleep
        start += duration + int(a.PROBE_GAP_SEC * SEC) + draw(st.integers(0, SEC))
    return resolution_digits, taps


def printed_start(ns, digits):
    frac = ns % SEC // 10 ** (9 - digits)
    return f"miunlock_start={ns // SEC}.{frac:0{digits}d}"


def logcat_line(ns):
    msec = ns // 10**6                                   # logcat truncates to ms
    return (f"{msec // 1000}.{msec % 1000:03d}  2678 13244 W MIUIInput: Input motion event "
            "injection from package: null action ACTION_DOWN")


ALIGNED = 1_800_000_000 * SEC + 999            # printed as ...000000: 999 ns too early


@given(run=probe_runs())
# the worst case of truncation: the start loses almost a whole microsecond, the injection
# (on a millisecond boundary) loses nothing
@example(run=(6, [{"start": ALIGNED, "delay": 53 * 10**6 - 999, "round_trip_ms": 120.0,
                   "printed": True, "logged": True}]))
def test_measured_delay_is_a_lower_bound_of_the_real_one(run):
    digits, taps = run
    printed = [t for t in taps if t["printed"]]
    starts = [a.tap_start(printed_start(t["start"], digits)) for t in printed]
    logcat = "\n".join([logcat_line(taps[0]["start"] - SEC)]      # the audit probe, before
                       + [logcat_line(t["start"] + t["delay"]) for t in taps if t["logged"]])
    measured = a.injection_delays(starts, a.injection_times(logcat),
                                  [t["round_trip_ms"] for t in printed])

    # one sample per tap whose start and injection were both seen, none for the others
    # (a later tap's injection is longer than this tap's round-trip and is dropped)
    expected = [t for t in printed if t["logged"]]
    assert len(measured) == len(expected)
    resolution_ms = 10 ** (3 - digits)
    for t, delay in zip(expected, measured):
        true_ms = t["delay"] / 1e6
        assert true_ms - 1 - resolution_ms - FLOAT_MS <= delay <= true_ms + FLOAT_MS


# ------------------------------------------------------------------- end to end
# A whole --test-in 150 run on the fake phone: a random jitter pattern of the real
# start -> injection delay; the real tap must land after target + margin.

@settings(max_examples=30, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(inject=st.lists(st.floats(min_value=1, max_value=400), min_size=1, max_size=6),
       slack=st.floats(min_value=5, max_value=300), fixed=st.booleans())
def test_real_tap_never_lands_early(cache_file, inject, slack, fixed):
    cache_file.unlink(missing_ok=True)                  # every run measures for itself
    plans = []
    with pytest.MonkeyPatch.context() as mp:
        real_log_plan = a.log_plan

        def spy(plan, target_utc, send_utc, *rest):
            plans.append((plan, target_utc))
            return real_log_plan(plan, target_utc, send_utc, *rest)
        mp.setattr(a, "log_plan", spy)
        dev = FakeDevice(inject_ms=inject, tap_rt_ms=max(inject) + slack)
        argv = ["--test-in", "150"] + (["--timing", "fixed"] if fixed else [])
        assert run_with(mp, dev, argv) == a.EXIT_OK

    [(plan, target)] = plans
    [injected] = [t for cmd, t in dev.injections if cmd in dev.taps]
    assert plan.compensation_ms <= min(inject)
    assert injected >= (target + ms(plan.margin_ms)).timestamp() >= \
        (target + ms(a.MIN_ARRIVAL_MS)).timestamp()
