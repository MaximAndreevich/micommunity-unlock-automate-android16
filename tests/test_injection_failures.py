"""Injection failures in the middle of a live run, on the fake phone in virtual time.

The phone breaks at a chosen moment of a `--test-in 150` run: the "USB debugging
(Security settings)" toggle resets (SecurityException), taps are silently denied (exit
code 0, denial only in logcat), or the cable is pulled (every adb command fails). Whatever
breaks and whenever, the script must never tap early, never tap twice, never report
success for a tap that did not land, and must leave the screen settings as they were.
"""

from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from fakes import VIRTUAL_START, FakeDevice, a, ms, run_with

TEST_IN = 150
T = VIRTUAL_START + TEST_IN          # the target in virtual time.time(), give or take a few ms
BUTTON_TAP = "input tap 540 2070"

TOGGLE_RESET = {"inject": False, "adbinput": "0"}
SILENT_DENIAL = {"silent_denial": True}
CABLE_OUT = {"broken": ("",)}
FAULTS = {"toggle reset": TOGGLE_RESET, "silent denial": SILENT_DENIAL,
          "cable out": CABLE_OUT}
HEALTHY = {"inject": True, "adbinput": "1", "silent_denial": False, "broken": ()}

# moments of the run, seconds from the target (see fire()): audit at -150, latency probes
# at -120..-110, final check at -20 (no input injected), the tap at about 0, its
# verification up to +5
PROBES, BEFORE_FINAL_CHECK, BEFORE_TAP = -115, -60, -10
ORIGINAL_SETTINGS = {"global/stay_on_while_plugged_in": "0",
                     "system/screen_off_timeout": "30000"}


@dataclass
class Outcome:
    """What a simulated run did."""
    code: int
    target: datetime | None          # None if the run stopped before planning the tap
    injected: list[datetime]         # button taps that reached the app
    attempts: int                    # button tap commands sent


def simulate(monkeypatch, dev, *argv):
    """Runs like main() does: a DeviceError is logged and becomes EXIT_ERROR."""
    targets = []
    real_log_plan = a.log_plan

    def spy(plan, target_utc, *rest):
        targets.append(target_utc)
        return real_log_plan(plan, target_utc, *rest)
    monkeypatch.setattr(a, "log_plan", spy)
    try:
        code = run_with(monkeypatch, dev, ["--test-in", str(TEST_IN), *argv])
    except a.DeviceError as exc:
        a.log.error("%s", exc)
        code = a.EXIT_ERROR
    injected = [datetime.fromtimestamp(t, timezone.utc)
                for cmd, t in dev.injections if cmd == BUTTON_TAP]
    attempts = sum(cmd.startswith("echo") and cmd.endswith(BUTTON_TAP) for cmd in dev.commands)
    return Outcome(code, targets[0] if targets else None, injected, attempts)


def assert_safe(out, clicks=1):
    """No early tap, no extra tap, no false success."""
    assert out.code in (a.EXIT_OK, a.EXIT_ERROR, a.EXIT_AUDIT)
    assert out.attempts <= clicks
    if out.injected:
        assert out.target is not None
        assert min(out.injected) >= out.target + ms(a.MIN_ARRIVAL_MS)
    if out.code == a.EXIT_OK:
        assert len(out.injected) == clicks


def at_target(sec):
    return T + sec


# ------------------------------------------------------------- the run stops

STOPS = {   # (fault, moment): what the log says, button tap commands sent
    ("toggle reset", PROBES): ("input injection is denied", 0),
    ("silent denial", PROBES): ("input injection is denied", 0),
    ("cable out", PROBES): (a.NOT_RESPONDING, 0),
    ("toggle reset", BEFORE_FINAL_CHECK): ("'USB debugging (Security settings)' is OFF", 0),
    ("silent denial", BEFORE_FINAL_CHECK): ("The device rejected the taps", 1),  # undetectable
    ("cable out", BEFORE_FINAL_CHECK): (a.NOT_RESPONDING, 0),
    ("toggle reset", BEFORE_TAP): ("Tap 1/1 rejected", 1),
    ("silent denial", BEFORE_TAP): ("The device rejected the taps", 1),
    ("cable out", BEFORE_TAP): ("Tap 1/1 failed", 1),
}


@pytest.mark.parametrize("fault, moment", list(STOPS), ids=[f"{f} at T{m}" for f, m in STOPS])
def test_fault_stops_the_run_without_a_tap(monkeypatch, caplog, fault, moment):
    dev = FakeDevice()
    dev.at(at_target(moment), **FAULTS[fault])
    out = simulate(monkeypatch, dev)
    message, attempts = STOPS[fault, moment]
    assert_safe(out)
    assert (out.code, out.injected, out.attempts) == (a.EXIT_ERROR, [], attempts)
    assert message in caplog.text
    if fault == "cable out":
        assert "Restore it manually" in caplog.text
    else:
        assert dev.store == ORIGINAL_SETTINGS


def test_silent_denial_of_the_tap_is_not_reported_as_success(monkeypatch, caplog):
    caplog.set_level("INFO")
    dev = FakeDevice()
    dev.at(at_target(BEFORE_TAP), **SILENT_DENIAL)
    simulate(monkeypatch, dev)
    assert "Tap 1/1 sent" in caplog.text            # input exited 0 ...
    assert "[FAILED] only 0/1 taps" in caplog.text  # ... but logcat shows the denial
    assert "[SUCCESS]" not in caplog.text


def test_hanging_tap_is_not_repeated(monkeypatch, caplog):
    dev = FakeDevice()
    dev.at(at_target(BEFORE_TAP), hang=("echo",))
    out = simulate(monkeypatch, dev)
    assert (out.code, out.attempts) == (a.EXIT_ERROR, 1)
    assert "Tap 1/1 failed" in caplog.text and "timeout" in caplog.text
    assert dev.store == ORIGINAL_SETTINGS


def test_toggle_reset_between_two_taps_stops_the_second(monkeypatch, caplog):
    dev = FakeDevice()
    dev.at(at_target(30), **TOGGLE_RESET)
    out = simulate(monkeypatch, dev, "--clicks", "2")
    assert_safe(out, clicks=2)
    assert (out.code, len(out.injected), out.attempts) == (a.EXIT_ERROR, 1, 2)
    assert "Tap 2/2 rejected" in caplog.text
    assert "[FAILED] only 1/2 taps" in caplog.text
    assert dev.store == ORIGINAL_SETTINGS


# ------------------------------------------------------------- the run goes on

def test_short_adb_outage_during_probes_falls_back_to_standard_margin(monkeypatch, caplog,
                                                                      cache_file):
    dev = FakeDevice()
    dev.at(at_target(PROBES), **CABLE_OUT)
    dev.at(at_target(PROBES + 10), broken=())
    out = simulate(monkeypatch, dev)
    assert_safe(out)
    assert out.code == a.EXIT_OK
    assert "Probe: adb failed" in caplog.text
    assert "using the standard margin of 150 ms" in caplog.text
    assert out.injected[0] >= out.target + ms(a.DEFAULT_MARGIN_MS)
    assert not cache_file.exists()


def test_toggle_reset_while_waiting_is_reported_and_can_be_fixed(monkeypatch, caplog):
    dev = FakeDevice()
    dev.at(VIRTUAL_START + 30, **TOGGLE_RESET)     # the heartbeat at +60 s sees it
    dev.at(VIRTUAL_START + 90, inject=True, adbinput="1")
    out = simulate(monkeypatch, dev, "--test-in", "300")
    assert_safe(out)
    assert out.code == a.EXIT_OK
    assert any(r.levelname == "ERROR" and r.getMessage().startswith("Heartbeat:")
               and "Security settings" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("broken", [("logcat",), ("",)], ids=["logcat", "cable out"])
def test_adb_failure_after_the_tap_keeps_the_result(monkeypatch, caplog, broken):
    caplog.set_level("INFO")
    dev = FakeDevice()
    dev.at(at_target(1), broken=broken)
    out = simulate(monkeypatch, dev)
    assert_safe(out)
    assert (out.code, len(out.injected)) == (a.EXIT_OK, 1)
    assert "Could not check logcat for rejected taps" in caplog.text
    assert "[SUCCESS] 1/1 taps injected" in caplog.text


# ------------------------------------------------------------- any fault, any moment

@pytest.mark.parametrize("duration", [None, 8], ids=["for good", "for 8 s"])
@pytest.mark.parametrize("fault", list(FAULTS))
def test_no_early_or_extra_tap_whenever_the_phone_breaks(monkeypatch, cache_file, fault,
                                                        duration):
    for moment in range(-149, 8, 3):
        cache_file.unlink(missing_ok=True)     # every run measures for itself
        with monkeypatch.context() as mp:
            dev = FakeDevice()
            dev.at(at_target(moment), **FAULTS[fault])
            if duration:
                dev.at(at_target(moment + duration), **HEALTHY)
            out = simulate(mp, dev)
        try:
            assert_safe(out)
        except AssertionError as exc:
            raise AssertionError(f"{fault} at T{moment:+d} s: {out}") from exc
