"""Offline tests: a fake ADB device simulates a HyperOS phone with/without permissions.

Run: python -m pytest -q tests
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from fakes import (DRY, LOGCAT_DENIAL, SECURITY_EXC, T0, UI_XML, VIRTUAL_START,
                   FakeDevice, a, ms, plan_for, run_with,
                   use_virtual_time, write_cache)



def test_find_button_by_text():
    b = a.find_button(UI_XML, "Apply for unlocking", a.BUTTON_RESOURCE_ID)
    assert (b.x, b.y, b.matched_by) == (540, 2070, "text")


def test_find_button_fallback_to_resource_id():
    xml = UI_XML.replace("Apply for unlocking", "Подать заявку")
    b = a.find_button(xml, "Apply for unlocking", a.BUTTON_RESOURCE_ID)
    assert b.matched_by == "resource-id"


def test_find_button_substring_in_content_desc():
    xml = UI_XML.replace('text="Apply for unlocking"',
                         'text="" content-desc="Tap to apply for unlocking now"')
    b = a.find_button(xml, "Apply for unlocking", "x")
    assert (b.x, b.y, b.matched_by) == (540, 2070, "text~")


def test_find_button_skips_zero_size_node():
    hidden = '<node text="Apply for unlocking" bounds="[0,0][0,0]" enabled="true"/>'
    anchor = '<node text="Unlock bootloader"'
    xml = UI_XML.replace(anchor, hidden + "\n" + anchor)
    b = a.find_button(xml, "Apply for unlocking", a.BUTTON_RESOURCE_ID)
    assert (b.x, b.y, b.matched_by) == (540, 2070, "text")


def test_probe_target_is_static_text_in_app():
    t = a.find_probe_target(UI_XML, a.find_button(UI_XML, "Apply for unlocking", "x"))
    assert (t.x, t.y) == (370, 160)      # "Unlock bootloader", not systemui / Back


def test_probe_target_skips_children_of_clickable_nodes():
    xml = UI_XML.replace('package="com.mi.global.bbs" clickable="false"\n        bounds="[0,80]',
                         'package="com.mi.global.bbs" clickable="true"\n        bounds="[0,80]')
    assert a.find_probe_target(xml, None) is None


def test_probe_target_avoids_the_button():
    xml = UI_XML.replace('text="Unlock bootloader"', 'text=""')
    xml = xml.replace('clickable="true"\n          bounds="[100,2000]',
                      'clickable="false"\n          bounds="[100,2000]')
    button = a.find_button(xml, "Apply for unlocking", "x")
    assert a.find_probe_target(xml, button) is None


def test_find_button_quotes_in_text_do_not_break():
    assert a.find_button(UI_XML, "it's", "x") is None


def test_security_exception_detected():
    r = a.ShellResult("input tap 1 1", 0, SECURITY_EXC)   # rc 0 but exception printed
    assert not r.ok and r.security_denied


def test_next_occurrence_beijing_midnight():
    now = datetime(2026, 10, 5, 15, 0, tzinfo=timezone.utc)      # 23:00 CST
    t = a.next_occurrence("00:00:00", now, timedelta(hours=8))
    assert t == datetime(2026, 10, 5, 16, 0, tzinfo=timezone.utc)
    now = datetime(2026, 10, 5, 16, 0, 1, tzinfo=timezone.utc)   # just past 00:00 CST
    assert a.next_occurrence("00:00:00", now, timedelta(hours=8)).day == 6


def test_audit_ok(monkeypatch):
    assert run_with(monkeypatch, FakeDevice(), DRY) == a.EXIT_OK


def test_audit_fails_without_inject_events(monkeypatch, caplog):
    dev = FakeDevice(inject=False, settings=False)
    assert run_with(monkeypatch, dev, DRY) == a.EXIT_AUDIT
    assert "USB debugging (Security settings)" in caplog.text
    assert not dev.taps


def test_audit_fails_when_adbinput_off_but_probe_passes(monkeypatch, caplog):
    # HyperOS 3: off-screen probes succeed even with the toggle off, real taps do not
    dev = FakeDevice(inject=True, adbinput="0")
    assert run_with(monkeypatch, dev, ["--test-in", "5"]) == a.EXIT_AUDIT
    assert "Security settings OFF" in caplog.text
    assert not dev.taps


def test_missing_adbinput_on_other_brand_does_not_fail(monkeypatch):
    assert run_with(monkeypatch, FakeDevice(adbinput="", brand="Google"), DRY) == a.EXIT_OK


def test_audit_probes_inside_the_app_window(monkeypatch, caplog):
    caplog.set_level("INFO")
    dev = FakeDevice()
    assert run_with(monkeypatch, dev, ["--dry-run", "--test-in", "90"]) == a.EXIT_OK
    assert dev.probe_taps == ["input tap 370 160"] * 2     # audit + T-90 s probe
    assert "tap on static text 'Unlock bootloader' at (370, 160) in Mi Community accepted" \
        in caplog.text


def test_no_probe_in_the_last_minute(monkeypatch, caplog):
    dev = FakeDevice()
    assert run_with(monkeypatch, dev, DRY) == a.EXIT_OK
    assert dev.probe_taps == []
    assert "probe skipped: the target is less than a minute away" in caplog.text


def test_probes_fit_the_window_with_double_tap_safe_gap(monkeypatch):
    assert a.PROBE_GAP_SEC >= 0.4
    dev = FakeDevice()
    probe_times = []
    real_run = dev.run

    def run(cmd, timeout=30.0):
        if cmd.startswith("echo \"miunlock_start="):
            probe_times.append(a.time.time())
        return real_run(cmd, timeout)
    dev.run = run
    assert run_with(monkeypatch, dev, ["--dry-run", "--test-in", "150"]) == a.EXIT_OK
    assert len(probe_times) == 20
    gaps = [later - earlier for earlier, later in zip(probe_times, probe_times[1:])]
    assert min(gaps) >= a.PROBE_GAP_SEC
    target = VIRTUAL_START + 150                 # --test-in 150 (+ a few virtual ms)
    assert probe_times[-1] < target - a.PROBE_END_SEC - a.PROBE_SAFETY_SEC


@pytest.mark.parametrize("test_in", ["90", "200", "3600"])
def test_only_the_real_tap_in_the_last_minute(monkeypatch, test_in):
    dev = FakeDevice()
    inputs = []          # (virtual time, command)
    real_run = dev.run

    def run(cmd, timeout=30.0):
        if cmd.startswith("input"):
            inputs.append((a.time.time(), cmd))
        return real_run(cmd, timeout)
    dev.run = run
    assert run_with(monkeypatch, dev, ["--test-in", test_in]) == a.EXIT_OK
    (fired_at, tap), = [i for i in inputs if i[1] in dev.taps]
    assert tap == "input tap 540 2070"
    probes = [t for t, cmd in inputs if cmd != tap]
    assert probes and all(fired_at - t > a.PROBE_END_SEC for t in probes)


def test_audit_fails_on_silent_denial_in_logcat(monkeypatch, caplog):
    dev = FakeDevice(silent_denial=True, adbinput="")
    assert run_with(monkeypatch, dev, ["--test-in", "90"]) == a.EXIT_AUDIT
    assert "Permission denied: injecting" in caplog.text
    assert not dev.taps


def test_live_refuses_without_inject(monkeypatch):
    dev = FakeDevice(inject=False)
    assert run_with(monkeypatch, dev, ["--test-in", "5"]) == a.EXIT_AUDIT
    assert dev.store["system/screen_off_timeout"] == "30000"     # nothing touched


def test_lock_screen_detected(monkeypatch):
    assert run_with(monkeypatch, FakeDevice(focus="NotificationShade"), DRY) \
        == a.EXIT_AUDIT


def test_other_app_in_foreground_fails(monkeypatch):
    assert run_with(monkeypatch, FakeDevice(focus="com.android.chrome"), DRY) \
        == a.EXIT_AUDIT


def test_unknown_foreground_only_warns(monkeypatch, caplog):
    dev = FakeDevice()
    real_run = dev.run

    def run(cmd, timeout=30.0):
        if cmd.startswith("dumpsys window"):
            return a.ShellResult(cmd, 0, "  unrecognised output format")
        return real_run(cmd, timeout)
    dev.run = run
    assert run_with(monkeypatch, dev, DRY) == a.EXIT_OK
    assert "could not detect the focused app" in caplog.text


def test_dry_run_no_taps_and_settings_restored(monkeypatch):
    dev = FakeDevice()
    assert run_with(monkeypatch, dev, DRY) == a.EXIT_OK
    assert dev.taps == []
    assert dev.store == {"global/stay_on_while_plugged_in": "0",
                         "system/screen_off_timeout": "30000"}


def test_live_test_run_taps(monkeypatch):
    dev = FakeDevice()
    assert run_with(monkeypatch, dev, ["--test-in", "5", "--clicks", "3"]) == a.EXIT_OK
    assert dev.taps == ["input tap 540 2070"] * 3
    assert dev.store["system/screen_off_timeout"] == "30000"


def test_settings_restored_on_interrupt(monkeypatch):
    dev = FakeDevice()

    def boom(*_a, **_k):
        raise KeyboardInterrupt
    monkeypatch.setattr(a, "wait_until", boom)
    with pytest.raises(KeyboardInterrupt):
        run_with(monkeypatch, dev, ["--test-in", "5"])
    assert dev.store["system/screen_off_timeout"] == "30000"


class FakeClock(a.Clock):
    """Virtual clock: sleep() advances it, every now() call costs 1 ms."""

    def __init__(self):  # pylint: disable=super-init-not-called
        self.server, self.offset, self.synced = "fake", 0.0, True
        self.t = datetime(2026, 10, 5, 15, 0, tzinfo=timezone.utc)
        self.syncs = 0

    def sync(self):
        self.syncs += 1

    def now(self):
        self.t += timedelta(milliseconds=1)
        return self.t


@pytest.mark.parametrize("wait_sec, expected_syncs", [(600, 1), (50, 0)])
def test_ntp_resync_before_target(monkeypatch, wait_sec, expected_syncs):
    clock = FakeClock()
    monkeypatch.setattr(a.time, "sleep",
                        lambda s: setattr(clock, "t", clock.t + timedelta(seconds=s)))
    target = clock.t + timedelta(seconds=wait_sec)
    a.wait_until(target, clock, FakeDevice())
    assert clock.syncs == expected_syncs
    assert clock.t >= target


def test_single_click_by_default():
    args = a.build_parser().parse_args([])
    assert (args.clicks, args.delay) == (1, 61)


@pytest.mark.parametrize("argv", [["--clicks", "2", "--delay", "5"],
                                  ["--clicks", "3", "--delay", "59.9"]])
def test_fast_repeat_rejected(argv, capsys):
    p = a.build_parser()
    with pytest.raises(SystemExit):
        a.validate_args(p, p.parse_args(argv))
    assert "one unlock request per minute" in capsys.readouterr().err


def test_delay_ignored_with_single_click():
    p = a.build_parser()
    a.validate_args(p, p.parse_args(["--delay", "5"]))


def test_click_stops_after_security_denial(monkeypatch, caplog):
    monkeypatch.setattr(a.time, "sleep", lambda s: None)
    dev = FakeDevice(inject=False)
    button = a.find_button(UI_XML, "Apply for unlocking", a.BUTTON_RESOURCE_ID)
    args = a.build_parser().parse_args(["--clicks", "3"])
    assert a.click(dev, button, FakeClock(), args) == 0
    assert sum(c.startswith("input tap") for c in dev.commands) == 1
    assert "USB debugging (Security settings)" in caplog.text


def test_heartbeat_reports_toggle_reset(monkeypatch, caplog):
    use_virtual_time(monkeypatch)
    clock = a.Clock("fake", use_ntp=False)
    dev = FakeDevice(adbinput="0")
    a.wait_until(clock.now() + timedelta(seconds=200), clock, dev)
    errors = [r for r in caplog.records if r.levelname == "ERROR"]
    assert errors and "Security settings" in errors[0].getMessage()


def test_final_check_stops_when_toggle_reset(monkeypatch):
    monkeypatch.setattr(a.time, "sleep", lambda s: None)
    dev = FakeDevice(adbinput="0")
    button = a.find_button(UI_XML, "Apply for unlocking", a.BUTTON_RESOURCE_ID)
    with pytest.raises(a.DeviceError, match="Security settings"):
        a.final_check(dev, "Apply for unlocking", button, need_inject=True)


@pytest.mark.parametrize("measure", [False, True])
def test_probe_phase_stops_on_silent_denial(monkeypatch, measure):
    monkeypatch.setattr(a.time, "sleep", lambda s: None)
    dev = FakeDevice(silent_denial=True, adbinput="")
    clock = FakeClock()
    ses = a.Session(dev, clock, a.build_parser().parse_args([]),
                    clock.t + timedelta(seconds=120), measure)
    with pytest.raises(a.DeviceError, match="Permission denied: injecting"):
        a.probe_phase(ses, a.find_button(UI_XML, "Apply for unlocking", "x"))


@pytest.mark.parametrize("hang", [("uiautomator dump",), ("uiautomator dump", "dumpsys")])
def test_final_check_stays_within_budget(monkeypatch, caplog, hang):
    use_virtual_time(monkeypatch)
    dev = FakeDevice()
    dev.hang = hang
    button = a.find_button(UI_XML, "Apply for unlocking", a.BUTTON_RESOURCE_ID)
    start = a.time.monotonic()
    fresh, xml = a.final_check(dev, "Apply for unlocking", button, need_inject=True)
    assert a.time.monotonic() - start <= a.FINAL_CHECK_BUDGET_SEC + 0.05   # 1 ms per call
    assert (fresh, xml) == (button, "")
    assert sum(c.startswith("uiautomator dump") for c in dev.commands) <= 1
    assert any(r.levelname == "ERROR" and "tapping the audited coordinates" in r.getMessage()
               for r in caplog.records)


@pytest.mark.parametrize("late_ms, warns", [(100, True), (30, False)])
def test_late_send_warns(monkeypatch, caplog, late_ms, warns):
    monkeypatch.setattr(a.time, "sleep", lambda s: None)
    clock = FakeClock()
    button = a.find_button(UI_XML, "Apply for unlocking", a.BUTTON_RESOURCE_ID)
    args = a.build_parser().parse_args(["--dry-run"])
    planned = clock.t - timedelta(milliseconds=late_ms)
    fired = a.FiredTaps(a.TimingPlan("fixed", 150, "test"), "", planned, planned)
    a.click(FakeDevice(), button, clock, args, fired)
    assert ("ms late: planned at" in caplog.text) == warns


def test_final_check_injects_nothing(monkeypatch):
    monkeypatch.setattr(a.time, "sleep", lambda s: None)
    dev = FakeDevice()
    button = a.find_button(UI_XML, "Apply for unlocking", a.BUTTON_RESOURCE_ID)
    a.final_check(dev, "Apply for unlocking", button, need_inject=True)
    assert not [c for c in dev.commands if c.startswith("input")]


def test_taps_where_the_button_is_at_fire_time(monkeypatch, caplog):
    dev = FakeDevice()
    real_audit = a.run_audit

    def audit_then_scroll(*args, **kwargs):
        report = real_audit(*args, **kwargs)
        dev.xml = UI_XML.replace("[100,2000][980,2140]", "[100,1800][980,1940]")
        return report
    monkeypatch.setattr(a, "run_audit", audit_then_scroll)
    assert run_with(monkeypatch, dev, ["--test-in", "5", "--clicks", "1"]) == a.EXIT_OK
    assert dev.taps == ["input tap 540 1870"]
    assert "button moved from (540, 2070) to (540, 1870)" in caplog.text


def test_unchanged_screen_after_tap_points_to_screenshots(monkeypatch, caplog, tmp_path):
    caplog.set_level("INFO")
    dev = FakeDevice()
    log_file = tmp_path / "logs" / "unlock.log"
    log_file.parent.mkdir()
    argv = ["--test-in", "5", "--clicks", "1", "--log-file", str(log_file)]
    assert run_with(monkeypatch, dev, argv) == a.EXIT_OK
    shots = sorted(log_file.parent.glob("miunlock_*_tap+*.png"))
    assert [p.name.split("_tap")[1] for p in shots] == ["+0.5s.png", "+1.5s.png", "+3s.png"]
    assert all(p.read_bytes().startswith(b"\x89PNG") for p in shots)
    assert len(list(log_file.parent.glob("miunlock_*_app_logcat.txt"))) == 1
    assert any(c.startswith("logcat -d -v epoch --pid=21464") for c in dev.commands)
    record, = [r for r in caplog.records if "did not change" in r.getMessage()]
    assert record.levelname == "INFO" and str(shots[0]) in record.getMessage()


def test_screenshots_are_taken_while_a_toast_is_visible(monkeypatch):
    dev = FakeDevice()
    shot_times = []
    real_read = dev.read_bytes

    def read_bytes(cmd, timeout=15.0):
        shot_times.append(a.time.time())
        return real_read(cmd, timeout)
    dev.read_bytes = read_bytes
    taps = []
    real_run = dev.run

    def run(cmd, timeout=30.0):
        if cmd.startswith("echo \"miunlock_start="):
            taps.append(a.time.time())
        return real_run(cmd, timeout)
    dev.run = run
    assert run_with(monkeypatch, dev, ["--test-in", "5"]) == a.EXIT_OK
    after = [t - taps[-1] for t in shot_times]
    assert len(after) == 3 and after[0] < 1.0 and after[-1] < 3.5


def test_new_screen_text_after_tap_is_logged(caplog):
    caplog.set_level("INFO")
    dev = FakeDevice(xml=UI_XML.replace("Apply for unlocking", "Applied, come back tomorrow")
                     .replace('text="20:07"', 'text="00:00"'))
    button = a.find_button(UI_XML, "Apply for unlocking", a.BUTTON_RESOURCE_ID)
    assert a.verify_after_tap(dev, button, "Apply for unlocking", UI_XML, "") == (True, True)
    assert "New on screen: Applied, come back tomorrow" in caplog.text   # no systemui clock
    assert "Screen changed after tapping" in caplog.text


@pytest.mark.parametrize("line", [
    LOGCAT_DENIAL,
    "10-05 20:07:03.687  1500  1600 E InputManager: Input event injection failed: denied",
    "10-05 20:07:03.687  1500  1600 W MIUIInput: injection was rejected for uid 2000",
])
def test_logcat_denial_lines_are_detected(line):
    assert a._LOGCAT_DENIED_RE.search(line)


@pytest.mark.parametrize("line", [
    # granting the permission mentions INJECT_EVENTS but is not a refusal
    "10-05 20:07:03.687  1500  1600 I PackageManager: grant android.permission.INJECT_EVENTS "
    "to com.android.shell",
    "10-05 20:07:03.687  1500  1600 D PermissionManager: INJECT_EVENTS granted=true",
    # HyperOS logs every accepted injection
    "10-05 20:07:03.687  2678 13244 W MIUIInput: Input motion event injection from package: "
    "null action ACTION_DOWN",
    # a refusal text under an unrelated tag
    "10-05 20:07:03.687  4000  4001 W SomeApp: injection failed in my own test harness",
])
def test_logcat_lines_without_refusal_are_not_denials(line):
    assert not a._LOGCAT_DENIED_RE.search(line)


def test_inject_events_mention_does_not_cancel_live_run(monkeypatch):
    monkeypatch.setattr(a.time, "sleep", lambda s: None)
    dev = FakeDevice()
    dev.logcat = ("10-05 20:07:03.687  1500  1600 I PackageManager: grant "
                  "android.permission.INJECT_EVENTS to com.android.shell\n")
    clock = FakeClock()
    ses = a.Session(dev, clock, a.build_parser().parse_args([]),
                    clock.t + timedelta(seconds=120), False)
    a.probe_phase(ses, a.find_button(UI_XML, "Apply for unlocking", "x"))   # no raise


def test_logcat_denial_after_tap_fails():
    button = a.find_button(UI_XML, "Apply for unlocking", a.BUTTON_RESOURCE_ID)
    assert a.verify_after_tap(FakeDevice(), button, "Apply for unlocking", UI_XML,
                              LOGCAT_DENIAL) == (False, None)




def test_fixed_timing_sends_at_150_ms():
    plan, send = plan_for(["--timing", "fixed"], samples=[120, 125, 140])
    assert (plan.mode, plan.compensation_ms) == ("fixed", 0)
    assert send == T0 + ms(150)
    assert send.astimezone(timezone(a.BEIJING_OFFSET)).strftime("%H:%M:%S.%f") \
        == "00:00:00.150000"


def test_injection_delay_is_a_lower_bound():
    # start known to 1 us (EPOCHREALTIME), injection logged 70 ms later (truncated to ms)
    starts = [(100.0, 1e-6), (100.5, 1e-6)]
    delays = a.injection_delays(starts, [100.070, 100.076, 100.583, 100.589])
    assert delays == pytest.approx([69.999, 82.999])
    # /proc/uptime-like start resolution of 10 ms is subtracted in full
    assert a.injection_delays([(100.0, 0.01)], [100.070]) == pytest.approx([60.0])
    # no injection logged after the start, or one before it: no sample
    assert a.injection_delays([(100.0, 1e-6)], [99.990]) == []


def test_injection_of_a_later_tap_is_not_matched():
    # tap 1 logged nothing; tap 2 (start not printed) injected at 100.540: that is not
    # tap 1's injection - it is longer than tap 1's own round-trip
    assert a.injection_delays([(100.0, 1e-6)], [100.540], round_trips=[120.0]) == []
    assert a.injection_delays([(100.0, 1e-6)], [100.070], round_trips=[120.0]) == \
        pytest.approx([69.999])


def test_tap_start_parsing():
    assert a.tap_start("miunlock_start=1791228293.267669\n") == \
        pytest.approx((1791228293.267669, 1e-6))
    assert a.tap_start("miunlock_start=1791228317.N") is None     # date without %N
    assert a.tap_start("") is None


def test_adaptive_compensates_minimal_injection_delay():
    plan, send = plan_for([], samples=[120, 125, 140])
    assert (plan.mode, plan.margin_ms, plan.compensation_ms) == ("adaptive", 50, 120)
    assert send == T0 + ms(50) - ms(120)
    assert plan.earliest_arrival(T0) == T0 + ms(50)


def test_adaptive_compensates_half_of_network_rtt():
    plan, send = plan_for(["--api-host", "example.org"], samples=[120, 125, 140],
                          net=[80, 90, 300])
    assert plan.compensation_ms == 160
    assert send == T0 + ms(50) - ms(160)


def test_compensation_rounds_down():
    plan, send = plan_for([], samples=[120.9, 125, 140])
    assert plan.compensation_ms == 120
    assert send == T0 - ms(70)


def test_wide_spread_raises_margin(caplog):
    plan, send = plan_for([], samples=[100, 110, 120, 400])
    assert plan.margin_ms == 150
    assert send == T0 + ms(150) - ms(100)
    assert "Injection delay varies a lot" in caplog.text


def test_no_estimate_falls_back_to_standard_margin(caplog):
    plan, send = plan_for([])
    assert (plan.mode, send) == ("fixed", T0 + ms(150))
    assert "Latency estimate impossible - using the standard margin of 150 ms" \
        in caplog.text


def test_guard_rejects_early_arrival(caplog):
    plan, send = plan_for(["--adaptive-margin-ms", "10"], samples=[120, 125, 140])
    assert (plan.mode, send) == ("fixed", T0 + ms(150))
    assert any(r.levelname == "ERROR" and "Timing guard" in r.getMessage()
               for r in caplog.records)


def test_guard_rejects_small_fixed_margin(caplog):
    plan, send = plan_for(["--timing", "fixed", "--margin-ms", "20"])
    assert (plan.source, send) == ("guard fallback", T0 + ms(150))
    assert "margin 20 ms < 50 ms" in caplog.text


@pytest.mark.parametrize("adb, ok", [([30, 40], False), ([10, 12], True), (None, True)])
def test_injection_delay_cannot_exceed_round_trip(caplog, adb, ok):
    # input round-trip 110 ms; the device part cannot be longer than 110 - ADB RTT / 2
    plan, send = plan_for([], samples=[100, 105], round_trip=[110, 130], adb=adb)
    if ok:
        assert (plan.mode, plan.compensation_ms) == ("adaptive", 100)
    else:
        assert (plan.mode, plan.source, send) == ("fixed", "measurement error", T0 + ms(150))
        assert any(r.levelname == "ERROR" and "Latency measurement error" in r.getMessage()
                   for r in caplog.records)


def test_cached_implausible_measurement_is_rejected(monkeypatch, caplog, cache_file):
    write_cache(cache_file, samples=(130, 135, 140))
    data = json.loads(cache_file.read_text())
    data["round_trip"] = {"samples_ms": [120, 125]}
    cache_file.write_text(json.dumps(data))
    assert run_with(monkeypatch, FakeDevice(), ["--dry-run", "--test-in", "30"]) == a.EXIT_OK
    assert "Latency measurement error" in caplog.text


@pytest.mark.parametrize("argv", [["--margin-ms", "-1"], ["--adaptive-margin-ms", "-5"],
                                  ["--probes", "1"], ["--api-host", "x; reboot"]])
def test_bad_timing_args_rejected(argv):
    p = a.build_parser()
    with pytest.raises(SystemExit):
        a.validate_args(p, p.parse_args(argv))


def test_lead_ms_is_ignored_with_warning(monkeypatch, caplog):
    dev = FakeDevice()
    assert run_with(monkeypatch, dev, DRY + ["--lead-ms", "200"]) == a.EXIT_OK
    assert "--lead-ms is deprecated and ignored" in caplog.text


def test_adaptive_run_measures_in_the_probe_window(monkeypatch, caplog):
    caplog.set_level("INFO")
    dev = FakeDevice()
    assert run_with(monkeypatch, dev, ["--dry-run", "--test-in", "150"]) == a.EXIT_OK
    assert len(dev.probe_taps) == 1 + 20         # audit + latency probes
    assert dev.taps == []                        # dry run: no real tap
    assert "Start -> injection measured (device clock): min 69" in caplog.text
    assert "Timing: adaptive (measured)" in caplog.text
    assert "request reaches the server no earlier than" in caplog.text


def test_compensation_is_injection_delay_not_round_trip(monkeypatch, caplog):
    caplog.set_level("INFO")
    dev = FakeDevice(inject_ms=70, tap_rt_ms=120)
    assert run_with(monkeypatch, dev, ["--dry-run", "--test-in", "150"]) == a.EXIT_OK
    assert "input tap round-trip (reference, not compensated): min 12" in caplog.text
    assert "compensation 69 ms, margin 50 ms" in caplog.text   # 70 ms - 1 us resolution
    assert "(target -19 ms)" in caplog.text


def test_no_injection_line_uses_standard_margin(monkeypatch, caplog, cache_file):
    dev = FakeDevice(inject_log=False)
    assert run_with(monkeypatch, dev, ["--dry-run", "--test-in", "150"]) == a.EXIT_OK
    assert "Latency measurement impossible: the injection time was found for 0/20" \
        in caplog.text
    assert "using the standard margin of 150 ms" in caplog.text
    assert any(r.levelname == "WARNING" and "Latency measurement impossible" in r.getMessage()
               for r in caplog.records)
    assert not cache_file.exists()


def test_start_time_missing_uses_standard_margin(monkeypatch, caplog, cache_file):
    dev = FakeDevice()
    real_run = dev.run

    def run(cmd, timeout=30.0):
        res = real_run(cmd, timeout)
        return a.ShellResult(cmd, res.returncode, res.output.replace("miunlock_start=", ""))
    dev.run = run
    assert run_with(monkeypatch, dev, ["--dry-run", "--test-in", "150"]) == a.EXIT_OK
    assert "using the standard margin of 150 ms" in caplog.text
    assert not cache_file.exists()


def test_adaptive_run_pings_api_host(monkeypatch, caplog):
    caplog.set_level("INFO")
    dev = FakeDevice()
    dev.ping_output = "\n".join(f"64 bytes from 1.2.3.4: icmp_seq={i} ttl=50 time={t} ms"
                                for i, t in enumerate([41.5, 40.2, 55.0]))
    argv = ["--dry-run", "--test-in", "150", "--api-host", "example.org"]
    assert run_with(monkeypatch, dev, argv) == a.EXIT_OK
    assert "Network RTT to example.org measured: min 40" in caplog.text
    assert any(r.levelname == "WARNING" and "--api-host is experimental" in r.getMessage()
               for r in caplog.records)
    assert "compensation 89 ms" in caplog.text   # 69 ms injection + 40 / 2


def test_unavailable_ping_is_not_compensated(monkeypatch, caplog):
    caplog.set_level("INFO")
    argv = ["--dry-run", "--test-in", "150", "--api-host", "example.org"]
    assert run_with(monkeypatch, FakeDevice(), argv) == a.EXIT_OK
    assert "ping example.org from the phone is not available" in caplog.text
    assert "compensation 69 ms, margin 50 ms" in caplog.text


def test_late_start_does_not_measure(monkeypatch, caplog):
    dev = FakeDevice()
    assert run_with(monkeypatch, dev, ["--dry-run", "--test-in", "100"]) == a.EXIT_OK
    assert len(dev.probe_taps) == 2              # audit + one injection probe, no timing
    assert "no latency measurement" in caplog.text
    assert "using the standard margin of 150 ms" in caplog.text


def test_failed_probes_are_inconclusive(monkeypatch, caplog):
    dev = FakeDevice()
    real_run = dev.run

    def run(cmd, timeout=30.0):
        if cmd == "input tap 370 160" and len(dev.probe_taps) > 1:
            return a.ShellResult(cmd, 1, "Error: injection timed out")
        return real_run(cmd, timeout)
    dev.run = run
    assert run_with(monkeypatch, dev, ["--dry-run", "--test-in", "150"]) == a.EXIT_OK
    assert "Latency measurement inconclusive" in caplog.text
    assert "using the standard margin of 150 ms" in caplog.text
