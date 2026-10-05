"""Offline tests: a fake ADB device simulates a HyperOS phone with/without permissions.

Run: python -m pytest -q tests
"""

import json
import math
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import automate as a  # noqa: E402

UI_XML = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node text="" resource-id="" package="com.android.systemui" clickable="false"
        bounds="[0,0][1080,80]" enabled="true">
    <node text="20:07" package="com.android.systemui" clickable="false"
          bounds="[40,10][200,70]" enabled="true"/>
  </node>
  <node text="" resource-id="" package="com.mi.global.bbs" clickable="false"
        bounds="[0,80][1080,2400]" enabled="true">
    <node text="Back" package="com.mi.global.bbs" clickable="true"
          bounds="[0,100][100,200]" enabled="true"/>
    <node text="Unlock bootloader" resource-id="" package="com.mi.global.bbs"
          clickable="false" bounds="[140,120][600,200]" enabled="true"/>
    <node text="Apply for unlocking" resource-id="com.mi.global.bbs:id/btnApply"
          package="com.mi.global.bbs" clickable="true"
          bounds="[100,2000][980,2140]" enabled="true"/>
  </node>
</hierarchy>"""

SECURITY_EXC = (
    "Exception occurred while executing 'tap':\n"
    "java.lang.SecurityException: Injecting input events requires the caller (or the "
    "source of the instrumentation, if any) to have the INJECT_EVENTS permission.\n"
    "\tat com.android.server.input.InputManagerService.injectInputEventToTarget"
)
LOGCAT_DENIAL = ("10-05 20:07:03.687  1500  1600 W InputDispatcher: Permission denied: "
                 "injecting event from pid 9825 uid 2000 to window Window{e1 u0 "
                 "com.mi.global.bbs/.Unlock}")
SETTINGS_EXC = ("Exception occurred while executing 'put':\njava.lang.SecurityException: "
                "Permission denial: writing to settings requires:android.permission."
                "WRITE_SECURE_SETTINGS")


@pytest.fixture(autouse=True)
def cache_file(tmp_path, monkeypatch):
    """Keeps tests away from the real latency cache next to the script."""
    monkeypatch.chdir(tmp_path)          # screenshots / logcat after a tap land here
    path = tmp_path / "latency.json"
    monkeypatch.setattr(a, "DEFAULT_CACHE_FILE", str(path))
    return path


class FakeDevice(a.Device):
    def __init__(self, inject=True, settings=True, focus="com.mi.global.bbs", xml=UI_XML,
                 adbinput=None, brand="Xiaomi", silent_denial=False, inject_ms=70.0,
                 tap_rt_ms=120.0, inject_log=True):
        self.serial = "fake123"
        self.inject, self.settings, self.focus, self.xml = inject, settings, focus, xml
        # Xiaomi toggle; follows `inject` unless set explicitly ("" = property missing)
        self.adbinput = ("1" if inject else "0") if adbinput is None else adbinput
        self.brand = brand
        self.silent_denial = silent_denial   # taps exit 0, denial only shows in logcat
        self.logcat = ""
        self.probe_taps = []                 # taps outside the unlock button
        self.store = {"global/stay_on_while_plugged_in": "0",
                      "system/screen_off_timeout": "30000"}
        self.taps = []
        self.commands = []
        self.ping_output = ""                # "" = ping not available
        self.inject_ms = inject_ms           # command start -> injection (device clock)
        self.tap_rt_ms = tap_rt_ms           # round-trip of a tap command
        self.inject_log = inject_log         # HyperOS logs every injection (MIUIInput)

    hang = ()                                # command prefixes that never answer

    def _shell(self, cmd, timeout):
        self.commands.append(cmd)
        if cmd.startswith(self.hang):
            a.time.sleep(timeout)
            raise a.DeviceError(f"adb shell '{cmd}' failed: timeout")
        tap = re.fullmatch(r'echo "miunlock_start=\$\{EPOCHREALTIME:-\$\(date \+%s\.%N\)\}"; '
                           r'(input tap .*)', cmd)
        if tap:
            return self._timed_tap(tap.group(1), timeout)
        out, rc = "", 0
        if cmd == "echo ok":
            out = "ok"
        elif cmd.startswith("getprop"):
            out = {"ro.build.version.sdk": "36", "ro.build.version.release": "16",
                   "ro.product.manufacturer": self.brand, "ro.product.model": "23090RA98G",
                   "ro.mi.os.version.name": "OS3.0", "ro.product.mod_device": "garnet_global",
                   "persist.security.adbinput": self.adbinput,
                   }.get(cmd.split()[1], "")
        elif cmd.startswith("input"):
            if not self.inject:
                out, rc = SECURITY_EXC.replace("'tap'", f"'{cmd.split()[1]}'"), 255
            elif cmd.startswith("input tap") and "-500" not in cmd:
                x, y = map(int, cmd.split()[2:4])
                button = a.find_button(self.xml, "Apply for unlocking", a.BUTTON_RESOURCE_ID)
                if self.silent_denial:
                    self.logcat += LOGCAT_DENIAL + "\n"
                elif button and a._contains(button.bounds, x, y):
                    self.taps.append(cmd)
                else:
                    self.probe_taps.append(cmd)
        elif cmd.startswith("pidof"):
            out = "21464"
        elif cmd.startswith("ping"):
            out, rc = self.ping_output, (0 if self.ping_output else 2)
        elif cmd.startswith("date"):
            out = "10-05 20:07:03.000"
        elif cmd.startswith("logcat"):
            out, self.logcat = self.logcat, ""
        elif cmd.startswith("settings get"):
            _, _, ns, key = cmd.split()
            out = self.store.get(f"{ns}/{key}", "null")
        elif cmd.startswith(("settings put", "settings delete")):
            if not self.settings:
                out, rc = SETTINGS_EXC, 255
            else:
                parts = cmd.split()
                if parts[1] == "put":
                    self.store[f"{parts[2]}/{parts[3]}"] = parts[4]
                else:
                    self.store.pop(f"{parts[2]}/{parts[3]}", None)
        elif cmd.startswith("dumpsys power"):
            out = "  mWakefulness=Awake"
        elif cmd.startswith("dumpsys window"):
            out = (f"  mCurrentFocus=Window{{4f2 u0 {self.focus}/com.mi.Unlock}}"
                   if self.focus != "NotificationShade"
                   else "  mCurrentFocus=Window{9c u0 NotificationShade}\n"
                        "  mFocusedApp=ActivityRecord{1 u0 com.mi.global.bbs/.Unlock t5}")
        elif cmd.startswith("uiautomator dump"):
            out = f"UI hierchary dumped to: {a.DEVICE_XML_PATH}"
        elif cmd.startswith("cat"):
            out = self.xml
        return a.ShellResult(cmd, rc, out)

    def read_bytes(self, cmd, timeout=15.0):
        self.commands.append(cmd)
        return b"\x89PNG\r\n\x1a\nfake"

    def _timed_tap(self, cmd, timeout):
        """tap_command(): prints the start time, logs the injection like HyperOS."""
        start = a.time.time()
        res = self.run(cmd, timeout)
        if res.returncode == 0 and self.inject_log and not self.silent_denial:
            logged = math.floor((start + self.inject_ms / 1000) * 1000) / 1000   # truncated
            self.logcat += (f"{logged:.3f}  2678 13244 W MIUIInput: Input motion event "
                            "injection from package: null action ACTION_DOWN\n")
        a.time.sleep(self.tap_rt_ms / 1000)
        return a.ShellResult(cmd, res.returncode, f"miunlock_start={start:.6f}\n" + res.output)


VIRTUAL_START = 1_800_000_000.0


def use_virtual_time(monkeypatch):
    """time.sleep() advances a virtual time.time(); every time() call costs 1 ms."""
    now = [VIRTUAL_START]

    def fake_time():
        now[0] += 0.001
        return now[0]

    def fake_sleep(sec):
        now[0] += sec
    monkeypatch.setattr(a.time, "time", fake_time)
    monkeypatch.setattr(a.time, "monotonic", fake_time)
    monkeypatch.setattr(a.time, "perf_counter", fake_time)
    monkeypatch.setattr(a.time, "sleep", fake_sleep)


DRY = ["--dry-run", "--test-in", "5"]


def run_with(monkeypatch, dev, argv):
    monkeypatch.setattr(a, "connect_device", lambda serial: dev)
    use_virtual_time(monkeypatch)
    args = a.build_parser().parse_args(argv + ["--no-ntp"])
    a.validate_args(a.build_parser(), args)
    return a.run(args)


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
    a.click(FakeDevice(), button, clock, args, planned=clock.t - timedelta(milliseconds=late_ms))
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
    assert a.verify_after_tap(dev, button, "Apply for unlocking", UI_XML,
                              "10-05 20:07:03.000") == (True, True)
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
    dev = FakeDevice()
    dev.logcat = LOGCAT_DENIAL
    button = a.find_button(UI_XML, "Apply for unlocking", a.BUTTON_RESOURCE_ID)
    assert a.verify_after_tap(dev, button, "Apply for unlocking", UI_XML,
                              "10-05 20:07:03.000") == (False, None)


# --------------------------------------------------------------------------- timing

T0 = datetime(2026, 10, 6, 16, 0, tzinfo=timezone.utc)      # 00:00:00 CST


def measurement(inject, round_trip=None, adb=None, net=None):
    stats = a.LatencyStats
    return a.Measurement(stats(inject), stats(round_trip or [x + 50 for x in inject]),
                         stats(adb) if adb else None, stats(net) if net else None)


def plan_for(argv, samples=None, net=None, round_trip=None, adb=None):
    args = a.build_parser().parse_args(argv)
    measured = measurement(samples, round_trip, adb, net) if samples else None
    plan = a.plan_timing(args, measured, "test")
    return a.checked_send_time(plan, T0)


def ms(n):
    return timedelta(milliseconds=n)


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


# --------------------------------------------------------------------------- cache

def write_cache(path, serial="fake123", connection="usb", age=timedelta(hours=1),
                samples=(70, 75, 90), now=None, method=a.CACHE_METHOD):
    now = now or datetime.fromtimestamp(VIRTUAL_START, timezone.utc)
    data = {"serial": serial, "connection": connection,
            "measured_at": (now - age).isoformat(),
            "inject": {"samples_ms": list(samples)},
            "round_trip": {"samples_ms": [x + 50 for x in samples]},
            "adb_rtt": {"samples_ms": [4, 5, 6]}, "net": None, "api_host": None}
    if method:
        data["method"] = method
    path.write_text(json.dumps(data))


def test_measurement_is_saved(monkeypatch, cache_file):
    assert run_with(monkeypatch, FakeDevice(), ["--dry-run", "--test-in", "150"]) == a.EXIT_OK
    data = json.loads(cache_file.read_text())
    assert (data["method"], data["serial"], data["connection"]) == \
        ("device_inject_v1", "fake123", "usb")
    assert len(data["inject"]["samples_ms"]) == len(data["round_trip"]["samples_ms"]) == 20
    assert len(data["adb_rtt"]["samples_ms"]) == 5
    assert {"min_ms", "median_ms", "p95_ms"} <= data["inject"].keys()
    assert datetime.fromisoformat(data["measured_at"]).tzinfo is not None


def test_late_start_without_cache_uses_standard_margin(monkeypatch, caplog, cache_file):
    caplog.set_level("INFO")
    assert run_with(monkeypatch, FakeDevice(), ["--dry-run", "--test-in", "30"]) == a.EXIT_OK
    assert "Latency estimate impossible - using the standard margin of 150 ms" \
        in caplog.text
    assert "compensation 0 ms, margin 150 ms" in caplog.text
    assert not cache_file.exists()


def test_late_start_uses_cache(monkeypatch, caplog, cache_file):
    caplog.set_level("INFO")
    write_cache(cache_file)
    dev = FakeDevice()
    assert run_with(monkeypatch, dev, ["--dry-run", "--test-in", "30"]) == a.EXIT_OK
    assert "Latency measurement not possible - using the one saved on" in caplog.text
    assert "compensation 70 ms, margin 50 ms" in caplog.text
    assert dev.probe_taps == []


def test_old_round_trip_cache_is_not_used(monkeypatch, caplog, cache_file):
    caplog.set_level("INFO")
    now = datetime.fromtimestamp(VIRTUAL_START, timezone.utc)
    cache_file.write_text(json.dumps({          # the format of the previous version
        "serial": "fake123", "connection": "usb", "measured_at": now.isoformat(),
        "tap": {"samples_ms": [109.26, 148.1]}, "net": None, "api_host": None}))
    assert run_with(monkeypatch, FakeDevice(), ["--dry-run", "--test-in", "30"]) == a.EXIT_OK
    assert "has an old measurement format (input round-trip) - not used" in caplog.text
    assert "using the standard margin of 150 ms" in caplog.text


def test_no_cache_flag(monkeypatch, caplog, cache_file):
    write_cache(cache_file)
    before = cache_file.read_text()
    assert run_with(monkeypatch, FakeDevice(),
                    ["--dry-run", "--test-in", "30", "--no-cache"]) == a.EXIT_OK
    assert "using the standard margin of 150 ms" in caplog.text
    assert run_with(monkeypatch, FakeDevice(),
                    ["--dry-run", "--test-in", "150", "--no-cache"]) == a.EXIT_OK
    assert cache_file.read_text() == before


def test_cache_used_only_for_the_same_device_and_fresh(cache_file):
    now = datetime(2026, 10, 6, 15, 0, tzinfo=timezone.utc)
    write_cache(cache_file, now=now, age=timedelta(days=6, hours=23))
    assert a.load_cache(str(cache_file), "fake123", 7, now).measured.inject.min == 70
    for kwargs in ({"serial": "other"}, {"connection": "tcp"},
                   {"age": timedelta(days=7, minutes=1)}, {"age": -timedelta(days=1)}):
        write_cache(cache_file, now=now, **kwargs)
        assert a.load_cache(str(cache_file), "fake123", 7, now) is None, kwargs


def test_tcp_cache_matches_tcp_serial(cache_file):
    now = datetime(2026, 10, 6, 15, 0, tzinfo=timezone.utc)
    write_cache(cache_file, serial="192.168.1.5:5555", connection="tcp", now=now)
    assert a.load_cache(str(cache_file), "192.168.1.5:5555", 7, now) is not None
    assert a.connection_type("adb-abc._adb-tls-connect._tcp") == "tcp"
    assert a.connection_type("a1b2c3d4") == "usb"


V1 = '"method": "device_inject_v1", '
SAMPLES = '"inject": {"samples_ms": [70]}, "round_trip": {"samples_ms": [120]}'


@pytest.mark.parametrize("content", ["{not json", "[]", '{' + V1 + '"serial": "fake123"}',
                                     '{' + V1 + '"serial": "fake123", "connection": "usb", '
                                     '"measured_at": "2026-10-06T10:00:00", ' + SAMPLES + '}',
                                     '{' + V1 + '"serial": "fake123", "connection": "usb", '
                                     '"measured_at": "2026-10-06T10:00:00+00:00", '
                                     '"inject": {"samples_ms": []}, '
                                     '"round_trip": {"samples_ms": [120]}}'])
def test_broken_cache_is_ignored(cache_file, caplog, content):
    cache_file.write_text(content)
    now = datetime(2026, 10, 6, 15, 0, tzinfo=timezone.utc)
    assert a.load_cache(str(cache_file), "fake123", 7, now) is None
    assert "ignored" in caplog.text


def test_broken_cache_does_not_stop_the_run(monkeypatch, caplog, cache_file):
    cache_file.write_text("{not json")
    assert run_with(monkeypatch, FakeDevice(), ["--dry-run", "--test-in", "30"]) == a.EXIT_OK
    assert "is unreadable" in caplog.text
    assert "using the standard margin of 150 ms" in caplog.text
