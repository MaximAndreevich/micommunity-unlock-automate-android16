"""Offline tests: a fake ADB device simulates a HyperOS phone with/without permissions.

Run: python -m pytest -q tests
"""

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


class FakeDevice(a.Device):
    def __init__(self, inject=True, settings=True, focus="com.mi.global.bbs", xml=UI_XML,
                 adbinput=None, brand="Xiaomi", silent_denial=False):
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

    def run(self, cmd, timeout=30.0):
        self.commands.append(cmd)
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


def use_virtual_time(monkeypatch):
    """time.sleep() advances a virtual time.time(); every time() call costs 1 ms."""
    now = [1_800_000_000.0]

    def fake_time():
        now[0] += 0.001
        return now[0]

    def fake_sleep(sec):
        now[0] += sec
    monkeypatch.setattr(a.time, "time", fake_time)
    monkeypatch.setattr(a.time, "monotonic", fake_time)
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
    assert "in Mi Community accepted" in caplog.text


def test_no_probe_in_the_last_minute(monkeypatch, caplog):
    dev = FakeDevice()
    assert run_with(monkeypatch, dev, DRY) == a.EXIT_OK
    assert dev.probe_taps == []
    assert "probe skipped: the target is less than a minute away" in caplog.text


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


def test_probe_phase_stops_on_silent_denial(monkeypatch):
    monkeypatch.setattr(a.time, "sleep", lambda s: None)
    dev = FakeDevice(silent_denial=True, adbinput="")
    button = a.find_button(UI_XML, "Apply for unlocking", a.BUTTON_RESOURCE_ID)
    with pytest.raises(a.DeviceError, match="Permission denied: injecting"):
        a.probe_phase(dev, "Apply for unlocking", button, need_inject=True)


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


def test_unchanged_screen_after_tap_warns(monkeypatch, caplog):
    dev = FakeDevice()
    assert run_with(monkeypatch, dev, ["--test-in", "5", "--clicks", "1"]) == a.EXIT_OK
    assert "Screen unchanged after tapping" in caplog.text


def test_new_screen_text_after_tap_is_logged(caplog):
    caplog.set_level("INFO")
    dev = FakeDevice(xml=UI_XML.replace("Apply for unlocking", "Applied, come back tomorrow")
                     .replace('text="20:07"', 'text="00:00"'))
    button = a.find_button(UI_XML, "Apply for unlocking", a.BUTTON_RESOURCE_ID)
    assert a.verify_after_tap(dev, button, "Apply for unlocking", UI_XML, "10-05 20:07:03.000")
    assert "New on screen: Applied, come back tomorrow" in caplog.text   # no systemui clock
    assert "Screen changed after tapping" in caplog.text


def test_logcat_denial_after_tap_fails():
    dev = FakeDevice()
    dev.logcat = LOGCAT_DENIAL
    button = a.find_button(UI_XML, "Apply for unlocking", a.BUTTON_RESOURCE_ID)
    assert not a.verify_after_tap(dev, button, "Apply for unlocking", UI_XML,
                                  "10-05 20:07:03.000")
