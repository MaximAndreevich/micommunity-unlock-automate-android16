"""Shared fakes for the offline tests: a simulated HyperOS phone over ADB, virtual
time, timing and cache helpers."""

import itertools
import json
import math
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import automate as a  # noqa: E402  pylint: disable=wrong-import-position


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
                 adbinput=None, brand="Xiaomi", silent_denial=False, inject_ms=70.0,
                 tap_rt_ms=120.0, inject_log=True, real_tap_inject_ms=None):
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
        # command start -> injection (device clock); a list is cycled through (jitter)
        self.delays = itertools.cycle(inject_ms if isinstance(inject_ms, (list, tuple))
                                      else [inject_ms])
        self.injections = []                 # (command, moment the event was injected)
        self.real_tap_inject_ms = real_tap_inject_ms   # the button tap's own delay (None:
                                                       # the next one of inject_ms)
        self.tap_rt_ms = tap_rt_ms           # round-trip of a tap command
        self.inject_log = inject_log         # HyperOS logs every injection (MIUIInput)
        self.broken = ()                     # command prefixes failing with an adb error
        self.timeline = []                   # (virtual time, state changes), see at()

    hang = ()                                # command prefixes that never answer

    def at(self, moment, **changes):
        """From `moment` (virtual time.time()) on, the phone behaves as `changes` say:
        e.g. inject=False (toggle reset), silent_denial=True, broken=("",) (cable out)."""
        self.timeline.append((moment, changes))
        self.timeline.sort(key=lambda event: event[0])

    def _advance(self):
        if not self.timeline:
            return                           # no extra clock calls in plain tests
        now = a.time.time()
        while self.timeline and self.timeline[0][0] <= now:
            for name, value in self.timeline.pop(0)[1].items():
                setattr(self, name, value)

    def _shell(self, cmd, timeout):
        self._advance()
        self.commands.append(cmd)
        if cmd.startswith(self.broken):
            raise a.DeviceError(f"adb shell '{cmd}' failed: device offline")
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
        self._advance()
        self.commands.append(cmd)
        if cmd.startswith(self.broken):
            raise a.DeviceError(f"adb shell '{cmd}' failed: device offline")
        return b"\x89PNG\r\n\x1a\nfake"

    def _timed_tap(self, cmd, timeout):
        """tap_command(): prints the start time, logs the injection like HyperOS."""
        start = a.time.time()
        button_taps = len(self.taps)
        res = self.run(cmd, timeout)
        hit_button = len(self.taps) > button_taps
        delay = (self.real_tap_inject_ms if hit_button and self.real_tap_inject_ms is not None
                 else next(self.delays))
        injected = start + delay / 1000
        if res.returncode == 0 and not self.silent_denial:
            self.injections.append((cmd, injected))
        if res.returncode == 0 and self.inject_log and not self.silent_denial:
            logged = math.floor(injected * 1000) / 1000   # truncated
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
