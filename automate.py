# Python script to automate Mi Community unlock request at 00:00 beijing time via ADB
# Copyright (C) 2025 chickendrop89
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

"""
Automates the Mi Community "Apply for unlocking" request at the moment
the daily quota resets (00:00 Beijing time).

Flow:
  1. Preflight audit: ADB, device state, shell permissions (input injection,
     settings write), UI dump, Mi Community in foreground, button present, NTP.
  2. Keep the screen on, wait until the target time (NTP-corrected clock).
  3. Tap the button N times, verifying every tap actually got injected.
  4. Restore the original screen settings, even on Ctrl+C or errors.

Exit codes: 0 ok, 1 runtime error, 2 audit failed, 130 interrupted.
"""

from __future__ import annotations

# single-file script on purpose: easy to download and run
# pylint: disable=too-many-lines

import argparse
import logging
import math
import re
import statistics
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from xml.etree import ElementTree as ET

import ntplib
import adbutils
from adbutils.errors import AdbError

log = logging.getLogger("miunlock")

APP_PACKAGE = "com.mi.global.bbs"
BUTTON_TEXT = "Apply for unlocking"
BUTTON_RESOURCE_ID = "com.mi.global.bbs:id/btnApply"

BEIJING_OFFSET = timedelta(hours=8)
# Send moment = target + margin - compensation. A request that reaches the server before
# 00:00:00 CST counts for the previous day (quota used up) and blocks the next one for a
# minute, so every error must make it late, never early: only measured delays are
# compensated (by their minimum), unmeasured ones count as 0.
DEFAULT_MARGIN_MS = 150          # fixed mode, and the fallback without a measurement
DEFAULT_ADAPTIVE_MARGIN_MS = 50  # covers NTP error, network asymmetry, faster-than-min taps
WIDE_SPREAD_MS = 100             # tap latency p95 - min above this is unreliable ...
WIDE_SPREAD_MARGIN_MS = 150      # ... and gets this margin
MIN_ARRIVAL_MS = 50              # guard: the request may never arrive before target + this
DEFAULT_PROBES = 20              # latency probes (taps on static text, never the button)
PROBE_GAP_SEC = 0.1
NTP_SERVER = "pool.ntp.org"
NTP_SAMPLES = 4

# /data/local/tmp is owned by the shell user; /sdcard is less reliable on newer Android
DEVICE_XML_PATH = "/data/local/tmp/miunlock_ui_dump.xml"
STAY_ON_KEY = "stay_on_while_plugged_in"
STAY_ON_ALL = "7"                # AC | USB | wireless
SCREEN_TIMEOUT_MAX = "2147483647"

ADBINPUT_PROP = "persist.security.adbinput"   # Xiaomi: "USB debugging (Security settings)"

HEARTBEAT_SEC = 60.0             # how often to re-check the device while waiting
NTP_RESYNC_SEC = 60.0            # re-query NTP this many seconds before a long wait ends
# Schedule relative to the target T. Taps into the app (always on static text, never the
# button) only happen before T-60 s; after that only checks without input and the real tap.
PROBE_START_SEC = 120.0          # in-app probes / latency measurement start at T-120 s ...
PROBE_END_SEC = 60.0             # ... and must be done by T-60 s
PROBE_MIN_SEC = 5.0              # no probes if less than this is left before T-60 s
FINAL_CHECK_SEC = 20.0           # last check (state + UI dump, no input) at T-20 s
PROBE_SAFETY_SEC = 2.0           # the last probe must start this long before T-60 s

MIN_CLICK_DELAY_SEC = 60.0       # the server accepts one unlock request per minute
DEFAULT_CLICK_DELAY_SEC = 61.0

EXIT_OK, EXIT_ERROR, EXIT_AUDIT, EXIT_INTERRUPTED = 0, 1, 2, 130

# Android prints exceptions from shell commands to stdout/stderr and often still exits 0
_EXCEPTION_RE = re.compile(r"(Exception|Error)( occurred|:)|Permission denial", re.IGNORECASE)
_SECURITY_RE = re.compile(
    r"SecurityException|INJECT_EVENTS|WRITE_SECURE_SETTINGS|Permission denial")
# Some builds drop a rejected injection silently and only log it. Note that HyperOS logs
# every injection as "MIUIInput: Input ... event injection from package" - not a denial.
_LOGCAT_DENIED_RE = re.compile(
    r"INJECT_EVENTS|Permission denied: injecting|injection (was )?(denied|failed|rejected)",
    re.IGNORECASE)
_DEVICE_TIME_RE = re.compile(r"\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}")
_PING_TIME_RE = re.compile(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms")
_HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.:-]*")

INJECT_HINT = """\
The shell user is not allowed to inject input (INJECT_EVENTS).
On Xiaomi / HyperOS this is controlled by a separate developer option:
  Settings -> Additional settings -> Developer options ->
  "USB debugging (Security settings)"  -> ON
Check: 'adb shell getprop persist.security.adbinput' must print 1.
Notes:
  * The toggle requires being signed in to a Mi account (and on many builds a SIM card
    inserted + mobile data / internet on while you flip it).
  * On HyperOS 2/3 (Android 15/16) it often resets after a reboot or an OTA, and some
    builds silently reset it after ~a few minutes if the Mi account check fails.
    Toggle it OFF and ON again, then unplug/replug USB and re-run with
    --dry-run --test-in 90.
  * Re-authorise the computer if prompted ("Revoke USB debugging authorisations" helps
    when the toggle seems ignored).
  * Other OEMs: look for "Disable permission monitoring" (ColorOS/realme/OnePlus)."""

SETTINGS_HINT = """\
The shell user cannot write system settings (WRITE_SECURE_SETTINGS). The script can
still run, but the screen may turn off before the target time: set the screen timeout
to the maximum manually and keep the device plugged in."""


class DeviceError(RuntimeError):
    """ADB / device level failure (disconnect, timeout, unexpected shell output)."""


class PermissionDenied(DeviceError):
    """The device refused a shell command because of a missing permission."""


# --------------------------------------------------------------------------- ADB layer

@dataclass
class ShellResult:
    """Result of an adb shell command (exit code + combined output)."""
    cmd: str
    returncode: int
    output: str

    @property
    def ok(self) -> bool:
        """True if the command exited 0 and printed no exception."""
        return self.returncode == 0 and not _EXCEPTION_RE.search(self.output)

    @property
    def security_denied(self) -> bool:
        """True if the output mentions a missing permission."""
        return bool(_SECURITY_RE.search(self.output))

    def first_line_of_error(self) -> str:
        """Most relevant error line for logging."""
        lines = self.output.splitlines()
        # prefer the actual exception ("java.lang.SecurityException: ...") over the header
        for line in lines:
            if _SECURITY_RE.search(line) and "occurred while" not in line:
                return line.strip()[:200]
        for line in lines:
            if _EXCEPTION_RE.search(line):
                return line.strip()
        if self.output.strip():
            return self.output.strip().splitlines()[0]
        return f"exit code {self.returncode}"


class Device:
    """Thin wrapper over adbutils that never lets raw adbutils/socket errors escape."""

    def __init__(self, adb_device: adbutils.AdbDevice) -> None:
        self._dev = adb_device
        self.serial = adb_device.serial

    def run(self, cmd: str, timeout: float = 30.0) -> ShellResult:
        """Runs a shell command; raises DeviceError only on transport failures."""
        try:
            ret = self._dev.shell2(cmd, timeout=timeout, rstrip=True)
        except (AdbError, OSError) as exc:
            raise DeviceError(f"adb shell '{cmd}' failed: {exc}") from exc
        return ShellResult(cmd, ret.returncode, ret.output or "")

    def check(self, cmd: str, timeout: float = 30.0) -> str:
        """Runs a command and raises if it failed. Returns stripped output."""
        res = self.run(cmd, timeout)
        if res.ok:
            return res.output.strip()
        if res.security_denied:
            raise PermissionDenied(f"'{cmd}': {res.first_line_of_error()}")
        raise DeviceError(f"'{cmd}': {res.first_line_of_error()}")

    def getprop(self, name: str) -> str:
        """Returns a system property ('' if unavailable)."""
        try:
            return self.check(f"getprop {name}", timeout=10)
        except DeviceError:
            return ""

    def is_alive(self) -> bool:
        """True if the shell responds."""
        try:
            return self.run("echo ok", timeout=5).output.strip() == "ok"
        except DeviceError:
            return False


def connect_device(serial: str | None) -> Device:
    """Finds exactly one usable device, with readable errors for every bad state."""
    client = adbutils.AdbClient(host="127.0.0.1", port=5037)
    try:
        client.server_version()
        infos = client.list()
    except (AdbError, OSError) as exc:
        raise DeviceError(
            f"ADB server is not reachable ({exc}). Start it with 'adb start-server'."
        ) from exc

    if serial:
        infos = [i for i in infos if i.serial == serial]
        if not infos:
            raise DeviceError(f"Device '{serial}' not found. Check 'adb devices'.")

    if not infos:
        raise DeviceError("No devices found. Connect the phone and enable USB debugging.")

    bad_states = {
        "unauthorized": "confirm the 'Allow USB debugging?' prompt on the phone",
        "offline": "replug the cable or run 'adb kill-server'",
        "recovery": "boot the phone into Android",
        "bootloader": "boot the phone into Android",
    }
    ready = [i for i in infos if i.state == "device"]
    for info in infos:
        if info.state != "device":
            hint = bad_states.get(info.state, "check the connection")
            log.warning("Device %s is in state '%s' - %s", info.serial, info.state, hint)

    if not ready:
        raise DeviceError("No device in a usable state (see warnings above).")
    if len(ready) > 1:
        serials = ", ".join(i.serial for i in ready)
        raise DeviceError(f"Several devices connected ({serials}). Pick one with --serial.")

    return Device(client.device(serial=ready[0].serial))


# --------------------------------------------------------------------------- clock

class Clock:
    """
    NTP-corrected wall clock. NTP is queried at startup and once more shortly before
    the target (several samples each time), never in a loop.
    """

    def __init__(self, server: str, use_ntp: bool = True) -> None:
        self.server = server
        self.offset = 0.0            # seconds to add to time.time()
        self.synced = False
        if use_ntp:
            self.sync()

    def sync(self) -> None:
        """Measures the local clock offset against NTP (best of several samples)."""
        client = ntplib.NTPClient()
        samples: list[tuple[float, float]] = []   # (delay, offset)
        errors: list[str] = []
        for _ in range(NTP_SAMPLES):
            try:
                resp = client.request(self.server, version=3, timeout=2)
                samples.append((resp.delay, resp.offset))
            except (ntplib.NTPException, OSError) as exc:
                errors.append(str(exc))
            time.sleep(0.2)
        if not samples:
            if self.synced:
                log.warning("NTP %s resync failed (%s) - keeping offset %+.3f s.",
                            self.server, errors[-1] if errors else "?", self.offset)
                return
            log.warning("NTP %s unreachable (%s) - using the local clock.",
                        self.server, errors[-1] if errors else "?")
            self.synced = False
            return
        # the sample with the smallest round-trip is the most accurate one
        delay, offset = min(samples)
        self.offset, self.synced = offset, True
        log.info("NTP %s: local clock offset %+.3f s (rtt %.0f ms, %d/%d samples)",
                 self.server, offset, delay * 1000, len(samples), NTP_SAMPLES)

    def now(self) -> datetime:
        """Current NTP-corrected time in UTC."""
        return datetime.fromtimestamp(time.time() + self.offset, tz=timezone.utc)


def next_occurrence(time_str: str, now_utc: datetime, tz_offset: timedelta) -> datetime:
    """Next moment (UTC) when the wall clock in `tz_offset` shows `time_str`."""
    tz = timezone(tz_offset)
    local_now = now_utc.astimezone(tz)
    t = parse_time(time_str)
    if t is None:
        raise ValueError(f"bad time '{time_str}'")
    target = datetime.combine(local_now.date(), t, tzinfo=tz)
    if target <= local_now:
        target += timedelta(days=1)
    return target.astimezone(timezone.utc)


def parse_time(value: str):
    """Parses HH:MM[:SS[.fff]], returns None if invalid."""
    for fmt in ("%H:%M:%S.%f", "%H:%M:%S", "%H:%M"):
        try:
            return datetime.strptime(value, fmt).time()
        except ValueError:
            continue
    return None


# --------------------------------------------------------------------------- UI

@dataclass
class Button:
    """Located unlock button: tap point, bounds and how it was matched."""
    x: int
    y: int
    bounds: str
    enabled: bool
    matched_by: str


_BOUNDS_RE = re.compile(r"\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]")


def _node_labels(node: ET.Element) -> tuple[str, str]:
    return node.get("text") or "", node.get("content-desc") or ""


def _match_exact(node: ET.Element, button_text: str, _resource_id: str) -> bool:
    return button_text in _node_labels(node)


def _match_substring(node: ET.Element, button_text: str, _resource_id: str) -> bool:
    wanted = button_text.casefold()
    return any(wanted in label.casefold() for label in _node_labels(node))


def _match_resource_id(node: ET.Element, _button_text: str, resource_id: str) -> bool:
    return node.get("resource-id") == resource_id


# tried in this order; the label ends up in Button.matched_by
_BUTTON_MATCHERS = (
    ("text", _match_exact),
    ("text~", _match_substring),
    ("resource-id", _match_resource_id),
)


def _button_from_node(node: ET.Element, matched_by: str) -> Button | None:
    """Button at the centre of the node, None if it has no visible bounds."""
    bounds = node.get("bounds") or ""
    m = _BOUNDS_RE.fullmatch(bounds)
    if not m:
        return None
    x1, y1, x2, y2 = map(int, m.groups())
    if x2 <= x1 or y2 <= y1:
        return None    # invisible / zero-size node
    return Button((x1 + x2) // 2, (y1 + y2) // 2, bounds,
                  node.get("enabled", "true") == "true", matched_by)


def find_button(xml_text: str, button_text: str, resource_id: str) -> Button | None:
    """Finds the button by exact text, then case-insensitive substring, then resource-id."""
    nodes = list(ET.fromstring(xml_text).iter("node"))
    for label, matches in _BUTTON_MATCHERS:
        for node in nodes:
            if not matches(node, button_text, resource_id):
                continue
            button = _button_from_node(node, label)
            if button is not None:
                return button
    return None


def _blocks_tap(node: ET.Element) -> bool:
    """True if tapping inside the node can trigger something."""
    return (any(node.get(attr) == "true"
                for attr in ("clickable", "long-clickable", "checkable"))
            or "EditText" in (node.get("class") or ""))


def _contains(bounds: str, x: int, y: int) -> bool:
    m = _BOUNDS_RE.fullmatch(bounds)
    if not m:
        return False
    x1, y1, x2, y2 = map(int, m.groups())
    return x1 <= x <= x2 and y1 <= y <= y2


def find_probe_target(xml_text: str, avoid: Button | None) -> Button | None:
    """
    Static text in the Mi Community window that a tap cannot activate: neither the node
    nor any of its ancestors is clickable, and it lies outside the unlock button.
    A tap there goes through the same window-owner permission check as the real tap.
    """
    def walk(node: ET.Element, blocked: bool) -> Button | None:
        blocked = blocked or _blocks_tap(node)
        if (not blocked and node.get("package") == APP_PACKAGE
                and (node.get("text") or "").strip()):
            target = _button_from_node(node, "probe")
            if target and not (avoid and _contains(avoid.bounds, target.x, target.y)):
                return target
        for child in node:
            found = walk(child, blocked)
            if found:
                return found
        return None
    return walk(ET.fromstring(xml_text), False)


def dump_ui(dev: Device, attempts: int = 3) -> str:
    """uiautomator dump with retries (it fails while animations are running)."""
    last_err = ""
    for attempt in range(1, attempts + 1):
        res = dev.run(f"uiautomator dump {DEVICE_XML_PATH}", timeout=40)
        if res.ok and "dumped to" in res.output.lower():
            xml = dev.run(f"cat {DEVICE_XML_PATH}", timeout=20).output
            dev.run(f"rm -f {DEVICE_XML_PATH}", timeout=10)
            if xml.lstrip().startswith("<?xml"):
                return xml
            last_err = "dump file is empty or not XML"
        else:
            last_err = res.first_line_of_error()
        log.debug("uiautomator dump attempt %d failed: %s", attempt, last_err)
        time.sleep(1.5)
    raise DeviceError(f"uiautomator dump failed: {last_err}")


def foreground_package(dev: Device) -> str:
    """Package of the focused window ('' if unknown)."""
    out = dev.run("dumpsys window | grep -E 'mCurrentFocus|mFocusedApp'", timeout=15).output
    # mCurrentFocus=Window{1a2b u0 com.mi.global.bbs/com.mi...Activity}
    # On the lock screen it is e.g. Window{... u0 NotificationShade} - no package, and
    # mFocusedApp would still name the app behind the keyguard, so it is only a fallback.
    m = re.search(r"mCurrentFocus=Window\{\S+ \S+ ([^}\s]+)\}", out)
    if m:
        return m.group(1).split("/", 1)[0]
    m = re.search(r"mFocusedApp=.*? ([\w.]+)/", out)
    return m.group(1) if m else ""


def screen_awake(dev: Device) -> bool | None:
    """True/False from dumpsys power, None if unknown."""
    out = dev.run("dumpsys power | grep -m1 mWakefulness=", timeout=15).output
    if "mWakefulness=" not in out:
        return None
    return "Awake" in out


# --------------------------------------------------------------------------- audit

class Status(Enum):
    """Audit check result level."""
    OK = "OK"
    INFO = "INFO"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass
class Check:
    """Single audit check line."""
    name: str
    status: Status
    detail: str = ""
    hint: str = ""


@dataclass
class AuditReport:
    """Collected audit checks plus facts the run needs (button, permissions)."""
    checks: list[Check] = field(default_factory=list)
    button: Button | None = None
    can_write_settings: bool = False
    can_inject: bool = False
    xiaomi: bool = False
    probe_target: Button | None = None

    def add(self, name: str, status: Status, detail: str = "", hint: str = "") -> Check:
        """Appends a check and returns it."""
        check = Check(name, status, detail, hint)
        self.checks.append(check)
        return check

    @property
    def failed(self) -> bool:
        """True if any check is FAIL."""
        return any(c.status is Status.FAIL for c in self.checks)

    def print(self) -> None:
        """Logs the report as a table with hints for WARN/FAIL items."""
        log.info("-" * 64)
        log.info("Preflight audit")
        log.info("-" * 64)
        for c in self.checks:
            line = f"[{c.status.value:4}] {c.name}"
            if c.detail:
                line += f": {c.detail}"
            level = {Status.FAIL: logging.ERROR, Status.WARN: logging.WARNING}.get(
                c.status, logging.INFO)
            log.log(level, line)
            if c.hint and c.status in (Status.FAIL, Status.WARN):
                for hint_line in c.hint.splitlines():
                    log.log(level, "         %s", hint_line)
        log.info("-" * 64)
        verdict = "FAILED - fix the items above" if self.failed else "passed"
        log.log(logging.ERROR if self.failed else logging.INFO, "Audit %s.", verdict)


@dataclass
class InjectProbe:
    """Outcome of an input injection probe."""
    result: ShellResult
    targeted: bool                 # True = tapped into the Mi Community window
    latency_ms: float = 0.0        # round-trip of the input command itself
    logcat_denial: str = ""        # logcat line reporting a rejected injection

    @property
    def ok(self) -> bool:
        """True if the event was accepted."""
        return self.result.ok and not self.logcat_denial

    @property
    def denied(self) -> bool:
        """True if the device reported a missing permission."""
        return self.result.security_denied or bool(self.logcat_denial)

    def error(self) -> str:
        """Most relevant error line for logging."""
        return self.logcat_denial or self.result.first_line_of_error()


def device_time(dev: Device) -> str:
    """Device clock in logcat -T format ('' if unknown)."""
    out = dev.run("date '+%m-%d %H:%M:%S.000'", timeout=10).output.strip()
    return out if _DEVICE_TIME_RE.fullmatch(out) else ""


def logcat_denial(dev: Device, since: str) -> str:
    """First logcat line since `since` that reports a rejected injection ('' if none)."""
    if not since:
        return ""
    out = dev.run(f"logcat -d -T '{since}'", timeout=20).output
    for line in out.splitlines():
        if _LOGCAT_DENIED_RE.search(line):
            return line.strip()[:200]
    return ""


def timed_run(dev: Device, cmd: str) -> tuple[ShellResult, float]:
    """Runs cmd, returns the result and its round-trip in ms."""
    t0 = time.perf_counter()
    res = dev.run(cmd, timeout=15)
    return res, (time.perf_counter() - t0) * 1000


def probe_input_injection(dev: Device, target: Button | None) -> InjectProbe:
    """
    Input injection probe. With a target (static text in the Mi Community window) the
    tap is checked exactly like the real one, then logcat is scanned for a silent denial.
    Without a target, fall back to KEYCODE_UNKNOWN / an off-screen tap: those reach no
    window, so on HyperOS they pass even when real taps are denied - not a proof.
    """
    if target is not None:
        since = device_time(dev)
        res, latency = timed_run(dev, f"input tap {target.x} {target.y}")
        time.sleep(0.3)    # let InputDispatcher deliver (and log) the event
        return InjectProbe(res, True, latency, logcat_denial(dev, since))
    res, latency = timed_run(dev, "input keyevent 0")
    if not (res.ok or res.security_denied):
        log.debug("keyevent probe inconclusive (%s), trying off-screen tap",
                  res.first_line_of_error())
        res, latency = timed_run(dev, "input tap -500 -500")
    return InjectProbe(res, False, latency)


def probe_settings_write(dev: Device) -> tuple[bool, str]:
    """Writes the current value back - proves WRITE_SECURE_SETTINGS without side effects."""
    cur = dev.run(f"settings get global {STAY_ON_KEY}", timeout=10)
    if not cur.ok:
        return False, cur.first_line_of_error()
    value = cur.output.strip()
    value = "0" if value in {"", "null"} else value
    res = dev.run(f"settings put global {STAY_ON_KEY} {value}", timeout=10)
    return res.ok, ("" if res.ok else res.first_line_of_error())


def _audit_device_info(dev: Device, rep: AuditReport) -> None:
    sdk = dev.getprop("ro.build.version.sdk")
    release = dev.getprop("ro.build.version.release")
    brand = dev.getprop("ro.product.manufacturer")
    model = dev.getprop("ro.product.model")
    hyperos = dev.getprop("ro.mi.os.version.name") or dev.getprop("ro.miui.ui.version.name")
    rep.add("Device", Status.INFO,
            f"{brand} {model} ({dev.serial}), Android {release} / SDK {sdk}"
            + (f", HyperOS/MIUI {hyperos}" if hyperos else ""))

    rep.xiaomi = brand.lower() in {"xiaomi", "redmi", "poco"}
    if brand and not rep.xiaomi:
        rep.add("Manufacturer", Status.WARN, f"'{brand}' is not Xiaomi",
                "Mi Community bootloader unlock only applies to Xiaomi devices.")

    region = dev.getprop("ro.product.mod_device")
    if region:
        rep.add("ROM (mod_device)", Status.INFO,
                region + ("" if "global" in region or "eea" in region
                          else "  <- China ROMs are not supported by this flow"))


def _audit_inject_probe(dev: Device, rep: AuditReport, name: str) -> None:
    probe = probe_input_injection(dev, rep.probe_target)
    rep.can_inject = probe.ok
    if probe.denied:
        rep.add(name, Status.FAIL, probe.error(), INJECT_HINT)
    elif not probe.ok:
        rep.add(name, Status.WARN, f"probe inconclusive: {probe.error()}",
                "Run 'adb shell input tap 1 1' manually to check.")
    elif probe.targeted:
        t = rep.probe_target
        rep.add(name, Status.OK,
                f"tap on static text at ({t.x}, {t.y}) in Mi Community accepted")
    else:
        rep.add(name, Status.WARN, "only an off-screen probe passed",
                "No static text to tap was found in the Mi Community window, so it is\n"
                + "not proven that taps reach the app. Check --save-dump.")
    rep.add("Input tap round-trip", Status.INFO, f"{probe.latency_ms:.0f} ms")


def _audit_permissions(dev: Device, rep: AuditReport, allow_probe: bool) -> None:
    name = "Input injection (INJECT_EVENTS)"
    if allow_probe:
        _audit_inject_probe(dev, rep, name)
    else:
        rep.can_inject = True     # only persist.security.adbinput below can veto it
        rep.add(name, Status.WARN, "probe skipped: the target is less than a minute away",
                "No input is injected in the last minute before the target except the\n"
                + "real tap. Start earlier (e.g. --test-in 90) to probe a tap into the app.")

    # On Xiaomi this property is the "USB debugging (Security settings)" toggle itself.
    # The probe above cannot be trusted on its own: events that reach no app window
    # pass even with the toggle off.
    adbinput = dev.getprop(ADBINPUT_PROP)
    if adbinput == "0" and rep.xiaomi:
        rep.can_inject = False
        rep.add(ADBINPUT_PROP, Status.FAIL, "0 (Security settings OFF)", INJECT_HINT)
    elif adbinput:
        state = "ON" if adbinput == "1" else "OFF"
        rep.add(ADBINPUT_PROP, Status.OK if adbinput == "1" else Status.INFO,
                f"{adbinput} (Security settings {state})")

    ok, err = probe_settings_write(dev)
    rep.can_write_settings = ok
    if ok:
        rep.add("Settings write (WRITE_SECURE_SETTINGS)", Status.OK, "screen can be kept on")
    else:
        rep.add("Settings write (WRITE_SECURE_SETTINGS)", Status.WARN, err, SETTINGS_HINT)


def _audit_screen(dev: Device, rep: AuditReport) -> None:
    awake = screen_awake(dev)
    if awake is False:
        rep.add("Screen", Status.FAIL, "screen is off",
                "Unlock the phone and open Mi Community -> Me -> Unlock bootloader.")
    elif awake:
        rep.add("Screen", Status.OK, "awake")

    pkg = foreground_package(dev)
    if pkg == APP_PACKAGE:
        rep.add("Mi Community in foreground", Status.OK, pkg)
    elif not pkg:
        # dumpsys output format differs between builds - do not block the run on it
        rep.add("Mi Community in foreground", Status.WARN,
                "could not detect the focused app",
                "Make sure Mi Community -> Me -> Unlock bootloader is on screen.")
    else:
        rep.add("Mi Community in foreground", Status.FAIL,
                f"focused app is '{pkg}'",
                "Open Mi Community -> Me -> Unlock bootloader and leave it on screen.")


def _audit_button(dev: Device, rep: AuditReport, button_text: str,
                  save_dump: str | None) -> None:
    try:
        xml = dump_ui(dev)
    except DeviceError as exc:
        rep.add("UI dump (uiautomator)", Status.FAIL, str(exc),
                "Make sure the screen is on and no system dialog covers the app.")
        return
    rep.add("UI dump (uiautomator)", Status.OK, f"{len(xml)} bytes")
    if save_dump:
        with open(save_dump, "w", encoding="utf-8") as fh:
            fh.write(xml)
        rep.add("UI dump saved", Status.INFO, save_dump)

    try:
        button = find_button(xml, button_text, BUTTON_RESOURCE_ID)
    except ET.ParseError as exc:
        rep.add("UI dump (uiautomator)", Status.FAIL, f"invalid XML: {exc}",
                "Re-run; if it persists, check the dump with --save-dump.")
        return
    if button is None:
        rep.add("Unlock button", Status.FAIL, f"'{button_text}' not found on screen",
                "Open the 'Unlock bootloader' page. If the app is not in English,\n"
                + "pass the button label with --button-text, or check --save-dump.")
        return
    rep.button = button
    rep.probe_target = find_probe_target(xml, button)
    if button.enabled:
        rep.add("Unlock button", Status.OK,
                f"({button.x}, {button.y}) bounds {button.bounds}, "
                f"matched by {button.matched_by}")
    else:
        rep.add("Unlock button", Status.WARN,
                f"({button.x}, {button.y}) bounds {button.bounds}, "
                f"matched by {button.matched_by}, currently DISABLED",
                "The button is greyed out now; it may get enabled at reset time.")


def _audit_clock(clock: Clock, rep: AuditReport, no_ntp: bool) -> None:
    if clock.synced:
        status = Status.OK if abs(clock.offset) < 2 else Status.WARN
        rep.add("Clock", status, f"NTP offset {clock.offset:+.3f} s",
                "Your PC clock is off - the NTP correction is applied anyway.")
    elif no_ntp:
        rep.add("Clock", Status.WARN, "NTP disabled (--no-ntp), local clock used")
    else:
        rep.add("Clock", Status.WARN, f"NTP {clock.server} unreachable, local clock used",
                "Try --ntp-server time.google.com, or sync the PC clock.")


def _audit_latency(dev: Device, rep: AuditReport) -> None:
    rtts = []
    for _ in range(5):
        t0 = time.perf_counter()
        if dev.is_alive():
            rtts.append(time.perf_counter() - t0)
    if rtts:
        rep.add("ADB latency", Status.INFO, f"median {statistics.median(rtts) * 1000:.0f} ms")


def run_audit(dev: Device, clock: Clock, args, allow_probe: bool = True) -> AuditReport:
    """
    Runs all preflight checks without changing anything on the device.
    allow_probe=False skips the in-app tap probe (the target is less than a minute away).
    """
    rep = AuditReport()
    _audit_device_info(dev, rep)

    if not dev.is_alive():
        rep.add("ADB shell", Status.FAIL, "shell does not respond", "Replug USB, re-run.")
        return rep
    rep.add("ADB shell", Status.OK, "responds")

    # the UI dump comes first: the injection probe taps static text found in it
    _audit_screen(dev, rep)
    _audit_button(dev, rep, args.button_text, args.save_dump)
    _audit_permissions(dev, rep, allow_probe)
    _audit_clock(clock, rep, args.no_ntp)
    _audit_latency(dev, rep)
    return rep


# --------------------------------------------------------------------------- timing

@dataclass
class LatencyStats:
    """Latency samples in ms."""
    samples: list[float]

    @property
    def min(self) -> float:
        """Smallest sample - the only safe value to compensate by."""
        return min(self.samples)

    @property
    def median(self) -> float:
        """Median sample."""
        return statistics.median(self.samples)

    @property
    def p95(self) -> float:
        """95th percentile (nearest rank)."""
        ordered = sorted(self.samples)
        return ordered[math.ceil(0.95 * len(ordered)) - 1]

    def describe(self) -> str:
        """min / median / p95 for the log."""
        return (f"min {self.min:.0f} / median {self.median:.0f} / p95 {self.p95:.0f} ms "
                f"(n={len(self.samples)})")


@dataclass
class Measurement:
    """Measured delays: input tap round-trip, optionally the network RTT to the API host."""
    click: LatencyStats
    net: LatencyStats | None = None


def measure_click_latency(dev: Device, target: Button, clock: Clock, deadline: datetime,
                          count: int) -> tuple[list[float], str]:
    """
    Times `count` taps on static text of the Mi Community window (never the button),
    stopping at `deadline`. Returns the round-trips in ms and a denial ('' if none).
    """
    since = device_time(dev)
    samples: list[float] = []
    for _ in range(count):
        if clock.now() >= deadline:
            log.warning("Latency probes stopped by the deadline after %d/%d.",
                        len(samples), count)
            break
        res, latency = timed_run(dev, f"input tap {target.x} {target.y}")
        if res.security_denied:
            return samples, res.first_line_of_error()
        if res.ok:
            samples.append(latency)
        else:
            log.debug("Latency probe failed: %s", res.first_line_of_error())
        time.sleep(PROBE_GAP_SEC)
    time.sleep(0.3)    # let InputDispatcher deliver (and log) the last event
    return samples, logcat_denial(dev, since)


def measure_network_rtt(dev: Device, host: str, count: int, budget_sec: float) -> list[float]:
    """RTTs in ms of `ping` from the phone to host ([] if ping is unavailable)."""
    deadline = max(1, int(budget_sec))
    try:
        res = dev.run(f"ping -c {count} -i 0.2 -W 1 -w {deadline} {host}",
                      timeout=deadline + 5)
    except DeviceError as exc:
        log.debug("ping failed: %s", exc)
        return []
    samples = [float(m) for m in _PING_TIME_RE.findall(res.output)]
    if not samples:
        log.debug("ping output: %s", res.output.strip()[:200])
    return samples


@dataclass
class TimingPlan:
    """When to send the tap: target + margin - compensation."""
    mode: str                       # "adaptive" or "fixed"
    margin_ms: int
    source: str
    click: LatencyStats | None = None
    net: LatencyStats | None = None

    @property
    def compensation_ms(self) -> int:
        """Measured delays only, by their minimum; rounded down (later is safe)."""
        if self.mode != "adaptive" or self.click is None:
            return 0
        net = self.net.min / 2 if self.net else 0.0
        return math.floor(self.click.min + net)

    def send_time(self, target_utc: datetime) -> datetime:
        """Moment to run the input command."""
        return target_utc + timedelta(milliseconds=self.margin_ms - self.compensation_ms)

    def earliest_arrival(self, target_utc: datetime) -> datetime:
        """Lower bound of when the request reaches the server."""
        return self.send_time(target_utc) + timedelta(milliseconds=self.compensation_ms)


def plan_timing(args, tap: LatencyStats | None, net: LatencyStats | None,
                source: str) -> TimingPlan:
    """Picks the margin and compensation for --timing."""
    if args.timing == "fixed":
        return TimingPlan("fixed", args.margin_ms, "--timing fixed")
    if tap is None:
        log.warning("Latency estimate impossible - using the standard margin of %d ms.",
                    args.margin_ms)
        return TimingPlan("fixed", args.margin_ms, "no latency estimate")
    margin = args.adaptive_margin_ms
    spread = tap.p95 - tap.min
    if spread > WIDE_SPREAD_MS:
        margin = max(margin, WIDE_SPREAD_MARGIN_MS)
        log.warning("Tap latency varies a lot (p95 - min = %.0f ms > %d ms) - margin %d ms.",
                    spread, WIDE_SPREAD_MS, margin)
    return TimingPlan("adaptive", margin, source, tap, net)


def checked_send_time(plan: TimingPlan, target_utc: datetime) -> tuple[TimingPlan, datetime]:
    """
    Guard against a false start: the request may never arrive before target + 50 ms.
    A plan that breaks it is a calculation error - fall back to the fixed margin.
    """
    floor = target_utc + timedelta(milliseconds=MIN_ARRIVAL_MS)
    if plan.compensation_ms < 0 or plan.earliest_arrival(target_utc) < floor:
        log.error("Timing guard: the request could arrive at %s CST, before %s CST - "
                  + "falling back to fixed timing with a %d ms margin.",
                  fmt_time(plan.earliest_arrival(target_utc), BEIJING_OFFSET),
                  fmt_time(floor, BEIJING_OFFSET), DEFAULT_MARGIN_MS)
        plan = TimingPlan("fixed", DEFAULT_MARGIN_MS, "guard fallback")
    return plan, plan.send_time(target_utc)


def fmt_time(moment: datetime, offset: timedelta | None = None) -> str:
    """HH:MM:SS.fff in the given UTC offset (None = local time)."""
    tz = timezone(offset) if offset is not None else None
    return moment.astimezone(tz).strftime("%H:%M:%S.%f")[:-3]


def log_plan(plan: TimingPlan, target_utc: datetime, send_utc: datetime,
             api_host: str | None) -> None:
    """Logs the chosen timing and where the numbers come from."""
    log.info("Timing: %s (%s)", plan.mode, plan.source)
    if plan.click:
        log.info("  tap latency: %s", plan.click.describe())
    if plan.net:
        log.info("  network RTT to %s: %s (half of min compensated)", api_host,
                 plan.net.describe())
    log.info("  compensation %d ms, margin %d ms", plan.compensation_ms, plan.margin_ms)
    log.info("  send at %s CST / %s local", fmt_time(send_utc, BEIJING_OFFSET),
             fmt_time(send_utc))
    log.info("  request reaches the server no earlier than %s CST",
             fmt_time(plan.earliest_arrival(target_utc), BEIJING_OFFSET))


# --------------------------------------------------------------------------- session

class ScreenKeeper:
    """Keeps the screen on for the session and restores the exact original values."""

    def __init__(self, dev: Device, can_write: bool) -> None:
        self.dev = dev
        self.can_write = can_write
        self.saved: dict[str, str] = {}

    def __enter__(self) -> "ScreenKeeper":
        if not self.can_write:
            log.warning("Cannot change screen settings - keep the screen on manually.")
            return self
        for ns, key in (("global", STAY_ON_KEY), ("system", "screen_off_timeout")):
            val = self.dev.run(f"settings get {ns} {key}", timeout=10).output.strip()
            self.saved[f"{ns}/{key}"] = val
        try:
            self.dev.check(f"settings put global {STAY_ON_KEY} {STAY_ON_ALL}", timeout=10)
            self.dev.check(f"settings put system screen_off_timeout {SCREEN_TIMEOUT_MAX}",
                           timeout=10)
            log.info("Screen kept on (saved: %s).", self.saved)
        except DeviceError as exc:
            log.warning("Could not keep the screen on: %s", exc)
        return self

    def __exit__(self, *_exc) -> None:
        for ns_key, val in self.saved.items():
            ns, key = ns_key.split("/", 1)
            cmd = (f"settings delete {ns} {key}" if val in {"", "null"}
                   else f"settings put {ns} {key} {val}")
            try:
                self.dev.check(cmd, timeout=10)
            except DeviceError as exc:
                log.error("Could not restore %s=%s: %s. Restore it manually.", ns_key, val, exc)
        if self.saved:
            log.info("Screen settings restored.")


NOT_RESPONDING = "device is not responding over ADB"
INJECT_OFF = (f"{ADBINPUT_PROP}=0: 'USB debugging (Security settings)' is OFF, "
              "taps will be rejected - turn it on again")


def health_check(dev: Device) -> list[str]:
    """Problems found right now (empty list = all good). Cheap, no input injected."""
    if not dev.is_alive():
        return [NOT_RESPONDING]
    problems = []
    if dev.getprop(ADBINPUT_PROP) == "0":
        problems.append(INJECT_OFF)
    if dev.run("settings get global adb_enabled", timeout=10).output.strip() == "0":
        problems.append("USB debugging (adb_enabled) is off")
    if screen_awake(dev) is False:
        problems.append("screen is off")
    pkg = foreground_package(dev)
    if pkg and pkg != APP_PACKAGE:
        problems.append(f"Mi Community is not in foreground (focused: {pkg})")
    return problems


def final_check(dev: Device, button_text: str, button: Button,
                need_inject: bool) -> tuple[Button, str]:
    """
    Last check before firing: device state and a fresh UI dump (the app may have
    restarted or scrolled since the audit). Injects no input - it runs in the last
    minute before the target. Returns the button to tap and the UI dump ('' if it failed).
    Raises DeviceError if tapping is certain to fail.
    """
    problems = health_check(dev)
    for p in problems:
        log.error("Final check: %s", p)
    if NOT_RESPONDING in problems or (need_inject and INJECT_OFF in problems):
        raise DeviceError("device not ready for clicking: " + "; ".join(problems))

    try:
        xml = dump_ui(dev, attempts=2)
        fresh = find_button(xml, button_text, BUTTON_RESOURCE_ID)
    except (DeviceError, ET.ParseError) as exc:
        log.error("Final check: UI dump failed (%s) - tapping the audited coordinates.", exc)
        return button, ""
    if fresh is None:
        log.error("Final check: '%s' is not on screen - tapping the audited coordinates.",
                  button_text)
        return button, xml
    if (fresh.x, fresh.y) != (button.x, button.y):
        log.warning("Final check: the button moved from (%d, %d) to (%d, %d).",
                    button.x, button.y, fresh.x, fresh.y)
    log.info("Final check passed: button at (%d, %d).", fresh.x, fresh.y)
    return fresh, xml


@dataclass
class Session:
    """What the steps after the audit share."""
    dev: Device
    clock: Clock
    args: argparse.Namespace
    target_utc: datetime            # quota reset (00:00:00 CST or the test target)
    measure: bool                   # measure the latency in the probe window


def probe_phase(ses: Session, button: Button) -> Measurement | None:
    """
    In-app probes in the T-120..T-60 s window: taps on static text of the Mi Community
    window (never the button), then logcat is scanned for a silent denial. With
    measure=True they are timed (--probes of them) and the API host is pinged.
    Raises DeviceError if the device rejects them and a real tap will follow.
    """
    dev, args, measure = ses.dev, ses.args, ses.measure
    try:
        xml = dump_ui(dev, attempts=2)
        target = find_probe_target(
            xml, find_button(xml, args.button_text, BUTTON_RESOURCE_ID) or button)
    except (DeviceError, ET.ParseError) as exc:
        log.warning("Probe: UI dump failed (%s) - no in-app probe.", exc)
        return None
    if target is None:
        log.warning("Probe: no static text to tap in the Mi Community window.")
        return None

    deadline = ses.target_utc - timedelta(seconds=PROBE_END_SEC + PROBE_SAFETY_SEC)
    samples, denial = measure_click_latency(dev, target, ses.clock, deadline,
                                            args.probes if measure else 1)
    if denial:
        msg = f"input injection is denied: {denial}"
        if not args.dry_run:
            raise DeviceError("device not ready for clicking: " + msg)
        log.error("Probe: %s", msg)
        return None
    if not measure:
        if samples:
            log.info("Probe: in-app tap on static text accepted (%.0f ms).", samples[0])
        else:
            log.warning("Probe inconclusive: the in-app tap failed.")
        return None

    needed = max(3, args.probes // 2)
    if len(samples) < needed:
        log.warning("Latency measurement inconclusive: %d/%d probes succeeded (need %d).",
                    len(samples), args.probes, needed)
        return None
    tap = LatencyStats(samples)
    log.info("Tap latency measured: %s", tap.describe())
    return Measurement(tap, _probe_network(ses, deadline) if args.api_host else None)


def _probe_network(ses: Session, deadline: datetime) -> LatencyStats | None:
    """Pings --api-host from the phone until the deadline; None if not possible."""
    host = ses.args.api_host
    budget = (deadline - ses.clock.now()).total_seconds()
    rtts = measure_network_rtt(ses.dev, host, ses.args.probes, budget) if budget >= 2 else []
    if not rtts:
        log.warning("ping %s from the phone is not available - the network delay "
                    + "is not compensated.", host)
        return None
    net = LatencyStats(rtts)
    log.info("Network RTT to %s measured: %s", host, net.describe())
    return net


def wait_until(target_utc: datetime, clock: Clock, dev: Device, quiet: bool = False) -> None:
    """
    Sleeps until target, with periodic device health checks and a precise final spin.
    quiet=True: no health checks and no NTP resync (used in the last minute).
    """
    remaining = (target_utc - clock.now()).total_seconds()
    log.info("Waiting %s until %s UTC.", timedelta(seconds=int(remaining)),
             target_utc.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3])

    # one more NTP sync before firing: the PC clock may drift or get adjusted by the OS
    # during a wait of several hours; skipped for short waits (the startup sync is fresh)
    resync_pending = not quiet and clock.synced and remaining > NTP_RESYNC_SEC + 30
    next_heartbeat = time.monotonic() + HEARTBEAT_SEC
    while True:
        remaining = (target_utc - clock.now()).total_seconds()
        if remaining <= 0:
            return

        if resync_pending and remaining <= NTP_RESYNC_SEC:
            resync_pending = False
            clock.sync()
            continue

        if not quiet and time.monotonic() >= next_heartbeat and remaining > 5:
            next_heartbeat = time.monotonic() + HEARTBEAT_SEC
            for p in health_check(dev):
                log.log(logging.ERROR if p == INJECT_OFF else logging.WARNING,
                        "Heartbeat: %s", p)
            log.info("%s remaining.", timedelta(seconds=int(remaining)))

        if remaining > 2:
            time.sleep(min(remaining - 2, 1.0))
        elif remaining > 0.05:
            time.sleep(remaining - 0.05)
        else:
            pass  # busy-wait the last 50 ms for precision


def screen_texts(xml: str) -> list[str]:
    """Visible texts of the Mi Community window (system UI such as the clock left out)."""
    return [n.get("text") for n in ET.fromstring(xml).iter("node")
            if n.get("text") and n.get("package", APP_PACKAGE) == APP_PACKAGE]


def verify_after_tap(dev: Device, button: Button, button_text: str,
                     xml_before: str, since: str) -> bool:
    """
    Checks that the taps had an effect. False if the device rejected them (logcat).
    An unchanged screen is only a warning: the request may still be on its way.
    """
    denial = logcat_denial(dev, since)
    if denial:
        log.error("The device rejected the taps: %s", denial)
        log.error(INJECT_HINT)
        return False
    try:
        xml_after = dump_ui(dev, attempts=1)
        after = screen_texts(xml_after)
        before = screen_texts(xml_before) if xml_before else []
        fresh = find_button(xml_after, button_text, BUTTON_RESOURCE_ID)
    except (DeviceError, ET.ParseError) as exc:
        log.warning("Could not check the screen after tapping: %s", exc)
        return True
    new = [t for t in after if t not in before]
    if new:
        log.info("New on screen: %s", " | ".join(new[:15]))
    if not xml_before:
        return True
    if new or fresh is None or fresh.enabled != button.enabled:
        log.info("Screen changed after tapping.")
    else:
        log.warning("Screen unchanged after tapping - the taps may have been dropped. "
                    "Check the phone.")
    return True


def click(dev: Device, button: Button, clock: Clock, args) -> int:
    """Taps args.clicks times. Returns the number of taps injected successfully."""
    cmd = f"input tap {button.x} {button.y}"
    count = args.clicks
    done = 0
    for i in range(1, count + 1):
        stamp = clock.now().astimezone(timezone(BEIJING_OFFSET)).strftime("%H:%M:%S.%f")[:-3]
        if args.dry_run:
            log.info("[DRY-RUN] tap %d/%d at %s CST: would run '%s'", i, count, stamp, cmd)
            done += 1
        else:
            try:
                res, latency = timed_run(dev, cmd)
            except DeviceError as exc:
                log.error("Tap %d/%d failed: %s", i, count, exc)
            else:
                if res.ok:
                    done += 1
                    # the stamp is taken before sending; the event lands up to `latency` later
                    log.info("Tap %d/%d sent at %s CST, input returned after %.0f ms.",
                             i, count, stamp, latency)
                else:
                    log.error("Tap %d/%d rejected: %s", i, count, res.first_line_of_error())
                    if res.security_denied:
                        log.error(INJECT_HINT)
                        break   # further taps will fail the same way
        if i < count:
            time.sleep(args.delay)
    return done


# --------------------------------------------------------------------------- CLI

def build_parser() -> argparse.ArgumentParser:
    """Command line interface."""
    p = argparse.ArgumentParser(
        description="Automate the Mi Community unlock request at 00:00 Beijing time via ADB.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  automate.py --dry-run --test-in 90  check setup, rehearse in 90 s, no real tap\n"
               "  automate.py --dry-run --test-in 150 same, including the latency measurement\n"
               "  automate.py --test-in 30            real tap in 30 s (sends a request!)\n"
               "  automate.py                         real run at 00:00 CST\n")
    p.add_argument("--clicks", type=int, default=1, help="number of taps (default: 1)")
    p.add_argument("--delay", type=float, default=DEFAULT_CLICK_DELAY_SEC,
                   help="seconds between taps if --clicks > 1, at least "
                        f"{MIN_CLICK_DELAY_SEC:g}: the server accepts one request per minute "
                        f"(default: {DEFAULT_CLICK_DELAY_SEC:g})")
    p.add_argument("--lead-ms", type=int, help=argparse.SUPPRESS)    # deprecated, ignored
    p.add_argument("--serial", help="device serial if several devices are connected")
    p.add_argument("--button-text", default=BUTTON_TEXT,
                   help=f"button label to look for (default: '{BUTTON_TEXT}')")
    p.add_argument("--ntp-server", default=NTP_SERVER, help=f"default: {NTP_SERVER}")
    p.add_argument("--no-ntp", action="store_true", help="use the local clock only")

    t = p.add_argument_group(
        "timing", "send = 00:00:00 CST + margin - measured delays (never earlier than "
                  + f"00:00:00 + {MIN_ARRIVAL_MS} ms on the server)")
    t.add_argument("--timing", choices=("adaptive", "fixed"), default="adaptive",
                   help="adaptive: compensate the measured tap latency (and the network "
                        "delay with --api-host); fixed: no compensation (default: adaptive)")
    t.add_argument("--margin-ms", type=int, default=DEFAULT_MARGIN_MS,
                   help="margin of fixed timing and of the fallback without a latency "
                        f"estimate (default: {DEFAULT_MARGIN_MS})")
    t.add_argument("--adaptive-margin-ms", type=int, default=DEFAULT_ADAPTIVE_MARGIN_MS,
                   help=f"margin of adaptive timing (default: {DEFAULT_ADAPTIVE_MARGIN_MS}; "
                        f"{WIDE_SPREAD_MARGIN_MS} if the latency varies a lot)")
    t.add_argument("--probes", type=int, default=DEFAULT_PROBES,
                   help="latency probes: taps on static text, never the button, between "
                        f"T-120 s and T-60 s (default: {DEFAULT_PROBES})")
    t.add_argument("--api-host", metavar="HOST",
                   help="also ping HOST from the phone and compensate half of the minimal "
                        "RTT (default: off, the network delay is not compensated)")

    g = p.add_argument_group("testing")
    g.add_argument("--dry-run", action="store_true",
                   help="do everything (audit, screen-on, wait) but do not tap")
    g.add_argument("--force", action="store_true",
                   help="continue even if the audit has FAIL items (not recommended)")
    g.add_argument("--test", action="store_true",
                   help="use --test-time/--test-timezone instead of 00:00 CST")
    g.add_argument("--test-time", help="HH:MM[:SS[.fff]] target for --test")
    g.add_argument("--test-timezone", type=float,
                   help="UTC offset in hours for --test-time (e.g. 3 or 5.5)")
    g.add_argument("--test-in", type=float, metavar="SEC",
                   help="target = now + SEC seconds (implies --test)")
    g.add_argument("--save-dump", metavar="FILE", help="save the UI dump XML to FILE")
    g.add_argument("--log-file", metavar="FILE", help="also write the full log to FILE")
    g.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    return p


def validate_args(p: argparse.ArgumentParser, args) -> None:
    """Validates argument combinations; exits via p.error() on bad input."""
    if args.clicks < 1:
        p.error("--clicks must be >= 1")
    if args.clicks > 1 and args.delay < MIN_CLICK_DELAY_SEC:
        p.error(f"--delay must be at least {MIN_CLICK_DELAY_SEC:g} s with --clicks > 1: "
                "the server accepts one unlock request per minute, a faster repeat is "
                "wasted and may hit the dialog opened by the first tap")
    if args.margin_ms < 0 or args.adaptive_margin_ms < 0:
        p.error("--margin-ms and --adaptive-margin-ms must be >= 0: sending before 00:00 "
                "makes the request count for the previous day")
    if not 3 <= args.probes <= 100:
        p.error("--probes must be between 3 and 100")
    if args.api_host is not None and not _HOST_RE.fullmatch(args.api_host):
        p.error("--api-host must be a host name or an IP address")
    if args.test_in is not None:
        if args.test_in < 5:
            p.error("--test-in must be at least 5 seconds")
        args.test = True
    elif args.test:
        if args.test_time is None or args.test_timezone is None:
            p.error("--test needs --test-time and --test-timezone (or use --test-in SEC)")
        if parse_time(args.test_time) is None:
            p.error("--test-time must be HH:MM, HH:MM:SS or HH:MM:SS.fff")
        if not -12 <= args.test_timezone <= 14:
            p.error("--test-timezone must be between -12 and 14")


def setup_logging(verbose: bool, log_file: str | None) -> None:
    """Console logging (INFO or DEBUG) plus an optional DEBUG log file."""
    fmt = logging.Formatter("%(asctime)s.%(msecs)03d %(levelname)-7s %(message)s", "%H:%M:%S")
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(fmt)
    root.addHandler(console)
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        root.addHandler(fh)
    logging.getLogger("adbutils").setLevel(logging.WARNING)


def compute_target(args, clock: Clock) -> tuple[datetime, str]:
    """Target moment (quota reset, before any margin) in UTC and a description of it."""
    now = clock.now()
    if args.test_in is not None:
        return now + timedelta(seconds=args.test_in), f"test: now + {args.test_in:g} s"
    if args.test:
        tz = timedelta(hours=args.test_timezone)
        target = next_occurrence(args.test_time, now, tz)
        return target, f"test: {args.test_time} @ UTC{args.test_timezone:+g}"
    return next_occurrence("00:00:00", now, BEIJING_OFFSET), "live: 00:00:00 CST"


def run(args) -> int:
    """Audit, wait, tap. Returns the process exit code."""
    mode = "DRY-RUN" if args.dry_run else "LIVE"
    if args.test:
        mode += " + TEST TIME"
    log.info("Mode: %s", mode)
    if args.lead_ms is not None:
        log.warning("--lead-ms is deprecated and ignored: sending before 00:00 makes the "
                    "request count for the previous day; use --timing / --margin-ms.")

    dev = connect_device(args.serial)
    log.info("Connected to %s", dev.serial)
    clock = Clock(args.ntp_server, use_ntp=not args.no_ntp)

    target_utc, label = compute_target(args, clock)
    remaining = (target_utc - clock.now()).total_seconds()
    can_probe = remaining > PROBE_END_SEC + PROBE_MIN_SEC     # no in-app taps after T-60 s
    measure = args.timing == "adaptive" and remaining >= PROBE_START_SEC
    report = run_audit(dev, clock, args, allow_probe=can_probe)
    report.print()

    if report.failed:
        if not args.force:
            log.error("Fix the FAIL items (or use --force). Nothing was changed on the device.")
            return EXIT_AUDIT
        log.warning("--force: continuing despite audit failures.")
    if report.button is None:
        log.error("Cannot continue without button coordinates.")
        return EXIT_AUDIT
    if not report.can_inject and not args.dry_run and not args.force:
        log.error("Input injection is not confirmed working - refusing to wait for nothing.")
        return EXIT_AUDIT

    cst = target_utc.astimezone(timezone(BEIJING_OFFSET))
    log.info("Target (%s): %s CST / %s local", label,
             cst.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
             target_utc.astimezone().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3])

    if args.timing == "adaptive" and not measure:
        log.warning("Started less than %d s before the target - no latency measurement.",
                    PROBE_START_SEC)

    with ScreenKeeper(dev, report.can_write_settings):
        done = fire(Session(dev, clock, args, target_utc, measure), report.button)
    return EXIT_OK if done == args.clicks else EXIT_ERROR


def fire(ses: Session, button: Button) -> int:
    """Probes, timing, final check, tap, verification. Returns the number of taps done."""
    dev, clock, args, target_utc = ses.dev, ses.clock, ses.args, ses.target_utc
    measured = None
    if (target_utc - clock.now()).total_seconds() > PROBE_END_SEC + PROBE_MIN_SEC:
        probe_at = target_utc - timedelta(seconds=PROBE_START_SEC)
        if probe_at > clock.now():
            wait_until(probe_at, clock, dev)
        measured = probe_phase(ses, button)
    plan = plan_timing(args, measured.click if measured else None,
                       measured.net if measured else None, "measured")
    plan, send_utc = checked_send_time(plan, target_utc)
    log_plan(plan, target_utc, send_utc, args.api_host)

    check_at = target_utc - timedelta(seconds=FINAL_CHECK_SEC)
    if check_at > clock.now():
        wait_until(check_at, clock, dev, quiet=True)
    button, xml_before = final_check(dev, args.button_text, button,
                                     need_inject=not args.dry_run)
    since = device_time(dev)    # logcat window for the post-tap denial check
    wait_until(send_utc, clock, dev, quiet=True)
    done = click(dev, button, clock, args)
    if not args.dry_run and done:
        log.info("Keeping the screen on for 5 s while the request loads...")
        time.sleep(5)
        if not verify_after_tap(dev, button, args.button_text, xml_before, since):
            done = 0
    if done == args.clicks:
        log.info("[SUCCESS] %d/%d taps %s.", done, args.clicks,
                 "simulated" if args.dry_run else "injected")
    else:
        log.error("[FAILED] only %d/%d taps were injected.", done, args.clicks)
    return done


def main() -> int:
    """Entry point: parses arguments and maps errors to exit codes."""
    parser = build_parser()
    args = parser.parse_args()
    validate_args(parser, args)
    setup_logging(args.verbose, args.log_file)
    try:
        return run(args)
    except KeyboardInterrupt:
        log.warning("Interrupted by user.")
        return EXIT_INTERRUPTED
    except DeviceError as exc:
        log.error("%s", exc)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
