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

import argparse
import logging
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
DEFAULT_LEAD_MS = 200            # fire 200 ms before 00:00:00 (= old 23:59:59.800)
NTP_SERVER = "pool.ntp.org"
NTP_SAMPLES = 4

# /data/local/tmp is owned by the shell user; /sdcard is less reliable on newer Android
DEVICE_XML_PATH = "/data/local/tmp/miunlock_ui_dump.xml"
STAY_ON_KEY = "stay_on_while_plugged_in"
STAY_ON_ALL = "7"                # AC | USB | wireless
SCREEN_TIMEOUT_MAX = "2147483647"

HEARTBEAT_SEC = 60.0             # how often to re-check the device while waiting
FINAL_CHECK_SEC = 20.0           # last full check this many seconds before firing
NTP_RESYNC_SEC = 60.0            # re-query NTP this many seconds before firing

EXIT_OK, EXIT_ERROR, EXIT_AUDIT, EXIT_INTERRUPTED = 0, 1, 2, 130

# Android prints exceptions from shell commands to stdout/stderr and often still exits 0
_EXCEPTION_RE = re.compile(r"(Exception|Error)( occurred|:)|Permission denial", re.IGNORECASE)
_SECURITY_RE = re.compile(
    r"SecurityException|INJECT_EVENTS|WRITE_SECURE_SETTINGS|Permission denial")

INJECT_HINT = """\
The shell user is not allowed to inject input (INJECT_EVENTS).
On Xiaomi / HyperOS this is controlled by a separate developer option:
  Settings -> Additional settings -> Developer options ->
  "USB debugging (Security settings)"  -> ON
Notes:
  * The toggle requires being signed in to a Mi account (and on many builds a SIM card
    inserted + mobile data / internet on while you flip it).
  * On HyperOS 2/3 (Android 15/16) it often resets after a reboot or an OTA, and some
    builds silently reset it after ~a few minutes if the Mi account check fails.
    Toggle it OFF and ON again, then unplug/replug USB and re-run with --audit.
  * Re-authorise the computer if prompted ("Revoke USB debugging authorisations" helps
    when the toggle seems ignored).
  * Other OEMs: look for "Disable permission monitoring" (ColorOS/realme/OnePlus)."""

SETTINGS_HINT = """\
The shell user cannot write system settings (WRITE_SECURE_SETTINGS) - on Xiaomi this
is the same "USB debugging (Security settings)" toggle. The script can still run, but
the screen may turn off before the target time: set the screen timeout to the maximum
manually and keep the device plugged in."""


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


def probe_input_injection(dev: Device) -> ShellResult:
    """
    Harmless input injection probe. A KEYCODE_UNKNOWN (0) key event goes through the
    same INJECT_EVENTS permission check as a tap but does nothing. If a build rejects
    keycode 0 for another reason, fall back to a tap far outside the screen, which is
    also permission-checked first and then dropped (no window there).
    """
    res = dev.run("input keyevent 0", timeout=15)
    if res.ok or res.security_denied:
        return res
    log.debug("keyevent probe inconclusive (%s), trying off-screen tap", res.first_line_of_error())
    return dev.run("input tap -500 -500", timeout=15)


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

    if brand and brand.lower() not in {"xiaomi", "redmi", "poco"}:
        rep.add("Manufacturer", Status.WARN, f"'{brand}' is not Xiaomi",
                "Mi Community bootloader unlock only applies to Xiaomi devices.")

    region = dev.getprop("ro.product.mod_device")
    if region:
        rep.add("ROM (mod_device)", Status.INFO,
                region + ("" if "global" in region or "eea" in region
                          else "  <- China ROMs are not supported by this flow"))


def _audit_permissions(dev: Device, rep: AuditReport) -> None:
    probe = probe_input_injection(dev)
    rep.can_inject = probe.ok
    if probe.ok:
        rep.add("Input injection (INJECT_EVENTS)", Status.OK, "input events can be injected")
    elif probe.security_denied:
        rep.add("Input injection (INJECT_EVENTS)", Status.FAIL,
                probe.first_line_of_error(), INJECT_HINT)
    else:
        rep.add("Input injection (INJECT_EVENTS)", Status.WARN,
                f"probe inconclusive: {probe.first_line_of_error()}",
                "Run 'adb shell input tap 1 1' manually to check.")

    adbinput = dev.getprop("persist.security.adbinput")
    if adbinput:
        state = "ON" if adbinput == "1" else "OFF"
        rep.add("persist.security.adbinput", Status.INFO,
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


def run_audit(dev: Device, clock: Clock, args) -> AuditReport:
    """Runs all preflight checks without changing anything on the device."""
    rep = AuditReport()
    _audit_device_info(dev, rep)

    if not dev.is_alive():
        rep.add("ADB shell", Status.FAIL, "shell does not respond", "Replug USB, re-run.")
        return rep
    rep.add("ADB shell", Status.OK, "responds")

    _audit_permissions(dev, rep)
    _audit_screen(dev, rep)
    _audit_button(dev, rep, args.button_text, args.save_dump)
    _audit_clock(clock, rep, args.no_ntp)
    _audit_latency(dev, rep)
    return rep


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


def health_check(dev: Device, full: bool) -> list[str]:
    """Problems found right now (empty list = all good)."""
    if not dev.is_alive():
        return ["device is not responding over ADB"]
    problems = []
    if screen_awake(dev) is False:
        problems.append("screen is off")
    pkg = foreground_package(dev)
    if pkg and pkg != APP_PACKAGE:
        problems.append(f"Mi Community is not in foreground (focused: {pkg})")
    if full:
        probe = probe_input_injection(dev)
        if probe.security_denied:
            problems.append("input injection is denied again "
                            "('USB debugging (Security settings)' was reset)")
    return problems


def wait_until(target_utc: datetime, clock: Clock, dev: Device, need_inject: bool) -> None:
    """Sleeps until target, with periodic device health checks and a precise final spin."""
    remaining = (target_utc - clock.now()).total_seconds()
    log.info("Waiting %s until %s UTC.", timedelta(seconds=int(remaining)),
             target_utc.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3])

    # one more NTP sync before firing: the PC clock may drift or get adjusted by the OS
    # during a wait of several hours; skipped for short waits (the startup sync is fresh)
    resync_pending = clock.synced and remaining > NTP_RESYNC_SEC + 30
    final_checked = False
    next_heartbeat = time.monotonic() + HEARTBEAT_SEC
    while True:
        remaining = (target_utc - clock.now()).total_seconds()
        if remaining <= 0:
            return

        if resync_pending and remaining <= NTP_RESYNC_SEC:
            resync_pending = False
            clock.sync()
            continue

        if not final_checked and remaining <= FINAL_CHECK_SEC:
            final_checked = True
            problems = health_check(dev, full=True)
            for p in problems:
                log.error("Final check: %s", p)
            fatal = [p for p in problems
                     if "not responding" in p or (need_inject and "denied" in p)]
            if fatal:
                raise DeviceError("device not ready for clicking: " + "; ".join(fatal))
        elif time.monotonic() >= next_heartbeat and remaining > FINAL_CHECK_SEC + 5:
            next_heartbeat = time.monotonic() + HEARTBEAT_SEC
            for p in health_check(dev, full=False):
                log.warning("Heartbeat: %s", p)
            log.info("%s remaining.", timedelta(seconds=int(remaining)))

        if remaining > 2:
            time.sleep(min(remaining - 2, 1.0))
        elif remaining > 0.05:
            time.sleep(remaining - 0.05)
        else:
            pass  # busy-wait the last 50 ms for precision


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
                res = dev.run(cmd, timeout=10)
            except DeviceError as exc:
                log.error("Tap %d/%d failed: %s", i, count, exc)
            else:
                if res.ok:
                    done += 1
                    log.info("Tap %d/%d injected at %s CST.", i, count, stamp)
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
               "  automate.py --audit                 check permissions/setup and exit\n"
               "  automate.py --dry-run --test-in 30  full rehearsal in 30 s, no taps\n"
               "  automate.py                         real run at 00:00 CST\n")
    p.add_argument("--clicks", type=int, default=2, help="number of taps (default: 2)")
    p.add_argument("--delay", type=float, default=2.0,
                   help="delay between taps in seconds (default: 2.0)")
    p.add_argument("--lead-ms", type=int, default=DEFAULT_LEAD_MS,
                   help=f"fire this many ms before the target (default: {DEFAULT_LEAD_MS})")
    p.add_argument("--serial", help="device serial if several devices are connected")
    p.add_argument("--button-text", default=BUTTON_TEXT,
                   help=f"button label to look for (default: '{BUTTON_TEXT}')")
    p.add_argument("--ntp-server", default=NTP_SERVER, help=f"default: {NTP_SERVER}")
    p.add_argument("--no-ntp", action="store_true", help="use the local clock only")

    g = p.add_argument_group("audit / testing")
    g.add_argument("--audit", action="store_true",
                   help="run the preflight audit only and exit (no taps, no waiting)")
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
    if args.delay < 0:
        p.error("--delay must be >= 0")
    if not 0 <= args.lead_ms <= 5000:
        p.error("--lead-ms must be between 0 and 5000")
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
    """Target moment in UTC and a human-readable description of it."""
    now = clock.now()
    if args.test_in is not None:
        return now + timedelta(seconds=args.test_in), f"test: now + {args.test_in:g} s"
    if args.test:
        tz = timedelta(hours=args.test_timezone)
        target = next_occurrence(args.test_time, now, tz)
        return target, f"test: {args.test_time} @ UTC{args.test_timezone:+g}"
    midnight = next_occurrence("00:00:00", now, BEIJING_OFFSET)
    return midnight - timedelta(milliseconds=args.lead_ms), \
        f"live: 00:00:00 CST minus {args.lead_ms} ms"


def run(args) -> int:
    """Audit, wait, tap. Returns the process exit code."""
    mode = "AUDIT" if args.audit else ("DRY-RUN" if args.dry_run else "LIVE")
    if args.test and not args.audit:
        mode += " + TEST TIME"
    log.info("Mode: %s", mode)

    dev = connect_device(args.serial)
    log.info("Connected to %s", dev.serial)
    clock = Clock(args.ntp_server, use_ntp=not args.no_ntp)

    report = run_audit(dev, clock, args)
    report.print()

    if args.audit:
        return EXIT_AUDIT if report.failed else EXIT_OK

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

    target_utc, label = compute_target(args, clock)
    cst = target_utc.astimezone(timezone(BEIJING_OFFSET))
    log.info("Target (%s): %s CST / %s local", label,
             cst.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
             target_utc.astimezone().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3])

    with ScreenKeeper(dev, report.can_write_settings):
        wait_until(target_utc, clock, dev, need_inject=not args.dry_run)
        done = click(dev, report.button, clock, args)
        if done == args.clicks:
            log.info("[SUCCESS] %d/%d taps %s.", done, args.clicks,
                     "simulated" if args.dry_run else "injected")
        else:
            log.error("[FAILED] only %d/%d taps were injected.", done, args.clicks)
        if not args.dry_run and done:
            log.info("Keeping the screen on for 5 s while the request loads...")
            time.sleep(5)
            try:
                xml = dump_ui(dev, attempts=1)
                texts = [n.get("text") for n in ET.fromstring(xml).iter("node") if n.get("text")]
                log.info("Screen text after tapping: %s", " | ".join(texts[:15]))
            except (DeviceError, ET.ParseError) as exc:
                log.debug("Post-click dump failed: %s", exc)
    return EXIT_OK if done == args.clicks else EXIT_ERROR


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
