# Python script to automate Mi Community unlock request at 00:00 beijing time via ADB
# Copyright (C) 2025 chickendrop89
# Modifications Copyright (C) 2026 Maksim Tsvetkov
#
# This file has been modified from the original by chickendrop89
# (https://github.com/chkndrp/micommunity-unlock-request-automate), last modified
# 2026-10-05: HyperOS 3 / Android 16 support, preflight audit, timing and latency
# measurement. See README "Credits / Origin" and the git history for details.
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

"""ADB layer: the device wrapper, the UI dump of Mi Community, the tap command and its
logcat, and the screen settings kept for the session."""

from __future__ import annotations

import logging
import math
import re
import time
from contextlib import contextmanager
from dataclasses import dataclass
from xml.etree import ElementTree as ET

import adbutils
from adbutils.errors import AdbError

log = logging.getLogger(__name__)

APP_PACKAGE = "com.mi.global.bbs"
BUTTON_TEXT = "Apply for unlocking"
BUTTON_RESOURCE_ID = "com.mi.global.bbs:id/btnApply"

# /data/local/tmp is owned by the shell user; /sdcard is less reliable on newer Android
DEVICE_XML_PATH = "/data/local/tmp/miunlock_ui_dump.xml"
STAY_ON_KEY = "stay_on_while_plugged_in"
STAY_ON_ALL = "7"                # AC | USB | wireless
SCREEN_TIMEOUT_MAX = "2147483647"

ADBINPUT_PROP = "persist.security.adbinput"   # Xiaomi: "USB debugging (Security settings)"

# Android prints exceptions from shell commands to stdout/stderr and often still exits 0
_EXCEPTION_RE = re.compile(r"(Exception|Error)( occurred|:)|Permission denial", re.IGNORECASE)
_SECURITY_RE = re.compile(
    r"SecurityException|INJECT_EVENTS|WRITE_SECURE_SETTINGS|Permission denial")
# Some builds drop a rejected injection silently and only log it. Only an input tag with
# the text of a refusal counts: in the live run a denial at T-120 s cancels the attempt,
# so a false match (e.g. a line about granting INJECT_EVENTS) would cost a day. Note that
# HyperOS logs every injection as "MIUIInput: Input ... event injection from package".
_LOGCAT_DENIED_RE = re.compile(
    r"\b(InputDispatcher|InputManager[\w-]*|MIUIInput)\s*:.*?"
    + r"(permission denied:? injecting|injection (was )?(denied|failed|rejected))",
    re.IGNORECASE)
_DEVICE_TIME_RE = re.compile(r"\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}")
# `logcat -v epoch` line of an accepted injection (HyperOS logs DOWN and UP)
_INJECT_LOG_RE = re.compile(r"^\s*(\d+\.\d+)\s.*\bMIUIInput\b.*injection from package",
                            re.IGNORECASE)
_TAP_START_RE = re.compile(r"^miunlock_start=(\d+\.(\d+))\s*$", re.MULTILINE)

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

    deadline: float | None = None    # time.monotonic() limit for commands, see time_budget

    def __init__(self, adb_device: adbutils.AdbDevice) -> None:
        self._dev = adb_device
        self.serial = adb_device.serial

    @contextmanager
    def time_budget(self, seconds: float):
        """Commands inside the block share `seconds`; then they raise DeviceError."""
        self.deadline = time.monotonic() + seconds
        try:
            yield
        finally:
            self.deadline = None

    def run(self, cmd: str, timeout: float = 30.0) -> ShellResult:
        """Runs a shell command; raises DeviceError only on transport failures/timeouts."""
        if self.deadline is not None:
            left = self.deadline - time.monotonic()
            if left <= 0:
                raise DeviceError(f"adb shell '{cmd}': time budget used up")
            timeout = min(timeout, left)
        return self._shell(cmd, timeout)

    def _shell(self, cmd: str, timeout: float) -> ShellResult:
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

    def read_bytes(self, cmd: str, timeout: float = 15.0) -> bytes:
        """Binary output of a shell command (e.g. screencap -p)."""
        try:
            return self._dev.shell(cmd, timeout=timeout, encoding=None, rstrip=False)
        except (AdbError, OSError) as exc:
            raise DeviceError(f"adb shell '{cmd}' failed: {exc}") from exc

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


# --------------------------------------------------------------------------- UI

@dataclass
class Button:
    """Located unlock button: tap point, bounds and how it was matched."""
    x: int
    y: int
    bounds: str
    enabled: bool
    matched_by: str
    text: str = ""


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
                  node.get("enabled", "true") == "true", matched_by,
                  (node.get("text") or node.get("content-desc") or "").strip())


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


def dump_ui(dev: Device, attempts: int = 3, timeout: float = 40.0) -> str:
    """uiautomator dump with retries (it fails while animations are running)."""
    last_err = ""
    for attempt in range(1, attempts + 1):
        res = dev.run(f"uiautomator dump {DEVICE_XML_PATH}", timeout=timeout)
        if res.ok and "dumped to" in res.output.lower():
            xml = dev.run(f"cat {DEVICE_XML_PATH}", timeout=20).output
            dev.run(f"rm -f {DEVICE_XML_PATH}", timeout=10)
            if xml.lstrip().startswith("<?xml"):
                return xml
            last_err = "dump file is empty or not XML"
        else:
            last_err = res.first_line_of_error()
        log.debug("uiautomator dump attempt %d failed: %s", attempt, last_err)
        if attempt < attempts:
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


def device_time(dev: Device) -> str:
    """Device clock in logcat -T format ('' if unknown)."""
    try:
        out = dev.run("date '+%m-%d %H:%M:%S.000'", timeout=10).output.strip()
    except DeviceError as exc:
        log.debug("Device time unknown: %s", exc)
        return ""
    return out if _DEVICE_TIME_RE.fullmatch(out) else ""


def read_logcat(dev: Device, since: str) -> str:
    """logcat since `since` (device_time() format) with epoch time stamps."""
    if not since:
        return ""
    return dev.run(f"logcat -d -v epoch -T '{since}'", timeout=20).output


def find_denial(logcat: str) -> str:
    """First logcat line that reports a rejected injection ('' if none)."""
    for line in logcat.splitlines():
        if _LOGCAT_DENIED_RE.search(line):
            return line.strip()[:200]
    return ""


def logcat_denial(dev: Device, since: str) -> str:
    """First logcat line since `since` that reports a rejected injection ('' if none)."""
    return find_denial(read_logcat(dev, since))


def tap_command(x: int, y: int) -> str:
    """
    `input tap` preceded by the device clock at its start ($EPOCHREALTIME of mksh,
    microseconds; `date +%s.%N` otherwise). Probes and the real tap use the same command.
    """
    return f'echo "miunlock_start=${{EPOCHREALTIME:-$(date +%s.%N)}}"; input tap {x} {y}'


def tap_start(output: str) -> tuple[float, float] | None:
    """(device time in s, its resolution in s) printed by tap_command, None if missing."""
    m = _TAP_START_RE.search(output)
    if not m:
        return None
    return float(m.group(1)), 10.0 ** -len(m.group(2))


def injection_times(logcat: str) -> list[float]:
    """Device times (epoch s, truncated to ms by logcat) of the logged injections."""
    return [float(m.group(1)) for m in map(_INJECT_LOG_RE.search, logcat.splitlines()) if m]


def injection_delays(starts: list[tuple[float, float]], injected: list[float],
                     round_trips: list[float] | None = None) -> list[float]:
    """
    Start -> injection in ms for each tap: the first injection logged after its start and
    before the next tap's start (the DOWN event). A lower bound of the real delay: logcat
    truncates its time (earlier), the start is moved later by its resolution, and the
    time before the shell started (PC -> device) counts as 0. Unmatched taps are left out,
    and so is a match longer than the tap's own round-trip (the event is injected before
    the command returns, so it belongs to a later tap whose start was not printed).
    """
    delays = []
    for i, (start, resolution) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else math.inf
        first_ms = math.floor(start * 1000) / 1000
        hits = [t for t in injected if first_ms <= t < end]
        if not hits:
            continue
        delay = (min(hits) - start - resolution) * 1000
        if delay >= 0 and (round_trips is None or delay <= round_trips[i]):
            delays.append(delay)
    return delays


def timed_run(dev: Device, cmd: str) -> tuple[ShellResult, float]:
    """Runs cmd, returns the result and its round-trip in ms."""
    t0 = time.perf_counter()
    res = dev.run(cmd, timeout=15)
    return res, (time.perf_counter() - t0) * 1000


# --------------------------------------------------------------------------- screen

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
