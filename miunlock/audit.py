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

"""Checks that inject no input into the button: the preflight audit, and the final and
focus checks in the last minute before the tap."""

from __future__ import annotations

import logging
import statistics
import time
from dataclasses import dataclass, field
from enum import Enum
from xml.etree import ElementTree as ET

from .adb import (ADBINPUT_PROP, APP_PACKAGE, BUTTON_RESOURCE_ID, INJECT_HINT, INJECT_OFF,
                  NOT_RESPONDING, STAY_ON_KEY, Button, Device, DeviceError, ShellResult,
                  device_time, dump_ui, find_button, find_probe_target, foreground_package,
                  health_check, logcat_denial, screen_awake, timed_run)
from .timing import Clock

log = logging.getLogger(__name__)

# The checks in the last minute inject no input and must not eat the send moment
FINAL_CHECK_BUDGET_SEC = 8.0     # final check (state + UI dump) takes at most this long ...
FINAL_DUMP_TIMEOUT_SEC = 6.0     # ... with a single uiautomator dump attempt
FOCUS_CHECK_BUDGET_SEC = 1.5     # focus check (screen + focus) before the first tap

SETTINGS_HINT = """\
The shell user cannot write system settings (WRITE_SECURE_SETTINGS). The script can
still run, but the screen may turn off before the target time: set the screen timeout
to the maximum manually and keep the device plugged in."""


# --------------------------------------------------------------------------- preflight audit

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
                f"tap on static text '{t.text}' at ({t.x}, {t.y}) in Mi Community accepted")
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


# --------------------------------------------------------------------------- last minute (no input)

def final_check(dev: Device, button_text: str, button: Button,
                need_inject: bool) -> tuple[Button, str]:
    """
    Last check before firing: device state and a fresh UI dump (the app may have
    restarted or scrolled since the audit). Injects no input - it runs in the last
    minute before the target - and takes at most FINAL_CHECK_BUDGET_SEC, so a hanging
    uiautomator cannot eat the send moment. Returns the button to tap and the UI dump
    ('' if it failed). Raises DeviceError if tapping is certain to fail.
    """
    with dev.time_budget(FINAL_CHECK_BUDGET_SEC):
        try:
            problems = health_check(dev)
        except DeviceError as exc:
            log.error("Final check: device state check failed (%s).", exc)
            problems = []
        for p in problems:
            log.error("Final check: %s", p)
        if NOT_RESPONDING in problems or (need_inject and INJECT_OFF in problems):
            raise DeviceError("device not ready for clicking: " + "; ".join(problems))

        try:
            xml = dump_ui(dev, attempts=1, timeout=FINAL_DUMP_TIMEOUT_SEC)
            fresh = find_button(xml, button_text, BUTTON_RESOURCE_ID)
        except (DeviceError, ET.ParseError) as exc:
            log.error("Final check: UI dump failed (%s) - tapping the audited coordinates.",
                      exc)
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


def window_ready(dev: Device) -> bool:
    """
    Last look before the first tap (FOCUS_CHECK_SEC before it): the screen is on and
    Mi Community has the focus. A dialog that opened after the final check, or the lock
    screen, would get the tap at the button's coordinates - then no tap is sent (False).
    Injects nothing and takes at most FOCUS_CHECK_BUDGET_SEC; if the state cannot be
    read in time, the tap goes ahead.
    """
    try:
        with dev.time_budget(FOCUS_CHECK_BUDGET_SEC):
            awake = screen_awake(dev)
            pkg = foreground_package(dev)
    except DeviceError as exc:
        log.warning("Focus check failed (%s) - tapping anyway.", exc)
        return True
    if awake is False:
        log.error("Focus check: the screen is off - no tap.")
        return False
    if pkg and pkg != APP_PACKAGE:
        log.error("Focus check: '%s' has the focus, not Mi Community (a dialog?) - no tap, "
                  + "it would land in that window.", pkg)
        return False
    if pkg:
        log.info("Focus check passed: Mi Community has the focus.")
    else:
        log.warning("Focus check: the focused app is unknown - tapping anyway.")
    return True
