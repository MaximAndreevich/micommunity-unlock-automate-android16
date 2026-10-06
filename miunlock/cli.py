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

"""Command line: the arguments, and the run itself - audit, probes, wait, tap and the
checks after it - with its exit codes."""

from __future__ import annotations

import argparse
import logging
import math
import re
import sys
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

from .adb import (APP_PACKAGE, BUTTON_RESOURCE_ID, BUTTON_TEXT, INJECT_HINT, Button,
                  Device, DeviceError, ScreenKeeper, ShellResult, connect_device, device_time,
                  dump_ui, find_button, find_denial, find_probe_target, injection_delays,
                  injection_times, read_logcat, tap_command, tap_start, timed_run)
from .audit import final_check, run_audit, window_ready
from .timing import (BEIJING_OFFSET, DEFAULT_ADAPTIVE_MARGIN_MS, DEFAULT_CACHE_MAX_AGE_DAYS,
                     DEFAULT_MARGIN_MS, DEFAULT_PROBES, MIN_ARRIVAL_MS, NTP_SERVER,
                     WIDE_SPREAD_MARGIN_MS, Clock, LatencyStats, Measurement, ProbeRun,
                     TimingPlan, checked_send_time, fmt_time, load_cache, log_plan,
                     measure_adb_rtt, measure_network_rtt, measure_tap_latency,
                     next_occurrence, parse_time, plan_timing, save_cache, wait_until)

log = logging.getLogger(__name__)

DEFAULT_CACHE_FILE = str(Path(__file__).resolve().parents[1] / "miunlock_latency.json")

# Schedule relative to the target T. Taps into the app (always on static text, never the
# button) only happen before T-60 s; after that only checks without input and the real tap.
PROBE_START_SEC = 120.0          # in-app probes / latency measurement start at T-120 s ...
PROBE_END_SEC = 60.0             # ... and must be done by T-60 s
PROBE_MIN_SEC = 5.0              # no probes if less than this is left before T-60 s
FINAL_CHECK_SEC = 20.0           # last check (state + UI dump, no input) at T-20 s
FOCUS_CHECK_SEC = 3.0            # last look (screen + focus, no input) before the first tap
LATE_SEND_WARN_MS = 50           # a tap sent later than planned by more than this warns
# The server reply is usually a toast: drawn by SystemUI, not in the app's UI dump, and
# gone after ~2 s. So the screen is captured at these moments after the tap.
SCREENSHOT_AFTER_SEC = (0.5, 1.5, 3.0)
VERIFY_AFTER_SEC = 5.0           # the UI dump of the app after the tap
PROBE_SAFETY_SEC = 2.0           # the last probe must start this long before T-60 s

MIN_CLICK_DELAY_SEC = 60.0       # the server accepts one unlock request per minute
DEFAULT_CLICK_DELAY_SEC = 61.0

EXIT_OK, EXIT_ERROR, EXIT_AUDIT, EXIT_INTERRUPTED = 0, 1, 2, 130

_HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.:-]*")


# --------------------------------------------------------------------------- session

@dataclass
class Session:
    """What the steps after the audit share."""
    dev: Device
    clock: Clock
    args: argparse.Namespace
    target_utc: datetime            # quota reset (00:00:00 CST or the test target)
    measure: bool                   # measure the latency in the probe window


def ready_before(ses: Session, send_utc: datetime) -> bool:
    """window_ready() FOCUS_CHECK_SEC before the first tap; True if that moment has
    passed already (then the final check has just looked)."""
    focus_at = send_utc - timedelta(seconds=FOCUS_CHECK_SEC)
    if focus_at <= ses.clock.now():
        return True
    wait_until(focus_at, ses.clock, ses.dev, quiet=True)
    return window_ready(ses.dev)


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
    try:
        adb_rtt = measure_adb_rtt(dev) if measure else []
        probes = measure_tap_latency(dev, target, ses.clock, deadline,
                                     args.probes if measure else 1)
    except DeviceError as exc:
        # not a denial: the final check decides whether the device is still usable
        log.warning("Probe: adb failed (%s) - no in-app probe.", exc)
        return None
    samples = probes.round_trips
    if probes.denial:
        msg = f"input injection is denied: {probes.denial}"
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
    return _measurement(ses, probes, adb_rtt, deadline)


def _measurement(ses: Session, probes: ProbeRun, adb_rtt: list[float],
                 deadline: datetime) -> Measurement | None:
    """Measurement from the probes; None (logged) if there are too few samples."""
    args, samples = ses.args, probes.round_trips
    needed = max(3, args.probes // 2)
    if len(samples) < needed:
        log.warning("Latency measurement inconclusive: %d/%d probes succeeded (need %d).",
                    len(samples), args.probes, needed)
        return None
    round_trip = LatencyStats(samples)
    log.info("Input tap round-trip (reference, not compensated): %s", round_trip.describe())
    if len(probes.inject_delays) < needed:
        log.warning("Latency measurement impossible: the injection time was found for %d/%d "
                    + "probes (need %d; start time on the device + MIUIInput 'injection "
                    + "from package' line in logcat).", len(probes.inject_delays),
                    len(samples), needed)
        return None
    inject = LatencyStats(probes.inject_delays)
    log.info("Start -> injection measured (device clock): %s", inject.describe())
    return Measurement(inject, round_trip, LatencyStats(adb_rtt) if adb_rtt else None,
                       _probe_network(ses, deadline) if args.api_host else None)


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


def screen_texts(xml: str) -> list[str]:
    """Visible texts of the Mi Community window (system UI such as the clock left out)."""
    return [n.get("text") for n in ET.fromstring(xml).iter("node")
            if n.get("text") and n.get("package", APP_PACKAGE) == APP_PACKAGE]


def verify_after_tap(dev: Device, button: Button, button_text: str,
                     xml_before: str, logcat: str) -> tuple[bool, bool | None]:
    """
    Checks that the taps had an effect. Returns (ok, screen changed or None if unknown);
    ok is False if the device rejected them (logcat). An unchanged app screen is no
    error: the reply may have been a toast.
    """
    denial = find_denial(logcat)
    if denial:
        log.error("The device rejected the taps: %s", denial)
        log.error(INJECT_HINT)
        return False, None
    try:
        xml_after = dump_ui(dev, attempts=1)
        after = screen_texts(xml_after)
        before = screen_texts(xml_before) if xml_before else []
        fresh = find_button(xml_after, button_text, BUTTON_RESOURCE_ID)
    except (DeviceError, ET.ParseError) as exc:
        log.warning("Could not check the screen after tapping: %s", exc)
        return True, None
    new = [t for t in after if t not in before]
    if new:
        log.info("New on screen: %s", " | ".join(new[:15]))
    if not xml_before:
        return True, None
    changed = bool(new) or fresh is None or fresh.enabled != button.enabled
    if changed:
        log.info("Screen changed after tapping.")
    return True, changed


def evidence_dir(args) -> Path:
    """Screenshots and logcat go next to the log file (or to the current directory)."""
    return Path(args.log_file).resolve().parent if args.log_file else Path.cwd()


def capture_screenshots(dev: Device, clock: Clock, tap_utc: datetime, out_dir: Path,
                        prefix: str) -> list[str]:
    """screencap at SCREENSHOT_AFTER_SEC after the tap, saved as PNG; returns the paths."""
    paths = []
    for offset in SCREENSHOT_AFTER_SEC:
        wait = (tap_utc + timedelta(seconds=offset) - clock.now()).total_seconds()
        if wait > 0:
            time.sleep(wait)
        path = out_dir / f"{prefix}_tap+{offset:g}s.png"
        try:
            png = dev.read_bytes("screencap -p")
            if not png.startswith(b"\x89PNG"):
                raise DeviceError(f"screencap returned no PNG ({png[:40]!r})")
            path.write_bytes(png)
        except (DeviceError, OSError) as exc:
            log.warning("Screenshot %g s after the tap failed: %s", offset, exc)
            continue
        paths.append(str(path))
    if paths:
        log.info("Screenshots after the tap: %s", ", ".join(paths))
    return paths


def save_app_logcat(dev: Device, since: str, out_dir: Path, prefix: str) -> None:
    """Saves the Mi Community logcat since `since` (the tap window) to a file."""
    try:
        pid = dev.run(f"pidof {APP_PACKAGE}", timeout=5).output.split()
        if not pid or not since:
            log.warning("App logcat not saved: %s", "no pid" if not pid else "no start time")
            return
        out = dev.run(f"logcat -d -v epoch --pid={pid[0]} -T '{since}'", timeout=20).output
        path = out_dir / f"{prefix}_app_logcat.txt"
        path.write_text(out, encoding="utf-8")
    except (DeviceError, OSError) as exc:
        log.warning("App logcat not saved: %s", exc)
        return
    log.info("App logcat of the tap window saved to %s.", path)


@dataclass
class SentTap:
    """A real tap whose command was accepted."""
    sent_utc: datetime              # clock.now() right before the command was sent
    result: ShellResult
    round_trip_ms: float


@dataclass
class FiredTaps:
    """The real taps, for the checks after them."""
    plan: TimingPlan
    since: str                      # device time before the taps (logcat window)
    first_utc: datetime             # planned moment of the first tap ...
    last_utc: datetime              # ... and of the last one
    sent: list[SentTap] = field(default_factory=list)


def report_tap_delays(logcat: str, fired: FiredTaps, target_utc: datetime) -> None:
    """
    Start -> injection of the real taps, measured after the fact like the probes (device
    clock, a lower bound). The command starts on the phone after the PC sent it, so
    sent_utc + that delay is the earliest moment the tap can have been injected, on the
    PC clock - compared with the target and with the compensation the plan relied on.
    """
    injected = injection_times(logcat)
    starts = [tap_start(tap.result.output) for tap in fired.sent]
    compensation = fired.plan.compensation_ms
    for i, (tap, start) in enumerate(zip(fired.sent, starts), 1):
        end = next((later[0] for later in starts[i:] if later), math.inf)
        delays = (injection_delays([start], [t for t in injected if t < end],
                                   [tap.round_trip_ms]) if start else [])
        if not delays:
            log.info("Real tap %d: start -> injection unknown (%s).", i,
                     "no injection line in logcat" if start else "no start time printed")
            continue
        earliest = tap.sent_utc + timedelta(milliseconds=delays[0])
        after_ms = (earliest - target_utc).total_seconds() * 1000
        log.info("Real tap %d: start -> injection %.1f ms (device clock), injected at %s CST "
                 + "or later (target %+.0f ms).", i, delays[0],
                 fmt_time(earliest, BEIJING_OFFSET), after_ms)
        if delays[0] < compensation:
            log.warning("Real tap %d was %.1f ms faster than the %d ms compensated "
                        + "(margin %d ms).", i, compensation - delays[0], compensation,
                        fired.plan.margin_ms)
        if after_ms < 0:
            log.warning("Real tap %d may have been injected %.0f ms before the target.",
                        i, -after_ms)


def after_tap(ses: Session, button: Button, xml_before: str, fired: FiredTaps) -> bool:
    """
    Screenshots, the denial / screen check, the delay of the real taps and the app
    logcat after the last tap.
    """
    last_tap_utc, since = fired.last_utc, fired.since
    out_dir = evidence_dir(ses.args)
    prefix = "miunlock_" + last_tap_utc.astimezone().strftime("%Y%m%d-%H%M%S")
    shots = capture_screenshots(ses.dev, ses.clock, last_tap_utc, out_dir, prefix)
    wait = (last_tap_utc + timedelta(seconds=VERIFY_AFTER_SEC)
            - ses.clock.now()).total_seconds()
    if wait > 0:
        log.info("Keeping the screen on for %.0f s while the request loads...", wait)
        time.sleep(wait)
    try:
        logcat = read_logcat(ses.dev, since)
    except DeviceError as exc:
        log.warning("Could not check logcat for rejected taps: %s", exc)
        logcat = ""
    report_tap_delays(logcat, fired, ses.target_utc)
    ok, changed = verify_after_tap(ses.dev, button, ses.args.button_text, xml_before, logcat)
    if changed is False:
        log.info("The app screen did not change; the reply may have been a toast - see "
                 + "the screenshots: %s", ", ".join(shots) or "none were saved")
    save_app_logcat(ses.dev, since, out_dir, prefix)
    return ok


def warn_if_late(i: int, count: int, due: datetime, now: datetime) -> None:
    """WARN if tap i is sent more than LATE_SEND_WARN_MS after its planned moment."""
    late_ms = (now - due).total_seconds() * 1000
    if late_ms > LATE_SEND_WARN_MS:
        log.warning("Tap %d/%d is %.0f ms late: planned at %s CST, sending at %s CST.",
                    i, count, late_ms, fmt_time(due, BEIJING_OFFSET), fmt_time(now, BEIJING_OFFSET))


def click(dev: Device, button: Button, clock: Clock, args,
          fired: FiredTaps | None = None) -> int:
    """
    Taps args.clicks times (the first one planned at fired.first_utc). Returns the number
    of taps injected successfully; the accepted ones are appended to fired.sent.
    """
    cmd = tap_command(button.x, button.y)
    count = args.clicks
    done = 0
    for i in range(1, count + 1):
        now = clock.now()
        stamp = fmt_time(now, BEIJING_OFFSET)
        if fired is not None:
            warn_if_late(i, count, fired.first_utc + timedelta(seconds=args.delay * (i - 1)),
                         now)
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
                    if fired is not None:
                        fired.sent.append(SentTap(now, res, latency))
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
               "  automate.py --test-in 30            REAL tap in 30 s: sends a real unlock\n"
               "                                      request and blocks the next one for a\n"
               "                                      minute - never run it after 23:58 CST\n"
               "  automate.py                         real run at 00:00 CST\n"
               "\n"
               "compensation = minimal time from the start of the tap command to the event\n"
               "injection, both on the phone clock (shell start time + MIUIInput logcat line).\n"
               "The input round-trip is only logged: the event is injected in the middle of\n"
               "it, so compensating it would send too early.\n")
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
                   help="adaptive: compensate the measured start -> injection delay of the "
                        "tap on the phone (and the network delay with --api-host); fixed: no "
                        "compensation (default: adaptive)")
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
                   help="EXPERIMENTAL: also ping HOST from the phone and compensate half of "
                        "the minimal RTT. Half a ping is not a lower bound of the one-way "
                        "delay on an asymmetric link, so this may send too early "
                        "(default: off, the network delay is not compensated)")

    t.add_argument("--cache-file", metavar="FILE", default=DEFAULT_CACHE_FILE,
                   help="where the last latency measurement is saved; used when no fresh "
                        "one is possible (default: miunlock_latency.json next to the script)")
    t.add_argument("--cache-max-age-days", type=float, metavar="DAYS",
                   default=DEFAULT_CACHE_MAX_AGE_DAYS,
                   help=f"ignore older measurements (default: {DEFAULT_CACHE_MAX_AGE_DAYS:g})")
    t.add_argument("--no-cache", action="store_true",
                   help="neither read nor write the latency cache")

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
                   help="target = now + SEC seconds (implies --test). Without --dry-run "
                        "the tap is REAL: it sends an unlock request and blocks the next one "
                        "for a minute - do not run it after 23:58 CST")
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
    if args.cache_max_age_days <= 0:
        p.error("--cache-max-age-days must be > 0")
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
    if args.api_host:
        log.warning("--api-host is experimental: half the ping RTT is not a lower bound of "
                    "the delay on an asymmetric link - the request may arrive early.")
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


def latency_estimate(ses: Session, measured: Measurement | None
                     ) -> tuple[Measurement | None, str]:
    """
    Fresh measurement (saved to the cache), else a valid cached one, else nothing.
    Returns the measurement and where it comes from.
    """
    args = ses.args
    if args.timing != "adaptive":
        return None, ""
    path = None if args.no_cache else args.cache_file
    if measured:
        if path:
            save_cache(path, ses.dev.serial, measured, args.api_host, ses.clock.now())
        return measured, "measured"
    cached = (load_cache(path, ses.dev.serial, args.cache_max_age_days, ses.clock.now())
              if path else None)
    if cached is None:
        return None, ""                # plan_timing warns about the standard margin
    stamp = cached.measured_at.astimezone().strftime("%Y-%m-%d %H:%M")
    log.warning("Latency measurement not possible - using the one saved on %s.", stamp)
    net = cached.measured.net if args.api_host and cached.api_host == args.api_host else None
    if args.api_host and net is None:
        log.warning("No saved ping to %s - the network delay is not compensated.",
                    args.api_host)
    return replace(cached.measured, net=net), f"cache from {stamp}"


def fire(ses: Session, button: Button) -> int:
    """Probes, timing, final check, tap, verification. Returns the number of taps done."""
    dev, clock, args, target_utc = ses.dev, ses.clock, ses.args, ses.target_utc
    measured = None
    if (target_utc - clock.now()).total_seconds() > PROBE_END_SEC + PROBE_MIN_SEC:
        probe_at = target_utc - timedelta(seconds=PROBE_START_SEC)
        if probe_at > clock.now():
            wait_until(probe_at, clock, dev)
        measured = probe_phase(ses, button)
    plan = plan_timing(args, *latency_estimate(ses, measured))
    plan, send_utc = checked_send_time(plan, target_utc)
    log_plan(plan, target_utc, send_utc, args.api_host)

    check_at = target_utc - timedelta(seconds=FINAL_CHECK_SEC)
    if check_at > clock.now():
        wait_until(check_at, clock, dev, quiet=True)
    button, xml_before = final_check(dev, args.button_text, button,
                                     need_inject=not args.dry_run)
    with dev.time_budget(2.0):
        since = device_time(dev)    # logcat window for the post-tap denial check
    fired = FiredTaps(plan, since, send_utc,
                      send_utc + timedelta(seconds=args.delay * (args.clicks - 1)))
    done = 0
    if ready_before(ses, send_utc):
        wait_until(send_utc, clock, dev, quiet=True)
        done = click(dev, button, clock, args, fired)
    if not args.dry_run and done and not after_tap(ses, button, xml_before, fired):
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
