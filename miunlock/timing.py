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

"""When to tap: the NTP clock, the target moment, the latency measurement and its cache,
the send moment and the wait for it. The reasoning is in docs/timing.md."""

from __future__ import annotations

import json
import logging
import math
import os
import re
import statistics
import time
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import ntplib

from .adb import (INJECT_OFF, Button, Device, DeviceError, device_time, find_denial,
                  health_check, injection_delays, injection_times, read_logcat, tap_command,
                  tap_start, timed_run)

log = logging.getLogger(__name__)

BEIJING_OFFSET = timedelta(hours=8)
# Send moment = target + margin - compensation. A request that reaches the server before
# 00:00:00 CST counts for the previous day (quota used up) and blocks the next one for a
# minute, so every error must make it late, never early: only measured delays are
# compensated (by a lower bound), unmeasured ones count as 0.
# The compensation is the time from the start of the tap command to the injection of the
# event, both on the device clock (shell start time, then the MIUIInput logcat line). The
# PC -> device leg counts as 0. The round-trip of `input tap` is NOT used: it also contains
# the JVM shutdown and the way back, the event is delivered in the middle of it.
DEFAULT_MARGIN_MS = 150          # fixed mode, and the fallback without a measurement
DEFAULT_ADAPTIVE_MARGIN_MS = 50  # covers NTP error, network asymmetry, faster-than-min taps
WIDE_SPREAD_MS = 100             # injection delay p95 - min above this is unreliable ...
WIDE_SPREAD_MARGIN_MS = 150      # ... and gets this margin
MIN_ARRIVAL_MS = 50              # guard: the request may never arrive before target + this
DEFAULT_PROBES = 20              # latency probes (taps on static text, never the button)
PROBE_GAP_SEC = 0.4              # > double-tap timeout: no zoom / double-tap actions
ADB_RTT_SAMPLES = 5
CACHE_METHOD = "device_inject_v1"   # older caches (round-trip) are not used
DEFAULT_CACHE_MAX_AGE_DAYS = 7.0
NTP_SERVER = "pool.ntp.org"
NTP_SAMPLES = 4

HEARTBEAT_SEC = 60.0             # how often to re-check the device while waiting
NTP_RESYNC_SEC = 60.0            # re-query NTP this many seconds before a long wait ends

_PING_TIME_RE = re.compile(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms")


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
    """
    Measured delays. `inject` (tap command start -> injection, device clock) is
    compensated; the round-trips are logged and only used for a sanity check.
    """
    inject: LatencyStats
    round_trip: LatencyStats              # `input tap` round-trip seen from the PC
    adb_rtt: LatencyStats | None = None   # `echo` round-trip seen from the PC
    net: LatencyStats | None = None       # ping from the phone to --api-host


@dataclass
class ProbeRun:
    """Raw result of the latency probes."""
    round_trips: list[float] = field(default_factory=list)
    inject_delays: list[float] = field(default_factory=list)
    denial: str = ""


def measure_adb_rtt(dev: Device) -> list[float]:
    """Round-trips in ms of a trivial shell command."""
    samples = []
    for _ in range(ADB_RTT_SAMPLES):
        res, rtt = timed_run(dev, "echo ok")
        if res.output.strip() == "ok":
            samples.append(rtt)
    return samples


def measure_tap_latency(dev: Device, target: Button, clock: Clock, deadline: datetime,
                        count: int) -> ProbeRun:
    """
    Times `count` taps on static text of the Mi Community window (never the button),
    stopping at `deadline`: the round-trip on the PC and start -> injection on the device.
    Then logcat is scanned for the injections and for a denial.
    """
    since = device_time(dev)
    run_ = ProbeRun()
    starts: list[tuple[float, float]] = []
    start_rtts: list[float] = []            # round-trips of the taps in `starts`
    for _ in range(count):
        if clock.now() >= deadline:
            log.warning("Latency probes stopped by the deadline after %d/%d.",
                        len(run_.round_trips), count)
            break
        res, latency = timed_run(dev, tap_command(target.x, target.y))
        if res.security_denied:
            run_.denial = res.first_line_of_error()
            return run_
        if res.ok:
            run_.round_trips.append(latency)
            start = tap_start(res.output)
            if start:
                starts.append(start)
                start_rtts.append(latency)
        else:
            log.debug("Latency probe failed: %s", res.first_line_of_error())
        time.sleep(PROBE_GAP_SEC)
    time.sleep(0.3)    # let InputDispatcher deliver (and log) the last event
    logcat = read_logcat(dev, since)
    run_.denial = find_denial(logcat)
    run_.inject_delays = injection_delays(starts, injection_times(logcat), start_rtts)
    if len(run_.inject_delays) < len(run_.round_trips):
        log.debug("Injection time found for %d/%d probes (start time printed for %d).",
                  len(run_.inject_delays), len(run_.round_trips), len(starts))
    return run_


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


def connection_type(serial: str) -> str:
    """'tcp' for adb over the network (host:port or an mDNS service name), else 'usb'."""
    return "tcp" if re.fullmatch(r".+:\d+", serial) or "._tcp" in serial else "usb"


@dataclass
class CachedLatency:
    """A measurement saved by an earlier run."""
    measured_at: datetime
    measured: Measurement
    api_host: str | None


def _stats_to_json(stats: LatencyStats) -> dict:
    # samples at full precision: rounding 53.996 up to 54.0 would add 1 ms of compensation;
    # the summary is rounded for people reading the file
    return {"samples_ms": list(stats.samples),
            "min_ms": round(stats.min, 2), "median_ms": round(stats.median, 2),
            "p95_ms": round(stats.p95, 2)}


def _stats_from_json(obj: dict | None) -> LatencyStats | None:
    if not obj:
        return None
    samples = [float(x) for x in obj["samples_ms"]]
    if not samples or not all(math.isfinite(x) and x >= 0 for x in samples):
        raise ValueError("bad samples_ms")
    return LatencyStats(samples)


def save_cache(path: str, serial: str, measured: Measurement, api_host: str | None,
               now: datetime) -> None:
    """Saves a successful measurement (never fails the run)."""
    def opt(stats: LatencyStats | None) -> dict | None:
        return _stats_to_json(stats) if stats else None
    data = {"method": CACHE_METHOD, "serial": serial, "connection": connection_type(serial),
            "measured_at": now.isoformat(), "inject": _stats_to_json(measured.inject),
            "round_trip": _stats_to_json(measured.round_trip),
            "adb_rtt": opt(measured.adb_rtt), "net": opt(measured.net),
            "api_host": api_host if measured.net else None}
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, path)
    except OSError as exc:
        log.warning("Could not save the latency cache %s: %s", path, exc)
        with suppress(OSError):
            os.remove(tmp)
        return
    log.info("Latency measurement saved to %s.", path)


def _read_cache_file(path: str) -> dict | None:
    """Parsed cache file; None (logged) if missing, unreadable or of an older method."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        log.debug("No latency cache at %s.", path)
        return None
    except (OSError, ValueError) as exc:
        log.warning("Latency cache %s is unreadable (%s) - ignored.", path, exc)
        return None
    if not isinstance(data, dict):
        log.warning("Latency cache %s is broken (not an object) - ignored.", path)
        return None
    if data.get("method") != CACHE_METHOD:
        log.info("Latency cache %s has an old measurement format (%s) - not used.", path,
                 data.get("method", "input round-trip"))
        return None
    return data


def load_cache(path: str, serial: str, max_age_days: float,
               now: datetime) -> CachedLatency | None:
    """
    The saved measurement if it is for this device and connection type and not too old.
    A broken file is ignored with a warning.
    """
    data = _read_cache_file(path)
    if data is None:
        return None
    try:
        inject, round_trip = _stats_from_json(data["inject"]), _stats_from_json(data["round_trip"])
        if inject is None or round_trip is None:
            raise ValueError("no samples")
        cached = CachedLatency(
            datetime.fromisoformat(data["measured_at"]),
            Measurement(inject, round_trip, _stats_from_json(data.get("adb_rtt")),
                        _stats_from_json(data.get("net"))),
            data.get("api_host"))
        age = now - cached.measured_at      # TypeError if measured_at has no time zone
        same_device = (data["serial"], data["connection"]) == (serial, connection_type(serial))
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        log.warning("Latency cache %s is broken (%s) - ignored.", path, exc)
        return None
    if not same_device:
        log.info("Latency cache %s is for %s over %s - not used.", path, data["serial"],
                 data["connection"])
        return None
    if not timedelta(hours=-1) <= age <= timedelta(days=max_age_days):
        log.info("Latency cache %s is from %s, not within %g days - not used.", path,
                 cached.measured_at.isoformat(timespec="seconds"), max_age_days)
        return None
    return cached


@dataclass
class TimingPlan:
    """When to send the tap: target + margin - compensation."""
    mode: str                       # "adaptive" or "fixed"
    margin_ms: int
    source: str
    measured: Measurement | None = None

    @property
    def compensation_ms(self) -> int:
        """Measured delays only, by their minimum; rounded down (later is safe)."""
        if self.mode != "adaptive" or self.measured is None:
            return 0
        net = self.measured.net.min / 2 if self.measured.net else 0.0
        return math.floor(self.measured.inject.min + net)

    def send_time(self, target_utc: datetime) -> datetime:
        """Moment to run the input command."""
        return target_utc + timedelta(milliseconds=self.margin_ms - self.compensation_ms)

    def earliest_arrival(self, target_utc: datetime) -> datetime:
        """Lower bound of when the request reaches the server."""
        return self.send_time(target_utc) + timedelta(milliseconds=self.compensation_ms)


def injection_limit_ms(measured: Measurement) -> float:
    """
    Sanity limit of the device-side delay: the same command seen from the PC took at
    least round_trip.min, and part of that is spent on the way over USB/TCP and back.
    """
    adb = measured.adb_rtt.min / 2 if measured.adb_rtt else 0.0
    return measured.round_trip.min - adb


def plan_timing(args, measured: Measurement | None, source: str) -> TimingPlan:
    """Picks the margin and compensation for --timing."""
    if args.timing == "fixed":
        return TimingPlan("fixed", args.margin_ms, "--timing fixed")
    if measured is None:
        log.warning("Latency estimate impossible - using the standard margin of %d ms.",
                    args.margin_ms)
        return TimingPlan("fixed", args.margin_ms, "no latency estimate")
    limit = injection_limit_ms(measured)
    if measured.inject.min > limit:
        log.error("Latency measurement error: start -> injection %.1f ms is longer than "
                  + "the input round-trip minus half the ADB round-trip (%.1f ms) - using "
                  + "fixed timing with %d ms.", measured.inject.min, limit, args.margin_ms)
        return TimingPlan("fixed", args.margin_ms, "measurement error")
    margin = args.adaptive_margin_ms
    spread = measured.inject.p95 - measured.inject.min
    if spread > WIDE_SPREAD_MS:
        margin = max(margin, WIDE_SPREAD_MARGIN_MS)
        log.warning("Injection delay varies a lot (p95 - min = %.0f ms > %d ms) - "
                    + "margin %d ms.", spread, WIDE_SPREAD_MS, margin)
    return TimingPlan("adaptive", margin, source, measured)


def checked_send_time(plan: TimingPlan, target_utc: datetime) -> tuple[TimingPlan, datetime]:
    """
    Guard against a false start. The compensation is a measured lower bound of the delay
    (plan_timing rejects implausible measurements), so the request arrives no earlier than
    send + compensation = target + margin; the guard checks the parts of that sum:
    margin >= MIN_ARRIVAL_MS, compensation >= 0 and send >= target - compensation.
    A plan that breaks them is a calculation error - fall back to the fixed margin.
    """
    send = plan.send_time(target_utc)
    problems = []
    if plan.margin_ms < MIN_ARRIVAL_MS:
        problems.append(f"margin {plan.margin_ms} ms < {MIN_ARRIVAL_MS} ms")
    if plan.compensation_ms < 0:
        problems.append(f"negative compensation {plan.compensation_ms} ms")
    if send < target_utc - timedelta(milliseconds=plan.compensation_ms):
        problems.append(f"send at {fmt_time(send, BEIJING_OFFSET)} CST is earlier than "
                        + "target - compensation")
    if problems:
        log.error("Timing guard: %s - falling back to fixed timing with a %d ms margin.",
                  "; ".join(problems), DEFAULT_MARGIN_MS)
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
    m = plan.measured
    if m:
        log.info("  start -> injection (device clock): %s", m.inject.describe())
        log.info("  input tap round-trip (reference, not compensated): %s",
                 m.round_trip.describe())
        if m.adb_rtt:
            log.info("  ADB round-trip: %s", m.adb_rtt.describe())
        if m.net:
            log.info("  network RTT to %s: %s (half of min compensated)", api_host,
                     m.net.describe())
    log.info("  compensation %d ms, margin %d ms", plan.compensation_ms, plan.margin_ms)
    log.info("  send at %s CST / %s local (target %+.0f ms)",
             fmt_time(send_utc, BEIJING_OFFSET), fmt_time(send_utc),
             (send_utc - target_utc).total_seconds() * 1000)
    log.info("  request reaches the server no earlier than %s CST",
             fmt_time(plan.earliest_arrival(target_utc), BEIJING_OFFSET))


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
