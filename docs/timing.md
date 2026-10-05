# Send timing
How `automate.py` picks the moment to send the tap, and why. The short version is in
the [README](../README.md#timing).

A request that reaches the server **before** 00:00:00 CST counts for the previous day
(the quota is used up) and blocks the next request for a minute — the attempt is lost.
Being 100–300 ms late costs little. So every error is made on the late side:

```
send = 00:00:00 CST + margin - compensation
```

Only **measured** delays are compensated, by a **lower bound** (the minimum, rounded down);
anything unmeasured counts as 0.

## What is compensated
The tap is the command `input tap X Y` run over `adb shell`. Seen from the computer its
round-trip is: PC → adb → shell → `app_process` (a JVM) → **event injection** → JVM shutdown →
adb → PC. The event is injected somewhere in the middle, so compensating the whole round-trip
(as the previous version did) sends the tap 30–60 ms too early. In a test run with a
109 ms compensation and a 50 ms margin the tap was sent 59 ms **before** the target, and the old
guard did not notice: it only checked `margin >= 50`.

So the script now measures **start of the command → injection on the phone clock**:

- each probe runs `echo "miunlock_start=$EPOCHREALTIME"; input tap X Y` — the shell prints
  the phone time (microseconds) right before `input` starts;
- HyperOS logs every injection as `MIUIInput: Input motion event injection from package ...`;
  `logcat -v epoch` gives its time on the same clock. The first such line after the start (the
  DOWN event) is the injection;
- logcat truncates its time to milliseconds (earlier — safe), the start time's resolution is
  subtracted, and the way PC → phone over adb counts as 0. So each sample is a lower bound;
- compensation = minimum over the probes, rounded down.

If the phone does not log the injection or the times cannot be matched, the measurement is
impossible: the standard 150 ms margin is used (WARN). There is **no** fallback to the
round-trip. The round-trip (min/median/p95) and the ADB round-trip of `echo` are still logged
for reference.

## Modes
- `--timing fixed`: no compensation, margin `--margin-ms` (150). The tap is sent at 00:00:00.150 CST.
- `--timing adaptive` (default): between T-120 s and T-60 s the script measures `--probes` (20)
  taps on static text in the Mi Community window (never the button), 0.4 s apart (longer than
  the double-tap timeout, so no zoom), and compensates the start → injection delay.
  Margin `--adaptive-margin-ms` (50) covers NTP error and taps faster than the measured
  minimum; if the delay varies a lot (p95 - min > 100 ms) the margin becomes 150 ms (WARN).
- `--api-host HOST` (**experimental**): also pings HOST from the phone and compensates half of
  the minimal RTT. Half a ping is **not** a lower bound of the one-way delay on an asymmetric
  link (e.g. mobile data), so this can send too early; the log warns when it is used.
  No host is guessed; without the flag, or if ping does not work, the network is not compensated.
- Started later than T-120 s, or the probes failed / were inconclusive (an adb error during
  the probes included): no fresh measurement.
  Then the last saved measurement is used (WARN `using the one saved on <date>`), or, without
  one, the standard 150 ms margin (WARN, fixed timing).
- Every successful measurement is saved to `miunlock_latency.json` next to the script
  (`--cache-file`): method (`device_inject_v1`), serial, connection type (usb / tcp), time and
  all samples with min/median/p95 of the injection delay, the input round-trip and the ADB
  round-trip. It is only used for the same serial and connection type and if it is not older
  than `--cache-max-age-days` (7). Caches of the old round-trip format are not used (INFO);
  a broken file is ignored with a warning. `--no-cache` turns reading and writing off.

## Guards
- Sanity check of the measurement: the phone-side delay cannot be longer than the round-trip
  of the same command minus half the ADB round-trip. If it is, the measurement is wrong
  (ERROR) and fixed timing with 150 ms is used.
- False start guard: margin >= 50 ms, compensation >= 0 and the send moment no earlier than
  target - compensation; a plan that breaks one of them is a calculation error (ERROR) and
  fixed timing with 150 ms is used.

The log shows the mode, min/median/p95 of the measured delays, the compensation, the margin,
the send moment in CST and local time and the earliest arrival at the server.
`--dry-run` goes through the measurement and the calculation, only without the real tap.

## How it is tested
All offline, on a simulated phone in virtual time (`tests/fakes.py`):
- `tests/test_timing_invariants.py` — a grid of measurements (fast, slow, jittery,
  implausible) and options: the earliest possible arrival is never before
  target + 50 ms, the compensation is a whole number of ms and never more than the
  measured minimum; a full `--test-in 150` run checks the moment the fake phone
  injects the real tap;
- `tests/test_timing_properties.py` — the same rules for random measurements, options
  and targets (hypothesis), plus: the order of the samples does not matter, a slower
  sample never raises the compensation, and the measured start → injection delay is
  a lower bound of the real one whatever the clock resolution, truncation and lost
  logcat or start lines;
- `tests/test_injection_failures.py` — the toggle resets, taps are silently denied or
  the cable is pulled at any moment of a run: never an early tap, never a second tap,
  never success for a tap that did not land;
- `tests/test_cache.py` — the cache format, old and broken files, and that a cached
  measurement gives exactly the same plan as a fresh one.
