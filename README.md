# micommunity-unlock-request-automate
Python script to automate Mi Community unlock request at 00:00 beijing time via `ADB`

## Credits / Origin
This is a maintained continuation of
[micommunity-unlock-request-automate](https://github.com/chkndrp/micommunity-unlock-request-automate)
by **chickendrop89**. The original repository is archived, so changes cannot be sent upstream.
Many thanks to chickendrop89 for the original script and the idea of driving the Mi Community
app over ADB. The concept comes from
[EstimateMuted4573 on Reddit](https://www.reddit.com/r/Android/comments/1mgn0yj/xiaomis_bootloader_unlock_system_is_broken_heres).

What this fork changes:
- HyperOS 3 / Android 16: checks `persist.security.adbinput` ("USB debugging (Security
  settings)") instead of trusting probes that pass even with the toggle off;
- a targeted injection probe: a tap on static text inside the Mi Community window, with a
  logcat check for silent denials;
- one tap by default and at most one request per minute;
- a "rather late than early" timing model: the request must never reach the server before
  00:00:00 CST;
- measurement of the tap delay on the phone clock, with a cache of the last measurement;
- checks right before firing: the toggle, the foreground app and the button position,
  without injecting anything in the last minute; screenshots after the tap.

The project stays under the GNU GPL v3 (see `LICENSE`).

## Why?
On newer global HyperOS devices, Xiaomi has implemented another unlock step for unlocking
the bootloader via the Mi Community app.

However, there is a daily quota of devices that can be unlocked per day on Xiaomi servers,
and it is reset at 00:00 GMT+8 (Beijing time), as the app states.

## Requirements
This script requires the device to have:
- `USB Debugging` enabled
- `USB Debugging (Security settings)` enabled — **mandatory**, without it Android refuses
  `input tap` with `SecurityException ... INJECT_EVENTS`
- `OEM Unlocking` enabled
- A binded Mi account that is older than 30 days

This will not work on devices that have Chinese firmware/region,
or specific devices that have blocked bootloader unlock.

This script also requires `Python 3.10+`, `ntplib` and `adbutils` to be installed:
```shell
pip install -r requirements.txt
```

## HyperOS 2/3 (Android 15/16): `INJECT_EVENTS` SecurityException
```
java.lang.SecurityException: Injecting input events requires the caller (...) to have the INJECT_EVENTS permission.
```
This is not a bug in the script: the shell user lost permission to inject input.
On Xiaomi it is granted only while **Developer options -> USB debugging (Security settings)** is ON.
On newer HyperOS builds this toggle:
- needs a signed-in Mi account (often also a SIM card and internet while you flip it);
- can reset itself after a reboot/OTA or a failed account check.

The toggle state is the property `persist.security.adbinput` (`1` = ON):
```shell
adb shell getprop persist.security.adbinput
```
With the toggle OFF, `input keyevent 0` or a tap outside the screen still succeed on
HyperOS 3 — only events delivered into another app's window are rejected. So the script
treats `adbinput=0` as a failure and probes by tapping static text inside the
Mi Community window (a title, never the button).

Toggle it OFF/ON, replug USB and run `python automate.py --dry-run --test-in 90`.

## Set up
1. Open the Mi community app, switch to global region in the app settings
2. Navigate to "Me -> Unlock Bootloader" and keep the screen at the page
3. Connect the device to the computer, run `python automate.py --dry-run --test-in 90`,
   fix anything marked `FAIL`
4. Run the script.

What the script does:
1. **Preflight audit** — ADB state (unauthorized/offline/several devices), Android/HyperOS version,
   input injection permission (`persist.security.adbinput` plus a tap on static text in the
   Mi Community window, never on the button), settings write permission,
   screen on, Mi Community in the foreground (not the lock screen), the button on screen, NTP clock.
   Any `FAIL` stops the script before it changes anything on the device.
2. Keeps the screen on and saves the original values.
3. Waits until the send moment (see [Timing](#timing)) using an NTP-corrected clock
   (NTP is queried once, not in a loop). Re-checks the device and the Security settings
   toggle every minute. Between T-120 s and T-60 s it repeats the in-app probe tap.
   **In the last minute no input is injected except the real tap**: the heartbeat stops,
   and the final check at T-20 s only reads the device state and dumps the UI again to
   re-locate the button (the app may have restarted or scrolled). The final check has a
   budget of 8 s (one `uiautomator dump` attempt of at most 6 s); if it runs out, the audited
   coordinates are tapped (ERROR). If the script is started less than a minute before the
   target, the audit skips the in-app probe (WARN).
4. Taps the button once (`--clicks`) and verifies that each tap was really injected
   (Android prints the exception but still exits with code 0, so the old version reported success anyway).
   A tap sent more than 50 ms after the planned moment is reported (WARN).
   Xiaomi's reply is usually a **toast**: SystemUI draws it, so it is not in the app's UI dump,
   and it is gone after ~2 s. So the script saves `screencap` PNGs 0.5, 1.5 and 3 s after the
   tap and the Mi Community logcat of the tap window next to the log file (`--log-file`, else
   the current directory; names start with `miunlock_<date>-<time>`), and prints their paths.
   5 s after the tap it checks logcat for rejected injections and logs the new text on screen;
   an unchanged app screen is only INFO pointing to the screenshots.
5. Restores the original screen settings — also on Ctrl+C and on errors.

One tap is the default on purpose: Mi Community accepts one unlock request per minute,
so a second tap 2 s later is wasted and may land in the dialog opened by the first one.
With `--clicks > 1` the taps are at least 60 s apart (`--delay`, default 61 s).

Exit codes: `0` ok, `1` runtime error, `2` audit failed, `130` interrupted.

## Timing
A request that reaches the server **before** 00:00:00 CST counts for the previous day
(the quota is used up) and blocks the next request for a minute — the attempt is lost.
Being 100–300 ms late costs little. So every error is made on the late side:

```
send = 00:00:00 CST + margin - compensation
```

Only **measured** delays are compensated, by a **lower bound** (the minimum, rounded down);
anything unmeasured counts as 0.

### What is compensated
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

### Modes
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
- Started later than T-120 s, or the probes failed / were inconclusive: no fresh measurement.
  Then the last saved measurement is used (WARN `using the one saved on <date>`), or, without
  one, the standard 150 ms margin (WARN, fixed timing).
- Every successful measurement is saved to `miunlock_latency.json` next to the script
  (`--cache-file`): method (`device_inject_v1`), serial, connection type (usb / tcp), time and
  all samples with min/median/p95 of the injection delay, the input round-trip and the ADB
  round-trip. It is only used for the same serial and connection type and if it is not older
  than `--cache-max-age-days` (7). Caches of the old round-trip format are not used (INFO);
  a broken file is ignored with a warning. `--no-cache` turns reading and writing off.

### Guards
- Sanity check of the measurement: the phone-side delay cannot be longer than the round-trip
  of the same command minus half the ADB round-trip. If it is, the measurement is wrong
  (ERROR) and fixed timing with 150 ms is used.
- False start guard: margin >= 50 ms, compensation >= 0 and the send moment no earlier than
  target - compensation; a plan that breaks one of them is a calculation error (ERROR) and
  fixed timing with 150 ms is used.

The log shows the mode, min/median/p95 of the measured delays, the compensation, the margin,
the send moment in CST and local time and the earliest arrival at the server.
`--dry-run` goes through the measurement and the calculation, only without the real tap.

## Long waits
The script usually waits many hours. Keep in mind:
- **Do not let the computer sleep** — the wait and the USB connection die with it. On macOS:
  `caffeinate -i python automate.py --log-file unlock.log`; on Windows/Linux disable sleep.
- **Hard stops leave the screen settings changed.** Ctrl+C and errors restore them, but a
  killed process, sleep or a pulled cable leaves `stay_on_while_plugged_in=7` and a maximal
  screen timeout. The original values are in the log line `Screen kept on (saved: {...})`:
  ```shell
  adb shell settings put global stay_on_while_plugged_in 0
  adb shell settings put system screen_off_timeout 30000
  ```
- **OLED burn-in**: a static page for ~22 h is not great. Start the script closer to the
  target and turn the brightness down.

## Usage
```shell
usage: automate.py [-h] [--clicks CLICKS] [--delay DELAY] [--serial SERIAL]
                   [--button-text BUTTON_TEXT] [--ntp-server NTP_SERVER] [--no-ntp]
                   [--timing {adaptive,fixed}] [--margin-ms MARGIN_MS]
                   [--adaptive-margin-ms ADAPTIVE_MARGIN_MS] [--probes PROBES]
                   [--api-host HOST] [--cache-file FILE]
                   [--cache-max-age-days DAYS] [--no-cache] [--dry-run]
                   [--force] [--test] [--test-time TEST_TIME]
                   [--test-timezone TEST_TIMEZONE] [--test-in SEC]
                   [--save-dump FILE] [--log-file FILE] [-v]

  --clicks CLICKS       number of taps (default: 1)
  --delay DELAY         seconds between taps if --clicks > 1, at least 60 (default: 61)
  --serial SERIAL       device serial if several devices are connected
  --button-text TEXT    button label (default: 'Apply for unlocking'); resource-id is used as fallback
  --ntp-server SERVER   default: pool.ntp.org
  --no-ntp              use the local clock only

timing:
  --timing {adaptive,fixed}  default: adaptive
  --margin-ms MS        fixed margin, also the fallback without an estimate (default: 150)
  --adaptive-margin-ms MS    adaptive margin (default: 50; 150 if the latency varies a lot)
  --probes N            latency probes between T-120 s and T-60 s (default: 20)
  --api-host HOST       EXPERIMENTAL: ping HOST from the phone, compensate half of the min RTT (default: off)
  --cache-file FILE     latency cache (default: miunlock_latency.json next to the script)
  --cache-max-age-days DAYS  ignore older measurements (default: 7)
  --no-cache            neither read nor write the latency cache
  --lead-ms             deprecated, ignored with a warning

testing:
  --dry-run             do everything (audit, screen-on, wait) but do not tap
  --force               continue even if the audit has FAIL items (not recommended)
  --test                use --test-time/--test-timezone instead of 00:00 CST
  --test-time TIME      HH:MM[:SS[.fff]] target for --test
  --test-timezone H     UTC offset in hours for --test-time (e.g. 3 or 5.5)
  --test-in SEC         target = now + SEC seconds (implies --test); without --dry-run the tap is REAL
  --save-dump FILE      save the UI dump XML to FILE
  --log-file FILE       also write the full log to FILE
  -v, --verbose         debug logging
```

## Examples
1. Check that everything is ready: full rehearsal in 90 seconds without tapping the button
```shell
python automate.py --dry-run --test-in 90
```

2. Full rehearsal including the latency measurement (starts it 150 s before the target)
```shell
python automate.py --dry-run --test-in 150
```

3. Real tap test in 30 seconds
```shell
python automate.py --test-in 30
```
> **Warning:** this sends a **real** unlock request. The server accepts one request per minute,
> so it blocks the next attempt for a minute — never run it after 23:58 CST.

4. Running the script normally, with a log file
```shell
python automate.py --log-file unlock.log
```

5. Old-style test at a fixed time
```shell
python automate.py --test --test-timezone 2 --test-time 16:20
```

## Tests
Offline tests with a simulated device (no phone needed):
```shell
pip install -r requirements-dev.txt
python -m pytest -q tests
pylint automate.py
```

## Alternative
This script below sends the request from the computer itself, instead of going through the Mi Community app.

However it is not cross-compatible with all OSes and environments (e.g. `Fedora`).

[GetToken / AQLR script from XDA developers](https://xdaforums.com/t/how-to-unlock-bootloader-on-xiaomi-hyperos-all-devices-except-cn.4654009)
