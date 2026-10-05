# micommunity-unlock-request-automate
Python script to automate Mi Community unlock request at 00:00 beijing time via `ADB`

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

Toggle it OFF/ON, replug USB and run `python automate.py --audit` — it checks this
without tapping anything. The same toggle also controls `settings put`
(keeping the screen on); without it the script still works, but you must set
the screen timeout manually.

## Set up
1. Open the Mi community app, switch to global region in the app settings
2. Navigate to "Me -> Unlock Bootloader" and keep the screen at the page
3. Connect the device to the computer, run `python automate.py --audit`, fix anything marked `FAIL`
4. Run the script.

What the script does:
1. **Preflight audit** — ADB state (unauthorized/offline/several devices), Android/HyperOS version,
   input injection permission (harmless probe, no taps), settings write permission,
   screen on, Mi Community in the foreground (not the lock screen), the button on screen, NTP clock.
   Any `FAIL` stops the script before it changes anything on the device.
2. Keeps the screen on and saves the original values.
3. Waits until 00:00:00 Beijing time minus `--lead-ms` (200 ms by default) using an NTP-corrected clock
   (NTP is queried once, not in a loop). Re-checks the device every minute and does a full
   check 20 s before firing (catches the Security settings toggle resetting itself).
4. Taps the button `--clicks` times and verifies that each tap was really injected
   (Android prints the exception but still exits with code 0, so the old version reported success anyway).
5. Restores the original screen settings — also on Ctrl+C and on errors.

Exit codes: `0` ok, `1` runtime error, `2` audit failed, `130` interrupted.

## Usage
```shell
usage: automate.py [-h] [--clicks CLICKS] [--delay DELAY] [--lead-ms LEAD_MS]
                   [--serial SERIAL] [--button-text BUTTON_TEXT]
                   [--ntp-server NTP_SERVER] [--no-ntp] [--audit] [--dry-run]
                   [--force] [--test] [--test-time TEST_TIME]
                   [--test-timezone TEST_TIMEZONE] [--test-in SEC]
                   [--save-dump FILE] [--log-file FILE] [-v]

  --clicks CLICKS       number of taps (default: 2)
  --delay DELAY         delay between taps in seconds (default: 2.0)
  --lead-ms LEAD_MS     fire this many ms before the target (default: 200)
  --serial SERIAL       device serial if several devices are connected
  --button-text TEXT    button label (default: 'Apply for unlocking'); resource-id is used as fallback
  --ntp-server SERVER   default: pool.ntp.org
  --no-ntp              use the local clock only

audit / testing:
  --audit               run the preflight audit only and exit (no taps, no waiting)
  --dry-run             do everything (audit, screen-on, wait) but do not tap
  --force               continue even if the audit has FAIL items (not recommended)
  --test                use --test-time/--test-timezone instead of 00:00 CST
  --test-time TIME      HH:MM[:SS[.fff]] target for --test
  --test-timezone H     UTC offset in hours for --test-time (e.g. 3 or 5.5)
  --test-in SEC         target = now + SEC seconds (implies --test)
  --save-dump FILE      save the UI dump XML to FILE
  --log-file FILE       also write the full log to FILE
  -v, --verbose         debug logging
```

## Examples
1. Check that everything is ready (no taps)
```shell
python automate.py --audit
```

2. Full rehearsal in 30 seconds without tapping
```shell
python automate.py --dry-run --test-in 30
```

3. Real tap test in 30 seconds (sends a real request!)
```shell
python automate.py --test-in 30 --clicks 1
```

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

## Credits
Concept from [EstimateMuted4573 on Reddit](https://www.reddit.com/r/Android/comments/1mgn0yj/xiaomis_bootloader_unlock_system_is_broken_heres)
