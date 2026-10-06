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

Modules:
  adb     device wrapper, UI dump, tap command and logcat, screen settings
  timing  NTP clock, latency measurement and cache, send moment, waiting
  audit   preflight audit, final and focus checks before the tap
  cli     arguments and the run itself (probes, wait, tap, checks after it)
"""
