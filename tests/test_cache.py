"""Latency cache: loading, saving and compatibility with older formats."""

import json
import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from fakes import T0, VIRTUAL_START, FakeDevice, measurement, ms, run_with, write_cache
from miunlock import cli, timing

FIXTURES = Path(__file__).resolve().with_name("fixtures")
V1_FILE = FIXTURES / "latency_cache_device_inject_v1.json"        # saved by a real run
LEGACY_FILE = FIXTURES / "latency_cache_round_trip.json"          # before device_inject_v1
DELETE = object()


def test_measurement_is_saved(monkeypatch, cache_file):
    assert run_with(monkeypatch, FakeDevice(), ["--dry-run", "--test-in", "150"]) == cli.EXIT_OK
    data = json.loads(cache_file.read_text())
    assert (data["method"], data["serial"], data["connection"]) == \
        ("device_inject_v1", "fake123", "usb")
    assert len(data["inject"]["samples_ms"]) == len(data["round_trip"]["samples_ms"]) == 20
    assert len(data["adb_rtt"]["samples_ms"]) == 5
    assert {"min_ms", "median_ms", "p95_ms"} <= data["inject"].keys()
    assert datetime.fromisoformat(data["measured_at"]).tzinfo is not None


def test_late_start_without_cache_uses_standard_margin(monkeypatch, caplog, cache_file):
    caplog.set_level("INFO")
    assert run_with(monkeypatch, FakeDevice(), ["--dry-run", "--test-in", "30"]) == cli.EXIT_OK
    assert "Latency estimate impossible - using the standard margin of 150 ms" \
        in caplog.text
    assert "compensation 0 ms, margin 150 ms" in caplog.text
    assert not cache_file.exists()


def test_late_start_uses_cache(monkeypatch, caplog, cache_file):
    caplog.set_level("INFO")
    write_cache(cache_file)
    dev = FakeDevice()
    assert run_with(monkeypatch, dev, ["--dry-run", "--test-in", "30"]) == cli.EXIT_OK
    assert "Latency measurement not possible - using the one saved on" in caplog.text
    assert "compensation 70 ms, margin 50 ms" in caplog.text
    assert dev.probe_taps == []


def test_old_round_trip_cache_is_not_used(monkeypatch, caplog, cache_file):
    caplog.set_level("INFO")
    now = datetime.fromtimestamp(VIRTUAL_START, timezone.utc)
    cache_file.write_text(json.dumps({          # the format of the previous version
        "serial": "fake123", "connection": "usb", "measured_at": now.isoformat(),
        "tap": {"samples_ms": [109.26, 148.1]}, "net": None, "api_host": None}))
    assert run_with(monkeypatch, FakeDevice(), ["--dry-run", "--test-in", "30"]) == cli.EXIT_OK
    assert "has an old measurement format (input round-trip) - not used" in caplog.text
    assert "using the standard margin of 150 ms" in caplog.text


def test_no_cache_flag(monkeypatch, caplog, cache_file):
    write_cache(cache_file)
    before = cache_file.read_text()
    assert run_with(monkeypatch, FakeDevice(),
                    ["--dry-run", "--test-in", "30", "--no-cache"]) == cli.EXIT_OK
    assert "using the standard margin of 150 ms" in caplog.text
    assert run_with(monkeypatch, FakeDevice(),
                    ["--dry-run", "--test-in", "150", "--no-cache"]) == cli.EXIT_OK
    assert cache_file.read_text() == before


def test_cache_used_only_for_the_same_device_and_fresh(cache_file):
    now = datetime(2026, 10, 6, 15, 0, tzinfo=timezone.utc)
    write_cache(cache_file, now=now, age=timedelta(days=6, hours=23))
    assert timing.load_cache(str(cache_file), "fake123", 7, now).measured.inject.min == 70
    for kwargs in ({"serial": "other"}, {"connection": "tcp"},
                   {"age": timedelta(days=7, minutes=1)}, {"age": -timedelta(days=1)}):
        write_cache(cache_file, now=now, **kwargs)
        assert timing.load_cache(str(cache_file), "fake123", 7, now) is None, kwargs


def test_tcp_cache_matches_tcp_serial(cache_file):
    now = datetime(2026, 10, 6, 15, 0, tzinfo=timezone.utc)
    write_cache(cache_file, serial="192.168.1.5:5555", connection="tcp", now=now)
    assert timing.load_cache(str(cache_file), "192.168.1.5:5555", 7, now) is not None
    assert timing.connection_type("adb-abc._adb-tls-connect._tcp") == "tcp"
    assert timing.connection_type("a1b2c3d4") == "usb"


V1 = '"method": "device_inject_v1", '
SAMPLES = '"inject": {"samples_ms": [70]}, "round_trip": {"samples_ms": [120]}'


@pytest.mark.parametrize("content", ["{not json", "[]", '{' + V1 + '"serial": "fake123"}',
                                     '{' + V1 + '"serial": "fake123", "connection": "usb", '
                                     '"measured_at": "2026-10-06T10:00:00", ' + SAMPLES + '}',
                                     '{' + V1 + '"serial": "fake123", "connection": "usb", '
                                     '"measured_at": "2026-10-06T10:00:00+00:00", '
                                     '"inject": {"samples_ms": []}, '
                                     '"round_trip": {"samples_ms": [120]}}'])
def test_broken_cache_is_ignored(cache_file, caplog, content):
    cache_file.write_text(content)
    now = datetime(2026, 10, 6, 15, 0, tzinfo=timezone.utc)
    assert timing.load_cache(str(cache_file), "fake123", 7, now) is None
    assert "ignored" in caplog.text


def test_broken_cache_does_not_stop_the_run(monkeypatch, caplog, cache_file):
    cache_file.write_text("{not json")
    assert run_with(monkeypatch, FakeDevice(), ["--dry-run", "--test-in", "30"]) == cli.EXIT_OK
    assert "is unreadable" in caplog.text
    assert "using the standard margin of 150 ms" in caplog.text


# --------------------------------------------------------------------------- regression

def load(path, now=None, serial="fake123", max_age_days=7):
    now = now or datetime(2026, 10, 5, 20, 40, tzinfo=timezone.utc)
    return timing.load_cache(str(path), serial, max_age_days, now)


def keys(obj):
    """Key structure of a cache file: top-level keys, and the keys of the nested stats."""
    return {k: sorted(v) if isinstance(v, dict) else None for k, v in obj.items()}


def test_cache_from_a_real_run_still_loads_and_plans_the_same():
    cached = load(V1_FILE)
    m = cached.measured
    assert (m.inject.min, m.round_trip.min, m.adb_rtt.min, m.net) == (53.04, 127.02, 60.99, None)
    assert len(m.inject.samples) == len(m.round_trip.samples) == 20
    args = cli.build_parser().parse_args([])
    plan, send = timing.checked_send_time(timing.plan_timing(args, m, "cache"), T0)
    assert (plan.mode, plan.compensation_ms, plan.margin_ms) == ("adaptive", 53, 50)
    assert send == T0 - ms(3)            # as in the acceptance dry run on the phone


def test_cache_format_is_frozen(cache_file):
    """Changing what save_cache writes needs a new CACHE_METHOD (and a new fixture)."""
    assert timing.CACHE_METHOD == json.loads(V1_FILE.read_text())["method"] == "device_inject_v1"
    timing.save_cache(str(cache_file), "fake123",
                      measurement([70, 75], adb_rtt=[5, 6], net=[40]), "example.org", T0)
    saved, golden = json.loads(cache_file.read_text()), json.loads(V1_FILE.read_text())
    golden["net"] = golden["inject"]                 # the fixture was saved without ping
    assert keys(saved) == keys(golden)


@pytest.mark.parametrize("inject, net", [([53.996, 60], None), ([69.9999, 70.004], None),
                                         ([0.004, 1.5], None), ([53.04, 66.58], [40.995])])
def test_cached_plan_equals_the_fresh_plan(cache_file, inject, net):
    """Saving must not round the measurement up: the cached plan sends no earlier."""
    fresh = measurement(inject, [x + 60 for x in inject], [4.004, 5], net)
    timing.save_cache(str(cache_file), "fake123", fresh, "example.org" if net else None, T0)
    cached = timing.load_cache(str(cache_file), "fake123", 7, T0).measured
    args = cli.build_parser().parse_args([])
    plans = [timing.checked_send_time(timing.plan_timing(args, m, "x"), T0)
             for m in (fresh, cached)]
    assert plans[0] == plans[1]
    assert cached == fresh


def test_legacy_round_trip_cache_is_ignored_quietly(cache_file, caplog):
    caplog.set_level("INFO")
    shutil.copy(LEGACY_FILE, cache_file)
    assert load(cache_file) is None
    assert "has an old measurement format (input round-trip) - not used" in caplog.text
    assert not [r for r in caplog.records if r.levelno >= 30]      # INFO, not a warning
    assert cache_file.read_text() == LEGACY_FILE.read_text()


def test_unknown_method_is_ignored(cache_file, caplog):
    caplog.set_level("INFO")
    data = json.loads(V1_FILE.read_text())
    data["method"] = "device_inject_v2"
    cache_file.write_text(json.dumps(data))
    assert load(cache_file) is None
    assert "old measurement format (device_inject_v2) - not used" in caplog.text


def test_fresh_measurement_replaces_a_legacy_cache(monkeypatch, cache_file):
    shutil.copy(LEGACY_FILE, cache_file)
    assert run_with(monkeypatch, FakeDevice(), ["--dry-run", "--test-in", "150"]) == cli.EXIT_OK
    assert json.loads(cache_file.read_text())["method"] == timing.CACHE_METHOD


def test_unknown_extra_keys_are_tolerated(cache_file):
    data = json.loads(V1_FILE.read_text())
    data["comment"] = "added by hand"
    data["inject"]["stddev_ms"] = 7.1
    cache_file.write_text(json.dumps(data))
    assert load(cache_file).measured.inject.min == 53.04


@pytest.mark.parametrize("field, value", [
    ("inject", {"samples_ms": [float("nan"), 70]}),
    ("inject", {"samples_ms": [float("inf")]}),
    ("inject", {"samples_ms": [-1, 70]}),
    ("inject", {"samples_ms": ["abc"]}),
    ("inject", {"samples_ms": 70}),
    ("inject", None),
    ("round_trip", {"samples_ms": []}),
    ("adb_rtt", {"samples_ms": [float("nan")]}),
    ("measured_at", "yesterday"),
    ("measured_at", None),
    ("serial", DELETE),
    ("connection", DELETE),
])
def test_corrupt_values_are_ignored(cache_file, caplog, field, value):
    data = json.loads(V1_FILE.read_text())
    data[field] = value
    if value is DELETE:
        del data[field]
    cache_file.write_text(json.dumps(data))        # NaN / Infinity as JSON literals
    assert load(cache_file) is None
    assert any(r.levelname == "WARNING" and "ignored" in r.getMessage()
               for r in caplog.records)


@pytest.mark.parametrize("age, ok", [(timedelta(days=7), True),
                                     (timedelta(days=7, seconds=1), False),
                                     (-timedelta(hours=1), True),
                                     (-timedelta(hours=1, seconds=1), False)])
def test_cache_age_limits(cache_file, age, ok):
    write_cache(cache_file, now=T0, age=age)
    assert (timing.load_cache(str(cache_file), "fake123", 7, T0) is not None) == ok


def test_failed_save_keeps_the_previous_cache(monkeypatch, cache_file, caplog):
    shutil.copy(V1_FILE, cache_file)

    def broken_replace(src, dst):
        raise OSError("disk full")
    monkeypatch.setattr(os, "replace", broken_replace)
    timing.save_cache(str(cache_file), "fake123", measurement([70]), None, T0)
    assert "Could not save the latency cache" in caplog.text
    assert cache_file.read_text() == V1_FILE.read_text()
    assert list(cache_file.parent.glob("*.tmp")) == []


def test_save_to_a_missing_directory_only_warns(tmp_path, caplog):
    timing.save_cache(str(tmp_path / "missing" / "c.json"), "fake123", measurement([70]), None, T0)
    assert "Could not save the latency cache" in caplog.text


@pytest.mark.parametrize("host, compensation", [("example.org", 90), ("other.org", 70)])
def test_cached_ping_is_used_only_for_the_same_api_host(monkeypatch, caplog, cache_file,
                                                        host, compensation):
    caplog.set_level("INFO")
    write_cache(cache_file)
    data = json.loads(cache_file.read_text())
    data["net"], data["api_host"] = {"samples_ms": [40.5, 44]}, "example.org"
    cache_file.write_text(json.dumps(data))
    argv = ["--dry-run", "--test-in", "30", "--api-host", host]
    assert run_with(monkeypatch, FakeDevice(), argv) == cli.EXIT_OK
    assert f"compensation {compensation} ms" in caplog.text
    assert ("No saved ping to other.org" in caplog.text) == (host == "other.org")
