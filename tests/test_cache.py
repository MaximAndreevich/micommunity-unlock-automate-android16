"""Latency cache: loading, saving and compatibility with older formats."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from fakes import VIRTUAL_START, FakeDevice, a, run_with, write_cache


def test_measurement_is_saved(monkeypatch, cache_file):
    assert run_with(monkeypatch, FakeDevice(), ["--dry-run", "--test-in", "150"]) == a.EXIT_OK
    data = json.loads(cache_file.read_text())
    assert (data["method"], data["serial"], data["connection"]) == \
        ("device_inject_v1", "fake123", "usb")
    assert len(data["inject"]["samples_ms"]) == len(data["round_trip"]["samples_ms"]) == 20
    assert len(data["adb_rtt"]["samples_ms"]) == 5
    assert {"min_ms", "median_ms", "p95_ms"} <= data["inject"].keys()
    assert datetime.fromisoformat(data["measured_at"]).tzinfo is not None


def test_late_start_without_cache_uses_standard_margin(monkeypatch, caplog, cache_file):
    caplog.set_level("INFO")
    assert run_with(monkeypatch, FakeDevice(), ["--dry-run", "--test-in", "30"]) == a.EXIT_OK
    assert "Latency estimate impossible - using the standard margin of 150 ms" \
        in caplog.text
    assert "compensation 0 ms, margin 150 ms" in caplog.text
    assert not cache_file.exists()


def test_late_start_uses_cache(monkeypatch, caplog, cache_file):
    caplog.set_level("INFO")
    write_cache(cache_file)
    dev = FakeDevice()
    assert run_with(monkeypatch, dev, ["--dry-run", "--test-in", "30"]) == a.EXIT_OK
    assert "Latency measurement not possible - using the one saved on" in caplog.text
    assert "compensation 70 ms, margin 50 ms" in caplog.text
    assert dev.probe_taps == []


def test_old_round_trip_cache_is_not_used(monkeypatch, caplog, cache_file):
    caplog.set_level("INFO")
    now = datetime.fromtimestamp(VIRTUAL_START, timezone.utc)
    cache_file.write_text(json.dumps({          # the format of the previous version
        "serial": "fake123", "connection": "usb", "measured_at": now.isoformat(),
        "tap": {"samples_ms": [109.26, 148.1]}, "net": None, "api_host": None}))
    assert run_with(monkeypatch, FakeDevice(), ["--dry-run", "--test-in", "30"]) == a.EXIT_OK
    assert "has an old measurement format (input round-trip) - not used" in caplog.text
    assert "using the standard margin of 150 ms" in caplog.text


def test_no_cache_flag(monkeypatch, caplog, cache_file):
    write_cache(cache_file)
    before = cache_file.read_text()
    assert run_with(monkeypatch, FakeDevice(),
                    ["--dry-run", "--test-in", "30", "--no-cache"]) == a.EXIT_OK
    assert "using the standard margin of 150 ms" in caplog.text
    assert run_with(monkeypatch, FakeDevice(),
                    ["--dry-run", "--test-in", "150", "--no-cache"]) == a.EXIT_OK
    assert cache_file.read_text() == before


def test_cache_used_only_for_the_same_device_and_fresh(cache_file):
    now = datetime(2026, 10, 6, 15, 0, tzinfo=timezone.utc)
    write_cache(cache_file, now=now, age=timedelta(days=6, hours=23))
    assert a.load_cache(str(cache_file), "fake123", 7, now).measured.inject.min == 70
    for kwargs in ({"serial": "other"}, {"connection": "tcp"},
                   {"age": timedelta(days=7, minutes=1)}, {"age": -timedelta(days=1)}):
        write_cache(cache_file, now=now, **kwargs)
        assert a.load_cache(str(cache_file), "fake123", 7, now) is None, kwargs


def test_tcp_cache_matches_tcp_serial(cache_file):
    now = datetime(2026, 10, 6, 15, 0, tzinfo=timezone.utc)
    write_cache(cache_file, serial="192.168.1.5:5555", connection="tcp", now=now)
    assert a.load_cache(str(cache_file), "192.168.1.5:5555", 7, now) is not None
    assert a.connection_type("adb-abc._adb-tls-connect._tcp") == "tcp"
    assert a.connection_type("a1b2c3d4") == "usb"


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
    assert a.load_cache(str(cache_file), "fake123", 7, now) is None
    assert "ignored" in caplog.text


def test_broken_cache_does_not_stop_the_run(monkeypatch, caplog, cache_file):
    cache_file.write_text("{not json")
    assert run_with(monkeypatch, FakeDevice(), ["--dry-run", "--test-in", "30"]) == a.EXIT_OK
    assert "is unreadable" in caplog.text
    assert "using the standard margin of 150 ms" in caplog.text
