"""Fixtures shared by all offline tests."""

import pytest

from fakes import a


@pytest.fixture(autouse=True)
def cache_file(tmp_path, monkeypatch):
    """Keeps tests away from the real latency cache next to the script."""
    monkeypatch.chdir(tmp_path)          # screenshots / logcat after a tap land here
    path = tmp_path / "latency.json"
    monkeypatch.setattr(a, "DEFAULT_CACHE_FILE", str(path))
    return path
