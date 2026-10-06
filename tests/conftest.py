"""Fixtures shared by all offline tests, and the hypothesis profiles."""

import os
import sys
from pathlib import Path

import pytest
from hypothesis import settings

# the miunlock package lives in the repository root, next to automate.py
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from miunlock import cli  # noqa: E402  pylint: disable=wrong-import-position

# HYPOTHESIS_PROFILE picks one. No deadline anywhere: a slow (macOS) runner is no bug.
# ci: the same examples on every run - a pull request cannot fail on a random
# counterexample that nobody can reproduce. nightly: random and many; the workflow
# prints the seed, `--hypothesis-seed=N` with this profile repeats the run.
settings.register_profile("dev", deadline=None)
settings.register_profile("ci", derandomize=True, deadline=None, print_blob=True)
settings.register_profile("nightly", max_examples=2000, deadline=None, print_blob=True)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "dev"))


@pytest.fixture(autouse=True)
def cache_file(tmp_path, monkeypatch):
    """Keeps tests away from the real latency cache next to the script."""
    monkeypatch.chdir(tmp_path)          # screenshots / logcat after a tap land here
    path = tmp_path / "latency.json"
    monkeypatch.setattr(cli, "DEFAULT_CACHE_FILE", str(path))
    return path
