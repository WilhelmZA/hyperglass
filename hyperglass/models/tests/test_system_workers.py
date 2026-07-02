"""Tests for HyperglassSettings.worker_count."""

# flake8: noqa
# Project
from hyperglass.util import cpu_count
from hyperglass.models.system import HyperglassSettings


def _settings(tmp_path, **kwargs):
    return HyperglassSettings(app_path=tmp_path, **kwargs)


def test_explicit_workers_honored(tmp_path):
    assert _settings(tmp_path, debug=False, workers=4).worker_count == 4


def test_workers_clamped_to_at_least_one(tmp_path):
    assert _settings(tmp_path, debug=False, workers=0).worker_count == 1


def test_debug_defaults_to_one(tmp_path):
    assert _settings(tmp_path, debug=True).worker_count == 1


def test_unset_non_debug_uses_cpu_default(tmp_path):
    assert _settings(tmp_path, debug=False).worker_count == cpu_count(2)


def test_explicit_workers_overrides_debug(tmp_path):
    # An explicit worker count wins even in debug mode.
    assert _settings(tmp_path, debug=True, workers=3).worker_count == 3
