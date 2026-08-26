"""Tests for local support bundle generation."""

# Standard Library
import json

# Third Party
from hyperglass.util.support_bundle import build_support_bundle, write_support_bundle


def test_support_bundle_only_includes_sanitized_query_failures(tmp_path):
    """Query samples must not expose targets, devices, raw output, or parsed output."""
    sample = {
        "timestamp": "2026-08-26T10:00:00+00:00",
        "device": {"id": "router-1", "name": "Production Router", "address": "192.0.2.1"},
        "query": {"type": "ping", "target": "198.51.100.5", "location": "Johannesburg"},
        "structured": False,
        "runtime_s": 1.25,
        "error": {"type": "DeviceTimeout", "message": "Timed out connecting to 192.0.2.1"},
        "raw": "private device output",
        "parsed": {"private": "route data"},
    }
    (tmp_path / "hyperglass_query_log.jsonl").write_text(json.dumps(sample) + "\n")

    bundle = build_support_bundle([tmp_path])
    failure = bundle["query_failures"][0]

    assert failure == {
        "timestamp": "2026-08-26T10:00:00+00:00",
        "query_type": "ping",
        "structured": False,
        "runtime_s": 1.25,
        "error": {"type": "DeviceTimeout", "message": "Timed out connecting to [REDACTED-IP]"},
    }
    assert "Production Router" not in json.dumps(bundle)
    assert "private device output" not in json.dumps(bundle)
    assert "route data" not in json.dumps(bundle)


def test_support_bundle_redacts_json_log_secrets_and_addresses(tmp_path):
    """Structured error logs are retained only after basic sanitization."""
    record = {
        "record": {
            "level": {"name": "ERROR"},
            "file": {"name": "/srv/private/source.py"},
            "message": "Request failed for 192.0.2.10",
            "extra": {"password": "do-not-share", "target": "192.0.2.20"},
        }
    }
    (tmp_path / "hyperglass.log.json").write_text(json.dumps(record) + "\n")

    bundle = build_support_bundle([tmp_path])
    serialized = json.dumps(bundle)

    assert "do-not-share" not in serialized
    assert "192.0.2.10" not in serialized
    assert "192.0.2.20" not in serialized
    assert "/srv/private/source.py" not in serialized
    assert "[REDACTED-IP]" in serialized


def test_write_support_bundle_creates_local_json(tmp_path):
    """The command writes a JSON file and does not require application state."""
    output = tmp_path / "nested" / "support.json"

    result = write_support_bundle(output, [tmp_path])

    assert result == output
    assert json.loads(output.read_text())["product"] == "Ultraglass"
