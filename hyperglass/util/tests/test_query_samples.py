"""Tests for JSONL query-sample logging."""

# flake8: noqa
# Standard Library
import json
from types import SimpleNamespace

# Project
from hyperglass.models.config.logging import QuerySamples
from hyperglass.util.query_samples import log_query_sample


def _fake_query():
    device = SimpleNamespace(id="dev1", name="Dev One", platform="mikrotik_routeros")
    return SimpleNamespace(
        device=device,
        query_type="bgp_route",
        query_target="1.0.0.0/24",
        query_location="dev1",
    )


def test_disabled_writes_nothing(tmp_path):
    cfg = QuerySamples(enable=False)
    log_query_sample(_fake_query(), cfg, tmp_path, raw=["x"], parsed={"a": 1})
    assert not (tmp_path / "hyperglass_query_log.jsonl").exists()


def test_success_record(tmp_path):
    cfg = QuerySamples(enable=True)
    log_query_sample(
        _fake_query(),
        cfg,
        tmp_path,
        raw=["ADDRESS ... first line"],
        parsed={"count": 2, "routes": []},
        runtime=1.5,
        structured=True,
    )
    f = tmp_path / "hyperglass_query_log.jsonl"
    assert f.exists()
    rec = json.loads(f.read_text().strip())
    assert rec["query"] == {"type": "bgp_route", "target": "1.0.0.0/24", "location": "dev1"}
    assert rec["device"]["platform"] == "mikrotik_routeros"
    assert rec["raw"] == ["ADDRESS ... first line"]
    assert rec["parsed"] == {"count": 2, "routes": []}
    assert rec["structured"] is True
    assert rec["error"] is None
    assert rec["runtime_s"] == 1.5
    assert "timestamp" in rec


def test_failure_record_and_include_flags(tmp_path):
    # include_parsed=False must omit the parsed key entirely; error captured.
    cfg = QuerySamples(enable=True, include_raw=True, include_parsed=False)
    log_query_sample(
        _fake_query(),
        cfg,
        tmp_path,
        raw="raw device text",
        parsed={"should": "be omitted"},
        error=ValueError("empty response"),
        runtime=0.2,
    )
    rec = json.loads((tmp_path / "hyperglass_query_log.jsonl").read_text().strip())
    assert rec["error"]["type"] == "ValueError"
    assert "empty response" in rec["error"]["message"]
    assert rec["raw"] == "raw device text"
    assert "parsed" not in rec


def test_custom_path_and_appends(tmp_path):
    p = tmp_path / "nested" / "custom.jsonl"
    cfg = QuerySamples(enable=True, path=p)
    q = _fake_query()
    log_query_sample(q, cfg, tmp_path, raw=["a"], parsed=None)
    log_query_sample(q, cfg, tmp_path, raw=["b"], parsed=None)
    lines = p.read_text().strip().splitlines()
    assert len(lines) == 2
    assert [json.loads(x)["raw"] for x in lines] == [["a"], ["b"]]


def test_rotation_keeps_single_backup(tmp_path):
    cfg = QuerySamples(enable=True, max_size="200B")
    q = _fake_query()
    for _ in range(20):
        log_query_sample(q, cfg, tmp_path, raw=["x" * 40], parsed=None)
    live = tmp_path / "hyperglass_query_log.jsonl"
    backup = tmp_path / "hyperglass_query_log.jsonl.1"
    assert live.exists() and backup.exists()
