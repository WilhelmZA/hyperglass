"""Structured request/response sample logging.

Appends one JSON object per line (JSONL) capturing each query's request, the raw
device output as hyperglass received it, and the parsed/structured result — plus
failures (empty responses, timeouts, parse errors). Intended to be tailed by a
log shipper (e.g. Grafana Alloy) into Loki, and to build a corpus of real
raw+parsed samples for parser regression fixtures.

Enabled via ``logging.samples`` in the hyperglass config; disabled by default.
Writing is best-effort and must never affect the query itself.
"""

# Standard Library
import json
import typing as t
import threading
from pathlib import Path
from datetime import datetime, timezone

# Project
from hyperglass.log import log

if t.TYPE_CHECKING:
    # Project
    from hyperglass.models.api import Query
    from hyperglass.models.config.logging import QuerySamples

# Guards the check-size-then-rotate step within a process. Not needed for the
# appends themselves — see _emit for why concurrent writes are already safe.
_write_lock = threading.Lock()

DEFAULT_FILENAME = "hyperglass_query_log.jsonl"


def _resolve_path(cfg: "QuerySamples", directory: Path) -> Path:
    """Determine the JSONL output path (explicit path, else <directory>/<default>)."""
    if cfg.path is not None:
        return Path(cfg.path)
    return Path(directory) / DEFAULT_FILENAME


def _rotate_if_needed(path: Path, max_size: int) -> None:
    """Size-based rotation: when the file reaches max_size, move it to '<name>.1'.

    A single backup is kept; a log shipper following the live file re-opens on
    rotation. Best-effort — rotation failures never block a write.
    """
    try:
        if max_size and path.exists() and path.stat().st_size >= max_size:
            backup = path.with_name(path.name + ".1")
            if backup.exists():
                backup.unlink()
            path.rename(backup)
    except Exception:  # noqa: BLE001 - rotation is best-effort
        pass


def _normalize_raw(raw: t.Any) -> t.Union[t.List[str], str, None]:
    """Represent raw device output as a list of strings (per command) or a string."""
    if raw is None:
        return None
    if isinstance(raw, (list, tuple)):
        return [r if isinstance(r, str) else str(r) for r in raw]
    return raw if isinstance(raw, str) else str(raw)


def _normalize_parsed(parsed: t.Any) -> t.Any:
    """Represent parsed output as JSON-friendly data (dict/list) or a string."""
    if parsed is None:
        return None
    # Structured hyperglass models expose export_dict().
    export = getattr(parsed, "export_dict", None)
    if callable(export):
        try:
            return export()
        except Exception:  # noqa: BLE001
            pass
    export_json = getattr(parsed, "export_json", None)
    if callable(export_json):
        try:
            return json.loads(export_json())
        except Exception:  # noqa: BLE001
            pass
    if isinstance(parsed, (dict, list, str, int, float, bool)):
        return parsed
    return str(parsed)


def build_sample(
    query: "Query",
    cfg: "QuerySamples",
    *,
    raw: t.Any,
    parsed: t.Any,
    error: t.Optional[BaseException],
    runtime: t.Optional[float],
    structured: bool,
) -> t.Dict[str, t.Any]:
    """Assemble the JSON record for one query, honoring include_raw/include_parsed."""
    device = query.device
    record: t.Dict[str, t.Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "device": {
            "id": getattr(device, "id", None),
            "name": getattr(device, "name", None),
            "platform": getattr(device, "platform", None),
        },
        "query": {
            "type": query.query_type,
            "target": query.query_target,
            "location": query.query_location,
        },
        "structured": structured,
        "runtime_s": runtime,
        "error": None
        if error is None
        else {"type": type(error).__name__, "message": str(error)},
    }
    if cfg.include_raw:
        record["raw"] = _normalize_raw(raw)
    if cfg.include_parsed:
        record["parsed"] = _normalize_parsed(parsed)
    return record


def log_query_sample(
    query: "Query",
    cfg: "QuerySamples",
    directory: Path,
    *,
    raw: t.Any = None,
    parsed: t.Any = None,
    error: t.Optional[BaseException] = None,
    runtime: t.Optional[float] = None,
    structured: bool = False,
) -> None:
    """Append one JSONL sample record. Best-effort; never raises to the caller."""
    if not cfg.enable:
        return
    try:
        path = _resolve_path(cfg, directory)
        record = build_sample(
            query,
            cfg,
            raw=raw,
            parsed=parsed,
            error=error,
            runtime=runtime,
            structured=structured,
        )
        line = json.dumps(record, default=str, ensure_ascii=False)
        _emit(path, line + "\n", int(cfg.max_size))
    except Exception as err:  # noqa: BLE001 - sample logging must not break queries
        log.bind(error=str(err)).debug("Failed to write query sample")


def _emit(path: Path, line: str, max_size: int) -> None:
    """Rotate-if-needed, then append one line. No lock files, no cross-process locks.

    Safe under multiple uvicorn workers because:

    * Each record is written to a file opened in append mode (``O_APPEND``), which
      the Linux kernel guarantees is atomic — concurrent workers cannot interleave
      or overwrite each other's lines, so no lock is needed for the writes.
    * The in-process ``threading.Lock`` only guards the check-size-then-rotate
      step against other async tasks in the same worker.
    * The one thing not serialized across *processes* is the rotation rename. At a
      looking-glass query rate against a large ``max_size`` that collision is
      vanishingly rare, and its only effect would be clobbering a redundant ``.1``
      backup whose lines a shipper (Alloy) has already delivered to Loki. This is
      an intentional trade to avoid lock-file machinery in a best-effort logger.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with _write_lock:
        _rotate_if_needed(path, max_size)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line)
