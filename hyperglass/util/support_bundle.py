"""Build a local, sanitized support bundle for bug reports."""

# Standard Library
import json
import platform
import re
import typing as t
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

# Project
from hyperglass.constants import __version__

_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_SECRET_KEY = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|credential|private[_-]?key)"
)
_ERROR_LEVELS = {"ERROR", "CRITICAL"}


def _redact_text(value: str) -> str:
    """Remove common credentials and IPv4 addresses from free-form log text."""
    value = re.sub(r"(?i)(bearer\s+)[^\s]+", r"\1[REDACTED]", value)
    value = re.sub(r"(?i)(https?://[^/\s:@]+:)[^@\s]+@", r"\1[REDACTED]@", value)
    return _IPV4.sub("[REDACTED-IP]", value)


def _redact(value: t.Any, key: t.Optional[str] = None) -> t.Any:
    """Recursively sanitize JSON-compatible values."""
    if key is not None and _SECRET_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def _tail(path: Path, limit: int) -> t.List[str]:
    """Read only the final lines from a log file."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return list(deque(handle, maxlen=limit))
    except (OSError, UnicodeError):
        return []


def _json_log_errors(path: Path, limit: int) -> t.List[t.Dict[str, t.Any]]:
    """Extract sanitized error records from a Loguru JSON log."""
    errors: t.List[t.Dict[str, t.Any]] = []
    for line in _tail(path, limit):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        source = record.get("record", {})
        level = source.get("level", {}).get("name")
        if level in _ERROR_LEVELS:
            error_record: t.Dict[str, t.Any] = {
                "timestamp": source.get("time", {}).get("repr"),
                "level": level,
                "message": _redact_text(str(source.get("message", ""))),
            }
            exception = source.get("exception")
            if exception:
                error_record["exception"] = _redact(
                    {
                        "type": exception.get("type"),
                        "value": exception.get("value"),
                    }
                )
            errors.append(error_record)
    return errors


def _text_log_errors(path: Path, limit: int) -> t.List[str]:
    """Extract sanitized error lines from a text log."""
    return [
        _redact_text(line.rstrip())
        for line in _tail(path, limit)
        if any(f"[{level}]" in line for level in _ERROR_LEVELS)
    ]


def _query_failures(path: Path, limit: int) -> t.List[t.Dict[str, t.Any]]:
    """Extract only non-sensitive failure metadata from query samples."""
    failures: t.List[t.Dict[str, t.Any]] = []
    for line in _tail(path, limit):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        error = record.get("error")
        if not error:
            continue
        query = record.get("query", {})
        failures.append(
            {
                "timestamp": record.get("timestamp"),
                "query_type": query.get("type"),
                "structured": record.get("structured", False),
                "runtime_s": record.get("runtime_s"),
                "error": _redact(error),
            }
        )
    return failures


def build_support_bundle(
    log_directories: t.Iterable[Path], *, log_lines: int = 200
) -> t.Dict[str, t.Any]:
    """Build a sanitized bundle without reading configuration or contacting a service."""
    bundle: t.Dict[str, t.Any] = {
        "format": 1,
        "product": "Ultraglass",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime": {
            "python": platform.python_version(),
            "system": platform.system(),
            "release": platform.release(),
        },
        "errors": {"json": [], "text": []},
        "query_failures": [],
    }

    seen: t.Set[Path] = set()
    for directory in log_directories:
        directory = directory.expanduser()
        if directory in seen or not directory.is_dir():
            continue
        seen.add(directory)

        json_log = directory / "hyperglass.log.json"
        text_log = directory / "hyperglass.log"
        samples = directory / "hyperglass_query_log.jsonl"

        if json_log.is_file():
            bundle["errors"]["json"].extend(_json_log_errors(json_log, log_lines))
        if text_log.is_file():
            bundle["errors"]["text"].extend(_text_log_errors(text_log, log_lines))
        if samples.is_file():
            bundle["query_failures"].extend(_query_failures(samples, log_lines))

    return bundle


def write_support_bundle(
    output: Path, log_directories: t.Iterable[Path], *, log_lines: int = 200
) -> Path:
    """Write a local support bundle and return its path."""
    output = output.expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(build_support_bundle(log_directories, log_lines=log_lines), indent=2) + "\n",
        encoding="utf-8",
    )
    return output
