"""Parse MikroTik traceroute output to structured data."""

# Standard Library
import typing as t

# Third Party
from pydantic import PrivateAttr, ValidationError

# Project
from hyperglass.log import log, log as _log
from hyperglass.exceptions.private import ParsingError
from hyperglass.models.parsing.mikrotik import MikrotikTracerouteTable
from hyperglass.state import use_state

# Local
from .._output import OutputPlugin

if t.TYPE_CHECKING:
    from hyperglass.models.data import OutputDataModel
    from hyperglass.models.api.query import Query
    from .._output import OutputType


def _normalize_output(output: t.Union[str, t.Sequence[str]]) -> t.List[str]:
    """Ensure the output is a list of strings."""
    if isinstance(output, str):
        return [output]
    return list(output)


def _clean_raw_output(output: t.Union[str, t.Sequence[str]], query: "Query"):
    """Run the Mikrotik garbage-output cleaner and return same-shaped result.

    If the original input was a single string, return a string. If it was a
    sequence, return the tuple produced by the cleaner.
    """
    # Import locally to avoid any potential circular imports at module load.
    from .mikrotik_garbage_output import MikrotikGarbageOutput

    out_list = _normalize_output(output)
    cleaner = MikrotikGarbageOutput()
    cleaned = cleaner.process(output=tuple(out_list), query=query)

    if isinstance(output, str):
        return cleaned[0] if cleaned else ""
    return cleaned


def parse_mikrotik_traceroute(
    output: t.Union[str, t.Sequence[str]], target: str, source: str
) -> "OutputDataModel":
    """Parse a MikroTik traceroute text response."""
    result = None
    out_list = _normalize_output(output)

    _log = log.bind(plugin=TraceroutePluginMikrotik.__name__)
    combined_output = "\n".join(out_list)

    # Minimal summary of the input - avoid dumping full raw output to logs
    contains_paging = "-- [Q quit|C-z pause]" in combined_output
    contains_multiple_tables = combined_output.count("ADDRESS") > 1
    _log.debug(
        "Received traceroute plugin input",
        target=target,
        source=source,
        pieces=len(out_list),
        combined_len=len(combined_output),
        contains_paging=contains_paging,
        multiple_tables=contains_multiple_tables,
    )

    try:
        # Pass the entire combined output to the parser at once
        validated = MikrotikTracerouteTable.parse_text(combined_output, target, source)
        result = validated.traceroute_result()

        # Store the CLEANED output (after garbage removal) for "Copy Raw" functionality
        # This is the processed output from MikrotikGarbageOutput plugin, not the original raw router output
        result.raw_output = combined_output

        # Concise structured logging for result
        _log.debug(
            "Parsed traceroute result",
            hops=len(validated.hops),
            target=result.target,
            source=result.source,
        )

    except ValidationError as err:
        _log.critical(err)
        raise ParsingError(err) from err
    except Exception as err:
        _log.bind(error=str(err)).critical("Failed to parse MikroTik traceroute output")
        raise ParsingError("Error parsing traceroute response data") from err

    return result


class TraceroutePluginMikrotik(OutputPlugin):
    """Convert MikroTik traceroute output to structured format."""

    _hyperglass_builtin: bool = PrivateAttr(True)
    platforms: t.Sequence[str] = ("mikrotik_routeros", "mikrotik_switchos", "mikrotik")
    directives: t.Sequence[str] = ("__hyperglass_mikrotik_traceroute__",)

    def process(self, *, output: "OutputType", query: "Query") -> "OutputDataModel":
        """Process the MikroTik traceroute output."""
        # Extract target from query
        target = getattr(query, "target", "unknown")
        source = getattr(query, "source", "unknown")

        # Try to get target from query_target which is more reliable
        if hasattr(query, "query_target") and query.query_target:
            target = str(query.query_target)

        if hasattr(query, "device") and query.device:
            source = getattr(query.device, "name", source)

        # Decide whether to return structured data or the raw output.
        device = getattr(query, "device", None)
        # DEBUG: Log the structured_output and params flag for diagnosis
        try:
            params = use_state("params")
        except Exception:
            params = None
        _log.debug(
            f"MikroTikPlugin: device.structured_output={getattr(device, 'structured_output', None)} params.structured.enable_for_traceroute={getattr(getattr(params, 'structured', None), 'enable_for_traceroute', None)}"
        )

        if device is not None:
            if not getattr(device, "structured_output", False):
                return _clean_raw_output(output, query)
        else:
            try:
                params = use_state("params")
            except Exception:
                params = None
            if not (params and getattr(params, "structured", None)):
                return _clean_raw_output(output, query)
            if getattr(params.structured, "enable_for_traceroute", None) is False:
                return _clean_raw_output(output, query)

        return parse_mikrotik_traceroute(output, target, source)
