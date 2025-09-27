"""Parse MikroTik traceroute output to structured data."""

# Standard Library
import typing as t

# Third Party
from pydantic import PrivateAttr, ValidationError

# Project
from hyperglass.log import log
from hyperglass.exceptions.private import ParsingError
from hyperglass.models.parsing.mikrotik import MikrotikTracerouteTable

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


def parse_mikrotik_traceroute(
    output: t.Union[str, t.Sequence[str]], target: str, source: str
) -> "OutputDataModel":
    """Parse a MikroTik traceroute text response."""
    result = None
    out_list = _normalize_output(output)

    _log = log.bind(plugin=TraceroutePluginMikrotik.__name__)
    combined_output = "\n".join(out_list)
    
    # DEBUG: Log the raw output we're about to parse
    _log.debug(f"=== MIKROTIK TRACEROUTE PLUGIN RAW INPUT ===")
    _log.debug(f"Target: {target}, Source: {source}")
    _log.debug(f"Output pieces: {len(out_list)}")
    for i, piece in enumerate(out_list):
        _log.debug(f"Output piece {i}: {repr(piece)}")
    _log.debug(f"Combined output length: {len(combined_output)}")
    _log.debug(f"Combined output: {repr(combined_output)}")
    _log.debug(f"=== END PLUGIN RAW INPUT ===")

    try:
        # Pass the entire combined output to the parser at once
        validated = MikrotikTracerouteTable.parse_text(combined_output, target, source)
        result = validated.traceroute_result()
        
        # DEBUG: Log the final structured result
        _log.debug(f"=== FINAL STRUCTURED TRACEROUTE RESULT ===")
        _log.debug(f"Successfully parsed {len(validated.hops)} traceroute hops")
        _log.debug(f"Target: {result.target}, Source: {result.source}")
        for hop in result.hops:
            _log.debug(f"Hop {hop.hop_number}: {hop.ip_address} - Loss: {hop.loss_pct}% - Sent: {hop.sent_count}")
        _log.debug(f"=== END STRUCTURED RESULT ===")

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
    directives: t.Sequence[str] = ("traceroute", "MikroTik_Traceroute")

    def process(self, *, output: "OutputType", query: "Query") -> "OutputDataModel":
        """Process the MikroTik traceroute output."""
        # Extract target from query
        target = getattr(query, "target", "unknown")
        source = getattr(query, "source", "unknown")

        if hasattr(query, "device") and query.device:
            source = getattr(query.device, "name", source)

        return parse_mikrotik_traceroute(output, target, source)
