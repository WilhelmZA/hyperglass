"""Parse FRR traceroute output to structured data."""

# Standard Library
import re
import typing as t
from ipaddress import ip_address as validate_ip

# Third Party
from pydantic import PrivateAttr

# Project
from hyperglass.log import log
from hyperglass.exceptions.private import ParsingError
from hyperglass.models.data.traceroute import TracerouteResult, TracerouteHop
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


def parse_frr_traceroute(
    output: t.Union[str, t.Sequence[str]], target: str, source: str
) -> "OutputDataModel":
    """Parse an FRR traceroute text response."""
    result = None
    out_list = _normalize_output(output)

    _log = log.bind(plugin=TraceroutePluginFrr.__name__)
    combined_output = "\n".join(out_list)

    # DEBUG: Log the raw output we're about to parse
    _log.debug(f"=== FRR TRACEROUTE PLUGIN RAW INPUT ===")
    _log.debug(f"Target: {target}, Source: {source}")
    _log.debug(f"Output pieces: {len(out_list)}")
    _log.debug(f"Combined output length: {len(combined_output)}")
    _log.debug(f"First 500 chars: {repr(combined_output[:500])}")
    _log.debug(f"=== END PLUGIN RAW INPUT ===")

    try:
        result = FrrTracerouteTable.parse_text(combined_output, target, source)
    except Exception as exc:
        _log.error(f"Failed to parse FRR traceroute: {exc}")
        raise ParsingError(f"Failed to parse FRR traceroute output: {exc}") from exc

    _log.debug(f"=== FINAL STRUCTURED TRACEROUTE RESULT ===")
    _log.debug(f"Successfully parsed {len(result.hops)} traceroute hops")
    _log.debug(f"Target: {target}, Source: {source}")
    for hop in result.hops:
        _log.debug(f"Hop {hop.hop_number}: {hop.ip_address or '*'} - RTT: {hop.rtt1 or 'timeout'}")
    _log.debug(f"Raw output length: {len(combined_output)} characters")
    _log.debug(f"=== END STRUCTURED RESULT ===")

    return result


class FrrTracerouteTable(TracerouteResult):
    """FRR traceroute table parser."""

    @classmethod
    def parse_text(cls, text: str, target: str, source: str) -> TracerouteResult:
        """Parse FRR traceroute text output into structured data."""
        _log = log.bind(parser="FrrTracerouteTable")

        _log.debug(f"=== RAW FRR TRACEROUTE INPUT ===")
        _log.debug(f"Target: {target}, Source: {source}")
        _log.debug(f"Raw text length: {len(text)} characters")
        _log.debug(f"Raw text:\n{repr(text)}")
        _log.debug(f"=== END RAW INPUT ===")

        hops = []

        # Parse the traceroute output line by line
        lines = text.strip().split("\n")
        _log.debug(f"Split into {len(lines)} lines")

        # Patterns for different line formats
        # Pattern for regular hop: " 1  102.216.76.37  0.221 ms"
        simple_pattern = re.compile(r"^\s*(\d+)\s+([\d\.:a-fA-F]+)\s+([\d.]+)\s+ms")

        # Pattern for timeout hop: " 9  *"
        timeout_pattern = re.compile(r"^\s*(\d+)\s+\*\s*$")

        # Pattern for hop with hostname: " 2  hostname.example.com (192.168.1.1)  15.234 ms"
        hostname_pattern = re.compile(r"^\s*(\d+)\s+(\S+)\s+\(([\d\.:a-fA-F]+)\)\s+([\d.]+)\s+ms")

        # Pattern for multiple RTTs: " 3  192.168.1.1  15.234 ms  16.123 ms  14.567 ms"
        multi_rtt_pattern = re.compile(
            r"^\s*(\d+)\s+([\d\.:a-fA-F]+)\s+([\d.]+)\s+ms(?:\s+([\d.]+)\s+ms)?(?:\s+([\d.]+)\s+ms)?"
        )

        # Pattern for partial timeout: " 7  port-channel4.core4.mrs1.he.net (184.105.81.30)  132.624 ms  132.589 ms *"
        partial_timeout_pattern = re.compile(
            r"^\s*(\d+)\s+(\S+)\s+\(([\d\.:a-fA-F]+)\)\s+(?:([\d.]+)\s+ms\s+)?(?:([\d.]+)\s+ms\s+)?\*"
        )

        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue

            _log.debug(f"Line {i:2}: {repr(line)}")

            # Skip header lines
            if "traceroute to" in line.lower() or "hops max" in line.lower():
                _log.debug(f"Line {i:2}: SKIPPING HEADER")
                continue

            hop_number = None
            ip_address = None
            hostname = None
            rtt1 = None
            rtt2 = None
            rtt3 = None

            # Try to match timeout hop first
            timeout_match = timeout_pattern.match(line)
            if timeout_match:
                hop_number = int(timeout_match.group(1))
                _log.debug(f"Line {i:2}: TIMEOUT HOP - {hop_number}")

            # Try to match partial timeout
            elif partial_timeout_pattern.match(line):
                partial_match = partial_timeout_pattern.match(line)
                hop_number = int(partial_match.group(1))
                hostname = partial_match.group(2)
                ip_address = partial_match.group(3)
                rtt1 = float(partial_match.group(4)) if partial_match.group(4) else None
                rtt2 = float(partial_match.group(5)) if partial_match.group(5) else None
                _log.debug(
                    f"Line {i:2}: PARTIAL TIMEOUT HOP - {hop_number}: {hostname} ({ip_address}) {rtt1} {rtt2} *"
                )

            # Try to match hostname pattern
            elif hostname_pattern.match(line):
                hostname_match = hostname_pattern.match(line)
                hop_number = int(hostname_match.group(1))
                hostname = hostname_match.group(2)
                ip_address = hostname_match.group(3)
                rtt1 = float(hostname_match.group(4))
                _log.debug(
                    f"Line {i:2}: HOSTNAME HOP - {hop_number}: {hostname} ({ip_address}) {rtt1} ms"
                )

            # Try to match multiple RTT pattern
            elif multi_rtt_pattern.match(line):
                multi_match = multi_rtt_pattern.match(line)
                hop_number = int(multi_match.group(1))
                ip_address = multi_match.group(2)
                rtt1 = float(multi_match.group(3))
                rtt2 = float(multi_match.group(4)) if multi_match.group(4) else None
                rtt3 = float(multi_match.group(5)) if multi_match.group(5) else None
                _log.debug(
                    f"Line {i:2}: MULTI RTT HOP - {hop_number}: {ip_address} {rtt1} {rtt2} {rtt3}"
                )

            # Try to match simple pattern
            elif simple_pattern.match(line):
                simple_match = simple_pattern.match(line)
                hop_number = int(simple_match.group(1))
                ip_address = simple_match.group(2)
                rtt1 = float(simple_match.group(3))
                _log.debug(f"Line {i:2}: SIMPLE IP HOP - {hop_number}: {ip_address} {rtt1} ms")

            else:
                _log.debug(f"Line {i:2}: NO MATCH - skipping")
                continue

            # Create hop object if we have valid data
            if hop_number is not None:
                try:
                    # Validate IP address if present
                    if ip_address:
                        validate_ip(ip_address)
                except ValueError:
                    # If IP validation fails, treat as hostname
                    if not hostname:
                        hostname = ip_address
                    ip_address = None

                hop = TracerouteHop(
                    hop_number=hop_number,
                    ip_address=ip_address,
                    display_ip=None,
                    hostname=hostname,
                    rtt1=rtt1,
                    rtt2=rtt2,
                    rtt3=rtt3,
                    sent_count=None,
                    last_rtt=rtt1,
                    best_rtt=(
                        min(filter(None, [rtt1, rtt2, rtt3])) if any([rtt1, rtt2, rtt3]) else None
                    ),
                    worst_rtt=(
                        max(filter(None, [rtt1, rtt2, rtt3])) if any([rtt1, rtt2, rtt3]) else None
                    ),
                    loss_pct=None,
                    # BGP enrichment fields (will be populated by enrichment plugin)
                    asn=None,
                    org=None,
                    prefix=None,
                    country=None,
                    rir=None,
                    allocated=None,
                )
                hops.append(hop)

        # Clean up hops - remove duplicates and sort by hop number
        _log.debug(f"Before cleanup: {len(hops)} hops")

        # Group hops by hop number and merge data
        hop_dict = {}
        for hop in hops:
            if hop.hop_number in hop_dict:
                # Merge data for same hop number
                existing = hop_dict[hop.hop_number]
                # Keep the first non-None value for each field
                hop_dict[hop.hop_number] = TracerouteHop(
                    hop_number=hop.hop_number,
                    ip_address=existing.ip_address or hop.ip_address,
                    display_ip=existing.display_ip or hop.display_ip,
                    hostname=existing.hostname or hop.hostname,
                    rtt1=existing.rtt1 or hop.rtt1,
                    rtt2=existing.rtt2 or hop.rtt2,
                    rtt3=existing.rtt3 or hop.rtt3,
                    sent_count=existing.sent_count or hop.sent_count,
                    last_rtt=existing.last_rtt or hop.last_rtt,
                    best_rtt=existing.best_rtt or hop.best_rtt,
                    worst_rtt=existing.worst_rtt or hop.worst_rtt,
                    loss_pct=existing.loss_pct or hop.loss_pct,
                    asn=existing.asn or hop.asn,
                    org=existing.org or hop.org,
                    prefix=existing.prefix or hop.prefix,
                    country=existing.country or hop.country,
                    rir=existing.rir or hop.rir,
                    allocated=existing.allocated or hop.allocated,
                )
            else:
                hop_dict[hop.hop_number] = hop

        # Convert back to sorted list
        final_hops = [hop_dict[hop_num] for hop_num in sorted(hop_dict.keys())]
        _log.debug(f"After cleanup: {len(final_hops)} hops")

        # Debug final hop list
        for hop in final_hops:
            hostname_display = hop.hostname or "no-hostname"
            _log.debug(
                f"Final hop {hop.hop_number}: {hop.ip_address} ({hostname_display}) - RTTs: {hop.rtt1}/{hop.rtt2}/{hop.rtt3}"
            )

        _log.info(f"Parsed {len(final_hops)} hops from FRR traceroute")

        # Extract packet information from traceroute output
        max_hops = 30  # Default
        packet_size = 60  # FRR default

        # Try to extract from header line
        for line in lines:
            if "hops max" in line.lower():
                try:
                    # Look for pattern like "30 hops max, 60 byte packets"
                    match = re.search(r"(\d+)\s+hops\s+max.*?(\d+)\s+byte", line)
                    if match:
                        max_hops = int(match.group(1))
                        packet_size = int(match.group(2))
                        break
                except (ValueError, AttributeError):
                    pass

        return TracerouteResult(
            target=target,
            source=source,
            hops=final_hops,
            max_hops=max_hops,
            packet_size=packet_size,
            raw_output=text,
            asn_organizations={},
        )


class TraceroutePluginFrr(OutputPlugin):
    """Parse FRR traceroute output."""

    _hyperglass_builtin: bool = PrivateAttr(True)
    platforms: t.Sequence[str] = ("frr",)
    directives: t.Sequence[str] = ("__hyperglass_frr_traceroute__",)
    common: bool = False

    def process(self, output: "OutputType", query: "Query") -> "OutputType":
        """Process FRR traceroute output."""
        # Extract target and source with fallbacks
        target = str(query.query_target) if query.query_target else "unknown"
        source = "unknown"

        if hasattr(query, "device") and query.device:
            source = getattr(query.device, "display_name", None) or getattr(
                query.device, "name", "unknown"
            )

        # Logging
        _log = log.bind(plugin="TraceroutePluginFrr")
        _log.info(f"Processing Traceroute for {target} from {source}")

        device = getattr(query, "device", None)
        if device is not None:
            if not getattr(device, "structured_output", False):
                return output
            try:
                _params = use_state("params")
            except Exception:
                _params = None
            if (
                _params
                and getattr(_params, "structured", None)
                and getattr(_params.structured, "enable_for_traceroute", None) is False
            ):
                return output
        else:
            try:
                params = use_state("params")
            except Exception:
                params = None
            if not (params and getattr(params, "structured", None)):
                return output
            if getattr(params.structured, "enable_for_traceroute", None) is False:
                return output

        # Parse traceroute output
        return parse_frr_traceroute(
            output=output,
            target=target,
            source=source,
        )
