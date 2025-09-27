"""Parser for MikroTik RouterOS (ROS v6/v7) – structured in Huawei style."""

# Standard Library
import re
import typing as t

# Third Party
from pydantic import ConfigDict

# Project
from hyperglass.log import log
from hyperglass.models.data.bgp_route import BGPRoute, BGPRouteTable  # Add BGPRoute import

# Local
from ..main import HyperglassModel

RPKI_STATE_MAP = {
    "invalid": 0,
    "valid": 1,
    "unknown": 2,
    "unverified": 3,
}


def remove_prefix(text: str, prefix: str) -> str:
    if text.startswith(prefix):
        return text[len(prefix) :]
    return text


# Regex to find key=value pairs. The key can contain dots and hyphens.
# The value can be quoted or a single word.
TOKEN_RE = re.compile(r'([a-zA-Z0-9_.-]+)=(".*?"|\S+)')

# Regex to find flags at the beginning of a line (e.g., "Ab   dst-address=...")
FLAGS_RE = re.compile(r"^\s*([DXIAcmsroivmyH\+b]+)\s+")


class MikrotikBase(HyperglassModel, extra="ignore"):
    def __init__(self, **kwargs: t.Any) -> None:
        super().__init__(**kwargs)


class MikrotikPaths(MikrotikBase):
    available: int = 0
    best: int = 0
    select: int = 0
    best_external: int = 0
    add_path: int = 0


class MikrotikRouteEntry(MikrotikBase):
    """MikroTik Route Entry."""

    model_config = ConfigDict(validate_assignment=False)

    prefix: str
    gateway: str = ""
    distance: int = 0
    scope: int = 0
    target_scope: int = 0
    as_path: t.List[int] = []
    communities: t.List[str] = []
    large_communities: t.List[str] = []
    ext_communities: t.List[str] = []
    local_preference: int = 100
    metric: int = 0  # MED
    origin: str = ""
    is_active: bool = False
    is_best: bool = False
    is_valid: bool = False
    rpki_state: int = RPKI_STATE_MAP.get("unknown", 2)

    @property
    def next_hop(self) -> str:
        return self.gateway

    @property
    def age(self) -> int:
        # MikroTik output does not provide route age, returning -1 to indicate unavailable.
        return -1

    @property
    def weight(self) -> int:
        return self.distance

    @property
    def med(self) -> int:
        return self.metric

    @property
    def active(self) -> bool:
        return self.is_active or self.is_best

    @property
    def all_communities(self) -> t.List[str]:
        return self.communities + self.large_communities + self.ext_communities

    @property
    def source_as(self) -> int:
        return self.as_path[-1] if self.as_path else 0

    @property
    def source_rid(self) -> str:
        # MikroTik output does not provide source RID, returning empty string.
        return ""

    @property
    def peer_rid(self) -> str:
        return self.gateway


def _extract_paths(lines: t.List[str]) -> MikrotikPaths:
    """Simple count based on lines with dst/dst-address and 'A' flag."""
    available = 0
    best = 0
    for raw in lines:
        if ("dst-address=" in raw) or (" dst=" in f" {raw} "):
            available += 1
            m = FLAGS_RE.match(raw)
            if m and "A" in m.group(1):
                best += 1
    return MikrotikPaths(available=available, best=best, select=best)


def _process_kv(route: dict, key: str, val: str):
    _log = log.bind(parser="MikrotikBGPTable")
    """Process a key-value pair and update the route dictionary."""
    # Normalize quoted values
    if val.startswith('"') and val.endswith('"'):
        val = val[1:-1]

    if key in ("dst-address", "dst"):
        route["prefix"] = val
    elif key in ("gateway", "nexthop"):
        # Extract only the IP from gateway (e.g., 168.254.0.2%vlan-2000)
        route["gateway"] = val.split("%")[0]
    elif key == "distance":
        route["distance"] = int(val) if val.isdigit() else route.get("distance", 0)
    elif key == "scope":
        route["scope"] = int(val) if val.isdigit() else route.get("scope", 0)
    elif key in ("target-scope", "target_scope"):
        route["target_scope"] = int(val) if val.isdigit() else route.get("target_scope", 0)

    # v7 keys (with dot)
    elif key in (".as-path", "as-path", "bgp-as-path"):
        if val and val.lower() != "none":
            # Find all numbers in the as-path string
            nums = re.findall(r"\b\d{1,10}\b", val)
            route["as_path"] = [int(n) for n in nums if 1 <= int(n) <= 4294967295]
    elif key in (".origin", "origin", "bgp-origin"):
        route["origin"] = val
    elif key in (".med", "med", "bgp-med"):
        route["metric"] = int(val) if val.isdigit() else 0
    elif key in (".local-pref", "local-pref", "bgp-local-pref"):
        route["local_preference"] = int(val) if val.isdigit() else 100
    elif key in (".communities", "communities", "bgp-communities"):
        if val and val.lower() != "none":
            route["communities"] = [c.strip() for c in val.split(",") if c.strip()]
    elif key in (".large-communities", "large-communities", "bgp-large-communities"):
        if val and val.lower() != "none":
            route["large_communities"] = [c.strip() for c in val.split(",") if c.strip()]
    elif key == "bgp-ext-communities":
        if val and val.lower() != "none":
            route["ext_communities"] = [c.strip() for c in val.split(",") if c.strip()]
    elif key == "rpki":
        # _log.debug(f"RPKI raw value: {val!r}")
        clean_val = val.strip().strip('"').lower()
        route["rpki_state"] = RPKI_STATE_MAP.get(clean_val, 2)


def _extract_route_entries(lines: t.List[str]) -> t.List[MikrotikRouteEntry]:
    """Extract route entries from a list of lines."""
    routes: t.List[MikrotikRouteEntry] = []
    current_route_lines = []

    for line in lines:
        stripped_line = line.strip()
        # A new route entry starts with flags or is a continuation line.
        # An empty line signifies the end of the previous block.
        if not stripped_line and current_route_lines:
            # Process the completed route block
            route_data = _parse_route_block(current_route_lines)
            if route_data:
                routes.append(route_data)
            current_route_lines = []
        elif stripped_line:
            # Check if this line is the start of a new entry
            if FLAGS_RE.match(stripped_line) and current_route_lines:
                route_data = _parse_route_block(current_route_lines)
                if route_data:
                    routes.append(route_data)
                current_route_lines = [stripped_line]
            else:
                current_route_lines.append(stripped_line)

    # Process any remaining lines
    if current_route_lines:
        route_data = _parse_route_block(current_route_lines)
        if route_data:
            routes.append(route_data)

    return routes


def _parse_route_block(block: t.List[str]) -> t.Optional[MikrotikRouteEntry]:
    """Parse a single route block and return a MikrotikRouteEntry."""
    if not block:
        return None

    full_block_text = " ".join(block)
    if "dst-address=" not in full_block_text and " dst=" not in f" {full_block_text} ":
        return None

    rd = {
        "prefix": "",
        "gateway": "",
        "distance": 20,
        "scope": 30,
        "target_scope": 10,
        "as_path": [],
        "communities": [],
        "large_communities": [],
        "ext_communities": [],
        "local_preference": 100,
        "metric": 0,
        "origin": "",
        "is_active": False,
        "is_best": False,
        "is_valid": False,
        "rpki_state": RPKI_STATE_MAP.get("unknown", 2),
    }

    # Check for 'A' (active) flag in the first line
    m = FLAGS_RE.match(block[0])
    if m and "A" in m.group(1):
        rd["is_active"] = True
        rd["is_best"] = True

    # Find all key=value tokens in the entire block
    for k, v in TOKEN_RE.findall(full_block_text):
        _process_kv(rd, k, v)

    if rd["prefix"]:
        try:
            return MikrotikRouteEntry(**rd)
        except Exception as e:
            log.warning(f"Failed to create MikroTik route entry ({rd.get('prefix','?')}: {e}")
    return None


class MikrotikBGPRouteTable(BGPRouteTable):
    """Canonical MikroTik BGP Route Table."""

    # No custom __init__ needed; inherit from BGPRouteTable (which should be a Pydantic model)


class MikrotikBGPTable(MikrotikBase):
    """MikroTik BGP Table in canonical format."""

    local_router_id: str = ""
    local_as_number: int = 0
    paths: MikrotikPaths = MikrotikPaths()
    routes: t.List[MikrotikRouteEntry] = []

    @classmethod
    def parse_text(cls, text: str) -> "MikrotikBGPTable":
        _log = log.bind(parser="MikrotikBGPTable")
        inst = cls()

        lines = text.splitlines()
        if not lines:
            return inst

        # Filter out command echoes and header lines
        lines = [ln for ln in lines if not ln.strip().startswith((">", "Flags:", "[", "#"))]

        inst.paths = _extract_paths(lines)
        inst.routes = _extract_route_entries(lines)

        _log.debug(f"Parsed {len(inst.routes)} MikroTik routes")
        return inst

    def bgp_table(self) -> BGPRouteTable:
        routes = []
        for route in self.routes:
            route_data = {
                "prefix": route.prefix,
                "active": route.active,
                "age": route.age,
                "weight": route.weight,
                "med": route.med,
                "local_preference": route.local_preference,
                "as_path": route.as_path,
                "communities": route.all_communities,
                "next_hop": route.next_hop,
                "source_as": route.source_as,
                "source_rid": route.source_rid,
                "peer_rid": route.peer_rid,
                "rpki_state": route.rpki_state,
            }
            # Instantiate BGPRoute to trigger validation (including external RPKI)
            routes.append(BGPRoute(**route_data))
        return MikrotikBGPRouteTable(
            vrf="default",
            count=len(routes),
            routes=routes,
            winning_weight="low",
        )


class MikrotikTracerouteTable(MikrotikBase):
    """MikroTik Traceroute Table."""

    target: str
    source: str
    hops: t.List["MikrotikTracerouteHop"] = []
    max_hops: int = 30
    packet_size: int = 60

    @classmethod
    def parse_text(cls, text: str, target: str, source: str) -> "MikrotikTracerouteTable":
        """Parse MikroTik traceroute output.

        MikroTik traceroute format:
        ADDRESS                          LOSS SENT    LAST     AVG    BEST   WORST STD-DEV STATUS
        102.130.66.77                      0%    3   0.2ms     0.2     0.2     0.2       0
                                         100%    3 timeout
        80.81.193.70                       0%    1   182ms     182     182     182       0
        """
        _log = log.bind(parser="MikrotikTracerouteTable")

        lines = text.strip().split("\n")
        hops = []
        hop_number = 0
        found_header = False

        for line in lines:
            line_stripped = line.strip()

            # Skip empty lines
            if not line_stripped:
                continue

            # Look for header line
            if "ADDRESS" in line_stripped and "LOSS" in line_stripped and "SENT" in line_stripped:
                found_header = True
                continue

            # Process data lines after header
            if found_header and line_stripped:
                hop_number += 1

                # Check if this is a timeout line (no IP address at start)
                if line_stripped.startswith("100%") and "timeout" in line_stripped:
                    hops.append(
                        MikrotikTracerouteHop(
                            hop_number=hop_number,
                            ip_address=None,
                            hostname=None,
                            loss_pct=100,
                            sent_count=3,  # Default MikroTik sends 3 probes
                            last_rtt=None,
                            avg_rtt=None,
                            best_rtt=None,
                            worst_rtt=None,
                        )
                    )
                    continue

                # Parse IP address and timing data
                # Pattern: IP_ADDRESS   LOSS% SENT LAST AVG BEST WORST STD-DEV [STATUS]
                mikrotik_pattern = re.compile(
                    r"^([^\s]+)\s+(\d+)%\s+(\d+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)"
                )

                match = mikrotik_pattern.match(line_stripped)
                if match:
                    ip_address = match.group(1)
                    loss_pct = int(match.group(2))
                    sent_count = int(match.group(3))
                    last_rtt = match.group(4)
                    avg_rtt = match.group(5)
                    best_rtt = match.group(6)
                    worst_rtt = match.group(7)

                    # Convert timing values (handle 'timeout' and numeric values with units)
                    def parse_rtt(rtt_str: str) -> t.Optional[float]:
                        if rtt_str == "timeout" or rtt_str == "-":
                            return None
                        # Remove 'ms' suffix and convert to float
                        rtt_clean = re.sub(r"ms$", "", rtt_str)
                        try:
                            return float(rtt_clean)
                        except ValueError:
                            return None

                    hops.append(
                        MikrotikTracerouteHop(
                            hop_number=hop_number,
                            ip_address=ip_address,
                            hostname=None,  # MikroTik doesn't do reverse DNS in traceroute by default
                            loss_pct=loss_pct,
                            sent_count=sent_count,
                            last_rtt=parse_rtt(last_rtt),
                            avg_rtt=parse_rtt(avg_rtt),
                            best_rtt=parse_rtt(best_rtt),
                            worst_rtt=parse_rtt(worst_rtt),
                        )
                    )
                else:
                    # Handle malformed or aggregated lines like "... (N more timeout hops)"
                    if "more timeout hops" in line_stripped:
                        # Extract count from aggregation message
                        count_match = re.search(r"\((\d+) more timeout hops\)", line_stripped)
                        if count_match:
                            timeout_count = int(count_match.group(1))
                            for _ in range(timeout_count):
                                hop_number += 1
                                hops.append(
                                    MikrotikTracerouteHop(
                                        hop_number=hop_number,
                                        ip_address=None,
                                        hostname=None,
                                        loss_pct=100,
                                        sent_count=3,
                                        last_rtt=None,
                                        avg_rtt=None,
                                        best_rtt=None,
                                        worst_rtt=None,
                                    )
                                )
                    else:
                        # Unknown format, create a timeout hop
                        hops.append(
                            MikrotikTracerouteHop(
                                hop_number=hop_number,
                                ip_address=None,
                                hostname=None,
                                loss_pct=100,
                                sent_count=3,
                                last_rtt=None,
                                avg_rtt=None,
                                best_rtt=None,
                                worst_rtt=None,
                            )
                        )

        result = MikrotikTracerouteTable(target=target, source=source, hops=hops)

        _log.info(f"Parsed {len(hops)} hops from MikroTik traceroute output")
        return result

    def traceroute_result(self):
        """Convert to TracerouteResult format."""
        from hyperglass.models.data.traceroute import TracerouteResult, TracerouteHop

        converted_hops = []
        for hop in self.hops:
            converted_hops.append(
                TracerouteHop(
                    hop_number=hop.hop_number,
                    ip_address=hop.ip_address,
                    hostname=hop.hostname,
                    rtt1=hop.best_rtt,
                    rtt2=hop.avg_rtt,
                    rtt3=hop.worst_rtt,
                    # MikroTik-specific statistics
                    loss_pct=hop.loss_pct,
                    sent_count=hop.sent_count,
                    last_rtt=hop.last_rtt,
                    avg_rtt=hop.avg_rtt,
                    best_rtt=hop.best_rtt,
                    worst_rtt=hop.worst_rtt,
                    # BGP enrichment fields will be populated by enrichment plugin
                    asn=None,
                    org=None,
                    prefix=None,
                    country=None,
                    rir=None,
                    allocated=None,
                )
            )

        return TracerouteResult(
            target=self.target,
            source=self.source,
            hops=converted_hops,
            max_hops=self.max_hops,
            packet_size=self.packet_size,
        )


class MikrotikTracerouteHop(MikrotikBase):
    """Individual MikroTik traceroute hop."""

    hop_number: int
    ip_address: t.Optional[str] = None
    hostname: t.Optional[str] = None

    # MikroTik-specific statistics
    loss_pct: t.Optional[int] = None
    sent_count: t.Optional[int] = None
    last_rtt: t.Optional[float] = None
    avg_rtt: t.Optional[float] = None
    best_rtt: t.Optional[float] = None
    worst_rtt: t.Optional[float] = None

    @property
    def is_timeout(self) -> bool:
        """Check if this hop is a timeout."""
        return self.ip_address is None or self.loss_pct == 100
