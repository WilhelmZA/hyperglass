"""Traceroute Data Models."""

# Standard Library
import typing as t
from ipaddress import ip_address, AddressValueError

# Third Party
from pydantic import field_validator

# Project
from hyperglass.external.bgptools import TargetDetail

# Local
from ..main import HyperglassModel


class TracerouteHop(HyperglassModel):
    """Individual hop in a traceroute."""

    hop_number: int
    ip_address: t.Optional[str] = None
    hostname: t.Optional[str] = None
    rtt1: t.Optional[float] = None
    rtt2: t.Optional[float] = None
    rtt3: t.Optional[float] = None

    # MikroTik-specific statistics
    loss_pct: t.Optional[int] = None
    sent_count: t.Optional[int] = None
    last_rtt: t.Optional[float] = None
    avg_rtt: t.Optional[float] = None
    best_rtt: t.Optional[float] = None
    worst_rtt: t.Optional[float] = None

    # BGP.tools enriched data
    asn: t.Optional[str] = None
    org: t.Optional[str] = None
    prefix: t.Optional[str] = None
    country: t.Optional[str] = None
    rir: t.Optional[str] = None
    allocated: t.Optional[str] = None

    @field_validator("ip_address")
    def validate_ip_address(cls, value):
        """Validate IP address format."""
        if value is not None:
            # Handle truncated addresses (MikroTik sometimes truncates long IPv6 addresses with ...)
            if value.endswith('...') or value.endswith('..'):
                return None
            try:
                ip_address(value)
            except AddressValueError:
                return None
        return value

    @property
    def avg_rtt(self) -> t.Optional[float]:
        """Calculate average RTT from available measurements."""
        rtts = [rtt for rtt in [self.rtt1, self.rtt2, self.rtt3] if rtt is not None]
        return sum(rtts) / len(rtts) if rtts else None

    @property
    def is_timeout(self) -> bool:
        """Check if this hop is a timeout (no IP and no RTTs)."""
        return self.ip_address is None and all(
            rtt is None for rtt in [self.rtt1, self.rtt2, self.rtt3]
        )

    @property
    def asn_display(self) -> str:
        """Display ASN with organization name."""
        if self.asn and self.org and self.asn != "None" and self.org != "None":
            return f"AS{self.asn} ({self.org})"
        elif self.asn and self.asn != "None":
            return f"AS{self.asn}"
        return "Unknown"


class TracerouteResult(HyperglassModel):
    """Complete traceroute result."""

    target: str
    source: str
    hops: t.List[TracerouteHop]
    max_hops: int = 30
    packet_size: int = 60
    raw_output: t.Optional[str] = None  # Store cleaned output for "Copy Raw" functionality

    @property
    def hop_count(self) -> int:
        """Total number of hops."""
        return len(self.hops)

    @property
    def unique_asns(self) -> t.List[str]:
        """List of unique ASNs encountered in the path."""
        asns = set()
        for hop in self.hops:
            if hop.asn and hop.asn != "None":
                asns.add(hop.asn)
        return sorted(list(asns))

    @property
    def as_path_summary(self) -> str:
        """Summary of AS path traversed."""
        as_path = []
        current_asn = None

        for hop in self.hops:
            if hop.asn and hop.asn != "None" and hop.asn != current_asn:
                current_asn = hop.asn
                as_path.append(hop.asn)

        return " -> ".join([f"AS{asn}" for asn in as_path]) if as_path else "Unknown"

    async def enrich_with_bgptools(self):
        """Enrich traceroute hops with BGP.tools data."""
        from hyperglass.external.bgptools import network_info

        # Extract all IP addresses that need enrichment
        ips_to_lookup = []
        for hop in self.hops:
            if hop.ip_address and hop.asn is None:  # Only lookup if not already enriched
                ips_to_lookup.append(hop.ip_address)

        if not ips_to_lookup:
            return

        # Bulk lookup IP information
        network_data = await network_info(*ips_to_lookup)

        # Enrich hops with the retrieved data
        for hop in self.hops:
            if hop.ip_address in network_data:
                data: TargetDetail = network_data[hop.ip_address]
                hop.asn = data.get("asn", "None")
                hop.org = data.get("org", "None")
                hop.prefix = data.get("prefix", "None")
                hop.country = data.get("country", "None")
                hop.rir = data.get("rir", "None")
                hop.allocated = data.get("allocated", "None")
