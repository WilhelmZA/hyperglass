"""Traceroute Data Models."""

# Standard Library
import typing as t
from ipaddress import ip_address, AddressValueError

# Third Party
from pydantic import field_validator

# Project
from hyperglass.external.ip_enrichment import TargetDetail

# Local
from ..main import HyperglassModel


class TracerouteHop(HyperglassModel):
    """Individual hop in a traceroute."""

    hop_number: int
    ip_address: t.Optional[str] = None
    display_ip: t.Optional[str] = None  # For truncated IPs that can't be validated
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

    # IP enrichment data
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
            if value.endswith("...") or value.endswith(".."):
                return None  # Invalid for BGP enrichment but kept in display_ip
            try:
                ip_address(value)
            except AddressValueError:
                return None
        return value

    @property
    def ip_display(self) -> t.Optional[str]:
        """Get the IP address for display purposes (may be truncated)."""
        return self.display_ip or self.ip_address

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
            # ASN already has "AS" prefix or is "IXP" - use as-is
            return f"{self.asn} ({self.org})"
        elif self.asn and self.asn != "None":
            # ASN already has "AS" prefix or is "IXP" - use as-is  
            return self.asn
        return "Unknown"


class TracerouteResult(HyperglassModel):
    """Complete traceroute result."""

    target: str
    source: str
    hops: t.List[TracerouteHop]
    max_hops: int = 30
    packet_size: int = 60
    raw_output: t.Optional[str] = (
        None  # Store cleaned/processed output for "Copy Raw" functionality (not original raw router output)
    )

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
            if hop.asn and hop.asn not in ["None", None] and hop.asn != current_asn:
                current_asn = hop.asn
                as_path.append(hop.asn)  # hop.asn already has "AS" prefix or is "IXP"

        return " -> ".join(as_path) if as_path else "Unknown"

    @property
    def as_path_detailed(self) -> str:
        """Detailed AS path with organization names."""
        as_path = []
        current_asn = None
        current_org = None

        for hop in self.hops:
            if hop.asn and hop.asn not in ["None", None] and hop.asn != current_asn:
                current_asn = hop.asn  # Already has "AS" prefix or is "IXP"
                current_org = hop.org

                # Format with org name if we have it
                if current_org and current_org not in ["None", None]:
                    if current_asn == "IXP":
                        as_path.append(f"IXP ({current_org})")
                    else:
                        as_path.append(f"{current_asn} ({current_org})")
                else:
                    as_path.append(current_asn)

        return " -> ".join(as_path) if as_path else "Unknown"

    async def enrich_with_ip_enrichment(self):
        """Enrich traceroute hops with IP enrichment data."""
        from hyperglass.external.ip_enrichment import network_info

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
                # ASN field should already be properly formatted from ip_enrichment
                asn_value = data.get("asn")
                if asn_value and asn_value != "None":
                    hop.asn = asn_value  # Use as-is (already has "AS" prefix or is "IXP")
                else:
                    hop.asn = None

                hop.org = data.get("org") if data.get("org") != "None" else None
                hop.prefix = data.get("prefix") if data.get("prefix") != "None" else None
                hop.country = data.get("country") if data.get("country") != "None" else None
                hop.rir = data.get("rir") if data.get("rir") != "None" else None
                hop.allocated = data.get("allocated") if data.get("allocated") != "None" else None
