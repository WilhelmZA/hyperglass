"""IP enrichment service - the main network lookup system for hyperglass.

This completely replaces bgp.tools with bulk data approach using:
- BGP.tools static files for CIDR->ASN mapping
- BGP.tools ASN database for ASN->Organization names
- PeeringDB for IXP detection

Core Functions:
- lookup_ip(ip_address) -> ASN number/name OR IXP name
- lookup_asn_name(asn_number) -> ASN organization name
- network_info(*ips) -> bulk lookup (for compatibility)
"""

import asyncio
import json
import csv
import typing as t
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address
from pathlib import Path

from hyperglass.log import log
from hyperglass.state import use_state

# Optional dependencies - graceful fallback if not available
try:
    import httpx
except ImportError:
    log.warning("httpx not available - IP enrichment will be disabled")
    httpx = None

try:
    import aiofiles
except ImportError:
    log.warning("aiofiles not available - IP enrichment will use slower sync I/O")
    aiofiles = None

# Cache keys
CACHE_KEY_CIDR_DATA = "hyperglass.ip_enrichment.cidr_data"
CACHE_KEY_ASN_DATA = "hyperglass.ip_enrichment.asn_data"
CACHE_KEY_IXP_DATA = "hyperglass.ip_enrichment.ixp_data"
CACHE_KEY_LAST_UPDATE = "hyperglass.ip_enrichment.last_update"

# Data URLs
BGP_TOOLS_TABLE_URL = "https://bgp.tools/table.jsonl"
BGP_TOOLS_ASNS_URL = "https://bgp.tools/asns.csv"
PEERINGDB_IXLAN_URL = "https://www.peeringdb.com/api/ixlan"
PEERINGDB_IXPFX_URL = "https://www.peeringdb.com/api/ixpfx"

# Cache duration (24 hours default, configurable)
DEFAULT_CACHE_DURATION = 24 * 60 * 60


def get_cache_duration() -> int:
    """Get cache duration from config, ensuring minimum of 24 hours."""
    try:
        from hyperglass.state import use_state
        params = use_state("params")
        cache_timeout = params.structured.ip_enrichment.cache_timeout
        return max(cache_timeout, DEFAULT_CACHE_DURATION)
    except Exception:
        # Fallback if config not available
        return DEFAULT_CACHE_DURATION


# Simple result classes
class IPInfo:
    """Result of IP lookup."""

    def __init__(
        self,
        ip: str,
        asn: t.Optional[int] = None,
        asn_name: t.Optional[str] = None,
        prefix: t.Optional[str] = None,
        country: t.Optional[str] = None,
        is_ixp: bool = False,
        ixp_name: t.Optional[str] = None,
    ):
        self.ip = ip
        self.asn = asn
        self.asn_name = asn_name
        self.prefix = prefix  # The CIDR prefix from table.jsonl
        self.country = country  # Country code from asns.csv
        self.is_ixp = is_ixp
        self.ixp_name = ixp_name


class IPEnrichmentService:
    """Main IP enrichment service."""

    def __init__(self):
        self.cidr_networks: t.List[t.Tuple[t.Union[IPv4Address, IPv6Address], int, int, str]] = (
            []
        )  # (network, prefixlen, asn, cidr_string)
        self.asn_info: t.Dict[int, t.Dict[str, str]] = {}  # asn -> {name, country}
        self.ixp_networks: t.List[t.Tuple[t.Union[IPv4Address, IPv6Address], int, str]] = (
            []
        )  # (network, prefixlen, ixp_name)
        self.last_update: t.Optional[datetime] = None

    async def ensure_data_loaded(self) -> bool:
        """Ensure data is loaded and fresh."""
        state = use_state()

        # Check if we have cached data that's still fresh
        cached_time = state.get(CACHE_KEY_LAST_UPDATE)
        cache_duration = get_cache_duration()

        if cached_time:
            age_seconds = (datetime.now() - cached_time).total_seconds()
            age_hours = age_seconds / 3600
            log.debug(
                f"Found cached IP enrichment data from {cached_time}, age: {age_hours:.1f} hours"
            )

            if age_seconds < cache_duration:
                # Try to load from cache
                cidr_data = state.get(CACHE_KEY_CIDR_DATA)
                asn_data = state.get(CACHE_KEY_ASN_DATA)
                ixp_data = state.get(CACHE_KEY_IXP_DATA)

                if cidr_data and asn_data and ixp_data:
                    log.info(f"Loading IP enrichment data from cache (age: {age_hours:.1f}h)")
                    log.debug(
                        f"Cache contains: {len(cidr_data)} CIDR entries, "
                        f"{len(asn_data)} ASN entries, {len(ixp_data)} IXP networks"
                    )
                    self.cidr_networks = cidr_data
                    self.asn_info = asn_data
                    self.ixp_networks = ixp_data
                    self.last_update = cached_time
                    return True
                else:
                    log.warning("Cache timestamp exists but data missing - will re-download")
            else:
                log.info(
                    f"Cache expired (age: {age_hours:.1f}h, max: {cache_duration/3600:.1f}h) - will re-download"
                )
        else:
            log.info("No cached IP enrichment data found - will download fresh data")

        # Download fresh data
        if not httpx:
            log.error("httpx not available - cannot download IP enrichment data")
            return False

        try:
            log.info("🌐 Starting fresh IP enrichment data download...")
            download_start = datetime.now()

            async with httpx.AsyncClient(timeout=300) as client:
                # Download BGP data
                await self._download_bgp_data(client)
                # Download IXP data
                await self._download_ixp_data(client)

            download_duration = (datetime.now() - download_start).total_seconds()

            # Cache the data
            log.debug("💾 Caching IP enrichment data to Redis...")
            cache_start = datetime.now()
            state.set(CACHE_KEY_CIDR_DATA, self.cidr_networks)
            state.set(CACHE_KEY_ASN_DATA, self.asn_info)
            state.set(CACHE_KEY_IXP_DATA, self.ixp_networks)
            state.set(CACHE_KEY_LAST_UPDATE, datetime.now())
            cache_duration_actual = (datetime.now() - cache_start).total_seconds()

            self.last_update = datetime.now()
            log.info(f"✅ IP enrichment data loaded successfully!")
            log.info(
                f"📊 Data summary: {len(self.cidr_networks)} CIDR entries, "
                f"{len(self.asn_info)} ASN entries, {len(self.ixp_networks)} IXP networks"
            )
            log.debug(
                f"⏱️  Download time: {download_duration:.1f}s, Cache time: {cache_duration_actual:.1f}s"
            )
            return True

        except Exception as e:
            log.error(f"Failed to download IP enrichment data: {e}")
            return False

    async def _download_bgp_data(self, client: "httpx.AsyncClient") -> None:
        """Download BGP.tools data."""
        log.info("📥 Downloading BGP.tools CIDR table from bgp.tools...")
        download_start = datetime.now()
        response = await client.get(BGP_TOOLS_TABLE_URL)
        response.raise_for_status()
        download_time = (datetime.now() - download_start).total_seconds()

        # Process JSONL data
        process_start = datetime.now()
        cidr_count = 0
        total_lines = len(response.text.strip().split("\n"))
        log.debug(f"Processing {total_lines} lines from CIDR table...")

        for line in response.text.strip().split("\n"):
            if line.strip():
                try:
                    entry = json.loads(line)
                    cidr = entry.get("CIDR")
                    asn = entry.get("ASN")
                    if cidr and asn:
                        network = ip_network(cidr, strict=False)
                        self.cidr_networks.append(
                            (network.network_address, network.prefixlen, asn, cidr)
                        )
                        cidr_count += 1
                except Exception as e:
                    continue

        process_time = (datetime.now() - process_start).total_seconds()
        log.info(
            f"✅ Downloaded {cidr_count}/{total_lines} CIDR entries "
            f"(download: {download_time:.1f}s, process: {process_time:.1f}s)"
        )

        # Sort by prefix length (descending) for longest-match lookup
        sort_start = datetime.now()
        self.cidr_networks.sort(key=lambda x: x[1], reverse=True)
        sort_time = (datetime.now() - sort_start).total_seconds()
        log.debug(f"Sorted CIDR entries by prefix length in {sort_time:.1f}s")

        # Download ASN names
        log.info("📥 Downloading BGP.tools ASN names from bgp.tools...")
        download_start = datetime.now()
        response = await client.get(BGP_TOOLS_ASNS_URL)
        response.raise_for_status()
        download_time = (datetime.now() - download_start).total_seconds()

        # Process CSV data
        process_start = datetime.now()
        reader = csv.DictReader(response.text.strip().split("\n"))
        asn_count = 0
        total_asns = 0
        for row in reader:
            total_asns += 1
            try:
                asn = int(row.get("asn", 0))
                name = row.get("name", "").strip()
                country = row.get("cc", "").strip()  # Country code from CC column
                if asn > 0 and name:
                    self.asn_info[asn] = {"name": name, "country": country}
                    asn_count += 1
            except Exception:
                continue

        process_time = (datetime.now() - process_start).total_seconds()
        log.info(
            f"✅ Downloaded {asn_count}/{total_asns} ASN entries with country codes "
            f"(download: {download_time:.1f}s, process: {process_time:.1f}s)"
        )

    async def _download_ixp_data(self, client: "httpx.AsyncClient") -> None:
        """Download PeeringDB IXP data."""
        log.info("📥 Downloading PeeringDB IXP data from peeringdb.com...")

        # Get IXLANs (exchange point LANs)
        download_start = datetime.now()
        response = await client.get(PEERINGDB_IXLAN_URL)
        response.raise_for_status()
        ixlans = response.json()["data"]
        ixlan_time = (datetime.now() - download_start).total_seconds()

        # Create mapping of ixlan_id -> ixp_name
        ixlan_to_name = {}
        for ixlan in ixlans:
            ixlan_id = ixlan.get("id")
            ixp_name = ixlan.get("name", "")
            if ixlan_id and ixp_name:
                ixlan_to_name[ixlan_id] = ixp_name

        log.debug(f"Found {len(ixlan_to_name)} IXP LANs in {ixlan_time:.1f}s")

        # Get IXP prefixes
        download_start = datetime.now()
        response = await client.get(PEERINGDB_IXPFX_URL)
        response.raise_for_status()
        ixpfxs = response.json()["data"]
        prefix_time = (datetime.now() - download_start).total_seconds()

        # Process IXP prefixes
        process_start = datetime.now()
        ixp_count = 0
        total_prefixes = len(ixpfxs)
        for ixpfx in ixpfxs:
            try:
                prefix = ixpfx.get("prefix")
                ixlan_id = ixpfx.get("ixlan_id")

                if prefix and ixlan_id in ixlan_to_name:
                    network = ip_network(prefix, strict=False)
                    ixp_name = ixlan_to_name[ixlan_id]
                    self.ixp_networks.append((network.network_address, network.prefixlen, ixp_name))
                    ixp_count += 1
            except Exception:
                continue

        process_time = (datetime.now() - process_start).total_seconds()

        # Sort by prefix length (descending) for longest-match lookup
        sort_start = datetime.now()
        self.ixp_networks.sort(key=lambda x: x[1], reverse=True)
        sort_time = (datetime.now() - sort_start).total_seconds()

        log.info(
            f"✅ Downloaded {ixp_count}/{total_prefixes} IXP networks "
            f"(IXLAN: {ixlan_time:.1f}s, prefixes: {prefix_time:.1f}s, "
            f"process: {process_time:.1f}s, sort: {sort_time:.1f}s)"
        )

    async def lookup_ip(self, ip_str: str) -> IPInfo:
        """Lookup an IP address and return ASN or IXP information."""
        if not await self.ensure_data_loaded():
            log.warning("IP enrichment data not available")
            return IPInfo(ip_str)

        try:
            target_ip = ip_address(ip_str)
        except ValueError:
            log.debug(f"Invalid IP address: {ip_str}")
            return IPInfo(ip_str)

        # Check if it's a private/special address
        if not (target_ip.is_global or target_ip.is_unspecified):
            return IPInfo(ip_str)

        # First check IXP networks (more specific usually)
        for net_addr, prefixlen, ixp_name in self.ixp_networks:
            try:
                network = ip_network(f"{net_addr}/{prefixlen}", strict=False)
                if target_ip in network:
                    log.debug(f"Found IXP match for {ip_str}: {ixp_name}")
                    return IPInfo(ip_str, is_ixp=True, ixp_name=ixp_name)
            except Exception:
                continue

        # Then check CIDR networks for ASN
        for net_addr, prefixlen, asn, cidr_string in self.cidr_networks:
            try:
                network = ip_network(f"{net_addr}/{prefixlen}", strict=False)
                if target_ip in network:
                    asn_data = self.asn_info.get(asn, {})
                    asn_name = asn_data.get("name", f"AS{asn}")
                    country = asn_data.get("country", "")
                    log.debug(
                        f"Found ASN match for {ip_str}: AS{asn} ({asn_name}) in {cidr_string}"
                    )
                    return IPInfo(
                        ip_str, asn=asn, asn_name=asn_name, prefix=cidr_string, country=country
                    )
            except Exception:
                continue

        log.debug(f"No enrichment data found for {ip_str}")
        return IPInfo(ip_str)

    async def lookup_asn_name(self, asn: int) -> str:
        """Get the organization name for an ASN."""
        if not await self.ensure_data_loaded():
            return f"AS{asn}"

        asn_data = self.asn_info.get(asn, {})
        return asn_data.get("name", f"AS{asn}")

    async def lookup_asn_country(self, asn: int) -> str:
        """Get the country code for an ASN."""
        if not await self.ensure_data_loaded():
            return ""

        asn_data = self.asn_info.get(asn, {})
        return asn_data.get("country", "")


# Global service instance
_service = IPEnrichmentService()


# Public API functions
async def lookup_ip(ip_address: str) -> IPInfo:
    """Lookup an IP address and return ASN or IXP information."""
    return await _service.lookup_ip(ip_address)


async def lookup_asn_name(asn: int) -> str:
    """Get the organization name for an ASN number."""
    return await _service.lookup_asn_name(asn)


async def lookup_asn_country(asn: int) -> str:
    """Get the country code for an ASN number."""
    return await _service.lookup_asn_country(asn)


# Compatibility functions for existing code
TargetDetail = t.TypedDict(
    "TargetDetail",
    {
        "asn": str,
        "ip": str,
        "prefix": str,
        "country": str,
        "rir": str,
        "allocated": str,
        "org": str,
    },
)

TargetData = t.Dict[str, TargetDetail]


def default_ip_targets(*targets: str) -> t.Tuple[TargetData, t.List[str]]:
    """Filter targets and create default data for private/special addresses."""
    _log = log.bind(source="ip_enrichment")

    default_data: TargetData = {}
    query_targets: t.List[str] = []

    for target in targets:
        try:
            target_ip = ip_address(target)

            # Check for special address types
            special_types = [
                (target_ip.is_loopback, "Loopback Address"),
                (target_ip.is_multicast, "Multicast Address"),
                (target_ip.is_link_local, "Link Local Address"),
                (target_ip.is_private, "Private Address"),
                (target_ip.version == 6 and target_ip.is_site_local, "Site Local Address"),
            ]

            is_special = False
            for check, rir_type in special_types:
                if check:
                    default_data[target] = {
                        "asn": "None",
                        "ip": target,
                        "prefix": "None",
                        "country": "None",
                        "rir": rir_type,
                        "allocated": "None",
                        "org": "None",
                    }
                    is_special = True
                    break

            if not is_special and (target_ip.is_global or target_ip.is_unspecified):
                query_targets.append(target)
            elif not is_special:
                # Other non-global addresses
                default_data[target] = {
                    "asn": "None",
                    "ip": target,
                    "prefix": "None",
                    "country": "None",
                    "rir": "Reserved Address",
                    "allocated": "None",
                    "org": "None",
                }

        except ValueError:
            # Invalid IP address
            default_data[target] = {
                "asn": "None",
                "ip": target,
                "prefix": "None",
                "country": "None",
                "rir": "Invalid Address",
                "allocated": "None",
                "org": "None",
            }

    return default_data, query_targets


async def network_info(*targets: str) -> TargetData:
    """Get network information using IP enrichment - compatibility function."""
    _log = log.bind(source="ip_enrichment")

    default_data, query_targets = default_ip_targets(*targets)

    if not query_targets:
        _log.debug("No valid global IPs to query")
        return default_data

    try:
        _log.info(f"Enriching {len(query_targets)} IP addresses")

        query_data = {}

        # Process each target
        for target in query_targets:
            ip_info = await lookup_ip(target)

            # Convert to TargetDetail format
            if ip_info.is_ixp and ip_info.ixp_name:
                # IXP case - put IXP name in org field
                detail: TargetDetail = {
                    "asn": "None",  # IXPs don't have ASNs in this context
                    "ip": target,
                    "prefix": "None",
                    "country": "None",
                    "rir": "IXP",  # Mark as IXP in RIR field
                    "allocated": "None",
                    "org": ip_info.ixp_name,
                }
            elif ip_info.asn is not None:
                # ASN case - normal network
                detail = {
                    "asn": str(ip_info.asn),
                    "ip": target,
                    "prefix": ip_info.prefix or "None",  # Use the CIDR from table.jsonl
                    "country": ip_info.country or "None",  # Use country code from asns.csv
                    "rir": "UNKNOWN",  # Not available from our enrichment
                    "allocated": "None",  # Not available from our enrichment
                    "org": ip_info.asn_name or "None",
                }
            else:
                # No match found
                detail = {
                    "asn": "None",
                    "ip": target,
                    "prefix": "None",
                    "country": "None",
                    "rir": "Unknown",
                    "allocated": "None",
                    "org": "None",
                }

            query_data[target] = detail

            if ip_info.is_ixp:
                _log.debug(f"Enriched {target}: IXP={ip_info.ixp_name}")
            elif ip_info.asn:
                _log.debug(f"Enriched {target}: AS{ip_info.asn} ({ip_info.asn_name})")
            else:
                _log.debug(f"No enrichment data found for {target}")

    except Exception as e:
        _log.error(f"Error in network_info lookup: {e}")
        # Return default data for all targets on error
        query_data = {}
        for target in query_targets:
            query_data[target] = {
                "asn": "None",
                "ip": target,
                "prefix": "None",
                "country": "None",
                "rir": "Error",
                "allocated": "None",
                "org": "None",
            }

    return {**default_data, **query_data}


def network_info_sync(*targets: str) -> TargetData:
    """Synchronous wrapper for network_info."""
    return asyncio.run(network_info(*targets))


async def network_info_single(target: str) -> TargetDetail:
    """Get network information for a single IP address."""
    result = await network_info(target)
    return result[target]
