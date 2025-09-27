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

# File paths for persistent storage
IP_ENRICHMENT_DATA_DIR = Path("/etc/hyperglass/ip_enrichment")
CIDR_DATA_FILE = IP_ENRICHMENT_DATA_DIR / "cidr_data.json"
ASN_DATA_FILE = IP_ENRICHMENT_DATA_DIR / "asn_data.json"
IXP_DATA_FILE = IP_ENRICHMENT_DATA_DIR / "ixp_data.json"
LAST_UPDATE_FILE = IP_ENRICHMENT_DATA_DIR / "last_update.txt"

# Raw data files for debugging/inspection
RAW_TABLE_FILE = IP_ENRICHMENT_DATA_DIR / "table.jsonl"
RAW_ASNS_FILE = IP_ENRICHMENT_DATA_DIR / "asns.csv"

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


def should_refresh_data(force_refresh: bool = False) -> tuple[bool, str]:
    """Check if data should be refreshed and return reason."""
    if force_refresh:
        return True, "Force refresh requested"
    
    if not LAST_UPDATE_FILE.exists():
        return True, "No timestamp file found"
    
    # Check required files exist
    required_files = [CIDR_DATA_FILE, ASN_DATA_FILE, IXP_DATA_FILE]
    missing_files = [f.name for f in required_files if not f.exists()]
    if missing_files:
        return True, f"Missing data files: {', '.join(missing_files)}"
    
    # Check file age
    try:
        with open(LAST_UPDATE_FILE, "r") as f:
            cached_time = datetime.fromisoformat(f.read().strip())
        
        age_seconds = (datetime.now() - cached_time).total_seconds()
        cache_duration = get_cache_duration()
        
        if age_seconds >= cache_duration:
            age_hours = age_seconds / 3600
            return True, f"Data expired (age: {age_hours:.1f}h, max: {cache_duration/3600:.1f}h)"
    
    except Exception as e:
        return True, f"Failed to read timestamp: {e}"
    
    return False, "Data is fresh"


def validate_data_files() -> tuple[bool, str]:
    """Validate that data files contain reasonable data."""
    try:
        # Check CIDR data
        if CIDR_DATA_FILE.exists():
            with open(CIDR_DATA_FILE, "r") as f:
                cidr_data = json.load(f)
            if not isinstance(cidr_data, list) or len(cidr_data) < 1000:
                return False, f"CIDR data invalid or too small: {len(cidr_data) if isinstance(cidr_data, list) else 'not a list'}"
        
        # Check ASN data
        if ASN_DATA_FILE.exists():
            with open(ASN_DATA_FILE, "r") as f:
                asn_data = json.load(f)
            if not isinstance(asn_data, dict) or len(asn_data) < 100:
                return False, f"ASN data invalid or too small: {len(asn_data) if isinstance(asn_data, dict) else 'not a dict'}"
        
        return True, "Data files are valid"
    
    except Exception as e:
        return False, f"Data validation failed: {e}"


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

    async def ensure_data_loaded(self, force_refresh: bool = False) -> bool:
        """Ensure data is loaded and fresh from persistent files."""
        # Create data directory if it doesn't exist
        IP_ENRICHMENT_DATA_DIR.mkdir(parents=True, exist_ok=True)

        # Check if refresh is needed
        should_refresh, reason = should_refresh_data(force_refresh)
        
        if not should_refresh:
            # Validate existing data files
            is_valid, validation_msg = validate_data_files()
            if not is_valid:
                should_refresh = True
                reason = f"Data validation failed: {validation_msg}"
        
        if not should_refresh:
            # Load from existing files
            try:
                with open(CIDR_DATA_FILE, "r") as f:
                    cidr_data = json.load(f)
                with open(ASN_DATA_FILE, "r") as f:
                    asn_data = json.load(f)
                with open(IXP_DATA_FILE, "r") as f:
                    ixp_data = json.load(f)
                with open(LAST_UPDATE_FILE, "r") as f:
                    cached_time = datetime.fromisoformat(f.read().strip())

                age_hours = (datetime.now() - cached_time).total_seconds() / 3600
                log.info(f"Loading IP enrichment data from files (age: {age_hours:.1f}h)")
                log.debug(
                    f"Files contain: {len(cidr_data)} CIDR entries, "
                    f"{len(asn_data)} ASN entries, {len(ixp_data)} IXP networks"
                )
                
                # Convert string IP addresses back to IP objects
                self.cidr_networks = [(ip_address(net), prefixlen, asn, cidr) for net, prefixlen, asn, cidr in cidr_data]
                # ASN data has integer keys that become strings in JSON
                self.asn_info = {int(k): v for k, v in asn_data.items()}
                self.ixp_networks = [(ip_address(net), prefixlen, name) for net, prefixlen, name in ixp_data]
                self.last_update = cached_time
                return True
                
            except Exception as e:
                log.warning(f"Failed to load existing data files: {e} - will refresh")
                should_refresh = True
                reason = f"Failed to load files: {e}"

        # Download fresh data
        log.info(f"Refreshing IP enrichment data: {reason}")
        
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

            # Save the data to persistent files
            log.debug("💾 Saving IP enrichment data to persistent files...")
            cache_start = datetime.now()
            
            # Convert IP addresses to strings for JSON serialization
            cidr_file_data = [(str(net), prefixlen, asn, cidr) for net, prefixlen, asn, cidr in self.cidr_networks]
            ixp_file_data = [(str(net), prefixlen, name) for net, prefixlen, name in self.ixp_networks]
            
            with open(CIDR_DATA_FILE, "w") as f:
                json.dump(cidr_file_data, f, separators=(',', ':'))  # Compact JSON
            with open(ASN_DATA_FILE, "w") as f:
                json.dump(self.asn_info, f, separators=(',', ':'))
            with open(IXP_DATA_FILE, "w") as f:
                json.dump(ixp_file_data, f, separators=(',', ':'))
            with open(LAST_UPDATE_FILE, "w") as f:
                f.write(datetime.now().isoformat())
                
            cache_duration_actual = (datetime.now() - cache_start).total_seconds()

            self.last_update = datetime.now()
            log.info(f"✅ IP enrichment data loaded successfully!")
            log.info(
                f"📊 Data summary: {len(self.cidr_networks)} CIDR entries, "
                f"{len(self.asn_info)} ASN entries, {len(self.ixp_networks)} IXP networks"
            )
            log.debug(
                f"⏱️  Download time: {download_duration:.1f}s, Save time: {cache_duration_actual:.1f}s"
            )
            return True

        except Exception as e:
            log.error(f"Failed to download IP enrichment data: {e}")
            return False

    async def _download_bgp_data(self, client) -> None:
        """Download BGP.tools data."""
        log.info("📥 Downloading BGP.tools CIDR table from bgp.tools...")
        download_start = datetime.now()
        response = await client.get(BGP_TOOLS_TABLE_URL)
        response.raise_for_status()
        download_time = (datetime.now() - download_start).total_seconds()

        # Save raw file for debugging
        with open(RAW_TABLE_FILE, "w") as f:
            f.write(response.text)

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
                    log.debug(f"Failed to parse CIDR line: {line[:100]} - {e}")
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

        # Save raw file for debugging
        with open(RAW_ASNS_FILE, "w") as f:
            f.write(response.text)

        # Process CSV data
        process_start = datetime.now()
        lines = response.text.strip().split("\n")
        if not lines:
            log.error("Empty ASN data received")
            return
        
        # Debug: log the first few lines to see the format
        log.debug(f"ASN CSV header: {lines[0] if lines else 'NO HEADER'}")
        if len(lines) > 1:
            log.debug(f"ASN CSV first data line: {lines[1]}")
        
        reader = csv.DictReader(lines)
        asn_count = 0
        total_asns = 0
        failed_count = 0
        
        for row in reader:
            total_asns += 1
            try:
                asn_str = row.get("asn", "").strip()
                name = row.get("name", "").strip()
                country = row.get("cc", "").strip()  # Country code from CC column
                
                if not asn_str:
                    failed_count += 1
                    continue
                    
                # Handle ASN formats like "AS12345" or just "12345"
                if asn_str.upper().startswith("AS"):
                    asn = int(asn_str[2:])
                else:
                    asn = int(asn_str)
                    
                if asn > 0 and name:
                    self.asn_info[asn] = {"name": name, "country": country}
                    asn_count += 1
                else:
                    failed_count += 1
                    
            except Exception as e:
                failed_count += 1
                if failed_count < 5:  # Only log first few failures
                    log.debug(f"Failed to parse ASN row {total_asns}: {row} - {e}")
                continue

        process_time = (datetime.now() - process_start).total_seconds()
        log.info(
            f"✅ Downloaded {asn_count}/{total_asns} ASN entries with country codes "
            f"(download: {download_time:.1f}s, process: {process_time:.1f}s, failed: {failed_count})"
        )

    async def _download_ixp_data(self, client) -> None:
        """Download PeeringDB IXP data with rate limiting."""
        log.info("📥 Downloading PeeringDB IXP data from peeringdb.com...")

        try:
            # Get IXLANs (exchange point LANs) with retry
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

            # Add delay to avoid rate limiting
            await asyncio.sleep(1)

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
            
        except Exception as e:
            log.warning(f"Failed to download IXP data (rate limiting?): {e}")
            log.info("Continuing without IXP data - ASN lookups will still work")
            # Don't fail the entire process if IXP data fails
            self.ixp_networks = []

    async def lookup_ip(self, ip_str: str) -> IPInfo:
        """Lookup an IP address and return ASN or IXP information."""
        if not await self.ensure_data_loaded():
            log.warning("IP enrichment data not available")
            return IPInfo(ip_str)

        log.debug(f"Looking up IP {ip_str} - have {len(self.cidr_networks)} CIDR entries, {len(self.asn_info)} ASN entries")

        try:
            target_ip = ip_address(ip_str)
        except ValueError:
            log.debug(f"Invalid IP address: {ip_str}")
            return IPInfo(ip_str)

        # Check if it's a private/special address
        if not (target_ip.is_global or target_ip.is_unspecified):
            log.debug(f"IP {ip_str} is not global/unspecified - skipping lookup")
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
        # For debugging 1.1.1.1, let's check a few entries around it
        if ip_str == "1.1.1.1":
            log.debug(f"Debugging 1.1.1.1 lookup - checking first 10 CIDR entries:")
            for i, (net_addr, prefixlen, asn, cidr_string) in enumerate(self.cidr_networks[:10]):
                try:
                    network = ip_network(f"{net_addr}/{prefixlen}", strict=False)
                    log.debug(f"  Entry {i}: {cidr_string} (AS{asn}) - contains 1.1.1.1: {target_ip in network}")
                except Exception as e:
                    log.debug(f"  Entry {i}: Failed to create network from {net_addr}/{prefixlen}: {e}")
            
            # Also check if we have any 1.1.1.x entries
            matching_entries = []
            for net_addr, prefixlen, asn, cidr_string in self.cidr_networks:
                if "1.1.1" in str(net_addr) or "1.1.1" in cidr_string:
                    matching_entries.append((net_addr, prefixlen, asn, cidr_string))
            log.debug(f"Found {len(matching_entries)} entries containing '1.1.1': {matching_entries[:5]}")
        
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
            except Exception as e:
                if ip_str == "1.1.1.1":  # Only log for our test case
                    log.debug(f"Failed to check network {net_addr}/{prefixlen}: {e}")
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


async def refresh_ip_enrichment_data(force: bool = False) -> bool:
    """Manually refresh IP enrichment data."""
    log.info(f"Manual refresh requested (force={force})")
    return await _service.ensure_data_loaded(force_refresh=force)


def get_data_status() -> dict:
    """Get status information about IP enrichment data."""
    status = {
        "data_directory": str(IP_ENRICHMENT_DATA_DIR),
        "files_exist": {
            "cidr_data": CIDR_DATA_FILE.exists(),
            "asn_data": ASN_DATA_FILE.exists(),
            "ixp_data": IXP_DATA_FILE.exists(),
            "last_update": LAST_UPDATE_FILE.exists(),
            "raw_table": RAW_TABLE_FILE.exists(),
            "raw_asns": RAW_ASNS_FILE.exists(),
        },
        "last_update": None,
        "age_hours": None,
        "data_counts": {
            "cidr_entries": len(_service.cidr_networks),
            "asn_entries": len(_service.asn_info),
            "ixp_networks": len(_service.ixp_networks),
        }
    }
    
    if LAST_UPDATE_FILE.exists():
        try:
            with open(LAST_UPDATE_FILE, "r") as f:
                last_update = datetime.fromisoformat(f.read().strip())
                status["last_update"] = last_update.isoformat()
                status["age_hours"] = (datetime.now() - last_update).total_seconds() / 3600
        except Exception:
            pass
    
    return status


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
