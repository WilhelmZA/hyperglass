"""BGP.tools integration - compatibility layer for IP enrichment.""""""

BGP.tools compatibility layer using the central IP enrichment system.

import typing as t

import asyncioThis maintains the same interface as the original bgptools module

from ipaddress import ip_addressbut uses the new centralized ip_enrichment system underneath.

"""

from hyperglass.log import log

from hyperglass.external.ip_enrichment import lookup_ip, lookup_asn_nameimport typing as t

import asyncio

# Type definitions for compatibilityfrom ipaddress import ip_address

TargetDetail = t.TypedDict(

    "TargetDetail",from hyperglass.log import log

    {from hyperglass.external.ip_enrichment import lookup_ip

        "asn": str,

        "ip": str,DEFAULT_KEYS = ("asn", "ip", "prefix", "country", "rir", "allocated", "org")

        "prefix": str,

        "country": str,TargetDetail = t.TypedDict(

        "rir": str,    "TargetDetail",

        "allocated": str,    {

        "org": str,        "asn": str,

    },        "ip": str,

)        "prefix": str, 

        "country": str,

TargetData = t.Dict[str, TargetDetail]        "rir": str,

        "allocated": str,

        "org": str,

def default_ip_targets(*targets: str) -> t.Tuple[TargetData, t.List[str]]:    }

    """Filter targets and create default data for private/special addresses.""")

    _log = log.bind(source="ip_enrichment")

    TargetData = t.Dict[str, TargetDetail]

    default_data: TargetData = {}

    query_targets: t.List[str] = []

    def default_ip_targets(*targets: str) -> t.Tuple[TargetData, t.List[str]]:

    for target in targets:    """Filter targets and create default data for private/special addresses."""

        try:    _log = log.bind(source="bgptools_targets")

            target_ip = ip_address(target)    

                default_data: TargetData = {}

            # Check for special address types    query_targets: t.List[str] = []

            special_types = [    

                (target_ip.is_loopback, "Loopback Address"),    for target in targets:

                (target_ip.is_multicast, "Multicast Address"),        try:

                (target_ip.is_link_local, "Link Local Address"),            target_ip = ip_address(target)

                (target_ip.is_private, "Private Address"),            

                (target_ip.version == 6 and target_ip.is_site_local, "Site Local Address"),            # Check for special address types

            ]            special_types = [

                            (target_ip.is_loopback, "Loopback Address"),

            is_special = False                (target_ip.is_multicast, "Multicast Address"), 

            for check, rir_type in special_types:                (target_ip.is_link_local, "Link Local Address"),

                if check:                (target_ip.is_private, "Private Address"),

                    default_data[target] = {                (target_ip.version == 6 and target_ip.is_site_local, "Site Local Address"),

                        "asn": "None",            ]

                        "ip": target,            

                        "prefix": "None",            is_special = False

                        "country": "None",            for check, rir_type in special_types:

                        "rir": rir_type,                if check:

                        "allocated": "None",                    default_data[target] = {

                        "org": "None",                        "asn": "None",

                    }                        "ip": target,

                    is_special = True                        "prefix": "None",

                    break                        "country": "None",

                                    "rir": rir_type,

            if not is_special and (target_ip.is_global or target_ip.is_unspecified):                        "allocated": "None",

                query_targets.append(target)                        "org": "None",

            elif not is_special:                        "ixp_name": "None",

                # Other non-global addresses                        "ixp_description": "None",

                default_data[target] = {                    }

                    "asn": "None",                    is_special = True

                    "ip": target,                    break

                    "prefix": "None",            

                    "country": "None",            if not is_special and (target_ip.is_global or target_ip.is_unspecified):

                    "rir": "Reserved Address",                query_targets.append(target)

                    "allocated": "None",            elif not is_special:

                    "org": "None",                # Other non-global addresses

                }                default_data[target] = {

                                    "asn": "None",

        except ValueError:                    "ip": target, 

            # Invalid IP address                    "prefix": "None",

            default_data[target] = {                    "country": "None",

                "asn": "None",                    "rir": "Reserved Address",

                "ip": target,                    "allocated": "None",

                "prefix": "None",                    "org": "None",

                "country": "None",                    "ixp_name": "None",

                "rir": "Invalid Address",                    "ixp_description": "None",

                "allocated": "None",                }

                "org": "None",                

            }        except ValueError:

                # Invalid IP address

    return default_data, query_targets            default_data[target] = {

                "asn": "None",

                "ip": target,

async def network_info(*targets: str) -> TargetData:                "prefix": "None",

    """Get network information using the central IP enrichment system."""                "country": "None", 

    _log = log.bind(source="ip_enrichment")                "rir": "Invalid Address",

                    "allocated": "None",

    default_data, query_targets = default_ip_targets(*targets)                "org": "None",

                    "ixp_name": "None",

    if not query_targets:                "ixp_description": "None",

        _log.debug("No valid global IPs to query")            }

        return default_data    

        return default_data, query_targets

    try:

        _log.info(f"Enriching {len(query_targets)} IP addresses")CACHE_KEY = "hyperglass.external.bgptools"

        BULK_DATA_CACHE_KEY = "hyperglass.external.bgptools.bulk_data"

        query_data = {}BULK_DATA_EXPIRY_HOURS = 24

        

        # Process each targetTargetDetail = t.TypedDict(

        for target in query_targets:    "TargetDetail",

            ip_info = await lookup_ip(target)    {"asn": str, "ip": str, "prefix": str, "country": str, "rir": str, "allocated": str, "org": str},

            )

            # Convert to TargetDetail format

            if ip_info.is_ixp and ip_info.ixp_name:TargetData = t.Dict[str, TargetDetail]

                # IXP case - put IXP name in org field

                detail: TargetDetail = {# Standard Library

                    "asn": "None",  # IXPs don't have ASNs in this contextimport re

                    "ip": target,import csv

                    "prefix": "None",import json

                    "country": "None",import typing as t

                    "rir": "IXP",  # Mark as IXP in RIR fieldimport asyncio

                    "allocated": "None",from datetime import datetime, timedelta

                    "org": ip_info.ixp_name,from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network

                }

            elif ip_info.asn is not None:# Third Party

                # ASN case - normal networkimport aiohttp

                detail = {

                    "asn": str(ip_info.asn),# Project

                    "ip": target,from hyperglass.log import log

                    "prefix": "None",  # Not available from our enrichmentfrom hyperglass.state import use_state

                    "country": "None", # Not available from our enrichment

                    "rir": "UNKNOWN",  # Not available from our enrichmentDEFAULT_KEYS = ("asn", "ip", "prefix", "country", "rir", "allocated", "org")

                    "allocated": "None", # Not available from our enrichment

                    "org": ip_info.asn_name or "None",CACHE_KEY = "hyperglass.external.bgptools"

                }TABLE_CACHE_KEY = "hyperglass.external.bgptools.table"

            else:ASNS_CACHE_KEY = "hyperglass.external.bgptools.asns"

                # No match foundCACHE_DURATION = 24 * 60 * 60  # 24 hours in seconds

                detail = {

                    "asn": "None",TargetDetail = t.TypedDict(

                    "ip": target,    "TargetDetail",

                    "prefix": "None",)

                    "country": "None",

                    "rir": "Unknown",TargetData = t.Dict[str, TargetDetail]

                    "allocated": "None",

                    "org": "None",

                }class BulkBGPData:

                """Container for bulk BGP.tools data."""

            query_data[target] = detail    

                def __init__(self):

            if ip_info.is_ixp:        self.cidr_to_asn: t.Dict[str, t.Dict[str, t.Any]] = {}  # CIDR -> {ASN, Hits}

                _log.debug(f"Enriched {target}: IXP={ip_info.ixp_name}")        self.asn_to_org: t.Dict[int, t.Dict[str, str]] = {}    # ASN -> {name, class, cc}

            elif ip_info.asn:        self.ipv4_networks: t.List[IPv4Network] = []

                _log.debug(f"Enriched {target}: AS{ip_info.asn} ({ip_info.asn_name})")        self.ipv6_networks: t.List[IPv6Network] = []

            else:        self.loaded_at: t.Optional[datetime] = None

                _log.debug(f"No enrichment data found for {target}")    

        def add_cidr_entry(self, cidr: str, asn: int, hits: int):

    except Exception as e:        """Add a CIDR->ASN mapping entry."""

        _log.error(f"Error in network_info lookup: {e}")        self.cidr_to_asn[cidr] = {"ASN": asn, "Hits": hits}

        # Return default data for all targets on error        try:

        query_data = {}            network = ip_network(cidr, strict=False)

        for target in query_targets:            if network.version == 4:

            query_data[target] = {                self.ipv4_networks.append(network)

                "asn": "None",            else:

                "ip": target,                self.ipv6_networks.append(network)

                "prefix": "None",        except Exception as e:

                "country": "None",            log.warning(f"Invalid CIDR in BGP data: {cidr} - {e}")

                "rir": "Error",    

                "allocated": "None",    def add_asn_entry(self, asn: int, name: str, class_type: str, country: str):

                "org": "None",        """Add an ASN->Organization mapping entry."""

            }        self.asn_to_org[asn] = {

                "name": name,

    return {**default_data, **query_data}            "class": class_type, 

            "cc": country

        }

def network_info_sync(*targets: str) -> TargetData:    

    """Synchronous wrapper for network_info."""    def find_most_specific_cidr(self, ip_addr: str) -> t.Optional[t.Tuple[str, int, int]]:

    return asyncio.run(network_info(*targets))        """Find the most specific CIDR that contains the given IP address.

        

        Returns: (cidr, asn, hits) or None if not found

async def network_info_single(target: str) -> TargetDetail:        """

    """Get network information for a single IP address."""        try:

    result = await network_info(target)            target_ip = ip_address(ip_addr)

    return result[target]        except Exception:
            return None
        
        # Choose the right network list based on IP version
        networks = self.ipv4_networks if target_ip.version == 4 else self.ipv6_networks
        
        most_specific = None
        most_specific_prefix_len = -1
        
        for network in networks:
            if target_ip in network:
                # More specific = longer prefix length
                if network.prefixlen > most_specific_prefix_len:
                    most_specific = network
                    most_specific_prefix_len = network.prefixlen
        
        if most_specific:
            cidr_str = str(most_specific)
            if cidr_str in self.cidr_to_asn:
                entry = self.cidr_to_asn[cidr_str]
                return (cidr_str, entry["ASN"], entry["Hits"])
        
        return None
    
    def lookup_ip(self, ip_addr: str) -> TargetDetail:
        """Lookup IP address and return enriched data."""
        default_data: TargetDetail = {
            "asn": "None",
            "ip": ip_addr,
            "prefix": "None", 
            "country": "None",
            "rir": "UNKNOWN",  # We don't have RIR data in bulk files
            "allocated": "None",  # We don't have allocation dates in bulk files
            "org": "None"
        }
        
        # Check if IP is private/local/etc
        try:
            valid_ip = ip_address(ip_addr)
            checks = [
                (valid_ip.version == 6 and valid_ip.is_site_local, "Site Local Address"),
                (valid_ip.is_loopback, "Loopback Address"),
                (valid_ip.is_multicast, "Multicast Address"),
                (valid_ip.is_link_local, "Link Local Address"),
                (valid_ip.is_private, "Private Address"),
            ]
            for exp, rir in checks:
                if exp:
                    default_data["rir"] = rir
                    return default_data
            
            # Only lookup global addresses
            if not (valid_ip.is_global or valid_ip.is_unspecified or valid_ip.is_reserved):
                return default_data
                
        except Exception:
            return default_data
        
        # Find most specific CIDR
        cidr_result = self.find_most_specific_cidr(ip_addr)
        if not cidr_result:
            return default_data
            
        cidr, asn, hits = cidr_result
        default_data["prefix"] = cidr
        default_data["asn"] = str(asn)
        
        # Lookup ASN organization info
        if asn in self.asn_to_org:
            org_info = self.asn_to_org[asn]
            default_data["org"] = org_info.get("name", "None")
            default_data["country"] = org_info.get("cc", "None")
        
        return default_data


async def download_bulk_data() -> BulkBGPData:
    """Download bulk BGP.tools data files."""
    log.info("Downloading bulk BGP.tools data...")
    bulk_data = BulkBGPData()
    
    async with aiohttp.ClientSession() as session:
        # Download CIDR to ASN mapping
        log.info("Downloading CIDR-to-ASN table...")
        async with session.get("https://bgp.tools/table.jsonl") as response:
            if response.status == 200:
                content = await response.text()
                for line_num, line in enumerate(content.strip().split('\n')):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            cidr = data.get("CIDR")
                            asn = data.get("ASN")
                            hits = data.get("Hits", 0)
                            if cidr and asn:
                                bulk_data.add_cidr_entry(cidr, asn, hits)
                        except Exception as e:
                            log.warning(f"Error parsing CIDR line {line_num}: {e}")
            else:
                log.error(f"Failed to download CIDR table: HTTP {response.status}")
        
        # Download ASN to organization mapping
        log.info("Downloading ASN-to-organization table...")
        async with session.get("https://bgp.tools/asns.csv") as response:
            if response.status == 200:
                content = await response.text()
                reader = csv.DictReader(content.splitlines())
                for row_num, row in enumerate(reader):
                    try:
                        asn_str = row.get("asn", "").replace("AS", "")
                        if asn_str.isdigit():
                            asn = int(asn_str)
                            name = row.get("name", "Unknown")
                            class_type = row.get("class", "Unknown") 
                            country = row.get("cc", "Unknown")
                            bulk_data.add_asn_entry(asn, name, class_type, country)
                    except Exception as e:
                        log.warning(f"Error parsing ASN row {row_num}: {e}")
            else:
                log.error(f"Failed to download ASN table: HTTP {response.status}")
    
    # Sort networks by prefix length (most specific first) for efficient lookup
    bulk_data.ipv4_networks.sort(key=lambda x: x.prefixlen, reverse=True)
    bulk_data.ipv6_networks.sort(key=lambda x: x.prefixlen, reverse=True) 
    bulk_data.loaded_at = datetime.now()
    
    log.info(f"Loaded {len(bulk_data.cidr_to_asn)} CIDR entries and {len(bulk_data.asn_to_org)} ASN entries")
    return bulk_data


async def get_bulk_data() -> BulkBGPData:
    """Get bulk BGP data, downloading if needed or expired."""
    cache = use_state("cache")
    
    # Try to get cached data
    cached_data = cache.get(BULK_DATA_CACHE_KEY)
    if cached_data and isinstance(cached_data, BulkBGPData):
        # Check if data is still fresh (within 24 hours)
        if cached_data.loaded_at and datetime.now() - cached_data.loaded_at < timedelta(hours=BULK_DATA_EXPIRY_HOURS):
            log.debug("Using cached bulk BGP data")
            return cached_data
    
    # Download fresh data
    bulk_data = await download_bulk_data()
    
    # Cache the data
    cache.set(BULK_DATA_CACHE_KEY, bulk_data)
    log.info("Cached fresh bulk BGP data")
    
    return bulk_data


async def download_bgptools_data() -> t.Tuple[t.List[t.Dict], t.Dict[str, str]]:
    """Download BGP.tools bulk data files.
    
    Returns:
        Tuple of (table_data, asn_data) where:
        - table_data: List of CIDR to ASN mappings
        - asn_data: Dict of ASN to organization mappings
    """
    _log = log.bind(source="bgptools_download")
    
    async with aiohttp.ClientSession() as session:
        # Download table.jsonl (CIDR to ASN mappings)
        _log.info("Downloading BGP.tools table data")
        async with session.get("https://bgp.tools/table.jsonl") as response:
            if response.status != 200:
                raise Exception(f"Failed to download table.jsonl: HTTP {response.status}")
            
            table_data = []
            async for line in response.content:
                line = line.decode('utf-8').strip()
                if line:
                    try:
                        entry = json.loads(line)
                        table_data.append(entry)
                    except json.JSONDecodeError:
                        continue
        
        _log.info(f"Downloaded {len(table_data)} CIDR to ASN mappings")
        
        # Download asns.csv (ASN to organization mappings)
        _log.info("Downloading BGP.tools ASN data")
        async with session.get("https://bgp.tools/asns.csv") as response:
            if response.status != 200:
                raise Exception(f"Failed to download asns.csv: HTTP {response.status}")
            
            asn_text = await response.text()
            
        # Parse CSV data
        asn_data = {}
        csv_reader = csv.reader(asn_text.splitlines())
        next(csv_reader)  # Skip header
        
        for row in csv_reader:
            if len(row) >= 2:
                asn, org = row[0], row[1]
                asn_data[asn] = org
                
        _log.info(f"Downloaded {len(asn_data)} ASN to organization mappings")
        
    return table_data, asn_data


def find_prefix_for_ip(ip_str: str, table_data: t.List[t.Dict]) -> t.Optional[t.Dict]:
    """Find the most specific prefix that contains the given IP.
    
    Args:
        ip_str: IP address to lookup
        table_data: List of CIDR mappings from BGP.tools
        
    Returns:
        Dict with prefix info or None if not found
    """
    try:
        target_ip = ip_address(ip_str)
    except ValueError:
        return None
        
    best_match = None
    best_prefix_len = -1
    
    for entry in table_data:
        try:
            prefix = ip_network(entry.get('cidr', ''))
            if target_ip in prefix and prefix.prefixlen > best_prefix_len:
                best_match = entry
                best_prefix_len = prefix.prefixlen
        except ValueError:
            continue
            
    return best_match


def default_ip_targets(*targets: str) -> t.Tuple[TargetData, t.Tuple[str, ...]]:
    """Construct a mapping of default data and other data that should be queried.

    Targets in the mapping don't need to be queried and already have default values. Targets in the
    query tuple should be queried.
    """
    default_data = {}
    query = ()
    for target in targets:
        detail: TargetDetail = dict.fromkeys(DEFAULT_KEYS, "None")
        try:
            valid: t.Union[IPv4Address, IPv6Address] = ip_address(target)

            checks = (
                (valid.version == 6 and valid.is_site_local, "Site Local Address"),
                (valid.is_loopback, "Loopback Address"),
                (valid.is_multicast, "Multicast Address"),
                (valid.is_link_local, "Link Local Address"),
                (valid.is_private, "Private Address"),
            )
            for exp, rir in checks:
                if exp is True:
                    detail["rir"] = rir
                    break

            should_query = any((valid.is_global, valid.is_unspecified, valid.is_reserved))

            if not should_query:
                detail["ip"] = str(target)
                default_data[str(target)] = detail
            elif should_query:
                query += (str(target),)

        except ValueError:
            pass

    return default_data, query


async def get_cached_bgptools_data() -> t.Tuple[t.List[t.Dict], t.Dict[str, str]]:
    """Get BGP.tools bulk data from cache or download if expired."""
    cache = use_state("cache")
    _log = log.bind(source="bgptools_cache")
    
    # Check if we have cached data that's still valid
    table_data = cache.get(TABLE_CACHE_KEY)
    asn_data = cache.get(ASNS_CACHE_KEY)
    last_update = cache.get(f"{CACHE_KEY}.last_update")
    
    now = datetime.now().timestamp()
    cache_expired = (
        table_data is None or 
        asn_data is None or 
        last_update is None or 
        (now - last_update) > CACHE_DURATION
    )
    
    if cache_expired:
        _log.info("BGP.tools cache expired or missing, downloading fresh data")
        try:
            table_data, asn_data = await download_bgptools_data()
            
            # Cache the data
            cache.set(TABLE_CACHE_KEY, table_data)
            cache.set(ASNS_CACHE_KEY, asn_data)
            cache.set(f"{CACHE_KEY}.last_update", now)
            
            _log.info("Cached fresh BGP.tools data")
            
        except Exception as e:
            _log.error(f"Failed to download BGP.tools data: {e}")
            # If download failed but we have old cache, use it
            if table_data is not None and asn_data is not None:
                _log.warning("Using expired cache data due to download failure")
            else:
                raise
    else:
        _log.debug("Using cached BGP.tools data")
        
    return table_data, asn_data


async def network_info(*targets: str) -> TargetData:
    """Get comprehensive network information including BGP and IXP data."""
    _log = log.bind(source="enhanced_bgptools")
    
    if BULK_ENRICHMENT_AVAILABLE:
        # Use enhanced bulk enrichment system
        return await _network_info_bulk(*targets)
    else:
        # Fallback to legacy system
        return await _network_info_legacy(*targets)


async def _network_info_bulk(*targets: str) -> TargetData:
    """Network info using bulk enrichment system with IXP detection."""
    _log = log.bind(source="bulk_enrichment")
    
    default_data, query_targets = default_ip_targets(*targets)
    
    if not query_targets:
        _log.debug("No valid global IPs to query")
        return default_data
    
    try:
        _log.info(f"Enriching {len(query_targets)} IP addresses with bulk data")
        
        # Use bulk enrichment for all targets  
        enrichment_results = await enrich_ips_bulk(query_targets)
        
        query_data = {}
        
        for target in query_targets:
            enrichment = enrichment_results.get(target, {})
            
            # Create detailed result
            detail: TargetDetail = {
                "asn": enrichment.get("asn") or "None",
                "ip": target,
                "prefix": "None",  # Not available in bulk enrichment yet
                "country": "None",  # Not available in bulk enrichment yet
                "rir": "UNKNOWN",   # Would need separate RIR lookup
                "allocated": "None", # Would need separate allocation lookup
                "org": enrichment.get("organization") or "None",
                "ixp_name": enrichment.get("ixp_name") or "None",
                "ixp_description": enrichment.get("ixp_description") or "None",
            }
            
            query_data[target] = detail
            
            _log.debug(
                f"Enriched {target}: ASN={detail['asn']}, "
                f"Org={detail['org']}, IXP={detail['ixp_name']}"
            )
            
    except Exception as e:
        _log.error(f"Error in bulk network_info lookup: {e}")
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
                "ixp_name": "None", 
                "ixp_description": "None",
            }
    
    return {**default_data, **query_data}
    """Get ASN, Containing Prefix, and other info about an internet resource using bulk BGP.tools data."""
    _log = log.bind(source="bgptools_lookup")
    
    default_data, query_targets = default_ip_targets(*targets)
    
    if not query_targets:
        return default_data
    
    try:
        # Get bulk BGP.tools data
        table_data, asn_data = await get_cached_bgptools_data()
        
        query_data = {}
        
        for target in query_targets:
            _log.debug(f"Looking up {target}")
            
            # Initialize default values
            detail: TargetDetail = {
                "asn": "None",
                "ip": target,
                "prefix": "None", 
                "country": "None",
                "rir": "None",
                "allocated": "None",
                "org": "None"
            }
            
            # Find the most specific prefix for this IP
            prefix_info = find_prefix_for_ip(target, table_data)
            
            if prefix_info:
                asn = str(prefix_info.get('asn', ''))
                detail.update({
                    "asn": asn,
                    "prefix": prefix_info.get('cidr', 'None'),
                    "country": prefix_info.get('cc', 'None'),
                    "rir": prefix_info.get('rir', 'None'),
                    "allocated": prefix_info.get('date', 'None'),
                })
                
                # Look up organization name from ASN data
                if asn and asn in asn_data:
                    detail["org"] = asn_data[asn]
                    
                _log.debug(f"Found data for {target}: ASN {asn}, Org: {detail['org']}")
            else:
                _log.debug(f"No prefix found for {target}")
            
            query_data[target] = detail
            
    except Exception as e:
        _log.error(f"Error in network_info lookup: {e}")
        # Return default data for all targets on error
        query_data = {t: dict.fromkeys(DEFAULT_KEYS, "None") for t in query_targets}
        for target in query_targets:
            query_data[target]["ip"] = target

    return {**default_data, **query_data}


def network_info_sync(*targets: str) -> TargetData:
    """Get ASN, Containing Prefix, and other info about an internet resource."""
    return asyncio.run(network_info(*targets))
