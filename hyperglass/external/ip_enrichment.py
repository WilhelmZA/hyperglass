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
import time
import fcntl
import json
import csv
import pickle
import typing as t
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address
from pathlib import Path

from hyperglass.log import log
from hyperglass.state import use_state

# Global download coordination lock to prevent multiple workers from downloading simultaneously
# Use a process-wide file lock so separate worker processes (uvicorn/gunicorn workers)
# coordinate; asyncio.Lock is only per-process and doesn't prevent multiple processes
# from downloading concurrently (which caused the 429 flood).


class _ProcessFileLock:
    """Async-friendly process-wide lock using fcntl.flock in a thread executor.

    This provides the same `async with _download_lock:` API but uses a filesystem
    lock file so multiple processes can coordinate.
    """

    def __init__(self, lock_path: Path, timeout: int = 300, poll_interval: float = 0.1):
        self.lock_path = lock_path
        self.timeout = timeout
        self.poll_interval = poll_interval
        self._lock_dir: t.Optional[str] = None
        # Small startup jitter (seconds) to reduce thundering herd on many
        # worker processes starting at the same time.
        self._startup_jitter = 0.25

    def _acquire_blocking(self) -> None:
        # Use an atomic directory creation as the lock primitive. mkdir is
        # atomic on POSIX filesystems and works reliably across processes
        # (and in many container / overlayfs setups where fcntl.flock may be
        # unreliable). We'll create a lock directory alongside the intended
        # lock file path and remove it on release.
        import os

        lock_dir = str(self.lock_path) + ".lck"
        import random

        # Small random sleep before the first attempt to spread mkdir calls
        time.sleep(random.uniform(0, self._startup_jitter))
        start = time.time()

        while True:
            try:
                # Atomic attempt to create the directory; if it succeeds we
                # hold the lock. If it already exists, mkdir will raise
                # FileExistsError and we'll retry until timeout.
                os.mkdir(lock_dir)
                self._lock_dir = lock_dir
                return
            except FileExistsError:
                if (time.time() - start) >= self.timeout:
                    raise TimeoutError(f"Timed out waiting for lock {self.lock_path}")
                time.sleep(self.poll_interval)

    def _release_blocking(self) -> None:
        import os

        try:
            if self._lock_dir:
                try:
                    os.rmdir(self._lock_dir)
                except Exception:
                    # Best effort; ignore errors removing the lock dir
                    pass
                self._lock_dir = None
        except Exception:
            # Nothing we can do on release failure
            pass

    async def __aenter__(self):
        loop = asyncio.get_running_loop()
        # Run blocking acquire in executor
        await loop.run_in_executor(None, self._acquire_blocking)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._release_blocking)


# Instantiate a process-global lock file in the data dir. The data dir may not yet
# exist at import time; the constant path is defined below and we'll initialize
# the actual _download_lock after the paths are declared. (See below.)

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
COMBINED_CACHE_FILE = IP_ENRICHMENT_DATA_DIR / "combined_cache.pickle"

# Backoff marker file written when upstream rate-limits us (HTTP 429). The
# file contains an ISO timestamp until which downloads should be suppressed.
DOWNLOAD_BACKOFF_FILE = IP_ENRICHMENT_DATA_DIR / "download_backoff.txt"

# Raw data files for debugging/inspection
RAW_TABLE_FILE = IP_ENRICHMENT_DATA_DIR / "table.jsonl"
RAW_ASNS_FILE = IP_ENRICHMENT_DATA_DIR / "asns.csv"

# Data URLs
BGP_TOOLS_TABLE_URL = "https://bgp.tools/table.jsonl"
BGP_TOOLS_ASNS_URL = "https://bgp.tools/asns.csv"
PEERINGDB_IXPFX_URL = "https://www.peeringdb.com/api/ixpfx"

# Cache duration (24 hours default, configurable)
DEFAULT_CACHE_DURATION = 24 * 60 * 60


# Lazily-created process-wide download lock. Create this after the data
# directory is ensured to exist to avoid open() failing due to a missing
# parent directory and to ensure the lock file lives under the same path
# for all workers.
_download_lock: t.Optional[_ProcessFileLock] = None


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

    # If a backoff marker exists and it's still in the future, skip refreshes
    try:
        if DOWNLOAD_BACKOFF_FILE.exists():
            with open(DOWNLOAD_BACKOFF_FILE, "r") as f:
                retry_until = datetime.fromisoformat(f.read().strip())
            if datetime.now() < retry_until:
                return False, f"Backoff active until {retry_until.isoformat()}"
            else:
                # Expired backoff - remove the file
                try:
                    DOWNLOAD_BACKOFF_FILE.unlink()
                except Exception:
                    pass
    except Exception:
        # If anything goes wrong reading backoff, ignore and proceed
        pass

    if not LAST_UPDATE_FILE.exists():
        return True, "No timestamp file found"

    # Check each required file individually - if ANY are missing, refresh ALL
    required_files = [
        (CIDR_DATA_FILE, "cidr_data.json"),
        (ASN_DATA_FILE, "asn_data.json"),
        (IXP_DATA_FILE, "ixp_data.json"),
    ]

    missing_files = []
    for file_path, file_name in required_files:
        if not file_path.exists():
            missing_files.append(file_name)

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
                return (
                    False,
                    f"CIDR data invalid or too small: {len(cidr_data) if isinstance(cidr_data, list) else 'not a list'}",
                )

        # Check ASN data
        if ASN_DATA_FILE.exists():
            with open(ASN_DATA_FILE, "r") as f:
                asn_data = json.load(f)
            if not isinstance(asn_data, dict) or len(asn_data) < 100:
                return (
                    False,
                    f"ASN data invalid or too small: {len(asn_data) if isinstance(asn_data, dict) else 'not a dict'}",
                )

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
    """Main IP enrichment service with optimized lookups and pickle cache."""

    def __init__(self):
        self.cidr_networks: t.List[t.Tuple[t.Union[IPv4Address, IPv6Address], int, int, str]] = (
            []
        )  # (network, prefixlen, asn, cidr_string)
        self.asn_info: t.Dict[int, t.Dict[str, str]] = {}  # asn -> {name, country}
        self.ixp_networks: t.List[t.Tuple[t.Union[IPv4Address, IPv6Address], int, str]] = (
            []
        )  # (network, prefixlen, ixp_name)
        self.last_update: t.Optional[datetime] = None

        # Optimized lookup structures - populated after data load
        self._ipv4_networks: t.List[t.Tuple[int, int, int, str]] = (
            []
        )  # (net_int, mask_bits, asn, cidr)
        self._ipv6_networks: t.List[t.Tuple[int, int, int, str]] = (
            []
        )  # (net_int, mask_bits, asn, cidr)
        self._lookup_optimized = False

        # Combined cache for ultra-fast loading
        self._combined_cache: t.Optional[t.Dict[str, t.Any]] = None
        # Per-IP in-memory cache for bgp.tools lookups: ip -> (asn, asn_name, prefix, expires_at)
        self._per_ip_cache: t.Dict[
            str, t.Tuple[t.Optional[int], t.Optional[str], t.Optional[str], float]
        ] = {}
        # Small in-memory cache for per-IP lookups to avoid repeated websocket
        # queries during runtime. Maps ip_str -> (asn, asn_name, prefix)
        self._ip_cache: t.Dict[str, t.Tuple[t.Optional[int], t.Optional[str], t.Optional[str]]] = {}

    def _optimize_lookups(self):
        """Convert IP networks to integer format for faster lookups."""
        if self._lookup_optimized:
            return
        log.debug("Optimizing IP lookup structures...")
        optimize_start = datetime.now()

        self._ipv4_networks = []
        self._ipv6_networks = []

        for net_addr, prefixlen, asn, cidr_string in self.cidr_networks:
            if isinstance(net_addr, IPv4Address):
                net_int = int(net_addr)
                mask_bits = 32 - prefixlen
                self._ipv4_networks.append((net_int, mask_bits, asn, cidr_string))
            else:
                net_int = int(net_addr)
                mask_bits = 128 - prefixlen
                self._ipv6_networks.append((net_int, mask_bits, asn, cidr_string))

        self._ipv4_networks.sort(key=lambda x: x[1])
        self._ipv6_networks.sort(key=lambda x: x[1])

        optimize_time = (datetime.now() - optimize_start).total_seconds()
        log.debug(
            f"Optimized lookups: {len(self._ipv4_networks)} IPv4, {len(self._ipv6_networks)} IPv6 (took {optimize_time:.2f}s)"
        )
        self._lookup_optimized = True

    async def ensure_data_loaded(self, force_refresh: bool = False) -> bool:
        """Ensure data is loaded and fresh from persistent files.

        New behavior: only load PeeringDB IXP prefixes at startup. Do NOT bulk
        download BGP.tools CIDR or ASN data. Per-IP ASN lookups will query the
        bgp.tools API (websocket preferred) on-demand.
        """

        # Create data directory if it doesn't exist
        IP_ENRICHMENT_DATA_DIR.mkdir(parents=True, exist_ok=True)

        # Lazily instantiate the process-wide download lock now that the
        # data directory exists and is guaranteed to be the same path for
        # all worker processes.
        global _download_lock
        if _download_lock is None:
            _download_lock = _ProcessFileLock(IP_ENRICHMENT_DATA_DIR / "download.lock")

        # If a backoff is active, don't try to refresh
        should_refresh, reason = should_refresh_data(force_refresh)

        # If an IXP file exists, load it - we only need IXP prefixes to identify
        # IXPs at runtime. Don't force a full refresh just because other bulk
        # files (cidr/asn) are missing; use whatever IXP data is present on disk.
        try:
            if IXP_DATA_FILE.exists():
                with open(IXP_DATA_FILE, "r") as f:
                    ixp_data = json.load(f)
                self.ixp_networks = [
                    (ip_address(net), prefixlen, name) for net, prefixlen, name in ixp_data
                ]
                log.info(f"Loaded {len(self.ixp_networks)} IXP prefixes from disk")
                return True
        except Exception as e:
            log.warning(f"Failed to load existing IXP data: {e}")

        # Acquire lock and refresh IXP list only
        async with _download_lock:
            # Double-check in case another worker refreshed
            try:
                # Double-check: if another worker already refreshed the IXP file
                # while we were waiting for the lock, load it regardless of the
                # general should_refresh flag.
                if IXP_DATA_FILE.exists():
                    with open(IXP_DATA_FILE, "r") as f:
                        ixp_data = json.load(f)
                    self.ixp_networks = [
                        (ip_address(net), prefixlen, name) for net, prefixlen, name in ixp_data
                    ]
                    log.info(f"Loaded {len(self.ixp_networks)} IXP prefixes from disk (post-lock)")
                    return True
            except Exception:
                pass

            if not httpx:
                log.error("httpx not available - cannot download PeeringDB IXP prefixes")
                return False

            try:
                async with httpx.AsyncClient(timeout=30) as client:
                    await self._download_ixp_data(client)

                # Persist IXP data only if we actually downloaded prefixes.
                ixp_file_data = [
                    (str(net), prefixlen, name) for net, prefixlen, name in self.ixp_networks
                ]

                if len(ixp_file_data) == 0:
                    # If we have no prefixes from the download, do not overwrite an
                    # existing on-disk IXP file (which may contain valid data). This
                    # prevents a failed refresh (e.g., due to rate-limit) from
                    # replacing a previously-good file with an empty list.
                    if IXP_DATA_FILE.exists():
                        log.warning(
                            "Downloaded 0 IXP prefixes; keeping existing '%s' on disk",
                            IXP_DATA_FILE,
                        )
                        return False
                    else:
                        log.warning(
                            "Downloaded 0 IXP prefixes and no existing IXP file present; not persisting"
                        )
                        return False

                tmp_ixp = IXP_DATA_FILE.with_name(IXP_DATA_FILE.name + ".tmp")
                with open(tmp_ixp, "w") as f:
                    json.dump(ixp_file_data, f, separators=(",", ":"))
                import os

                os.replace(tmp_ixp, IXP_DATA_FILE)

                # Update last update marker
                tmp_last = LAST_UPDATE_FILE.with_name(LAST_UPDATE_FILE.name + ".tmp")
                with open(tmp_last, "w") as f:
                    f.write(datetime.now().isoformat())
                os.replace(tmp_last, LAST_UPDATE_FILE)

                self.last_update = datetime.now()
                log.info(f"Refreshed and saved {len(self.ixp_networks)} IXP prefixes")
                return True
            except Exception as e:
                log.error(f"Failed to refresh IXP prefixes: {e}")
                # If rate limited, write a short backoff file to avoid repeated retries
                try:
                    if "429" in str(e) or "Too Many Requests" in str(e):
                        retry_until = datetime.now() + timedelta(minutes=60)
                        with open(
                            DOWNLOAD_BACKOFF_FILE.with_name(DOWNLOAD_BACKOFF_FILE.name + ".tmp"),
                            "w",
                        ) as f:
                            f.write(retry_until.isoformat())
                        import os

                        os.replace(
                            DOWNLOAD_BACKOFF_FILE.with_name(DOWNLOAD_BACKOFF_FILE.name + ".tmp"),
                            DOWNLOAD_BACKOFF_FILE,
                        )
                except Exception:
                    pass
                return False

    async def _download_ixp_data(self, client) -> None:
        """Download PeeringDB IXP prefixes data - simplified approach using only IXPFX."""
        log.info("📥 Downloading PeeringDB IXP prefixes from peeringdb.com...")

        max_retries = 3
        base_delay = 5  # Start with 5 second delay

        for attempt in range(max_retries):
            try:
                if attempt > 0:
                    delay = base_delay * (2**attempt)  # Exponential backoff
                    log.info(f"Retry attempt {attempt + 1}/{max_retries} after {delay}s delay...")
                    await asyncio.sleep(delay)

                # Get IXP prefixes directly - no need for IXLAN lookup
                log.debug("Downloading IXP prefixes...")
                download_start = datetime.now()
                response = await client.get(PEERINGDB_IXPFX_URL)
                response.raise_for_status()
                ixpfxs = response.json()["data"]
                prefix_time = (datetime.now() - download_start).total_seconds()

                # Process IXP prefixes - use a generic IXP name since we don't need specific names
                process_start = datetime.now()
                ixp_count = 0
                total_prefixes = len(ixpfxs)
                failed_prefixes = 0

                for ixpfx in ixpfxs:
                    try:
                        prefix = ixpfx.get("prefix")

                        if prefix:
                            network = ip_network(prefix, strict=False)
                            # Use "IXP Network" as generic name since we only need to know it's an IXP
                            ixp_name = "IXP Network"
                            self.ixp_networks.append(
                                (network.network_address, network.prefixlen, ixp_name)
                            )
                            ixp_count += 1
                        else:
                            failed_prefixes += 1
                    except Exception:
                        failed_prefixes += 1

                process_time = (datetime.now() - process_start).total_seconds()

                # Sort by prefix length (descending) for longest-match lookup
                sort_start = datetime.now()
                self.ixp_networks.sort(key=lambda x: x[1], reverse=True)
                sort_time = (datetime.now() - sort_start).total_seconds()

                log.info(
                    f"✅ Downloaded {ixp_count}/{total_prefixes} IXP networks "
                    f"(download: {prefix_time:.1f}s, process: {process_time:.1f}s, "
                    f"sort: {sort_time:.1f}s, failed: {failed_prefixes})"
                )
                return  # Success - exit retry loop

            except Exception as e:
                if "429" in str(e) or "Too Many Requests" in str(e):
                    if attempt < max_retries - 1:
                        delay = base_delay * (2 ** (attempt + 1))
                        log.warning(
                            f"Rate limited by PeeringDB API (attempt {attempt + 1}/{max_retries}). Retrying in {delay}s..."
                        )
                        continue
                    else:
                        log.error(
                            f"Rate limited by PeeringDB API after {max_retries} attempts. Skipping IXP data."
                        )
                        break
                else:
                    log.warning(
                        f"Failed to download IXP data (attempt {attempt + 1}/{max_retries}): {e}"
                    )
                    if attempt < max_retries - 1:
                        continue
                    break

        # If we get here, all retries failed
        log.warning("Could not download IXP data after retries - continuing without IXP detection")
        log.info("ASN lookups will still work, but IXP networks won't be identified")
        self.ixp_networks = []

    async def _query_bgp_tools_for_ip(
        self, ip_str: str
    ) -> t.Tuple[t.Optional[int], t.Optional[str], t.Optional[str]]:
        """Query bgp.tools for a single IP. Prefer websocket API; fallback to httpx.

        Returns (asn_int, asn_name, prefix) or (None, None, None) on failure.
        """
        # Check cache first
        if ip_str in self._ip_cache:
            return self._ip_cache[ip_str]

        # Try websocket API if websockets package is available
        try:
            import websockets
            import asyncio as _asyncio

            uri = "wss://bgp.tools/ws"
            payload = {"query": "whois", "prefix": ip_str}

            async def ws_query():
                try:
                    async with websockets.connect(uri, ping_interval=None) as ws:
                        await ws.send(json.dumps(payload))
                        resp = await ws.recv()
                        return json.loads(resp)
                except Exception:
                    return None

            loop = asyncio.get_running_loop()
            resp = await ws_query()
        except Exception:
            resp = None

        # HTTP fallback: bgp.tools also exposes a direct lookup endpoint
        if resp is None:
            try:
                if not httpx:
                    return (None, None, None)
                url = f"https://bgp.tools/api/whois/{ip_str}"
                async with httpx.AsyncClient(timeout=15) as client:
                    r = await client.get(url)
                    if r.status_code != 200:
                        return (None, None, None)
                    resp = r.json()
            except Exception:
                return (None, None, None)

        # Parse response - expected keys depend on API; handle common forms
        try:
            # Example response might contain ASN and org
            asn = None
            org = None
            prefix = None

            if isinstance(resp, dict):
                # Attempt common fields
                if "asn" in resp:
                    try:
                        asn = int(resp.get("asn"))
                    except Exception:
                        asn = None
                if "org" in resp:
                    org = resp.get("org")
                if "prefix" in resp:
                    prefix = resp.get("prefix")

                # Some APIs return nested structures
                if not asn and resp.get("data"):
                    data = resp.get("data")
                    if isinstance(data, dict):
                        if "asn" in data:
                            try:
                                asn = int(data.get("asn"))
                            except Exception:
                                asn = None
                        org = org or data.get("org") or data.get("as_name")
                        prefix = prefix or data.get("prefix")

            # Cache result
            self._ip_cache[ip_str] = (asn, org, prefix)
            return (asn, org, prefix)
        except Exception:
            return (None, None, None)

    async def lookup_ip(self, ip_str: str) -> IPInfo:
        """Lookup an IP address and return ASN or IXP information."""
        if not await self.ensure_data_loaded():
            log.warning("IP enrichment data not available")
            return IPInfo(ip_str)

        # Ensure lookup optimization is done
        self._optimize_lookups()

        log.debug(
            f"Looking up IP {ip_str} - have {len(self.cidr_networks)} CIDR entries, {len(self.asn_info)} ASN entries"
        )

        try:
            target_ip = ip_address(ip_str)
        except ValueError:
            log.debug(f"Invalid IP address: {ip_str}")
            return IPInfo(ip_str)

        # Check if it's a private/reserved/loopback address
        if target_ip.is_private or target_ip.is_reserved or target_ip.is_loopback:
            log.debug(f"IP {ip_str} is in private/reserved range - returning AS0 'Private'")
            return IPInfo(ip_str, asn=0, asn_name="Private", prefix="Private Network")

        # First check IXP networks (more specific usually)
        for net_addr, prefixlen, ixp_name in self.ixp_networks:
            try:
                network = ip_network(f"{net_addr}/{prefixlen}", strict=False)
                if target_ip in network:
                    log.debug(f"Found IXP match for {ip_str}: {ixp_name}")
                    return IPInfo(ip_str, is_ixp=True, ixp_name=ixp_name)
            except Exception:
                continue

        # Fast integer-based lookup for ASN
        target_int = int(target_ip)

        if isinstance(target_ip, IPv4Address):
            # Use optimized IPv4 lookup
            for net_int, mask_bits, asn, cidr_string in self._ipv4_networks:
                if (target_int >> mask_bits) == (net_int >> mask_bits):
                    asn_data = self.asn_info.get(asn, {})
                    asn_name = asn_data.get("name", f"AS{asn}")
                    country = asn_data.get("country", "")
                    log.debug(
                        f"Found ASN match for {ip_str}: AS{asn} ({asn_name}) in {cidr_string}"
                    )
                    return IPInfo(
                        ip_str, asn=asn, asn_name=asn_name, prefix=cidr_string, country=country
                    )
        # Not found in local tables - do an on-demand query to bgp.tools
        try:
            asn, asn_name, prefix = await self._query_bgp_tools_for_ip(ip_str)
            if asn:
                # Update asn_info cache (best-effort)
                try:
                    self.asn_info[int(asn)] = {"name": asn_name or f"AS{asn}", "country": ""}
                except Exception:
                    pass
                return IPInfo(ip_str, asn=asn, asn_name=asn_name, prefix=prefix)
        except Exception:
            pass
        # Not found locally - try one-off query
        try:
            asn, asn_name, prefix = asyncio.get_event_loop().run_until_complete(
                self._query_bgp_tools_for_ip(ip_str)
            )
            if asn:
                try:
                    self.asn_info[int(asn)] = {"name": asn_name or f"AS{asn}", "country": ""}
                except Exception:
                    pass
                return IPInfo(ip_str, asn=asn, asn_name=asn_name, prefix=prefix)
        except Exception:
            pass
        else:
            # Use optimized IPv6 lookup
            for net_int, mask_bits, asn, cidr_string in self._ipv6_networks:
                if (target_int >> mask_bits) == (net_int >> mask_bits):
                    asn_data = self.asn_info.get(asn, {})
                    asn_name = asn_data.get("name", f"AS{asn}")
                    country = asn_data.get("country", "")
                    log.debug(
                        f"Found ASN match for {ip_str}: AS{asn} ({asn_name}) in {cidr_string}"
                    )
                    return IPInfo(
                        ip_str, asn=asn, asn_name=asn_name, prefix=cidr_string, country=country
                    )

        # No match found - return AS0 with "Unknown" to indicate missing data
        log.debug(f"No enrichment data found for {ip_str} - returning AS0 'Unknown'")
        return IPInfo(ip_str, asn=0, asn_name="Unknown")

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

    def lookup_ip_direct(self, ip_str: str) -> IPInfo:
        """Direct IP lookup without ensuring data is loaded - for bulk operations."""
        try:
            target_ip = ip_address(ip_str)
        except ValueError as e:
            log.error(f"Invalid IP address: {ip_str}: {e}")
            return IPInfo(ip_str)

        # Check if IP is in private/reserved ranges first
        if target_ip.is_private or target_ip.is_reserved or target_ip.is_loopback:
            log.debug(f"IP {ip_str} is in private/reserved range - returning AS0 'Private'")
            return IPInfo(ip_str, asn=0, asn_name="Private", prefix="Private Network")

        # Check IXP networks first
        for ixp_net, ixp_prefix, ixp_name in self.ixp_networks:
            try:
                ixp_network = ip_network(f"{ixp_net}/{ixp_prefix}")
                if target_ip in ixp_network:
                    log.debug(f"Found IXP match for {ip_str}: {ixp_name}")
                    return IPInfo(ip_str, is_ixp=True, ixp_name=ixp_name)
            except Exception:
                continue

        # Ensure optimized lookup is ready
        if not self._lookup_optimized:
            self._optimize_lookups()

        # Fast integer-based lookup for ASN
        target_int = int(target_ip)

        if isinstance(target_ip, IPv4Address):
            # Use optimized IPv4 lookup
            for net_int, mask_bits, asn, cidr_string in self._ipv4_networks:
                if (target_int >> mask_bits) == (net_int >> mask_bits):
                    asn_data = self.asn_info.get(asn, {})
                    asn_name = asn_data.get("name", f"AS{asn}")
                    country = asn_data.get("country", "")
                    log.debug(
                        f"Found ASN match for {ip_str}: AS{asn} ({asn_name}) in {cidr_string}"
                    )
                    return IPInfo(
                        ip_str, asn=asn, asn_name=asn_name, prefix=cidr_string, country=country
                    )
        else:
            # Use optimized IPv6 lookup
            for net_int, mask_bits, asn, cidr_string in self._ipv6_networks:
                if (target_int >> mask_bits) == (net_int >> mask_bits):
                    asn_data = self.asn_info.get(asn, {})
                    asn_name = asn_data.get("name", f"AS{asn}")
                    country = asn_data.get("country", "")
                    log.debug(
                        f"Found ASN match for {ip_str}: AS{asn} ({asn_name}) in {cidr_string}"
                    )
                    return IPInfo(
                        ip_str, asn=asn, asn_name=asn_name, prefix=cidr_string, country=country
                    )

        # No match found - return AS0 with "Unknown" to indicate missing data
        log.debug(f"No enrichment data found for {ip_str} - returning AS0 'Unknown'")
        return IPInfo(ip_str, asn=0, asn_name="Unknown")


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


async def lookup_asns_bulk(asns: t.List[t.Union[str, int]]) -> t.Dict[str, t.Dict[str, str]]:
    """Bulk lookup ASN organization names and countries.

    Args:
        asns: List of ASN numbers (as strings like "12345" or integers)

    Returns:
        Dict mapping ASN string to {"name": org_name, "country": country_code}
        Example: {"12345": {"name": "Example ISP", "country": "US"}}
    """
    await _service.ensure_data_loaded()

    results = {}
    for asn in asns:
        # Skip non-numeric ASNs like "IXP"
        if asn == "IXP" or asn is None:
            continue

        try:
            asn_int = int(asn)
            asn_data = _service.asn_info.get(asn_int, {})
            results[str(asn)] = {
                "name": asn_data.get("name", f"AS{asn}"),
                "country": asn_data.get("country", ""),
            }
        except (ValueError, TypeError):
            # Skip invalid ASN values
            continue

    return results


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
            "combined_cache": COMBINED_CACHE_FILE.exists(),
            "raw_table": RAW_TABLE_FILE.exists(),
            "raw_asns": RAW_ASNS_FILE.exists(),
        },
        "last_update": None,
        "age_hours": None,
        "data_counts": {
            "cidr_entries": len(_service.cidr_networks),
            "asn_entries": len(_service.asn_info),
            "ixp_networks": len(_service.ixp_networks),
        },
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

        # Load data ONCE for all lookups
        await _service.ensure_data_loaded()

        query_data = {}

        # Process each target without reloading data
        for target in query_targets:
            ip_info = _service.lookup_ip_direct(
                target
            )  # Use direct lookup that doesn't reload data

            # Convert to TargetDetail format
            if ip_info.is_ixp and ip_info.ixp_name:
                # IXP case - put "IXP" in ASN field and IXP name in org field
                detail: TargetDetail = {
                    "asn": "IXP",  # Show "IXP" as the ASN for IXPs
                    "ip": target,
                    "prefix": "None",
                    "country": "None",
                    "rir": "IXP",  # Mark as IXP in RIR field
                    "allocated": "None",
                    "org": ip_info.ixp_name,
                }
            elif ip_info.asn is not None:
                # ASN case - normal network - return just the NUMBER, no AS prefix
                detail = {
                    "asn": str(ip_info.asn),  # Just the number as string, e.g. "12345"
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
