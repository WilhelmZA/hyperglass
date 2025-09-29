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
import socket

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
        import random
        import json
        import shutil

        lock_dir = str(self.lock_path) + ".lck"

        # Small random sleep before the first attempt to spread mkdir calls
        time.sleep(random.uniform(0, self._startup_jitter))
        start = time.time()

        while True:
            try:
                # Atomic attempt to create the directory; if it succeeds we
                # hold the lock. If it already exists, mkdir will raise
                # FileExistsError and we'll retry until timeout.
                os.mkdir(lock_dir)

                # Write a small owner metadata file to help debugging stale locks
                try:
                    owner = {"pid": os.getpid(), "created": datetime.now().isoformat()}
                    with open(os.path.join(lock_dir, "owner.json"), "w") as f:
                        json.dump(owner, f)
                except Exception:
                    # Not critical; proceed even if writing metadata fails
                    pass

                self._lock_dir = lock_dir
                log.debug(f"Acquired process lock {lock_dir} (pid={os.getpid()})")
                return
            except FileExistsError:
                # If the existing lock looks stale (owner file older than timeout)
                # try to remove it and acquire again. This helps recover from
                # processes that crashed without releasing the lock.
                try:
                    owner_file = os.path.join(lock_dir, "owner.json")
                    mtime = None
                    if os.path.exists(owner_file):
                        mtime = os.path.getmtime(owner_file)
                    else:
                        mtime = os.path.getmtime(lock_dir)

                    # If owner file/dir mtime is older than timeout, remove it
                    if (time.time() - mtime) >= self.timeout:
                        log.warning(f"Removing stale lock directory {lock_dir}")
                        try:
                            shutil.rmtree(lock_dir)
                        except Exception:
                            # If we can't remove it, we'll continue to wait until
                            # the timeout is reached by this acquisition attempt.
                            pass
                        # After attempted cleanup, loop and try mkdir again
                        continue
                except Exception:
                    # Ignore issues during stale-check and continue waiting
                    pass

                if (time.time() - start) >= self.timeout:
                    raise TimeoutError(f"Timed out waiting for lock {self.lock_path}")
                time.sleep(self.poll_interval)

    def _release_blocking(self) -> None:
        import os
        import shutil

        try:
            if self._lock_dir:
                try:
                    owner_file = os.path.join(self._lock_dir, "owner.json")
                    if os.path.exists(owner_file):
                        try:
                            os.remove(owner_file)
                        except Exception:
                            pass

                    # Attempt to remove the directory. If it's empty, rmdir will
                    # succeed; if not, fall back to recursive removal as a best-effort.
                    try:
                        os.rmdir(self._lock_dir)
                    except Exception:
                        try:
                            shutil.rmtree(self._lock_dir)
                        except Exception:
                            log.debug(f"Failed to fully remove lock dir {self._lock_dir}")

                    log.debug(f"Released process lock {self._lock_dir}")
                    self._lock_dir = None
                except Exception:
                    # Best-effort; ignore errors removing the lock dir
                    pass
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
# Only persist PeeringDB IXP prefixes; per-IP lookups use bgp.tools on-demand
IXP_DATA_FILE = IP_ENRICHMENT_DATA_DIR / "ixp_data.json"
LAST_UPDATE_FILE = IP_ENRICHMENT_DATA_DIR / "last_update.txt"
# Optional raw PeeringDB dump that may be present on disk; if present and
# ixp_data.json is missing we'll convert it to the optimized runtime format.
IXPFX_RAW_FILE = IP_ENRICHMENT_DATA_DIR / "ixpfx.json"

# Backoff marker file written when upstream rate-limits us (HTTP 429). The
# file contains an ISO timestamp until which downloads should be suppressed.
DOWNLOAD_BACKOFF_FILE = IP_ENRICHMENT_DATA_DIR / "download_backoff.txt"

# PeeringDB API URL for IXP prefixes
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
    """Decide whether to refresh IXP data. Only PeeringDB IXP prefixes are
    considered relevant for startup refresh; BGP.tools bulk files are not used.
    """
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
                try:
                    DOWNLOAD_BACKOFF_FILE.unlink()
                except Exception:
                    pass
    except Exception:
        pass

    # If an IXP file exists, prefer it and do not perform automatic refreshes
    # unless the caller explicitly requested a force refresh.
    if IXP_DATA_FILE.exists() and not force_refresh:
        return False, "ixp_data.json exists; skipping automatic refresh"

    # If IXP file is missing, refresh is needed
    if not IXP_DATA_FILE.exists():
        return True, "No ixp_data.json present"

    # Otherwise check timestamp age
    try:
        with open(LAST_UPDATE_FILE, "r") as f:
            cached_time = datetime.fromisoformat(f.read().strip())
        age_seconds = (datetime.now() - cached_time).total_seconds()
        cache_duration = get_cache_duration()
        if age_seconds >= cache_duration:
            age_hours = age_seconds / 3600
            return True, f"Data expired (age: {age_hours:.1f}h, max: {cache_duration/3600:.1f}h)"
    except Exception as e:
        # If reading timestamp fails, prefer a refresh so we don't rely on stale data
        return True, f"Failed to read timestamp: {e}"

    return False, "Data is fresh"


# validate_data_files removed - legacy BGP.tools bulk files are no longer used


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
        # Lock to serialize data load so concurrent callers don't duplicate work
        self._ensure_lock = asyncio.Lock()

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

        # Fast-path: if already loaded in memory, return immediately
        if self.ixp_networks:
            return True

        # Serialize loads to avoid duplicate file reads when multiple callers
        # call ensure_data_loaded concurrently.
        async with self._ensure_lock:
            # Double-check after acquiring the lock
            if self.ixp_networks:
                return True

            # Immediate guard: if any IXP file already exists on disk and the
            # caller did not request a forced refresh, prefer it and skip any
            # network downloads. This ensures we never auto-download when a file
            # has been provided (even if it's empty) unless explicitly requested.
            try:
                if IXP_DATA_FILE.exists() and not force_refresh:
                    try:
                        with open(IXP_DATA_FILE, "r") as f:
                            ixp_data = json.load(f)
                        if ixp_data and isinstance(ixp_data, list) and len(ixp_data) > 0:
                            self.ixp_networks = [
                                (ip_address(net), prefixlen, name) for net, prefixlen, name in ixp_data
                            ]
                            log.info(f"Loaded {len(self.ixp_networks)} IXP prefixes from disk (early guard)")
                        else:
                            log.warning(
                                "ixp_data.json exists but is empty or invalid; honoring existing file and skipping automatic download"
                            )
                    except Exception as e:
                        log.warning(f"Failed to read existing ixp_data.json: {e}; honoring file existence and skipping automatic download")
                    return True
            except Exception:
                # Ignore filesystem errors and continue to refresh logic
                pass

        # If the optimized runtime file is missing but a raw PeeringDB dump
        # (`ixpfx.json`) exists, attempt to convert it into `ixp_data.json`.
        # This avoids contacting PeeringDB when a raw dump is already available
        # on disk (for example created by an operator).
        try:
            if not IXP_DATA_FILE.exists() and IXPFX_RAW_FILE.exists():
                log.info("Found raw ixpfx.json - attempting to convert to ixp_data.json")
                try:
                    with open(IXPFX_RAW_FILE, "r") as f:
                        raw = json.load(f)

                    # raw may be dict with "data" key or a list of objects
                    items = None
                    if isinstance(raw, dict) and "data" in raw and isinstance(raw["data"], list):
                        items = raw["data"]
                    elif isinstance(raw, list):
                        items = raw
                    else:
                        items = []

                    ixp_list = []
                    for rec in items:
                        # Accept multiple shapes: rec may itself be a mapping
                        # with 'prefix' or 'prefixes' fields; handle common cases
                        try:
                            # Some dumps have top-level 'prefix' field
                            if isinstance(rec, dict) and rec.get("prefix"):
                                prefix = rec.get("prefix")
                                ixp_list.append(prefix)
                                continue

                            # Some entries include nested objects or lists
                            if isinstance(rec, dict):
                                # If it's an ixpfx-style object it may have 'prefix' or 'prefixes'
                                if "prefix" in rec and rec.get("prefix"):
                                    ixp_list.append(rec.get("prefix"))
                                    continue
                                if "prefixes" in rec and isinstance(rec.get("prefixes"), list):
                                    for p in rec.get("prefixes"):
                                        if isinstance(p, dict) and p.get("prefix"):
                                            ixp_list.append(p.get("prefix"))
                                    continue
                        except Exception:
                            continue

                    # Normalize and build the tuple form we persist: (str(network), prefixlen, name)
                    parsed = []
                    for p in ixp_list:
                        try:
                            net = ip_network(p, strict=False)
                            parsed.append((str(net.network_address), net.prefixlen, "IXP Network"))
                        except Exception:
                            continue

                    if parsed:
                        # sort by prefixlen desc
                        parsed.sort(key=lambda x: x[1], reverse=True)
                        tmp_ixp = IXP_DATA_FILE.with_name(IXP_DATA_FILE.name + ".tmp")
                        with open(tmp_ixp, "w") as f:
                            json.dump(parsed, f, separators=(',', ':'))
                        import os

                        os.replace(tmp_ixp, IXP_DATA_FILE)
                        log.info(f"Converted {len(parsed)} IXP prefixes from ixpfx.json -> ixp_data.json")
                        # update last_update marker
                        try:
                            tmp_last = LAST_UPDATE_FILE.with_name(LAST_UPDATE_FILE.name + ".tmp")
                            with open(tmp_last, "w") as f:
                                f.write(datetime.now().isoformat())
                            os.replace(tmp_last, LAST_UPDATE_FILE)
                        except Exception:
                            pass
                        # load into memory
                        self.ixp_networks = [
                            (ip_address(net), prefixlen, name) for net, prefixlen, name in parsed
                        ]
                        return True
                    else:
                        log.warning("No prefixes extracted from ixpfx.json; will attempt network refresh if allowed")
                except Exception as e:
                    log.warning(f"Failed to convert ixpfx.json: {e}")
        except Exception:
            pass

            # If a backoff is active, don't try to refresh
            should_refresh, reason = should_refresh_data(force_refresh)

        # If an IXP file exists, prefer it and avoid downloads unless forced.
        try:
            if IXP_DATA_FILE.exists():
                try:
                    st = IXP_DATA_FILE.stat()
                    size = getattr(st, "st_size", None)
                except Exception:
                    size = None

                # If file size indicates non-empty typical JSON array (size>2) try to load
                if size is not None and size > 2:
                    try:
                        with open(IXP_DATA_FILE, "r") as f:
                            ixp_data = json.load(f)
                    except Exception as e:
                        log.warning(f"Failed to parse existing IXP data file: {e}")
                        ixp_data = None

                    if ixp_data and isinstance(ixp_data, list) and len(ixp_data) > 0:
                        self.ixp_networks = [
                            (ip_address(net), prefixlen, name) for net, prefixlen, name in ixp_data
                        ]
                        log.info(f"Loaded {len(self.ixp_networks)} IXP prefixes from disk (size={size})")
                        return True
                    else:
                        log.warning(
                            "Existing IXP data file '%s' appears empty or invalid (size=%s); will attempt to refresh",
                            IXP_DATA_FILE,
                            size,
                        )
                else:
                    log.debug(f"IXP data file exists but size indicates empty or very small (size={size})")
        except Exception as e:
            log.warning(f"Failed to load existing IXP data: {e}")

        # If we're currently under a backoff or refresh is not required, skip downloading
        if not should_refresh:
            log.info(f"Skipping IXP refresh: {reason}")
            return False

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

                    if not ixp_data or (isinstance(ixp_data, list) and len(ixp_data) == 0):
                        log.warning(
                            "Existing IXP data file '%s' is empty after lock wait; will attempt to refresh",
                            IXP_DATA_FILE,
                        )
                    else:
                        self.ixp_networks = [
                            (ip_address(net), prefixlen, name) for net, prefixlen, name in ixp_data
                        ]
                        log.info(
                            f"Loaded {len(self.ixp_networks)} IXP prefixes from disk (post-lock)"
                        )
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
    # end async with _ensure_lock

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

        # Use TCP WHOIS bulk mode on bgp.tools:43. We'll perform a blocking
        # socket WHOIS request in a thread executor to keep this function async.

        def _whois_blocking(single_ips: t.List[str]) -> t.Dict[str, t.Tuple[t.Optional[int], t.Optional[str], t.Optional[str]]]:
            out: t.Dict[str, t.Tuple[t.Optional[int], t.Optional[str], t.Optional[str]]] = {}
            host = "bgp.tools"
            port = 43
            # If a query is numeric-only we should send it as an ASN query (AS12345)
            send_keys = [f"AS{q}" if q.isdigit() else q for q in single_ips]
            payload = "begin\n" + "\n".join(send_keys) + "\nend\n"
            try:
                with socket.create_connection((host, port), timeout=10) as s:
                    s.settimeout(10)
                    s.sendall(payload.encode("utf-8"))
                    parts = []
                    try:
                        while True:
                            chunk = s.recv(4096)
                            if not chunk:
                                break
                            parts.append(chunk)
                    except socket.timeout:
                        pass

                    raw = b"".join(parts).decode("utf-8", errors="replace")
                    # Parse lines like: "13335   | 1.1.1.1          | 1.1.1.0/24          | US | ARIN | ... | Cloudflare, Inc."
                    for line in raw.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        # split by pipe if present, else whitespace
                        if "|" in line:
                            cols = [c.strip() for c in line.split("|")]
                            try:
                                asn = int(cols[0]) if cols[0].isdigit() else None
                            except Exception:
                                asn = None
                            ipcol = cols[1] if len(cols) > 1 else None
                            prefix = cols[2] if len(cols) > 2 else None
                            org = cols[-1] if len(cols) > 0 else None
                            if ipcol:
                                out[ipcol] = (asn, org, prefix)
                            else:
                                # ASN-only response (no IP column). Index by ASN too.
                                if asn is not None:
                                    out_key1 = f"AS{asn}"
                                    out_key2 = str(asn)
                                    out[out_key1] = (asn, org, prefix)
                                    out[out_key2] = (asn, org, prefix)
                        else:
                            # Fallback parsing: "AS12345 ip prefix org"
                            parts_line = line.split()
                            if len(parts_line) >= 3:
                                try:
                                    asn = int(parts_line[0])
                                except Exception:
                                    asn = None
                                ipcol = parts_line[1]
                                prefix = parts_line[2]
                                org = " ".join(parts_line[3:]) if len(parts_line) > 3 else None
                                if ipcol:
                                    out[ipcol] = (asn, org, prefix)
                                else:
                                    if asn is not None:
                                        out_key1 = f"AS{asn}"
                                        out_key2 = str(asn)
                                        out[out_key1] = (asn, org, prefix)
                                        out[out_key2] = (asn, org, prefix)
                    # Map results back to the original query keys. For numeric
                    # inputs we sent 'AS{n}', but callers may provide 'n'. Ensure
                    # we return entries keyed by the original queries.
                    mapped: t.Dict[str, t.Tuple[t.Optional[int], t.Optional[str], t.Optional[str]]] = {}
                    for orig, sent in zip(single_ips, send_keys):
                        if sent in out:
                            mapped[orig] = out[sent]
                        elif orig in out:
                            mapped[orig] = out[orig]
                        else:
                            # Try ASN variants
                            if orig.isdigit():
                                if f"AS{orig}" in out:
                                    mapped[orig] = out[f"AS{orig}"]
                                elif orig in out:
                                    mapped[orig] = out[orig]
                                else:
                                    mapped[orig] = (None, None, None)
                            else:
                                mapped[orig] = (None, None, None)
                    return mapped
            except Exception:
                # On any socket/connect error return empties for all requested IPs
                for ip in single_ips:
                    out[ip] = (None, None, None)
                return out

        loop = asyncio.get_running_loop()
        resp_map = await loop.run_in_executor(None, _whois_blocking, [ip_str])
        asn, org, prefix = resp_map.get(ip_str, (None, None, None))
        # Cache result
        self._ip_cache[ip_str] = (asn, org, prefix)
        return (asn, org, prefix)

    async def _query_bgp_tools_bulk(self, ips: t.List[str]) -> t.Dict[str, t.Tuple[t.Optional[int], t.Optional[str], t.Optional[str]]]:
        """Query bgp.tools for multiple IPs using a single websocket connection when possible.

        Returns a mapping ip -> (asn, asn_name, prefix).
        """
        results: t.Dict[str, t.Tuple[t.Optional[int], t.Optional[str], t.Optional[str]]] = {}

        # Implement TCP WHOIS bulk mode against bgp.tools:43. Perform the
        # blocking socket work in a thread executor so async callers are not
        # blocked.

        def _whois_bulk_blocking(bulk_ips: t.List[str]) -> t.Dict[str, t.Tuple[t.Optional[int], t.Optional[str], t.Optional[str]]]:
            host = "bgp.tools"
            port = 43
            out: t.Dict[str, t.Tuple[t.Optional[int], t.Optional[str], t.Optional[str]]] = {}
            # Normalize numeric-only queries to ASN form for the WHOIS service
            send_keys = [f"AS{q}" if q.isdigit() else q for q in bulk_ips]
            payload = "begin\n" + "\n".join(send_keys) + "\nend\n"
            try:
                with socket.create_connection((host, port), timeout=15) as s:
                    s.settimeout(15)
                    s.sendall(payload.encode("utf-8"))
                    parts = []
                    try:
                        while True:
                            chunk = s.recv(8192)
                            if not chunk:
                                break
                            parts.append(chunk)
                            if sum(len(p) for p in parts) > 512 * 1024:
                                # safety cap 512KB
                                break
                    except socket.timeout:
                        pass

                    raw = b"".join(parts).decode("utf-8", errors="replace")
                    for line in raw.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        if "|" in line:
                            cols = [c.strip() for c in line.split("|")]
                            try:
                                asn = int(cols[0]) if cols[0].isdigit() else None
                            except Exception:
                                asn = None
                            ipcol = cols[1] if len(cols) > 1 else None
                            prefix = cols[2] if len(cols) > 2 else None
                            org = cols[-1] if len(cols) > 0 else None
                            if ipcol:
                                out[ipcol] = (asn, org, prefix)
                            else:
                                # ASN-only response (no IP column). Index by ASN too.
                                if asn is not None:
                                    out_key1 = f"AS{asn}"
                                    out_key2 = str(asn)
                                    out[out_key1] = (asn, org, prefix)
                                    out[out_key2] = (asn, org, prefix)
                        else:
                            parts_line = line.split()
                            if len(parts_line) >= 3:
                                try:
                                    asn = int(parts_line[0])
                                except Exception:
                                    asn = None
                                ipcol = parts_line[1]
                                prefix = parts_line[2]
                                org = " ".join(parts_line[3:]) if len(parts_line) > 3 else None
                                out[ipcol] = (asn, org, prefix)

                    # Map results back to original query keys
                    mapped: t.Dict[str, t.Tuple[t.Optional[int], t.Optional[str], t.Optional[str]]] = {}
                    for orig, sent in zip(bulk_ips, send_keys):
                        if sent in out:
                            mapped[orig] = out[sent]
                        elif orig in out:
                            mapped[orig] = out[orig]
                        else:
                            # Try ASN variants for numeric orig
                            if orig.isdigit():
                                if f"AS{orig}" in out:
                                    mapped[orig] = out[f"AS{orig}"]
                                elif orig in out:
                                    mapped[orig] = out[orig]
                                else:
                                    mapped[orig] = (None, None, None)
                            else:
                                mapped[orig] = (None, None, None)
                    return mapped
            except Exception:
                for ip in bulk_ips:
                    out[ip] = (None, None, None)
                return out

        loop = asyncio.get_running_loop()
        resp = await loop.run_in_executor(None, _whois_bulk_blocking, ips)
        return resp

    async def lookup_ips_bulk(self, ips: t.List[str]) -> t.Dict[str, IPInfo]:
        """Bulk lookup for multiple IPs, using local data first and bgp.tools bulk queries for misses."""
        results: t.Dict[str, IPInfo] = {}

        # Ensure IXP data loaded
        await self.ensure_data_loaded()

        # Prepare misses
        misses: t.List[str] = []
        for ip in ips:
            try:
                target_ip = ip_address(ip)
            except Exception:
                results[ip] = IPInfo(ip)
                continue

            # private/reserved
            if target_ip.is_private or target_ip.is_reserved or target_ip.is_loopback:
                results[ip] = IPInfo(ip, asn=0, asn_name="Private", prefix="Private Network")
                continue

            # check IXP
            found_ixp = False
            for net_addr, prefixlen, ixp_name in self.ixp_networks:
                try:
                    network = ip_network(f"{net_addr}/{prefixlen}", strict=False)
                    if target_ip in network:
                        results[ip] = IPInfo(ip, is_ixp=True, ixp_name=ixp_name)
                        found_ixp = True
                        break
                except Exception:
                    continue
            if found_ixp:
                continue

            # try local optimized tables
            if not self._lookup_optimized:
                self._optimize_lookups()

            matched = False
            target_int = int(target_ip)
            if isinstance(target_ip, IPv4Address):
                for net_int, mask_bits, asn, cidr_string in self._ipv4_networks:
                    if (target_int >> mask_bits) == (net_int >> mask_bits):
                        asn_data = self.asn_info.get(asn, {})
                        asn_name = asn_data.get("name", f"AS{asn}")
                        country = asn_data.get("country", "")
                        results[ip] = IPInfo(ip, asn=asn, asn_name=asn_name, prefix=cidr_string, country=country)
                        matched = True
                        break
            else:
                for net_int, mask_bits, asn, cidr_string in self._ipv6_networks:
                    if (target_int >> mask_bits) == (net_int >> mask_bits):
                        asn_data = self.asn_info.get(asn, {})
                        asn_name = asn_data.get("name", f"AS{asn}")
                        country = asn_data.get("country", "")
                        results[ip] = IPInfo(ip, asn=asn, asn_name=asn_name, prefix=cidr_string, country=country)
                        matched = True
                        break

            if not matched:
                misses.append(ip)

        # Query bgp.tools in bulk for misses
        if misses:
            bulk = await self._query_bgp_tools_bulk(misses)
            for ip in misses:
                asn, asn_name, prefix = bulk.get(ip, (None, None, None))
                if asn:
                    try:
                        self.asn_info[int(asn)] = {"name": asn_name or f"AS{asn}", "country": ""}
                    except Exception:
                        pass
                    results[ip] = IPInfo(ip, asn=asn, asn_name=asn_name, prefix=prefix)
                else:
                    results[ip] = IPInfo(ip, asn=0, asn_name="Unknown")

        return results

    async def lookup_ip(self, ip_str: str) -> IPInfo:
        """Lookup an IP address and return ASN or IXP information."""
        # Try to load IXP data, but continue even if the load fails. We still
        # want to perform on-demand bgp.tools lookups for IPs when local data
        # is missing; failing to load the IXP file should not prevent remote
        # lookups.
        try:
            if not self.ixp_networks:
                await self.ensure_data_loaded()
        except Exception:
            log.debug("ensure_data_loaded raised an exception; continuing with on-demand lookups")

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
        # Attempt to load data but don't fail if we can't; fall back to
        # returning the numeric ASN string if we have no cached name.
        try:
            await self.ensure_data_loaded()
        except Exception:
            log.debug(
                "ensure_data_loaded raised an exception while getting ASN name; using cached data if present"
            )

        asn_data = self.asn_info.get(asn, {})
        name = asn_data.get("name")
        if name:
            return name

        # Fallback: query bgp.tools via WHOIS bulk for ASN (e.g., 'AS12345')
        try:
            query = f"AS{asn}"
            resp = await self._query_bgp_tools_bulk([query])
            # resp maps 'AS12345' -> (asn_int, org, prefix) or maps '12345' -> ...
            entry = resp.get(query) or resp.get(str(asn))
            if entry:
                a, org, _ = entry
                if org:
                    try:
                        self.asn_info[int(asn)] = {"name": org, "country": ""}
                    except Exception:
                        pass
                    return org
        except Exception:
            pass

        return f"AS{asn}"

    async def lookup_asn_country(self, asn: int) -> str:
        """Get the country code for an ASN."""
        try:
            await self.ensure_data_loaded()
        except Exception:
            log.debug(
                "ensure_data_loaded raised an exception while getting ASN country; using cached data if present"
            )

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
            "ixp_data": IXP_DATA_FILE.exists(),
            "last_update": LAST_UPDATE_FILE.exists(),
        },
        "last_update": None,
        "age_hours": None,
        "data_counts": {
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
        _log.info(f"Enriching {len(query_targets)} IP addresses using bulk lookup")

        # Use the bulk lookup to query bgp.tools efficiently
        query_data = {}
        bulk_results = await _service.lookup_ips_bulk(query_targets)

        for target, ip_info in bulk_results.items():
            # Convert to TargetDetail format
            if ip_info.is_ixp and ip_info.ixp_name:
                detail: TargetDetail = {
                    "asn": "IXP",
                    "ip": target,
                    "prefix": "None",
                    "country": "None",
                    "rir": "IXP",
                    "allocated": "None",
                    "org": ip_info.ixp_name,
                }
            elif ip_info.asn is not None and ip_info.asn != 0:
                detail = {
                    "asn": str(ip_info.asn),
                    "ip": target,
                    "prefix": ip_info.prefix or "None",
                    "country": ip_info.country or "None",
                    "rir": "UNKNOWN",
                    "allocated": "None",
                    "org": ip_info.asn_name or "None",
                }
            elif ip_info.asn == 0:
                detail = {
                    "asn": "None",
                    "ip": target,
                    "prefix": "None",
                    "country": "None",
                    "rir": "Unknown",
                    "allocated": "None",
                    "org": "None",
                }
            else:
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
