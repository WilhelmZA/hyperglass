"""API Events."""

# Standard Library
import typing as t

# Third Party
from litestar import Litestar

# Project
from hyperglass.state import use_state
from hyperglass.log import log

__all__ = ("check_redis", "init_ip_enrichment")


async def check_redis(_: Litestar) -> t.NoReturn:
    """Ensure Redis is running before starting server."""
    cache = use_state("cache")
    cache.check()


async def init_ip_enrichment(_: Litestar) -> None:
    """Initialize IP enrichment data at startup."""
    try:
        params = use_state("params")
        if not params.structured.ip_enrichment.enabled:
            log.debug("IP enrichment disabled, skipping initialization")
            return
    except Exception as e:
        log.debug(f"Could not check IP enrichment config: {e}")
        return

    try:
        # Import lazily to avoid importing heavy modules at top-level
        from hyperglass.external.ip_enrichment import (
            _service,
            IP_ENRICHMENT_DATA_DIR,
            LAST_UPDATE_FILE,
            get_cache_duration,
        )

        log.info("Scheduling IP enrichment IXP check at startup (non-blocking)...")

        # Create data directory if needed (best-effort)
        try:
            IP_ENRICHMENT_DATA_DIR.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        # If data is fresh, don't schedule a download
        try:
            if LAST_UPDATE_FILE.exists():
                with open(LAST_UPDATE_FILE, "r") as f:
                    ts = f.read().strip()
                try:
                    last = None
                    from datetime import datetime

                    last = datetime.fromisoformat(ts)
                    age_seconds = (datetime.now() - last).total_seconds()
                    if age_seconds < get_cache_duration():
                        log.debug("IP enrichment IXP data is fresh; skipping startup download")
                        return
                except Exception:
                    # If parsing fails, continue to allow a refresh
                    pass
        except Exception:
            pass

        # Attempt to be the single process that performs the initial download.
        # We use an atomic mkdir on a lock directory so only one process proceeds.
        import os

        startup_lock_path = IP_ENRICHMENT_DATA_DIR / "startup_ixp.lck"

        # Allow configuration of the startup lock TTL via params (seconds).
        try:
            ttl = int(params.structured.ip_enrichment.startup_lock_ttl)
        except Exception:
            ttl = 3600  # default 1 hour

        acquired = False
        try:
            os.mkdir(startup_lock_path)
            acquired = True
        except FileExistsError:
            # If the lock exists, check its mtime and remove if stale
            try:
                mtime = os.path.getmtime(startup_lock_path)
                import time as _time

                age = _time.time() - mtime
                if age > ttl:
                    log.warning(
                        "Found stale startup IXP lock (age %.0fs > %ds). Removing and acquiring.",
                        age,
                        ttl,
                    )
                    try:
                        os.rmdir(startup_lock_path)
                    except Exception:
                        # If remove fails, we won't acquire
                        acquired = False
                    else:
                        try:
                            os.mkdir(startup_lock_path)
                            acquired = True
                        except Exception:
                            acquired = False
                else:
                    acquired = False
            except Exception:
                acquired = False
        except Exception:
            acquired = False

        async def _run_startup_download():
            try:
                log.info("Startup process acquired IXP download responsibility; refreshing IXP data in background")
                success = await _service.ensure_data_loaded()
                if success:
                    log.info("IP enrichment IXP data refreshed by startup process")
                else:
                    log.warning("Startup IXP refresh failed")
            except Exception as exc:  # pragma: no cover - runtime guard
                log.error(f"Error during startup IXP refresh: {exc}")
            finally:
                # Remove our startup lock directory to clean up
                try:
                    os.rmdir(startup_lock_path)
                except Exception:
                    pass

        if acquired:
            # Schedule background task and return immediately so worker startup is fast
            try:
                import asyncio

                asyncio.create_task(_run_startup_download())
            except Exception:
                # Best-effort fallback: run synchronously (should be rare)
                try:
                    import asyncio

                    asyncio.get_event_loop().run_until_complete(_run_startup_download())
                except Exception:
                    pass
        else:
            log.debug("Another process will perform the startup IXP refresh; skipping")

    except Exception as e:
        log.error(f"Error scheduling IP enrichment IXP initialization: {e}")
