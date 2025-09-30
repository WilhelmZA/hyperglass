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
    # NOTE: Automatic startup refresh has been disabled. IP enrichment data
    # will be loaded on-demand when first required. Disabling the startup
    # refresh avoids concurrent multi-worker downloads and reduces the
    # likelihood of triggering PeeringDB rate limits during container start.
    return
