"""hyperglass state dependencies."""

# Standard Library
import asyncio
import typing as t

# Project
from hyperglass.state import HyperglassState, use_state
from hyperglass.exceptions.private import StateError


def _is_retryable(attr: t.Optional[str]) -> bool:
    """Whether a StateError for this attr is a transient (not-yet-populated) error.

    A request can arrive before the Redis-backed state is populated on startup,
    which surfaces as a StateError. Referencing an attribute that does not exist
    on HyperglassState is a permanent programming error and must not be retried.
    """
    return attr is None or attr in ("cache", "redis") or attr in HyperglassState.properties()


async def _get_state_with_retry(
    attr: t.Optional[str] = None, max_retries: int = 5, retry_delay: float = 0.5
) -> t.Any:
    """Get hyperglass state, retrying transient startup StateErrors."""
    for attempt in range(1, max_retries + 1):
        try:
            return use_state(attr)
        except StateError:
            if not _is_retryable(attr) or attempt == max_retries:
                raise
            await asyncio.sleep(retry_delay)


async def get_state(attr: t.Optional[str] = None):
    """Get hyperglass state as a FastAPI dependency."""
    return await _get_state_with_retry(attr)


async def get_params():
    """Get hyperglass params as FastAPI dependency."""
    return await _get_state_with_retry("params")


async def get_devices():
    """Get hyperglass devices as FastAPI dependency."""
    return await _get_state_with_retry("devices")


async def get_ui_params():
    """Get hyperglass ui_params as FastAPI dependency."""
    return await _get_state_with_retry("ui_params")
