"""hyperglass state dependencies."""

# Standard Library
import asyncio
import typing as t

# Project
from hyperglass.state import use_state
from hyperglass.exceptions.private import StateError


async def _get_state_with_retry(
    attr: t.Optional[str] = None, max_retries: int = 5, retry_delay: float = 0.5
):
    """Get hyperglass state with automatic retry on StateError."""
    last_error = None
    for attempt in range(max_retries):
        try:
            return use_state(attr)
        except StateError as e:
            last_error = e
            if attempt < max_retries - 1:
                await asyncio.sleep(retry_delay)
            continue
    # If all retries exhausted, raise the last error
    raise last_error


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
