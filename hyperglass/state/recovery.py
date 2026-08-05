"""Recover Redis-backed state that is lost while hyperglass is running.

All runtime configuration (`params`, `directives`, `devices`, `ui_params`) is written to
Redis exactly once, by `hyperglass.main.run` at startup. Redis is intentionally
ephemeral - the reference deployment runs it with no RDB and no AOF - so anything that
empties the store leaves a running hyperglass with no state and no way to get it back:
every state-touching request raises `StateError` until the process is restarted. A
replaced Redis container does exactly this, and `docker compose up -d` will replace
Redis without touching hyperglass.

This module repopulates the store in place instead. One process does the work, holding a
Redis lock so multiple uvicorn workers do not each re-read and re-validate the
configuration; the rest wait for the winner to finish.
"""

# Standard Library
import time
import typing as t
from uuid import uuid4

# Project
from hyperglass.log import log

if t.TYPE_CHECKING:
    # Local
    from .redis import RedisManager

__all__ = ("rebuild_state",)

# Keys that must all be present for state to be usable.
REQUIRED_KEYS = ("params", "directives", "devices", "ui_params")

# Lock key, held for the duration of a rebuild by the process performing it.
LOCK_KEY = ("rebuild", "lock")

# Expiry of the lock, so a process that dies mid-rebuild cannot block recovery forever.
LOCK_TIMEOUT = 60

# How long to wait for another process's rebuild before giving up.
WAIT_TIMEOUT = 30.0

# How often to check whether another process's rebuild has completed.
POLL_INTERVAL = 0.25

# How long to fail fast after a failed rebuild. Without this, a configuration that
# cannot be loaded would be re-read and re-validated on every single request.
FAILURE_COOLDOWN = 30.0

_last_failure: float = 0.0


def _initialize() -> None:
    """Write user configuration and the plugin registry to Redis.

    Imported lazily because both of these import `hyperglass.state`.
    """
    # Project
    from hyperglass.plugins import register_all_plugins
    from hyperglass.configuration import init_user_config

    # Deliberately *not* preceded by `state.clear()`. `run()` flushes before
    # initializing, which is correct once at startup, but mid-flight it would wipe
    # state that other workers are reading.
    init_user_config()

    # The plugin registry lives in the same store, so it is lost with the rest of it.
    # Without this, hyperglass recovers but silently stops parsing device output into
    # structured results.
    register_all_plugins()


def is_populated(cache: "RedisManager") -> bool:
    """Determine whether all required state keys exist in Redis."""
    keys = [cache.key(key) for key in REQUIRED_KEYS]
    return cache.instance.exists(*keys) == len(keys)


def _wait_for_rebuild(cache: "RedisManager") -> bool:
    """Wait for another process to finish rebuilding state.

    Waits for the lock to be released as well as the keys to appear, because the
    configuration is written before the plugin registry. Returning on the keys alone
    would let a waiter serve requests in the window where hyperglass has its
    configuration back but not its output plugins.
    """
    lock = cache.key(LOCK_KEY)
    deadline = time.monotonic() + WAIT_TIMEOUT
    while time.monotonic() < deadline:
        time.sleep(POLL_INTERVAL)
        if not cache.instance.exists(lock) and is_populated(cache):
            return True
    log.bind(timeout=WAIT_TIMEOUT).error("Timed out waiting for hyperglass state rebuild")
    return False


def rebuild_state(cache: "RedisManager") -> bool:
    """Repopulate configuration state in Redis after it has been lost.

    Returns `True` if state is populated by the time this returns, whether this process
    rebuilt it or another one did. Blocks for the duration of the rebuild.
    """
    global _last_failure  # noqa: PLW0603

    if is_populated(cache):
        # State came back between the failed read and now, or the miss was for
        # something this function does not manage.
        return True

    if time.monotonic() - _last_failure < FAILURE_COOLDOWN:
        return False

    lock = cache.key(LOCK_KEY)
    token = str(uuid4()).encode()

    if not cache.instance.set(lock, token, nx=True, ex=LOCK_TIMEOUT):
        return _wait_for_rebuild(cache)

    try:
        log.bind(keys=REQUIRED_KEYS).warning("hyperglass state is missing from Redis, rebuilding")
        _initialize()
    except Exception as error:
        _last_failure = time.monotonic()
        log.bind(error=str(error)).critical("Failed to rebuild hyperglass state")
        return False
    finally:
        if cache.instance.get(lock) == token:
            cache.instance.delete(lock)

    _last_failure = 0.0
    log.bind(generation=cache.get("generation")).warning("Rebuilt hyperglass state")
    return True
