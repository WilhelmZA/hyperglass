"""API Routes."""

# Standard Library
import json
import time
import asyncio
import typing as t
from datetime import UTC, datetime

# Third Party
from litestar import Request, Response, get, post
from litestar.di import Provide
from litestar.background_tasks import BackgroundTask

# Project
from hyperglass.log import log
from hyperglass.state import HyperglassState
from hyperglass.exceptions import HyperglassError
from hyperglass.models.api import Query
from hyperglass.models.data import OutputDataModel
from hyperglass.util.typing import is_type
from hyperglass.execution.main import execute
from hyperglass.models.api.response import QueryResponse
from hyperglass.models.config.params import Params, APIParams
from hyperglass.models.config.devices import Devices, APIDevice

# Local
from .state import get_state, get_params, get_devices
from .tasks import send_webhook
from .fake_output import fake_output

__all__ = (
    "device",
    "devices",
    "queries",
    "info",
    "query",
)

# MikroTik occasionally answers a BGP query before its routing table has finished
# assembling, returning an empty route table on the first attempt. For MikroTik
# BGP queries only, retry a few times (with a delay) while the result is empty.
_MIKROTIK_PLATFORMS = ("mikrotik_routeros", "mikrotik_switchos", "mikrotik")
_MIKROTIK_BGP_MAX_ATTEMPTS = 4
_MIKROTIK_BGP_RETRY_DELAY = 10  # seconds


def _is_empty_bgp_table(output: t.Any) -> bool:
    """True if output is a structured BGP table containing no routes."""
    if not is_type(output, OutputDataModel):
        return False
    try:
        raw = json.loads(output.export_json())
    except Exception:
        return False
    return (
        isinstance(raw, dict)
        and raw.get("count", None) == 0
        and not raw.get("routes")
    )


async def _execute_query(data: "Query") -> t.Any:
    """Execute a query, retrying MikroTik BGP queries that return an empty table."""
    directive_name = getattr(getattr(data, "directive", None), "name", "") or ""
    is_bgp_query = "bgp_" in data.query_type or "bgp" in directive_name.lower()
    is_mikrotik_bgp = data.device.platform in _MIKROTIK_PLATFORMS and is_bgp_query
    max_attempts = _MIKROTIK_BGP_MAX_ATTEMPTS if is_mikrotik_bgp else 1

    _log = log.bind(directive=data.query_type, device=data.device.name)
    if is_mikrotik_bgp:
        _log.bind(max_attempts=max_attempts, retry_delay=_MIKROTIK_BGP_RETRY_DELAY).debug(
            "MikroTik BGP empty-table retry enabled"
        )

    output = None
    for attempt in range(1, max_attempts + 1):
        if attempt > 1:
            _log.bind(attempt=attempt, max_attempts=max_attempts).warning(
                "MikroTik returned empty BGP table - retrying after {}s", _MIKROTIK_BGP_RETRY_DELAY
            )
            await asyncio.sleep(_MIKROTIK_BGP_RETRY_DELAY)

        output = await execute(data)

        if not (is_mikrotik_bgp and attempt < max_attempts and _is_empty_bgp_table(output)):
            break

    return output


@get("/api/devices/{id:str}", dependencies={"devices": Provide(get_devices)})
async def device(devices: Devices, id: str) -> APIDevice:
    """Retrieve a device by ID."""
    return devices[id].export_api()


@get("/api/devices", dependencies={"devices": Provide(get_devices)})
async def devices(devices: Devices) -> t.List[APIDevice]:
    """Retrieve all devices."""
    return devices.export_api()


@get("/api/queries", dependencies={"devices": Provide(get_devices)})
async def queries(devices: Devices) -> t.List[str]:
    """Retrieve all directive names."""
    return devices.directive_names()


@get("/api/info", dependencies={"params": Provide(get_params)})
async def info(params: Params) -> APIParams:
    """Retrieve looking glass parameters."""
    return params.export_api()


@post("/api/query", dependencies={"_state": Provide(get_state)})
async def query(_state: HyperglassState, request: Request, data: Query) -> QueryResponse:
    """Ingest request data pass it to the backend application to perform the query."""

    timestamp = datetime.now(UTC)

    # Initialize cache
    cache = _state.redis

    # Use hashed `data` string as key for for k/v cache store so
    # each command output value is unique.
    cache_key = f"hyperglass.query.{data.digest()}"

    _log = log.bind(query=data.summary())

    _log.info("Starting query execution")

    cache_response = cache.get_map(cache_key, "output")
    json_output = False
    cached = False
    runtime = 65535

    if cache_response:
        _log.bind(cache_key=cache_key).debug("Cache hit")

        # If a cached response exists, reset the expiration time.
        cache.expire(cache_key, expire_in=_state.params.cache.timeout)

        cached = True
        runtime = 0
        timestamp = cache.get_map(cache_key, "timestamp")

    elif not cache_response:
        _log.bind(cache_key=cache_key).debug("Cache miss")

        timestamp = data.timestamp

        starttime = time.time()

        if _state.params.fake_output:
            # Return fake, static data for development purposes, if enabled.
            output = await fake_output(
                query_type=data.query_type,
                structured=data.device.structured_output or False,
            )
        else:
            # Pass request to execution module (retries empty MikroTik BGP tables)
            output = await _execute_query(data)

        endtime = time.time()
        elapsedtime = round(endtime - starttime, 4)
        _log.debug("Runtime: {!s} seconds", elapsedtime)

        if output is None:
            raise HyperglassError(message=_state.params.messages.general, alert="danger")

        json_output = is_type(output, OutputDataModel)

        if json_output:
            # Export structured output as JSON string to guarantee value
            # is serializable, then convert it back to a dict.
            as_json = output.export_json()
            raw_output = json.loads(as_json)
        else:
            raw_output = str(output)

        cache.set_map_item(cache_key, "output", raw_output)
        cache.set_map_item(cache_key, "timestamp", timestamp)
        cache.expire(cache_key, expire_in=_state.params.cache.timeout)

        _log.bind(cache_timeout=_state.params.cache.timeout).debug("Response cached")

        runtime = int(round(elapsedtime, 0))

    # If it does, return the cached entry
    cache_response = cache.get_map(cache_key, "output")

    json_output = is_type(cache_response, t.Dict)
    response_format = "text/plain"

    if json_output:
        response_format = "application/json"
    _log.info("Execution completed")

    response = {
        "output": cache_response,
        "id": cache_key,
        "cached": cached,
        "runtime": runtime,
        "timestamp": timestamp,
        "format": response_format,
        "random": data.random(),
        "level": "success",
        "keywords": [],
    }

    return Response(
        response,
        background=BackgroundTask(
            send_webhook,
            params=_state.params,
            data=data,
            request=request,
            timestamp=timestamp,
        ),
    )
