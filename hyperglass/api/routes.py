"""API Routes."""

# Standard Library
import json
import time
import asyncio
import typing as t
from uuid import uuid4
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
from .tasks import enrich_query_output, send_webhook
from .fake_output import fake_output

__all__ = (
    "device",
    "devices",
    "queries",
    "info",
    "query",
    "aspath_enrich",
    "query_enrichment",
)

# MikroTik occasionally answers a BGP query before its routing table has finished
# assembling, returning an empty route table on the first attempt. For MikroTik
# BGP queries only, retry a few times (with a delay) while the result is empty.
_MIKROTIK_PLATFORMS = ("mikrotik_routeros", "mikrotik_switchos", "mikrotik")
_MIKROTIK_BGP_MAX_ATTEMPTS = 4
_MIKROTIK_BGP_RETRY_DELAY = 10  # seconds


def _is_empty_bgp_table(output: t.Any) -> bool:
    """Return whether output is a structured BGP table containing no routes."""
    if not is_type(output, OutputDataModel):
        return False
    try:
        raw = json.loads(output.export_json())
    except Exception:
        return False
    return isinstance(raw, dict) and raw.get("count", None) == 0 and not raw.get("routes")


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


# Cap the number of ASNs accepted per enrichment request to bound outbound lookups.
_MAX_ASPATH_ENRICH = 64


@post("/api/aspath/enrich")
async def aspath_enrich(data: dict) -> dict:
    """Enrich a list of ASNs with organization names on demand.

    Expected JSON payload: { "as_path": [123, 456, ...] }
    """
    as_path = data.get("as_path", []) if isinstance(data, dict) else []
    # Accept only numeric ASNs and bound the request size.
    asns = [str(a) for a in as_path if str(a).isdigit()][:_MAX_ASPATH_ENRICH]
    if not asns:
        return {"success": False, "error": "No valid as_path provided"}

    from hyperglass.external.ip_enrichment import lookup_asns_bulk

    try:
        results = await lookup_asns_bulk(asns)
    except Exception:
        # Log server-side; don't leak internal error detail to the client.
        log.bind(as_path=asns).error("AS path enrichment lookup failed")
        return {"success": False, "error": "Enrichment lookup failed"}

    return {"success": True, "asn_organizations": results}


@get("/api/query/{query_id:str}/enrichment")
async def query_enrichment(query_id: str) -> dict:
    """Return the current output and enrichment status for a cached query."""
    from hyperglass.state import use_state

    cache = use_state("redis")
    output = cache.get_map(query_id, "output")
    if output is None:
        return {"status": "not_found"}

    return {
        "status": cache.get_map(query_id, "enrichment_status") or "complete",
        "output": output,
    }


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
    cached_enrichment_status = cache.get_map(cache_key, "enrichment_status")
    if (
        cache_response
        and cached_enrichment_status is None
        and _state.params.structured.is_async_enrichment_enabled(cache_response)
    ):
        _log.bind(cache_key=cache_key).debug(
            "Discarding legacy cache entry without enrichment state"
        )
        cache.delete(cache_key)
        cache_response = None

    json_output = False
    cached = False
    runtime = 65535
    enrichment_status = "complete"
    enrichment_output = None
    enrichment_generation = None

    if cache_response:
        _log.bind(cache_key=cache_key).debug("Cache hit")

        # If a cached response exists, reset the expiration time.
        cache.expire(cache_key, expire_in=_state.params.cache.timeout)

        cached = True
        runtime = 0
        timestamp = cache.get_map(cache_key, "timestamp")
        enrichment_status = cached_enrichment_status or "complete"

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

        if _state.params.structured.is_async_enrichment_enabled(output):
            enrichment_status = "pending"
            enrichment_output = output
            enrichment_generation = uuid4().hex

        with cache.pipeline() as pipeline:
            pipeline.set_map_item(cache_key, "output", raw_output)
            pipeline.set_map_item(cache_key, "timestamp", timestamp)
            pipeline.set_map_item(cache_key, "enrichment_status", enrichment_status)
            if enrichment_generation is not None:
                pipeline.set_map_item(cache_key, "enrichment_generation", enrichment_generation)
            pipeline.expire(cache_key, expire_in=_state.params.cache.timeout)

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
        "enrichment": enrichment_status,
        "random": data.random(),
        "level": "success",
        "keywords": [],
    }

    return Response(
        response,
        background=BackgroundTask(
            _run_query_background_tasks,
            enrichment_output=enrichment_output,
            enrichment_generation=enrichment_generation,
            cache=cache,
            cache_key=cache_key,
            params=_state.params,
            data=data,
            request=request,
            timestamp=timestamp,
        ),
    )


async def _run_query_background_tasks(
    enrichment_output: t.Any,
    enrichment_generation: t.Optional[str],
    cache: t.Any,
    cache_key: str,
    params: Params,
    data: Query,
    request: Request,
    timestamp: datetime,
) -> None:
    """Run optional enrichment and webhook work after sending the response."""
    if enrichment_output is not None and enrichment_generation is not None:
        await enrich_query_output(enrichment_output, cache, cache_key, enrichment_generation)
    await send_webhook(params=params, data=data, request=request, timestamp=timestamp)
