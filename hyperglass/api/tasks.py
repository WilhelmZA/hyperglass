"""Tasks to be executed from web API."""

# Standard Library
import json
import typing as t
from datetime import datetime

# Third Party
from httpx import Headers
from litestar import Request

# Project
from hyperglass.log import log
from hyperglass.external import Webhook, network_info
from hyperglass.models.api import Query

if t.TYPE_CHECKING:
    # Project
    from hyperglass.models.config.params import Params

__all__ = ("enrich_query_output", "send_webhook")


async def process_headers(headers: Headers) -> t.Dict[str, t.Any]:
    """Filter out unwanted headers and return as a dictionary."""
    headers = dict(headers)
    header_keys = (
        "user-agent",
        "referer",
        "accept-encoding",
        "accept-language",
        "x-real-ip",
        "x-forwarded-for",
    )
    return {k: headers.get(k) for k in header_keys}


async def send_webhook(
    params: "Params",
    data: Query,
    request: Request,
    timestamp: datetime,
) -> t.NoReturn:
    """If webhooks are enabled, get request info and send a webhook."""
    try:
        if params.logging.http is not None:
            headers = await process_headers(headers=request.headers)

            if headers.get("x-real-ip") is not None:
                host = headers["x-real-ip"]
            elif headers.get("x-forwarded-for") is not None:
                host = headers["x-forwarded-for"]
            else:
                host = request.client.host

            network_result = await network_info(host)

            async with Webhook(params.logging.http) as hook:
                await hook.send(
                    query={
                        **data.dict(),
                        "headers": headers,
                        "source": host,
                        "network": network_result.get(host, {}),
                        "timestamp": timestamp,
                    }
                )
    except Exception as err:
        log.bind(destination=params.logging.http.provider, error=str(err)).error(
            "Failed to send webhook"
        )


async def enrich_query_output(output: t.Any, cache: t.Any, cache_key: str, generation: str) -> None:
    """Enrich a structured query result and update its cached representation."""
    from hyperglass.models.data.bgp_route import BGPRouteTable
    from hyperglass.models.data.traceroute import TracerouteResult

    status = "complete"
    try:
        if isinstance(output, BGPRouteTable):
            await output.enrich_as_path_organizations()
            await output.enrich_with_ip_enrichment()
        elif isinstance(output, TracerouteResult):
            from hyperglass.plugins._builtin.traceroute_ip_enrichment import (
                ZTracerouteIpEnrichment,
            )

            await ZTracerouteIpEnrichment().enrich(output)
    except Exception:
        status = "failed"
        log.exception("Failed to asynchronously enrich query output")

    try:
        updated = cache.set_map_items_if(
            cache_key,
            expected_item="enrichment_generation",
            expected_value=generation,
            values={
                "output": json.loads(output.export_json()),
                "enrichment_status": status,
            },
        )
        if not updated:
            log.bind(cache_key=cache_key).debug("Discarded stale asynchronous enrichment result")
    except Exception:
        log.exception("Failed to update asynchronously enriched query output")
