"""Validate RPKI state via Cloudflare GraphQL API."""

# Standard Library
import typing as t

# Third Party
import httpx

# Project
from hyperglass.log import log
from hyperglass.state import use_state
from hyperglass.external._base import BaseExternal

if t.TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address

# Maps normalized (lower-case, separators stripped) backend state names to the
# integer states hyperglass uses internally.
RPKI_STATE_MAP = {
    "invalid": 0,
    "valid": 1,
    "notfound": 2,
    "unknown": 2,
    "default": 3,
}
# Canonical integer -> display name, kept stable for logging.
RPKI_NAME_MAP = {0: "Invalid", 1: "Valid", 2: "NotFound", 3: "DEFAULT"}
CACHE_KEY = "hyperglass.external.rpki"


def _normalize_state(value: str) -> int:
    """Normalize a backend RPKI state string to an internal integer state."""
    key = str(value).strip().lower().replace("-", "").replace("_", "")
    return RPKI_STATE_MAP.get(key, 3)


def rpki_state(
    prefix: t.Union["IPv4Address", "IPv6Address", str],
    asn: t.Union[int, str],
    backend: str = "cloudflare",
    rpki_server_url: str = "",
) -> int:
    """Get RPKI state and map to expected integer."""
    _log = log.bind(prefix=prefix, asn=asn)
    _log.debug("Validating RPKI State")

    cache = use_state("cache")
    state = 3
    ro = f"{prefix!s}@{asn!s}"

    cached = cache.get_map(CACHE_KEY, ro)
    if cached is not None:
        state = cached
    else:
        try:
            if backend == "cloudflare":
                ql = 'query GetValidation {{ validation(prefix: "{}", asn: {}) {{ state }} }}'
                query = ql.format(prefix, asn)
                _log.bind(query=query).debug("Cloudflare RPKI GraphQL Query")
                with BaseExternal(base_url="https://rpki.cloudflare.com") as client:
                    response = client._post("/api/graphql", data={"query": query})
                validation_state = response["data"]["validation"]["state"]
            elif backend == "routinator":
                url = f"{rpki_server_url.rstrip('/')}/validity"
                _log.bind(url=url).debug("Routinator RPKI HTTP Query")
                response = httpx.get(
                    url, params={"asn": str(asn), "prefix": str(prefix)}, timeout=5
                )
                response.raise_for_status()
                data = response.json()
                validation_state = data["validated_route"]["validity"]["state"]
            else:
                raise ValueError(f"Unknown RPKI backend: {backend}")

            state = _normalize_state(validation_state)
            cache.set_map_item(CACHE_KEY, ro, state)
        except Exception as err:
            log.error(err)
            state = 3

    msg = "RPKI Validation State for {} via AS{} is {}".format(prefix, asn, RPKI_NAME_MAP[state])
    if cached is not None:
        msg += " [CACHED]"
    log.debug(msg)
    return state
