"""Huawei VRP structured BGP route parsing tests."""

# flake8: noqa
# Standard Library
import typing as t

# Third Party
import pytest

# Project
from hyperglass.state import use_state
from hyperglass.models.config.params import Params
from hyperglass.models.data.bgp_route import BGPRouteTable
from hyperglass.models.parsing.huawei import HuaweiBGPTable

if t.TYPE_CHECKING:
    from hyperglass.state import HyperglassState

# Representative `display bgp routing-table <prefix>` detail output: one best/
# selected (active) route and one valid-but-not-best route.
SAMPLE = """
 BGP local router ID : 192.0.2.1
 Local AS number : 64500
 Paths:   2 available, 1 best, 1 select

 BGP routing table entry information of 203.0.113.0/24:
 From: 198.51.100.1 (192.0.2.254)
 Route Duration: 0d00h05m12s
 Original nexthop: 198.51.100.1
 Community: 64500:100, 64500:200
 AS-path 64500 64501, origin igp, MED 0, localpref 100, pref-val 0, valid, external, best, select, pre 255

 BGP routing table entry information of 203.0.113.128/25:
 From: 198.51.100.2 (192.0.2.253)
 Route Duration: 0d00h01m00s
 Original nexthop: 198.51.100.2
 AS-path 64500 64999, origin incomplete, MED 10, localpref 90, pref-val 0, valid, external, pre 255
"""


@pytest.fixture
def params() -> t.Dict[str, t.Any]:
    return {}


@pytest.fixture
def state(*, params: t.Dict[str, t.Any]) -> t.Generator["HyperglassState", None, None]:
    """Initialize Redis-backed state with params for BGPRoute validation."""
    _state = use_state()
    _params = Params(**params)
    with _state.cache.pipeline() as pipeline:
        pipeline.set("params", _params)
    yield _state
    _state.clear()


def test_huawei_bgp_route(state):
    table = HuaweiBGPTable.parse_text(SAMPLE).bgp_table()

    assert isinstance(table, BGPRouteTable), "Parsed result is not a BGPRouteTable"
    assert table.count == 2, f"Expected 2 routes, got {table.count}"

    by_prefix = {r.prefix: r for r in table.routes}
    assert set(by_prefix) == {"203.0.113.0/24", "203.0.113.128/25"}

    best = by_prefix["203.0.113.0/24"]
    assert best.active is True, "best+select route should be active"
    assert best.as_path == [64500, 64501], f"Bad as_path: {best.as_path}"
    assert best.source_as == 64500, "source_as should be first ASN in path"
    assert best.next_hop == "198.51.100.1"
    assert "64500:100" in best.communities

    other = by_prefix["203.0.113.128/25"]
    assert other.active is False, "non-best route should not be active"
    assert other.as_path == [64500, 64999]
