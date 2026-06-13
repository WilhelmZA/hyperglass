"""MikroTik structured BGP route parsing tests.

The sample below is a trimmed, real `routing route print detail` capture from a
RouterOS 7.20.6 device (CCR2216), reduced to one active and one filtered route.
Long community lists are kept on a single line, matching what the device emits
to the looking-glass SSH driver (no terminal-width wrapping).
"""

# flake8: noqa
# Standard Library
import typing as t

# Third Party
import pytest

# Project
from hyperglass.state import use_state
from hyperglass.models.config.params import Params
from hyperglass.models.data.bgp_route import BGPRouteTable
from hyperglass.models.parsing.mikrotik import MikrotikBGPTable

if t.TYPE_CHECKING:
    from hyperglass.state import HyperglassState

SAMPLE = """Flags: X - disabled, F - filtered, U - unreachable, A - active;
c - connect, s - static, r - rip, b - bgp, n - bgp-net, o - ospf, i - isis, d - dhcp, v - vpn, m - modem, a - ldp-address, l - ldp-mapping, g - slaac, y - bgp-mpls-vpn, e - evpn;
H - hw-offloaded; + - ecmp, B - blackhole
 Ab   afi=ip contribution=active dst-address=1.0.0.0/24 routing-table=main pref-src=102.217.253.3 gateway=196.60.8.198
       immediate-gw=196.60.8.198%[sfp28-01] distance=20 scope=40 target-scope=10 belongs-to="bgp-IP-196.60.8.198"
       rpki=valid bgp.session=NAP-JHB-CloudFlare-v4-1 .as-path="13335" .communities=13335:10045 .large-communities=328964:2000:0,328964:2001:0 .local-pref=250 .med=0 .origin=igp

 Fb   afi=ip contribution=filtered dst-address=5.101.88.0/24 routing-table=main pref-src=102.217.253.3 gateway=102.130.66.77
       immediate-gw=102.130.66.77%[sfp28-10] distance=20 scope=40 target-scope=10 belongs-to="bgp-IP-102.130.66.77"
       rpki=invalid bgp.session=TRANSIT-ANGOLA-v4-1 .as-path="37468,41095,51601,50113,207569" .communities=37468:14100,37468:2000 .med=0 .origin=incomplete
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


def test_mikrotik_bgp_route(state):
    table = MikrotikBGPTable.parse_text(SAMPLE).bgp_table()

    assert isinstance(table, BGPRouteTable), "Parsed result is not a BGPRouteTable"
    assert table.count == 2, f"Expected 2 routes, got {table.count}"

    by_prefix = {r.prefix: r for r in table.routes}
    assert set(by_prefix) == {"1.0.0.0/24", "5.101.88.0/24"}

    # Active route (flag "A"): RPKI valid (state 1), single-ASN path.
    active = by_prefix["1.0.0.0/24"]
    assert active.active is True
    assert active.filtered is False
    assert active.as_path == [13335]
    assert active.next_hop == "196.60.8.198"
    assert "13335:10045" in active.communities
    assert active.rpki_state == 1  # valid

    # Filtered route (flag "F" => filtered per the RouterOS flags legend): RPKI
    # invalid (state 0), multi-ASN path.
    filtered = by_prefix["5.101.88.0/24"]
    assert filtered.active is False
    assert filtered.filtered is True, "F-flagged route should be marked filtered"
    assert filtered.as_path == [37468, 41095, 51601, 50113, 207569]
    assert filtered.rpki_state == 0  # invalid
