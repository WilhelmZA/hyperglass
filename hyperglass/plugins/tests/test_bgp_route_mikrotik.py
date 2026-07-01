"""MikroTik structured BGP route parsing tests.

The samples below are synthetic captures shaped exactly like RouterOS
`routing route print detail` output, but scrubbed of any real network data: all
addresses use the RFC 5737 (IPv4) documentation ranges, autonomous-system
numbers use the RFC 5398 documentation range (64496-64511), and peer/interface
names are generic. Only the *structure* of the output is real, which is all the
parser cares about.
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

# One active and one filtered route, each emitted on a single (unwrapped) line,
# as a wide terminal would produce.
SAMPLE = """Flags: X - disabled, F - filtered, U - unreachable, A - active;
c - connect, s - static, r - rip, b - bgp, n - bgp-net, o - ospf, i - isis, d - dhcp, v - vpn, m - modem, a - ldp-address, l - ldp-mapping, g - slaac, y - bgp-mpls-vpn, e - evpn;
H - hw-offloaded; + - ecmp, B - blackhole
 Ab   afi=ip contribution=active dst-address=203.0.113.0/24 routing-table=main pref-src=192.0.2.1 gateway=198.51.100.1
       immediate-gw=198.51.100.1%[ether1] distance=20 scope=40 target-scope=10 belongs-to="bgp-IP-198.51.100.1"
       rpki=valid bgp.session=peer-ix-1 .as-path="64496" .communities=64496:10045 .large-communities=64500:2000:0,64500:2001:0 .local-pref=250 .med=0 .origin=igp

 Fb   afi=ip contribution=filtered dst-address=198.51.100.0/24 routing-table=main pref-src=192.0.2.1 gateway=192.0.2.2
       immediate-gw=192.0.2.2%[ether2] distance=20 scope=40 target-scope=10 belongs-to="bgp-IP-192.0.2.2"
       rpki=invalid bgp.session=transit-1 .as-path="64497,64498,64499,64500,64501" .communities=64497:14100,64497:2000 .med=0 .origin=incomplete
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
    assert set(by_prefix) == {"203.0.113.0/24", "198.51.100.0/24"}

    # Active route (contribution=active): RPKI valid (state 1), single-ASN path.
    active = by_prefix["203.0.113.0/24"]
    assert active.active is True
    assert active.filtered is False
    assert active.as_path == [64496]
    assert active.next_hop == "198.51.100.1"
    assert "64496:10045" in active.communities
    assert active.rpki_state == 1  # valid

    # Filtered route (contribution=filtered): RPKI invalid (state 0), multi-ASN path.
    filtered = by_prefix["198.51.100.0/24"]
    assert filtered.active is False
    assert filtered.filtered is True, "filtered route should be marked filtered"
    assert filtered.as_path == [64497, 64498, 64499, 64500, 64501]
    assert filtered.rpki_state == 0  # invalid


# Wrapped/commented capture as RouterOS 7.21 emits it over the looking-glass SSH
# driver. Two properties that broke the legacy parser are exercised here:
#   1. The *active* route is learned from a commented peer, so RouterOS emits the
#      flag column ("Ab") and the ";;; comment" on a line of their own, with
#      "afi=ip" wrapped to the next line. Active state must come from
#      "contribution=active", not the (now-separated) flag column.
#   2. A long ".communities" list is wrapped across two terminal-width lines; all
#      members must survive (no truncation at the wrap point).
#   3. An unquoted interface description containing spaces ("vlan10 CORE LINK")
#      must not swallow the following key=value tokens.
WRAPPED_SAMPLE = """Flags: X - disabled, F - filtered, U - unreachable, A - active;
c - connect, s - static, r - rip, b - bgp, n - bgp-net, o - ospf, i - isis, d - dhcp, v - vpn, m - modem, a - ldp-address, l - ldp-mapping, g - slaac, y - bgp-mpls-vpn, e - evpn;
H - hw-offloaded; + - ecmp, B - blackhole
 Ab   ;;; peer-ix-1
    afi=ip
       contribution=active dst-address=203.0.113.0/24 routing-table=main
       pref-src=192.0.2.1 gateway=198.51.100.1
       immediate-gw=198.51.100.1%[ether1] IX PEERING
       distance=20 scope=40 target-scope=10 belongs-to="bgp-IP-198.51.100.1"
       rpki=valid bgp.session=peer-ix-1
       .aggregator="64496:192.0.2.1" .as-path="64496"
       .communities=64496:100,64496:200,64496:300,64497:100,64497:200,
       64497:300,64498:100,64498:200,64498:300
       .large-communities=64500:2000:0,64500:2001:0 .local-pref=250 .origin=igp
       debug.fwp-ptr=0x00000000

  b   afi=ip contribution=candidate dst-address=203.0.113.0/24 routing-table=main
       pref-src=192.0.2.1 gateway=192.0.2.10
       immediate-gw=192.0.2.10%vlan10 CORE LINK distance=200 scope=40
       target-scope=30 belongs-to="bgp-IP-192.0.2.10"
       bgp.session=core-edge-1 .as-path="64496" .communities=64496:400
       .local-pref=250 .origin=igp
       debug.fwp-ptr=0x00000001
"""


def test_mikrotik_bgp_route_wrapped_commented(state):
    """Regression: RouterOS 7.21 wrapped output with a commented active route."""
    parsed = MikrotikBGPTable.parse_text(WRAPPED_SAMPLE)

    # Exactly one active (best) route must be detected, via contribution=active,
    # even though its flag column sits on a separate ";;; comment" line.
    active_entries = [r for r in parsed.routes if r.is_active]
    assert len(active_entries) == 1, "commented active route must still be detected"
    active = active_entries[0]
    assert active.gateway == "198.51.100.1"

    # The wrapped 9-member community list must be captured in full, not truncated
    # at the terminal-width wrap point.
    assert active.communities == [
        "64496:100",
        "64496:200",
        "64496:300",
        "64497:100",
        "64497:200",
        "64497:300",
        "64498:100",
        "64498:200",
        "64498:300",
    ]

    # The candidate route's unquoted interface description ("vlan10 CORE LINK")
    # must not have swallowed the following key=value tokens.
    candidate = [r for r in parsed.routes if not r.is_active][0]
    assert candidate.gateway == "192.0.2.10"
    assert candidate.local_preference == 250
    assert candidate.communities == ["64496:400"]

    # The full conversion to the canonical BGP table must still succeed.
    table = parsed.bgp_table()
    assert isinstance(table, BGPRouteTable)
    assert table.count == 2, f"Expected 2 routes, got {table.count}"
