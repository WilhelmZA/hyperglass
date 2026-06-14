"""FRR structured traceroute parsing tests."""

# flake8: noqa
# Standard Library
import typing as t

# Third Party
import pytest

# Project
from hyperglass.models.data.traceroute import TracerouteResult
from hyperglass.plugins._builtin.trace_route_frr import FrrTracerouteTable

# Standard Linux `traceroute` output as emitted by FRR hosts: a plain hop, a
# hop with hostname + IP, a full timeout, and a multi-probe hop.
SAMPLE = """traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets
 1  198.51.100.1  0.221 ms
 2  router.example.net (203.0.113.1)  15.234 ms
 3  *
 4  8.8.8.8  20.001 ms  19.502 ms  21.110 ms
"""


def test_frr_traceroute():
    result = FrrTracerouteTable.parse_text(SAMPLE, target="8.8.8.8", source="192.0.2.1")

    assert isinstance(result, TracerouteResult)
    assert result.target == "8.8.8.8"
    assert len(result.hops) == 4, f"Expected 4 hops, got {len(result.hops)}"

    by_hop = {h.hop_number: h for h in result.hops}
    assert by_hop[1].ip_address == "198.51.100.1"
    assert by_hop[1].rtt1 == pytest.approx(0.221)

    # Hop 2 carries a resolved hostname alongside the IP.
    assert by_hop[2].ip_address == "203.0.113.1"
    assert by_hop[2].hostname == "router.example.net"

    # Hop 3 is a full timeout (no IP, no RTTs).
    assert by_hop[3].ip_address is None
    assert by_hop[3].rtt1 is None

    # Hop 4 reports three probes.
    assert by_hop[4].ip_address == "8.8.8.8"
    assert by_hop[4].rtt1 == pytest.approx(20.001)
    assert by_hop[4].rtt3 == pytest.approx(21.110)
