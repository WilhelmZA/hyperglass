"""Huawei VRP structured traceroute parsing tests."""

# flake8: noqa
# Standard Library
import typing as t

# Third Party
import pytest

# Project
from hyperglass.models.data.traceroute import TracerouteResult
from hyperglass.plugins._builtin.trace_route_huawei import HuaweiTracerouteTable

# Huawei `tracert -q 1` output: one RTT per hop, a timeout hop, then the target.
SAMPLE = """ traceroute to 8.8.8.8, max hops 30 ,press CTRL_C to break
 1 198.51.100.1 1 ms
 2 203.0.113.1 5 ms
 3 *
 4 8.8.8.8 21 ms
"""


def test_huawei_traceroute():
    result = HuaweiTracerouteTable.parse_text(SAMPLE, target="8.8.8.8", source="192.0.2.1")

    assert isinstance(result, TracerouteResult)
    assert result.target == "8.8.8.8"
    assert len(result.hops) == 4, f"Expected 4 hops, got {len(result.hops)}"

    by_hop = {h.hop_number: h for h in result.hops}
    assert by_hop[1].ip_address == "198.51.100.1"
    assert by_hop[1].rtt1 == pytest.approx(1.0)
    assert by_hop[2].ip_address == "203.0.113.1"

    # Hop 3 is a timeout (no IP / no RTT).
    assert by_hop[3].ip_address is None
    assert by_hop[3].rtt1 is None

    assert by_hop[4].ip_address == "8.8.8.8"
    assert by_hop[4].rtt1 == pytest.approx(21.0)
