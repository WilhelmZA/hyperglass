"""MikroTik structured traceroute parsing tests.

MikroTik's `/tool traceroute` redraws its table in place; the netmiko-based
looking-glass driver captures the final accumulated table (one row per hop,
SENT = total probes, with AVG/BEST/WORST filled in). This is a real RouterOS
7.20.6 capture of that final table.
"""

# flake8: noqa
# Project
from hyperglass.models.data.traceroute import TracerouteResult
from hyperglass.plugins._builtin.trace_route_mikrotik import parse_mikrotik_traceroute

SAMPLE = """ADDRESS                          LOSS SENT    LAST     AVG    BEST   WORST
196.60.9.113                       0%    3   2.2ms     1.8     1.5     2.2
192.178.98.217                     0%    3   1.3ms     1.4     1.3     1.6
192.178.73.125                     0%    3   0.6ms     0.6     0.6     0.6
8.8.8.8                            0%    3   0.5ms     0.5     0.5     0.5
"""


def test_mikrotik_traceroute():
    result = parse_mikrotik_traceroute(SAMPLE, target="8.8.8.8", source="JHB-1")

    assert isinstance(result, TracerouteResult), "Expected a TracerouteResult"
    assert len(result.hops) == 4, f"Expected 4 hops, got {len(result.hops)}"

    addrs = [h.ip_address for h in result.hops]
    assert addrs == [
        "196.60.9.113",
        "192.178.98.217",
        "192.178.73.125",
        "8.8.8.8",
    ], f"Unexpected hop addresses: {addrs}"

    # Final hop is the target; per-hop stats are captured.
    last = result.hops[-1]
    assert last.ip_address == "8.8.8.8"
    assert result.hops[0].best_rtt == 1.5
    assert result.hops[0].worst_rtt == 2.2
