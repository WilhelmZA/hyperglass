"""MikroTik structured traceroute parsing tests.

MikroTik's `/tool traceroute` redraws its table in place; the netmiko-based
looking-glass driver captures the final accumulated table (one row per hop,
SENT = total probes, with AVG/BEST/WORST filled in).

Real RouterOS devices emit two distinct table layouts, both of which must parse:

1. No index column, with a trailing STATUS column:
       ADDRESS         LOSS SENT  LAST   AVG  BEST  WORST STD-DEV STATUS
       198.51.100.7      0%    3  0.2ms  0.2  0.1   0.2   0

2. Leading hop-index column ("#") and no STATUS column:
       #  ADDRESS       LOSS  SENT  LAST     AVG   BEST  WORST  STD-DEV
       0  192.0.2.1     0%       3  15.8ms   15.8  15.8  15.9         0

The index column previously shifted every field and dropped all hops; the
parser now detects and strips it. The fixtures below preserve the exact shape
of real captures (hop counts, timeout rows, both layouts), but all addresses
are RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) rather than real network data.

The parser only populates fields it can read from the table (IP, loss, sent,
RTTs). ASN/IXP/org enrichment is applied later by a separate plugin, so these
parser tests assert only parser-produced fields.
"""

# flake8: noqa
# Standard Library
import typing as t

# Third Party
import pytest

# Project
from hyperglass.models.data.traceroute import TracerouteResult
from hyperglass.plugins._builtin.trace_route_mikrotik import parse_mikrotik_traceroute

# ---------------------------------------------------------------------------
# Fixtures: (raw table, target, source, expected hops)
# Each expected hop is (ip_address, loss_pct, best_rtt, worst_rtt).
# Addresses are RFC 5737 documentation ranges (anonymized).
# ---------------------------------------------------------------------------

# Indexed layout ("#" column, no STATUS), including a timeout hop.
INDEXED_5HOP = (
    """ #  ADDRESS        LOSS  SENT  LAST     AVG   BEST  WORST  STD-DEV
 0  192.0.2.1      0%       3  15.8ms   15.8  15.8  15.9         0
 1                 100%     3  timeout
 2  198.51.100.7   0%       3  17.4ms   17.4  17.4  17.5         0
 3  198.51.100.8   0%       3  16.4ms   16.4  16.4  16.4         0
 4  203.0.113.8    0%       3  16.3ms   16.3  16.3  16.3         0
""",
    "203.0.113.8",
    "router-a",
    [
        ("192.0.2.1", 0, 15.8, 15.9),
        (None, 100, None, None),
        ("198.51.100.7", 0, 17.4, 17.5),
        ("198.51.100.8", 0, 16.4, 16.4),
        ("203.0.113.8", 0, 16.3, 16.3),
    ],
)

# Indexed layout, short 2-hop trace.
INDEXED_2HOP = (
    """ #  ADDRESS        LOSS  SENT  LAST   AVG  BEST  WORST  STD-DEV
 0  192.0.2.20     0%       3  4.4ms  7.6  0.7   17.7   7.3
 1  203.0.113.1    0%       3  0.8ms  0.8  0.8   0.8    0
""",
    "203.0.113.1",
    "router-a",
    [
        ("192.0.2.20", 0, 0.7, 17.7),
        ("203.0.113.1", 0, 0.8, 0.8),
    ],
)

# Non-indexed layout with a trailing STATUS column.
STATUS_COL_4HOP = (
    """ADDRESS                          LOSS SENT    LAST     AVG    BEST   WORST STD-DEV STATUS
192.0.2.10                         0%    3   0.2ms     0.2     0.1     0.2       0
198.51.100.7                       0%    3   1.6ms     1.5     1.4     1.6     0.1
198.51.100.8                       0%    3   0.5ms     0.5     0.5     0.5       0
203.0.113.8                        0%    3     1ms       1       1       1       0
""",
    "203.0.113.8",
    "router-b",
    [
        ("192.0.2.10", 0, 0.1, 0.2),
        ("198.51.100.7", 0, 1.4, 1.6),
        ("198.51.100.8", 0, 0.5, 0.5),
        ("203.0.113.8", 0, 1.0, 1.0),
    ],
)

STATUS_COL_5HOP = (
    """ADDRESS                          LOSS SENT    LAST     AVG    BEST   WORST STD-DEV STATUS
192.0.2.1                          0%    3   0.7ms     0.7     0.7     0.7       0
192.0.2.10                         0%    3   0.9ms     0.9     0.8     0.9       0
198.51.100.9                       0%    3   2.5ms     2.5     2.4     2.6     0.1
198.51.100.10                      0%    3   2.3ms     2.2     2.1     2.3     0.1
203.0.113.8                        0%    3   1.3ms     1.3     1.3     1.3       0
""",
    "203.0.113.8",
    "router-c",
    [
        ("192.0.2.1", 0, 0.7, 0.7),
        ("192.0.2.10", 0, 0.8, 0.9),
        ("198.51.100.9", 0, 2.4, 2.6),
        ("198.51.100.10", 0, 2.1, 2.3),
        ("203.0.113.8", 0, 1.3, 1.3),
    ],
)

CASES = {
    "indexed-5hop": INDEXED_5HOP,
    "indexed-2hop": INDEXED_2HOP,
    "status-col-4hop": STATUS_COL_4HOP,
    "status-col-5hop": STATUS_COL_5HOP,
}


@pytest.mark.parametrize("case", CASES.values(), ids=list(CASES.keys()))
def test_mikrotik_traceroute(case: t.Tuple) -> None:
    raw, target, source, expected = case
    result = parse_mikrotik_traceroute(raw, target=target, source=source)

    assert isinstance(result, TracerouteResult), "Expected a TracerouteResult"
    assert len(result.hops) == len(expected), (
        f"Expected {len(expected)} hops, got {len(result.hops)}"
    )

    for i, (hop, (ip, loss, best, worst)) in enumerate(zip(result.hops, expected), start=1):
        assert hop.hop_number == i, f"Hop {i}: wrong hop_number {hop.hop_number}"
        assert hop.ip_address == ip, f"Hop {i}: expected ip {ip!r}, got {hop.ip_address!r}"
        assert hop.loss_pct == loss, f"Hop {i}: expected loss {loss}, got {hop.loss_pct}"
        # BEST/WORST are preserved verbatim (AVG is a computed float and not
        # safe for exact comparison).
        assert hop.best_rtt == best, f"Hop {i}: expected best {best}, got {hop.best_rtt}"
        assert hop.worst_rtt == worst, f"Hop {i}: expected worst {worst}, got {hop.worst_rtt}"

    # The final hop is always the queried target.
    assert result.hops[-1].ip_address == target


def test_mikrotik_traceroute_timeout_hop() -> None:
    """A 100%-loss (timeout) row yields a hop with no IP/RTT but loss recorded."""
    result = parse_mikrotik_traceroute(*INDEXED_5HOP[:3])
    timeout = result.hops[1]
    assert timeout.ip_address is None
    assert timeout.loss_pct == 100
    assert timeout.last_rtt is None and timeout.avg_rtt is None
