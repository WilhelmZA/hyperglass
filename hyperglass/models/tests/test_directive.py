"""Tests for directive target handling."""

# Third Party
import pytest

# Project
from hyperglass.models.directive import Directive


@pytest.mark.parametrize(
    ("condition", "target", "expected"),
    (
        ("0.0.0.0/0", "192.0.2.1/24", "192.0.2.0/24"),
        ("::/0", "2001:db8::1/64", "2001:db8::/64"),
        ("0.0.0.0/0", "192.0.2.1", "192.0.2.1"),
    ),
)
def test_normalize_target(condition: str, target: str, expected: str) -> None:
    """Canonicalize prefixed IP targets without changing host targets."""
    directive = Directive(
        id="test",
        name="Test",
        field={"description": "test"},
        rules=[{"condition": condition}],
    )

    assert directive.normalize_target(target) == expected
