"""Tests for structured IP enrichment configuration."""

import pytest

from hyperglass.models.config.structured import StructuredIpEnrichment


def test_ip_enrichment_defaults_to_inline() -> None:
    """Keep existing deployments on inline enrichment unless opted in."""
    assert StructuredIpEnrichment().mode == "inline"


def test_ip_enrichment_accepts_async_mode() -> None:
    """Allow asynchronous enrichment to be selected explicitly."""
    assert StructuredIpEnrichment(mode="async").mode == "async"


def test_ip_enrichment_rejects_unknown_mode() -> None:
    """Reject unsupported enrichment execution modes."""
    with pytest.raises(ValueError):
        StructuredIpEnrichment(mode="later")
