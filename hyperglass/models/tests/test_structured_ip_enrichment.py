"""Tests for structured IP enrichment configuration."""

from types import SimpleNamespace

import pytest

from hyperglass.api.tasks import is_async_enrichment_enabled
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


def test_async_enrichment_recognizes_legacy_cached_output() -> None:
    """Treat structured cache dictionaries without status as enrichment candidates."""
    params = SimpleNamespace(
        structured=SimpleNamespace(
            ip_enrichment=StructuredIpEnrichment(
                mode="async", enrich_bgproute=True, enrich_traceroute=True
            ),
            enable_for_bgp_route=True,
            enable_for_traceroute=True,
        )
    )

    assert is_async_enrichment_enabled({"routes": []}, params)
    assert is_async_enrichment_enabled({"hops": []}, params)
    assert not is_async_enrichment_enabled("123", params)
