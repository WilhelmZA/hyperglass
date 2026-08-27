"""Tests for IP enrichment caching."""

import pytest

from hyperglass.external.ip_enrichment import IPEnrichmentService


@pytest.mark.asyncio
async def test_bulk_lookup_caches_negative_results(monkeypatch) -> None:
    """Cache a missing bulk lookup so repeated queries do not repeat the network call."""
    service = IPEnrichmentService()
    calls = 0

    async def lookup(_ips):
        nonlocal calls
        calls += 1
        return {"8.8.8.8": (None, None, None)}

    monkeypatch.setattr(service, "_query_bgp_tools_bulk", lookup)

    first = await service.lookup_ips_bulk(["8.8.8.8"])
    second = await service.lookup_ips_bulk(["8.8.8.8"])

    assert calls == 1
    assert first["8.8.8.8"].asn == 0
    assert second["8.8.8.8"].asn == 0
