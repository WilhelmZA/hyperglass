"""IP enrichment for structured BGP route data - show path functionality."""

# Standard Library
import asyncio
import typing as t

# Third Party
from pydantic import PrivateAttr

# Project
from hyperglass.log import log
from hyperglass.plugins._output import OutputPlugin
from hyperglass.models.data.bgp_route import BGPRouteTable

if t.TYPE_CHECKING:
    from hyperglass.models.data import OutputDataModel
    from hyperglass.models.api.query import Query


class ZBgpRouteIpEnrichment(OutputPlugin):
    """Enrich structured BGP route output with IP enrichment for next-hop ASN/organization data."""

    _hyperglass_builtin: bool = PrivateAttr(True)
    platforms: t.Sequence[str] = (
        "mikrotik_routeros",
        "mikrotik_switchos",
        "mikrotik",
        "cisco_ios",
        "juniper_junos",
        "arista_eos",
        "frr",
    )
    directives: t.Sequence[str] = ("bgp_route", "bgp_community")
    common: bool = True

    async def _enrich_async(self, output: BGPRouteTable) -> None:
        """Async helper to enrich BGP route data."""
        await output.enrich_with_ip_enrichment()

    def process(self, *, output: "OutputDataModel", query: "Query") -> "OutputDataModel":
        """Enrich structured BGP route data with next-hop IP enrichment information."""

        if not isinstance(output, BGPRouteTable):
            return output

        _log = log.bind(plugin=self.__class__.__name__)
        _log.debug(f"Starting IP enrichment for {len(output.routes)} BGP routes")

        # Check if IP enrichment is enabled in config
        try:
            from hyperglass.settings import settings

            if not settings.structured.ip_enrichment.enabled:
                _log.debug("IP enrichment disabled in configuration")
                return output

            if not settings.structured.ip_enrichment.enrich_next_hop:
                _log.debug("Next-hop enrichment disabled in configuration")
                return output
        except Exception as e:
            _log.debug(f"Could not check IP enrichment config: {e}")

        # Use the built-in enrichment method from BGPRouteTable
        try:
            # Run async enrichment in sync context
            loop = None
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # If we're already in an event loop, create a new task
                    import concurrent.futures

                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        future = executor.submit(asyncio.run, self._enrich_async(output))
                        future.result()
                else:
                    loop.run_until_complete(self._enrich_async(output))
            except RuntimeError:
                # No event loop, create one
                asyncio.run(self._enrich_async(output))
            _log.debug("BGP route IP enrichment completed successfully")
        except Exception as e:
            _log.error(f"BGP route IP enrichment failed: {e}")

        _log.debug(f"Completed enrichment for BGP routes")
        return output
