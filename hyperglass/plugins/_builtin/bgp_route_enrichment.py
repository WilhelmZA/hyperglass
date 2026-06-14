"""ASN organization enrichment for structured BGP route data."""

# Standard Library
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


class ZBgpRouteEnrichment(OutputPlugin):
    """Enrich structured BGP route output with ASN organization data."""

    _hyperglass_builtin: bool = PrivateAttr(True)
    platforms: t.Sequence[str] = (
        "mikrotik_routeros",
        "mikrotik_switchos",
        "mikrotik",
        "cisco_ios",
        "juniper_junos",
        "huawei",
        "huawei_vrpv8",
        "arista_eos",
        "bird",
    )
    directives: t.Sequence[str] = ("bgp_route", "MikroTik_BGPRoute")
    common: bool = True

    def process(self, *, output: "OutputDataModel", query: "Query") -> "OutputDataModel":
        """Enrich structured BGP route data with ASN organization information."""

        if not isinstance(output, BGPRouteTable):
            return output

        _log = log.bind(plugin=self.__class__.__name__)

        # Check if BGP route enrichment is enabled in config
        try:
            from hyperglass.state import use_state
            from hyperglass.settings import Settings

            params = use_state("params")
            # If structured config missing or BGP route enrichment disabled, skip
            if (
                not getattr(params, "structured", None)
                or not params.structured.ip_enrichment.enrich_bgproute
                or getattr(params.structured, "enable_for_bgp_route", None) is False
            ):
                if Settings.debug:
                    _log.debug("ASN enrichment for BGP routes disabled in configuration")
                return output

            _log.info(f"Starting ASN and next-hop enrichment for {len(output.routes)} BGP routes")

            # Run enrichment in event loop
            import asyncio

            async def enrich_all():
                """Run both AS path and next-hop enrichment."""
                await output.enrich_as_path_organizations()
                await output.enrich_with_ip_enrichment()

            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # We're inside an event loop; create task
                    import concurrent.futures

                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        future = executor.submit(lambda: asyncio.run(enrich_all()))
                        future.result()
                else:
                    # No loop running, we can use asyncio.run directly
                    asyncio.run(enrich_all())
            except RuntimeError:
                # Fallback if we can't determine loop state
                asyncio.run(enrich_all())

            enriched_asn_count = len(output.asn_organizations)
            enriched_nexthop_count = sum(1 for r in output.routes if r.next_hop_org)
            _log.info(
                f"Enriched {enriched_asn_count} unique ASNs and {enriched_nexthop_count} next-hops with organization data"
            )

        except Exception as e:
            _log.error(f"BGP route enrichment failed: {e}")
            # Don't fail the entire request if enrichment fails

        return output
