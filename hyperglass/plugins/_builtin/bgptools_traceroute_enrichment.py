"""BGP.tools enrichment for traceroute output."""

# Standard Library
import re
import typing as t
import asyncio

# Third Party
from pydantic import PrivateAttr

# Project
from hyperglass.log import log
from hyperglass.state import use_state

# Local
from .._output import OutputType, OutputPlugin

if t.TYPE_CHECKING:
    # Project
    from hyperglass.models.api.query import Query


class BgpToolsTracerouteEnrichment(OutputPlugin):
    """Enrich traceroute output with BGP.tools ASN/organization data."""

    _hyperglass_builtin: bool = PrivateAttr(True)
    platforms: t.Sequence[str] = ("mikrotik_routeros", "mikrotik_switchos", "mikrotik", "cisco_ios", "juniper_junos")
    directives: t.Sequence[str] = ("traceroute", "MikroTik_Traceroute")

    def _should_enrich(self) -> bool:
        """Check if BGP.tools enrichment is enabled."""
        try:
            state = use_state()
            if (hasattr(state.params, 'structured') and 
                hasattr(state.params.structured, 'bgp_tools') and 
                state.params.structured.bgp_tools.enabled and
                state.params.structured.bgp_tools.enrich_traceroute):
                return True
        except Exception as e:
            log.debug(f"Error checking BGP.tools configuration: {e}")
        return False

    async def _enrich_ip_with_bgptools(self, ip: str) -> t.Dict[str, t.Any]:
        """Get BGP.tools data for an IP address."""
        try:
            from hyperglass.external.bgptools import BGPTools
            
            bgptools = BGPTools()
            result = await bgptools.query(ip)
            
            if result and hasattr(result, 'asn') and hasattr(result, 'org'):
                return {
                    'asn': result.asn,
                    'org': result.org,
                    'enriched': True
                }
        except Exception as e:
            log.debug(f"BGP.tools enrichment failed for {ip}: {e}")
        
        return {'enriched': False}

    def _extract_ips_from_traceroute(self, output: str) -> t.List[str]:
        """Extract IP addresses from traceroute output."""
        # Match IP addresses in various traceroute formats
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, output)
        
        # Remove duplicates while preserving order
        unique_ips = []
        for ip in ips:
            if ip not in unique_ips and not ip.startswith('0.') and not ip.startswith('127.'):
                unique_ips.append(ip)
        
        return unique_ips

    async def _enrich_traceroute_output(self, output: str) -> str:
        """Enrich traceroute output with BGP.tools data."""
        if not self._should_enrich():
            log.debug("BGP.tools enrichment not enabled")
            return output

        log.info("Enriching traceroute output with BGP.tools data")
        
        # Extract IPs from traceroute output
        ips = self._extract_ips_from_traceroute(output)
        
        if not ips:
            log.debug("No IPs found in traceroute output")
            return output

        log.debug(f"Found {len(ips)} IPs to enrich: {ips}")
        
        # Get BGP.tools data for all IPs
        enrichment_data = {}
        for ip in ips:
            data = await self._enrich_ip_with_bgptools(ip)
            if data.get('enriched'):
                enrichment_data[ip] = data
                log.debug(f"Enriched {ip}: AS{data['asn']} - {data['org']}")

        if not enrichment_data:
            log.debug("No enrichment data obtained from BGP.tools")
            return output

        # Add enrichment information to output
        enriched_output = output + "\n\n=== BGP.tools Enrichment ===\n"
        for ip, data in enrichment_data.items():
            enriched_output += f"{ip}: AS{data['asn']} - {data['org']}\n"
        
        log.info(f"Successfully enriched traceroute with {len(enrichment_data)} ASN lookups")
        return enriched_output

    def process(self, output: OutputType, query: "Query") -> OutputType:
        """Process traceroute output and add BGP.tools enrichment."""
        if isinstance(output, (list, tuple)):
            # Handle multiple output blocks
            processed_outputs = []
            for out in output:
                if isinstance(out, str):
                    enriched = asyncio.run(self._enrich_traceroute_output(out))
                    processed_outputs.append(enriched)
                else:
                    processed_outputs.append(out)
            return tuple(processed_outputs)
        elif isinstance(output, str):
            # Handle single output block
            return asyncio.run(self._enrich_traceroute_output(output))
        else:
            # Return unchanged if not string output
            return output