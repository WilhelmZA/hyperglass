"""BGP.tools traceroute enrichment plugin for hyperglass."""

# Standard Library
import re
import time
import typing as t
from typing import Any, Dict, List, Optional, Tuple, Union

# Third Party
from pydantic import PrivateAttr

# Project
from hyperglass.log import log
from hyperglass.plugins._output import OutputPlugin
from hyperglass.state import use_state

if t.TYPE_CHECKING:
    from hyperglass.models.data import Query

OutputType = Union[str, Tuple[str, ...]]

if t.TYPE_CHECKING:
    # Project
    from hyperglass.models.api.query import Query


class ZBgpToolsTracerouteEnrichment(OutputPlugin):
    """Enrich traceroute output with BGP.tools ASN/organization data."""

    _hyperglass_builtin: bool = PrivateAttr(True)
    platforms: t.Sequence[str] = ("mikrotik_routeros", "mikrotik_switchos", "mikrotik", "cisco_ios", "juniper_junos")
    directives: t.Sequence[str] = ("traceroute", "MikroTik_Traceroute")
    # Run in common phase after directive-specific plugins
    common: bool = True

    def _should_enrich(self) -> bool:
        """Check if BGP.tools enrichment should be enabled."""
        try:
            state = use_state()
            # Get params from cache/state instead of direct import
            params = state.cache.get("params")
            if params and hasattr(params, 'structured') and hasattr(params.structured, 'bgp_tools'):
                return bool(params.structured.bgp_tools)
            return False
        except Exception as e:
            log.debug(f"Failed to check BGP.tools configuration: {e}")
            return False

    def _enrich_ip_with_bgptools(self, ip: str) -> t.Dict[str, t.Any]:
        """Query BGP.tools whois interface for IP enrichment data.
        
        Args:
            ip: IP address to enrich
            
        Returns:
            Dictionary containing ASN and organization information
        """
        import socket
        
        try:
            # Connect to BGP.tools whois interface
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(('bgp.tools', 43))
            
            # Send whois query in bulk mode
            query = f"begin\nverbose\n{ip}\nend\n"
            sock.sendall(query.encode())
            
            # Read response
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            sock.close()
            
            # Parse response
            response_text = response.decode('utf-8', errors='ignore').strip()
            log.debug(f"BGP.tools response for {ip}: {response_text}")
            
            if response_text and '|' in response_text:
                # Parse format: ASN | IP | BGP Prefix | CC | Registry | Allocated | AS Name
                lines = response_text.split('\n')
                for line in lines:
                    if '|' in line and ip in line:
                        parts = [p.strip() for p in line.split('|')]
                        if len(parts) >= 7:
                            asn = parts[0]
                            org = parts[6] if len(parts) > 6 else ""
                            country = parts[3] if len(parts) > 3 else ""
                            return {
                                "asn": asn if asn and asn != "" else None,
                                "org": org,
                                "country": country
                            }
                        
        except Exception as e:
            log.debug(f"BGP.tools enrichment failed for {ip}: {e}")
        
        return {"asn": None, "org": "", "country": None}

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

    def _enrich_traceroute_output(self, output: str) -> str:
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
            data = self._enrich_ip_with_bgptools(ip)
            if data.get('asn') or data.get('org'):
                enrichment_data[ip] = data
                log.debug(f"Enriched {ip}: AS{data['asn']} - {data['org']}")
                # Add a small delay to be respectful to the API
                time.sleep(0.1)

        if not enrichment_data:
            log.debug("No enrichment data obtained from BGP.tools")
            return output

        # Add enrichment data as footer
        footer = "\n\n=== BGP.tools Enrichment ===\n"
        for ip, data in enrichment_data.items():
            asn = data.get('asn')
            org = data.get('org', '')
            country = data.get('country', '')
            
            if asn and asn != 'None':
                footer += f"{ip}: AS{asn}"
                if org:
                    footer += f" - {org}"
                if country:
                    footer += f" ({country})"
                footer += "\n"

        return output + footer

    def process(self, output: OutputType, query: "Query") -> OutputType:
        """Process traceroute output and add BGP.tools enrichment."""
        if isinstance(output, (list, tuple)):
            # Handle multiple output blocks
            processed_outputs = []
            for out in output:
                if isinstance(out, str):
                    enriched = self._enrich_traceroute_output(out)
                    processed_outputs.append(enriched)
                else:
                    processed_outputs.append(out)
            return tuple(processed_outputs)
        elif isinstance(output, str):
            # Handle single output block
            return self._enrich_traceroute_output(output)
        else:
            # Return unchanged if not string output
            return output