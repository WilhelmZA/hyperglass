"""BGP.tools Integration for Hyperglass - Usage Examples and Integration Guide

This module demonstrates how to integrate BGP.tools enrichment into hyperglass
for both structured BGP results and clean traceroute data.
"""

# Example Configuration (config.yaml)
EXAMPLE_CONFIG = """
# Enable BGP.tools enrichment in your config.yaml
structured:
  bgp_tools:
    enabled: true              # Enable/disable BGP.tools enrichment
    cache_timeout: 86400       # Cache results for 24 hours 
    enrich_next_hop: true      # Enrich BGP next-hop information
    enrich_traceroute: true    # Enrich traceroute hop information
  
  communities:
    mode: name                 # Use "name" mode to show friendly names
    names:
      "65001:100": "Customer Routes"
      "65001:200": "Peer Routes" 
      "65001:300": "Transit Routes"
"""


# Example Usage 1: Automatic Enrichment via Monkey Patching
def enable_bgptools_enrichment():
    """Enable BGP.tools enrichment automatically for all queries."""
    from hyperglass.execution.enhanced import monkey_patch_execute

    # This will automatically enrich all query results
    monkey_patch_execute()


# Example Usage 2: Manual Enrichment for Specific Queries
async def enrich_bgp_route_example():
    """Example of manually enriching BGP route results."""
    from hyperglass.models.data.bgp_route import BGPRouteTable, BGPRoute
    from hyperglass.execution.enrichment import enrich_output_with_bgptools

    # Create sample BGP route table
    routes = [
        BGPRoute(
            prefix="1.1.1.0/24",
            active=True,
            age=3600,
            weight=100,
            med=0,
            local_preference=100,
            as_path=[65001, 13335],
            communities=["65001:100"],
            next_hop="192.0.2.1",  # This will be enriched with ASN info
            source_as=13335,
            source_rid="192.0.2.1",
            peer_rid="192.0.2.2",
            rpki_state=1,
        )
    ]

    route_table = BGPRouteTable(vrf="default", count=1, routes=routes, winning_weight="high")

    # Enrich with BGP.tools data
    enriched_table = await enrich_output_with_bgptools(route_table)

    # Access enriched data
    for route in enriched_table.routes:
        print(f"Next-hop {route.next_hop} is AS{route.next_hop_asn} ({route.next_hop_org})")


# Example Usage 3: Traceroute Parsing and Enrichment
async def enrich_traceroute_example():
    """Example of parsing and enriching traceroute results."""
    from hyperglass.models.parsing.traceroute import get_traceroute_parser
    from hyperglass.execution.enrichment import enrich_output_with_bgptools

    # Sample traceroute output
    traceroute_output = """
    traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets
     1  192.168.1.1 (192.168.1.1)  1.234 ms  1.456 ms  1.678 ms
     2  203.0.113.1 (203.0.113.1)  5.123 ms  5.234 ms  5.345 ms  
     3  198.51.100.1 (198.51.100.1)  15.123 ms  15.234 ms  15.345 ms
     4  8.8.8.8 (8.8.8.8)  25.123 ms  25.234 ms  25.345 ms
    """

    # Parse traceroute output
    parser = get_traceroute_parser("juniper")
    traceroute_result = parser.parse_text(
        text=traceroute_output, target="8.8.8.8", source="192.168.1.100"
    )

    # Enrich with BGP.tools data
    enriched_traceroute = await enrich_output_with_bgptools(traceroute_result)

    # Access enriched data
    print(f"AS Path: {enriched_traceroute.as_path_summary}")
    for hop in enriched_traceroute.hops:
        if hop.ip_address and hop.asn:
            print(f"Hop {hop.hop_number}: {hop.ip_address} [{hop.asn_display}] {hop.country}")


# Example Usage 4: Custom Output Formatting
def format_enriched_results():
    """Example of custom formatting for enriched results."""
    from hyperglass.execution.enrichment import (
        format_enriched_bgp_output,
        format_enriched_traceroute_output,
    )

    # These functions provide formatted output that includes BGP.tools data
    # They can be used in custom UI components or API responses
    pass


# Integration Steps:
INTEGRATION_STEPS = """
1. Add BGP.tools enrichment configuration to your config.yaml:
   structured:
     bgp_tools:
       enabled: true
       enrich_next_hop: true 
       enrich_traceroute: true

2. Choose one of three integration approaches:

   A. Automatic (Recommended): Monkey patch during startup
      from hyperglass.execution.enhanced import monkey_patch_execute
      monkey_patch_execute()
   
   B. Replace imports in routes.py:
      # Replace: from hyperglass.execution.main import execute
      # With: from hyperglass.execution.enhanced import execute_enhanced as execute
   
   C. Manual enrichment for specific use cases:
      from hyperglass.execution.enrichment import enrich_output_with_bgptools
      enriched_data = await enrich_output_with_bgptools(query_result)

3. For traceroute support, add parsing to your device drivers:
   from hyperglass.models.parsing.traceroute import get_traceroute_parser
   
   parser = get_traceroute_parser(device.platform)
   structured_result = parser.parse_text(raw_output, target, source)

4. Configure caching and timeout settings as needed for your environment.
"""

# Expected Benefits:
BENEFITS = """
- Next-hop ASN and organization information in BGP route tables
- ASN path visualization in traceroute results  
- Country/RIR information for network troubleshooting
- Cached results for improved performance
- Configurable enrichment levels
- Fallback gracefully if BGP.tools is unavailable
"""

if __name__ == "__main__":
    print("BGP.tools Integration for Hyperglass")
    print("=" * 50)
    print(INTEGRATION_STEPS)
    print("\nBenefits:")
    print(BENEFITS)
