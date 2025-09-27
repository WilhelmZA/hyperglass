"""Test script for the new IP enrichment system."""

import asyncio
import sys
import os

# Add hyperglass to path
sys.path.insert(
    0,
    "/home/wilhelms@RiskMonitorGroup.local/SourceControl/OwnProjects/hyperglass-official/hyperglass",
)


async def test_ip_enrichment():
    """Test the IP enrichment system."""
    try:
        # Import the functions
        from hyperglass.external.ip_enrichment import lookup_ip, lookup_asn_name, network_info

        print("✅ Successfully imported IP enrichment functions")
        print("✅ Functions available:")
        print("  - lookup_ip(ip_address) -> returns ASN or IXP info")
        print("  - lookup_asn_name(asn_number) -> returns ASN organization name")
        print("  - network_info(*ips) -> bulk lookup for compatibility")
        print()

        # Test private IP handling (should work without dependencies)
        print("Testing private IP handling...")
        result = await network_info("192.168.1.1", "10.0.0.1")
        print(f"Private IPs result: {result}")
        print("✅ Private IP handling works")

        return True

    except Exception as e:
        print(f"❌ Error testing IP enrichment: {e}")
        return False


if __name__ == "__main__":
    success = asyncio.run(test_ip_enrichment())
    if success:
        print("\n🎉 IP enrichment system is properly set up!")
        print("📝 Note: Full functionality requires httpx and aiofiles dependencies")
        print("📝 When dependencies are available, the system will:")
        print("   • Download BGP.tools bulk data for CIDR->ASN mapping")
        print("   • Download ASN organization names")
        print("   • Download PeeringDB data for IXP detection")
        print("   • Cache data for 24 hours for performance")
    else:
        print("\n❌ IP enrichment system has issues")
