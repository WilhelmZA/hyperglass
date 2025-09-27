#!/usr/bin/env python3
"""Debug MikroTik traceroute parser."""

import sys
import os
sys.path.insert(0, "/home/wilhelms@RiskMonitorGroup.local/SourceControl/OwnProjects/hyperglass-official/hyperglass")

from hyperglass.models.parsing.mikrotik import MikrotikTracerouteTable

# Test data from user's output
test_data = """ADDRESS                          LOSS SENT    LAST     AVG    BEST   WORST STD-DEV STATUS                                                                                                                                                                                                                                                                                                                                                                                                                                     
102.217.253.3                      0%    1  15.3ms    15.3    15.3    15.3       0                                                                                                                                                                                                                                                                                                                                                                                                                                            
196.60.9.113                       0%    1  16.5ms    16.5    16.5    16.5       0                                                                                                                                                                                                                                                                                                                                                                                                                                            
172.253.65.179                     0%    1  15.7ms    15.7    15.7    15.7       0                                                                                                                                                                                                                                                                                                                                                                                                                                            
192.178.86.205                     0%    1    16ms      16      16      16       0                                                                                                                                                                                                                                                                                                                                                                                                                                            
8.8.8.8                            0%    1  15.7ms    15.7    15.7    15.7       0                                                                                                                                                                                                                                                                                                                                                                                                                                            
102.217.253.3                      0%    2  15.3ms    15.3    15.3    15.3       0                                                                                                                                                                                                                                                                                                                                                                                                                                            
196.60.9.113                       0%    2  16.3ms    16.4    16.3    16.5     0.1                                                                                                                                                                                                                                                                                                                                                                                                                                            
172.253.65.179                     0%    2  15.7ms    15.7    15.7    15.7       0                                                                                                                                                                                                                                                                                                                                                                                                                                            
192.178.86.205                     0%    2  16.3ms    16.2      16    16.3     0.2                                                                                                                                                                                                                                                                                                                                                                                                                                            
8.8.8.8                            0%    2  15.7ms    15.7    15.7    15.7       0                                                                                                                                                                                                                                                                                                                                                                                                                                            
102.217.253.3                      0%    3  15.3ms    15.3    15.3    15.3       0                                                                                                                                                                                                                                                                                                                                                                                                                                            
196.60.9.113                       0%    3  16.4ms    16.4    16.3    16.5     0.1                                                                                                                                                                                                                                                                                                                                                                                                                                            
172.253.65.179                     0%    3  15.8ms    15.7    15.7    15.8       0                                                                                                                                                                                                                                                                                                                                                                                                                                            
192.178.86.205                     0%    3  16.2ms    16.2      16    16.3     0.1                                                                                                                                                                                                                                                                                                                                                                                                                                            
8.8.8.8                            0%    3  15.7ms    15.7    15.7    15.7       0"""

def main():
    print("=== Testing MikroTik Traceroute Parser ===")
    print(f"Input data has {len(test_data.split(chr(10)))} lines")
    
    try:
        result = MikrotikTracerouteTable.parse_text(test_data, "8.8.8.8", "test")
        print(f"\n=== Parser Result ===")
        print(f"Target: {result.target}")
        print(f"Source: {result.source}")
        print(f"Number of hops: {len(result.hops)}")
        
        print(f"\n=== Hop Details ===")
        for hop in result.hops:
            print(f"Hop {hop.hop_number}: {hop.ip_address} - Loss: {hop.loss_pct}% - Sent: {hop.sent_count} - Last: {hop.last_rtt}ms")
            
        # Convert to TracerouteResult
        traceroute_result = result.traceroute_result()
        print(f"\n=== TracerouteResult ===")
        print(f"Number of converted hops: {len(traceroute_result.hops)}")
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()