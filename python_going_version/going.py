#!/usr/bin/env python3
"""
Enhanced TCP Connection Monitor
- Parses /proc/net/tcp
- Shows both IPv4 and IPv6 connections
- Clean tabular output
"""

import os
import re
from typing import List, NamedTuple

class Socket(NamedTuple):
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str

TCP_STATES = {
    1: "ESTABLISHED",
    2: "SYN_SENT",
    3: "SYN_RECV",
    4: "FIN_WAIT1",
    5: "FIN_WAIT2",
    6: "TIME_WAIT",
    7: "CLOSE",
    8: "CLOSE_WAIT",
    9: "LAST_ACK",
    10: "LISTEN",
    11: "CLOSING",
    12: "NEW_SYN_RECV",
}

def parse_hex_ip_port(hex_str: str) -> tuple[str, int]:
    """Parse IP:port from hex format (e.g. '0100007F:0016')"""
    try:
        ip_part, port_part = hex_str.split(':')
        ip_bytes = bytes.fromhex(ip_part)
        
        # IPv4 (4 bytes)
        if len(ip_bytes) == 4:
            ip = '.'.join(str(b) for b in reversed(ip_bytes))
        # IPv6 (16 bytes)
        else:
            ip = ':'.join(f"{(ip_bytes[i]<<8)+ip_bytes[i+1]:04x}" 
                         for i in range(0, 16, 2))
        
        return ip, int(port_part, 16)
    except ValueError:
        raise ValueError(f"Invalid format: {hex_str}")

def read_tcp_connections() -> List[Socket]:
    """Read active TCP connections from /proc/net/tcp"""
    sockets = []
    try:
        with open('/proc/net/tcp', 'r') as f:
            next(f)  # Skip header
            for line in f:
                fields = re.split(r'\s+', line.strip())
                if len(fields) < 4:
                    continue
                
                try:
                    local = parse_hex_ip_port(fields[1])
                    remote = parse_hex_ip_port(fields[2])
                    state_code = int(fields[3], 16)
                    
                    sockets.append(Socket(
                        local_ip=local[0],
                        local_port=local[1],
                        remote_ip=remote[0],
                        remote_port=remote[1],
                        state=TCP_STATES.get(state_code, f"UNKNOWN({state_code})")
                    ))
                except ValueError:
                    continue
                    
        return sockets
    except IOError as e:
        print(f" Error reading /proc/net/tcp: {e}")
        return []

def display_connections(sockets: List[Socket]) -> None:
    """Print connections in formatted table"""
    if not sockets:
        print("No active TCP connections found")
        return
    
    # Print header
    print("\nACTIVE TCP CONNECTIONS:")
    print(f"{'State':<15} {'Local Address':<25} {'Remote Address':<25}")
    print("-" * 65)
    
    # Print each connection
    for s in sockets:
        print(f"{s.state:<15} {f'{s.local_ip}:{s.local_port}':<25} {f'{s.remote_ip}:{s.remote_port}':<25}")

if __name__ == "__main__":
    display_connections(read_tcp_connections())
