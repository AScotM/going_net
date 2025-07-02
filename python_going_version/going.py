#!/usr/bin/env python3
"""
TCP Connection Monitor - Python Version
"""

import os
import re
from typing import List, Dict, NamedTuple

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
    """Parse hexadecimal IP:port string into (IP, port) tuple."""
    try:
        ip_part, port_part = hex_str.split(':')
        
        # Parse IP address (network byte order)
        ip_bytes = bytes.fromhex(ip_part)
        
        # IPv4 case (4 bytes)
        if len(ip_bytes) == 4:
            ip_bytes = bytes(reversed(ip_bytes))
            ip = '.'.join(str(b) for b in ip_bytes)
        # IPv6 case (16 bytes)
        else:
            # Convert to 8 groups of 2 bytes each
            ip_groups = []
            for i in range(0, 16, 2):
                group = (ip_bytes[i] << 8) + ip_bytes[i+1]
                ip_groups.append(f"{group:x}")
            ip = ':'.join(ip_groups)
        
        # Parse port
        port = int(port_part, 16)
        
        return ip, port
    except (ValueError, AttributeError):
        raise ValueError(f"Invalid IP:port format: {hex_str}")

def read_tcp_connections() -> List[Socket]:
    """Read and parse /proc/net/tcp file."""
    sockets = []
    try:
        with open('/proc/net/tcp', 'r') as f:
            next(f)  # Skip header line
            
            for line in f:
                fields = re.split(r'\s+', line.strip())
                if len(fields) < 4:
                    continue
                
                try:
                    # Parse local and remote addresses
                    local_ip, local_port = parse_hex_ip_port(fields[1])
                    remote_ip, remote_port = parse_hex_ip_port(fields[2])
                    
                    # Parse state
                    state_code = int(fields[3], 16)
                    state = TCP_STATES.get(state_code, f"UNKNOWN({state_code})")
                    
                    sockets.append(Socket(
                        local_ip=local_ip,
                        local_port=local_port,
                        remote_ip=remote_ip,
                        remote_port=remote_port,
                        state=state
                    ))
                except ValueError:
                    continue
                    
    except IOError as e:
        print(f"Error reading /proc/net/tcp: {e}")
        return []
    
    return sockets

def display_connections(sockets: List[Socket]) -> None:
    """Display connections in a formatted table."""
    # Header
    print(f"{'State':<15} {'Local Address':<25} {'Remote Address':<25}")
    print("-" * 65)
    
    # Rows
    for s in sockets:
        print(f"{s.state:<15} "
              f"{f'{s.local_ip}:{s.local_port}':<25} "
              f"{f'{s.remote_ip}:{s.remote_port}':<25}")

def main() -> None:
    """Main function."""
    sockets = read_tcp_connections()
    display_connections(sockets)

if __name__ == "__main__":
    main()
