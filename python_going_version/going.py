#!/usr/bin/env python3
"""
Enhanced TCP Connection Monitor
- Parses /proc/net/tcp and /proc/net/tcp6
- Shows both IPv4 and IPv6 connections
- Clean tabular output with dynamic column widths
"""

import argparse
import logging
import os
import re
from typing import List, NamedTuple

# Configure logging
logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')

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
    """Parse IP:port from hex format (e.g., '0100007F:0016' or '20010DB8...:1F90')"""
    try:
        ip_part, port_part = hex_str.split(':')
        ip_bytes = bytes.fromhex(ip_part)
        
        # IPv4 (4 bytes)
        if len(ip_bytes) == 4:
            ip = '.'.join(str(b) for b in reversed(ip_bytes))
        # IPv6 (16 bytes)
        elif len(ip_bytes) == 16:
            ip = ':'.join(f"{(ip_bytes[i] << 8) + ip_bytes[i+1]:04x}"
                         for i in range(0, 16, 2))
        else:
            raise ValueError(f"Invalid IP length: {len(ip_bytes)}")
        
        port = int(port_part, 16)
        return ip, port
    except ValueError as e:
        raise ValueError(f"Invalid format: {hex_str}, error: {e}")

def read_tcp_connections(file_path: str) -> List[Socket]:
    """Read active TCP connections from the specified file"""
    sockets = []
    if not os.path.exists(file_path):
        logging.warning(f"File {file_path} does not exist")
        return sockets

    try:
        with open(file_path, 'r') as f:
            next(f)  # Skip header
            for line in f:
                fields = re.split(r'\s+', line.strip())
                if len(fields) < 4:
                    logging.warning(f"Skipping malformed line: {line.strip()}")
                    continue
                
                try:
                    local = parse_hex_ip_port(fields[1])
                    remote = parse_hex_ip_port(fields[2])
                    
                    # Parse state code explicitly
                    try:
                        state_code = int(fields[3], 16)
                    except ValueError as e:
                        logging.warning(f"Skipping line due to state parse error: {e}")
                        continue
                    
                    state = TCP_STATES.get(state_code, f"UNKNOWN({state_code})")
                    if state.startswith("UNKNOWN"):
                        logging.warning(f"Unknown state code: {state_code}")
                    
                    sockets.append(Socket(
                        local_ip=local[0],
                        local_port=local[1],
                        remote_ip=remote[0],
                        remote_port=remote[1],
                        state=state
                    ))
                except ValueError as e:
                    logging.warning(f"Skipping line due to parse error: {e}")
                    continue
                    
        return sockets
    except IOError as e:
        logging.error(f"Error reading {file_path}: {e}")
        return []

def display_connections(sockets: List[Socket]) -> None:
    """Print connections in formatted table with dynamic column widths"""
    if not sockets:
        print("No active TCP connections found")
        return
    
    # Calculate maximum address length for dynamic column width
    max_addr_len = 25  # Minimum width
    for s in sockets:
        local_addr = f"{s.local_ip}:{s.local_port}"
        remote_addr = f"{s.remote_ip}:{s.remote_port}"
        max_addr_len = max(max_addr_len, len(local_addr), len(remote_addr))
    
    # Print header
    print("\nACTIVE TCP CONNECTIONS:")
    print(f"{'State':<15} {'Local Address':<{max_addr_len}} {'Remote Address':<{max_addr_len}}")
    print("-" * (15 + max_addr_len * 2 + 2))
    
    # Print each connection
    for s in sockets:
        local_addr = f"{s.local_ip}:{s.local_port}"
        remote_addr = f"{s.remote_ip}:{s.remote_port}"
        print(f"{s.state:<15} {local_addr:<{max_addr_len}} {remote_addr:<{max_addr_len}}")

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="TCP Connection Monitor")
    parser.add_argument("--tcp-file", default="/proc/net/tcp", help="Path to TCP file")
    parser.add_argument("--tcp6-file", default="/proc/net/tcp6", help="Path to TCP6 file")
    args = parser.parse_args()

    # Read IPv4 and IPv6 connections
    sockets = []
    for file_path in [args.tcp_file, args.tcp6_file]:
        sockets.extend(read_tcp_connections(file_path))
    
    display_connections(sockets)

if __name__ == "__main__":
    main()
