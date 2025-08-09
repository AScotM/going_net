#!/usr/bin/env python3
"""
Enhanced TCP Connection Monitor
- Parses /proc/net/tcp and /proc/net/tcp6
- Shows both IPv4 and IPv6 connections
- Clean tabular output with dynamic column widths
- Supports real-time monitoring, process information, filtering, permissions handling, and colorized output
"""

import argparse
import logging
import os
import re
import time
import glob
from typing import List, NamedTuple
from colorama import Fore, init

# Initialize colorama for colored output
init()

# Configure logging
logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')

class Socket(NamedTuple):
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    process: str  # New field for process name and PID

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

STATE_COLORS = {
    "ESTABLISHED": Fore.GREEN,
    "LISTEN": Fore.BLUE,
    "CLOSE": Fore.RED,
    "TIME_WAIT": Fore.YELLOW,
    "SYN_SENT": Fore.CYAN,
    "SYN_RECV": Fore.CYAN,
    "FIN_WAIT1": Fore.MAGENTA,
    "FIN_WAIT2": Fore.MAGENTA,
    "CLOSE_WAIT": Fore.RED,
    "LAST_ACK": Fore.RED,
    "CLOSING": Fore.RED,
    "NEW_SYN_RECV": Fore.CYAN
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

def get_process_name(inode: str) -> str:
    """Find process name and PID by matching socket inode"""
    for pid_dir in glob.glob("/proc/[0-9]*/fd/*"):
        try:
            if os.path.islink(pid_dir) and os.readlink(pid_dir).endswith(f"socket:[{inode}]"):
                pid = pid_dir.split("/")[2]
                with open(f"/proc/{pid}/comm", "r") as f:
                    return f"{f.read().strip()} ({pid})"
        except (IOError, OSError):
            continue
    return "Unknown"

def read_tcp_connections(file_path: str) -> List[Socket]:
    """Read active TCP connections from the specified file"""
    sockets = []
    if not os.path.exists(file_path):
        logging.error(f"File {file_path} does not exist")
        return sockets
    if not os.access(file_path, os.R_OK):
        logging.error(f"No read permission for {file_path}. Try running with sudo.")
        return sockets

    try:
        with open(file_path, 'r') as f:
            header = f.readline().strip()
            if not re.match(r'\s*sl\s+local_address\s+rem_address', header):
                logging.error(f"Invalid TCP file format: {file_path}")
                return sockets
            for line in f:
                fields = re.split(r'\s+', line.strip())
                if len(fields) < 10:  # Need inode field (index 9)
                    logging.warning(f"Skipping malformed line: {line.strip()}")
                    continue
                
                try:
                    local = parse_hex_ip_port(fields[1])
                    remote = parse_hex_ip_port(fields[2])
                    state_code = int(fields[3], 16)
                    inode = fields[9]  # Inode field for process mapping
                    
                    state = TCP_STATES.get(state_code, f"UNKNOWN({state_code})")
                    if state.startswith("UNKNOWN"):
                        logging.warning(f"Unknown state code: {state_code}")
                    
                    process = get_process_name(inode)
                    
                    sockets.append(Socket(
                        local_ip=local[0],
                        local_port=local[1],
                        remote_ip=remote[0],
                        remote_port=remote[1],
                        state=state,
                        process=process
                    ))
                except ValueError as e:
                    logging.warning(f"Skipping line due to parse error: {e}")
                    continue
                    
        return sockets
    except IOError as e:
        logging.error(f"Error reading {file_path}: {e}")
        return []

def filter_sockets(sockets: List[Socket], args) -> List[Socket]:
    """Filter sockets based on command-line arguments"""
    filtered = sockets
    if args.state:
        filtered = [s for s in filtered if s.state == args.state.upper()]
    if args.local_ip:
        filtered = [s for s in filtered if s.local_ip == args.local_ip]
    if args.remote_ip:
        filtered = [s for s in filtered if s.remote_ip == args.remote_ip]
    if args.port:
        filtered = [s for s in filtered if s.local_port == args.port or s.remote_port == args.port]
    return filtered

def display_connections(sockets: List[Socket]) -> None:
    """Print connections in formatted table with dynamic column widths and colors"""
    if not sockets:
        print("No active TCP connections found")
        return
    
    # Calculate maximum lengths for dynamic column widths
    max_addr_len = 25  # Minimum width
    max_process_len = 15  # Minimum width for process column
    for s in sockets:
        local_addr = f"{s.local_ip}:{s.local_port}"
        remote_addr = f"{s.remote_ip}:{s.remote_port}"
        max_addr_len = max(max_addr_len, len(local_addr), len(remote_addr))
        max_process_len = max(max_process_len, len(s.process))
    
    # Print header
    print("\nACTIVE TCP CONNECTIONS:")
    print(f"{'State':<15} {'Local Address':<{max_addr_len}} {'Remote Address':<{max_addr_len}} {'Process':<{max_process_len}}")
    print("-" * (15 + max_addr_len * 2 + max_process_len + 3))
    
    # Print each connection with colored state
    for s in sockets:
        local_addr = f"{s.local_ip}:{s.local_port}"
        remote_addr = f"{s.remote_ip}:{s.remote_port}"
        color = STATE_COLORS.get(s.state, Fore.WHITE)
        print(f"{color}{s.state:<15}{Fore.RESET} {local_addr:<{max_addr_len}} {remote_addr:<{max_addr_len}} {s.process:<{max_process_len}}")

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="TCP Connection Monitor")
    parser.add_argument("--tcp-file", default="/proc/net/tcp", help="Path to TCP file")
    parser.add_argument("--tcp6-file", default="/proc/net/tcp6", help="Path to TCP6 file")
    parser.add_argument("--watch", type=float, default=0, help="Refresh interval in seconds (0 for single snapshot)")
    parser.add_argument("--state", help="Filter by connection state (e.g., ESTABLISHED)")
    parser.add_argument("--local-ip", help="Filter by local IP address")
    parser.add_argument("--remote-ip", help="Filter by remote IP address")
    parser.add_argument("--port", type=int, help="Filter by local or remote port")
    args = parser.parse_args()

    # Read and display connections
    if args.watch > 0:
        while True:
            sockets = []
            for file_path in [args.tcp_file, args.tcp6_file]:
                sockets.extend(read_tcp_connections(file_path))
            sockets = filter_sockets(sockets, args)
            os.system('clear')
            display_connections(sockets)
            time.sleep(args.watch)
    else:
        sockets = []
        for file_path in [args.tcp_file, args.tcp6_file]:
            sockets.extend(read_tcp_connections(file_path))
        sockets = filter_sockets(sockets, args)
        display_connections(sockets)

if __name__ == "__main__":
    main()
