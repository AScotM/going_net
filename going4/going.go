package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

var warnLog = log.New(os.Stderr, "WARNING: ", log.LstdFlags)

var tcpStates = map[int]string{
	1:  "ESTABLISHED",
	2:  "SYN_SENT",
	3:  "SYN_RECV",
	4:  "FIN_WAIT1",
	5:  "FIN_WAIT2",
	6:  "TIME_WAIT",
	7:  "CLOSE",
	8:  "CLOSE_WAIT",
	9:  "LAST_ACK",
	10: "LISTEN",
	11: "CLOSING",
	12: "NEW_SYN_RECV",
}

// Socket represents a TCP connection with local and remote addresses and state.
type Socket struct {
	LocalIP    string
	LocalPort  int
	RemoteIP   string
	RemotePort int
	State      string
}

// parseHexIPPort parses a hex-encoded IP:port string into IP address and port number.
func parseHexIPPort(s string) (string, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid format: %s", s)
	}

	// Parse IP
	ipBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", 0, fmt.Errorf("failed to decode IP: %v", err)
	}

	var ip string
	if len(ipBytes) == 4 || len(ipBytes) == 16 {
		ip = net.IP(ipBytes).String() // Handles both IPv4 and IPv6 correctly
	} else {
		return "", 0, fmt.Errorf("invalid IP length: %d", len(ipBytes))
	}

	// Parse port
	port, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return "", 0, fmt.Errorf("failed to parse port: %v", err)
	}
	if port < 0 || port > 65535 {
		return "", 0, fmt.Errorf("port %d out of range (0-65535)", port)
	}

	return ip, int(port), nil
}

// readTCPConnections reads TCP connections from a file like /proc/net/tcp or /proc/net/tcp6.
func readTCPConnections(filePath string) ([]Socket, error) {
	// Check if file exists and is readable
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("file %s does not exist", filePath)
	} else if err != nil {
		return nil, fmt.Errorf("failed to access %s: %v", filePath, err)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %v", filePath, err)
	}
	defer file.Close()

	sockets := make([]Socket, 0, 100) // Preallocate for performance
	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			warnLog.Printf("Skipping malformed line in %s: %s", filePath, scanner.Text())
			continue
		}

		// Parse addresses
		localIP, localPort, err := parseHexIPPort(fields[1])
		if err != nil {
			warnLog.Printf("Skipping line in %s due to local address parse error: %v", filePath, err)
			continue
		}

		remoteIP, remotePort, err := parseHexIPPort(fields[2])
		if err != nil {
			warnLog.Printf("Skipping line in %s due to remote address parse error: %v", filePath, err)
			continue
		}

		// Parse state
		stateCode, err := strconv.ParseInt(fields[3], 16, 32)
		if err != nil {
			warnLog.Printf("Skipping line in %s due to state parse error: %v", filePath, err)
			continue
		}
		state := tcpStates[int(stateCode)]
		if state == "" {
			state = fmt.Sprintf("UNKNOWN(%d)", stateCode)
			warnLog.Printf("Unknown state code in %s: %d", filePath, stateCode)
		}

		sockets = append(sockets, Socket{
			LocalIP:    localIP,
			LocalPort:  localPort,
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
			State:      state,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading %s: %v", filePath, err)
	}

	return sockets, nil
}

// Main function to parse and display TCP connections.
func main() {
	// Define command-line flags
	tcpFile := flag.String("tcp-file", "/proc/net/tcp", "Path to TCP file")
	tcp6File := flag.String("tcp6-file", "/proc/net/tcp6", "Path to TCP6 file")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	// Validate file paths
	if *tcpFile == "" || *tcp6File == "" {
		fmt.Fprintf(os.Stderr, "Error: TCP file paths cannot be empty\n")
		flag.Usage()
		os.Exit(1)
	}

	// Read IPv4 and IPv6 connections
	sockets := make([]Socket, 0, 200) // Preallocate for both IPv4 and IPv6
	var errors []string
	for _, filePath := range []string{*tcpFile, *tcp6File} {
		connections, err := readTCPConnections(filePath)
		if err != nil {
			if os.IsNotExist(err) {
				warnLog.Printf("Skipping %s: %v", filePath, err)
				continue
			}
			errors = append(errors, fmt.Sprintf("Failed to read TCP connections from %s: %v", filePath, err))
			continue
		}
		sockets = append(sockets, connections...)
	}

	// Report errors if any
	if len(errors) > 0 {
		for _, err := range errors {
			fmt.Fprintf(os.Stderr, "%s\n", err)
		}
		if len(sockets) == 0 {
			fmt.Fprintf(os.Stderr, "No connections could be read\n")
			os.Exit(1)
		}
	}

	// Calculate max lengths for dynamic formatting
	maxStateLen := len("State")
	maxLocalLen := len("Local Address")
	maxRemoteLen := len("Remote Address")
	for _, s := range sockets {
		if len(s.State) > maxStateLen {
			maxStateLen = len(s.State)
		}
		localAddr := fmt.Sprintf("%s:%d", s.LocalIP, s.LocalPort)
		if len(localAddr) > maxLocalLen {
			maxLocalLen = len(localAddr)
		}
		remoteAddr := fmt.Sprintf("%s:%d", s.RemoteIP, s.RemotePort)
		if len(remoteAddr) > maxRemoteLen {
			maxRemoteLen = len(remoteAddr)
		}
	}

	// Print header
	fmt.Printf("%-*s %-*s %-*s\n", maxStateLen, "State", maxLocalLen, "Local Address", maxRemoteLen, "Remote Address")
	fmt.Println(strings.Repeat("-", maxStateLen+maxLocalLen+maxRemoteLen+2))
	for _, s := range sockets {
		fmt.Printf("%-*s %-*s %-*s\n",
			maxStateLen, s.State,
			maxLocalLen, fmt.Sprintf("%s:%d", s.LocalIP, s.LocalPort),
			maxRemoteLen, fmt.Sprintf("%s:%d", s.RemoteIP, s.RemotePort),
		)
	}
}
