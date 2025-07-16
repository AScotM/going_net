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

type Socket struct {
	LocalIP    string
	LocalPort  int
	RemoteIP   string
	RemotePort int
	State      string
}

func parseHexIPPort(s string) (string, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid format: %s", s)
	}

	// Parse IP (network byte order)
	ipBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", 0, fmt.Errorf("failed to decode IP: %v", err)
	}

	var ip string
	if len(ipBytes) == 4 {
		// Reverse bytes for IPv4
		for i := 0; i < len(ipBytes)/2; i++ {
			j := len(ipBytes) - i - 1
			ipBytes[i], ipBytes[j] = ipBytes[j], ipBytes[i]
		}
		ip = net.IP(ipBytes).String()
	} else if len(ipBytes) == 16 {
		// Handle IPv6
		ip = net.IP(ipBytes).To16().String()
	} else {
		return "", 0, fmt.Errorf("invalid IP length: %d", len(ipBytes))
	}

	// Parse port
	port, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return "", 0, fmt.Errorf("failed to parse port: %v", err)
	}

	return ip, int(port), nil
}

func readTCPConnections(filePath string) ([]Socket, error) {
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
			log.Printf("Skipping malformed line: %s", scanner.Text())
			continue
		}

		// Parse addresses
		localIP, localPort, err := parseHexIPPort(fields[1])
		if err != nil {
			log.Printf("Skipping line due to local address parse error: %v", err)
			continue
		}

		remoteIP, remotePort, err := parseHexIPPort(fields[2])
		if err != nil {
			log.Printf("Skipping line due to remote address parse error: %v", err)
			continue
		}

		// Parse state
		stateCode, err := strconv.ParseInt(fields[3], 16, 32)
		if err != nil {
			log.Printf("Skipping line due to state parse error: %v", err)
			continue
		}
		state := tcpStates[int(stateCode)]
		if state == "" {
			state = fmt.Sprintf("UNKNOWN(%d)", stateCode)
			log.Printf("Unknown state code: %d", stateCode)
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

func main() {
	// Define command-line flags
	tcpFile := flag.String("tcp-file", "/proc/net/tcp", "Path to TCP file")
	tcp6File := flag.String("tcp6-file", "/proc/net/tcp6", "Path to TCP6 file")
	flag.Parse()

	// Read IPv4 and IPv6 connections
	sockets := []Socket{}
	for _, filePath := range []string{*tcpFile, *tcp6File} {
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			log.Printf("Skipping %s: file does not exist", filePath)
			continue
		}
		connections, err := readTCPConnections(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read TCP connections from %s: %v\n", filePath, err)
			os.Exit(1)
		}
		sockets = append(sockets, connections...)
	}

	// Print formatted output
	fmt.Printf("%-15s %-45s %-45s\n", "State", "Local Address", "Remote Address")
	fmt.Println(strings.Repeat("-", 105))
	for _, s := range sockets {
		fmt.Printf("%-15s %-45s %-45s\n",
			s.State,
			fmt.Sprintf("%s:%d", s.LocalIP, s.LocalPort),
			fmt.Sprintf("%s:%d", s.RemoteIP, s.RemotePort),
		)
	}
}
