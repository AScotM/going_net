package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
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
		return "", 0, fmt.Errorf("invalid format")
	}

	// Parse IP (network byte order)
	ipBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", 0, err
	}
	
	// Reverse bytes for correct IPv4 interpretation
	if len(ipBytes) == 4 {
		for i := 0; i < len(ipBytes)/2; i++ {
			j := len(ipBytes) - i - 1
			ipBytes[i], ipBytes[j] = ipBytes[j], ipBytes[i]
		}
	}
	ip := net.IP(ipBytes).String()

	// Parse port
	port, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return "", 0, err
	}

	return ip, int(port), nil
}

func readTCPConnections() ([]Socket, error) {
	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var sockets []Socket
	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}

		// Parse addresses
		localIP, localPort, err := parseHexIPPort(fields[1])
		if err != nil {
			continue
		}

		remoteIP, remotePort, err := parseHexIPPort(fields[2])
		if err != nil {
			continue
		}

		// Parse state
		stateCode, _ := strconv.ParseInt(fields[3], 16, 32)
		state := tcpStates[int(stateCode)]
		if state == "" {
			state = fmt.Sprintf("UNKNOWN(%d)", stateCode)
		}

		sockets = append(sockets, Socket{
			LocalIP:    localIP,
			LocalPort:  localPort,
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
			State:      state,
		})
	}

	return sockets, scanner.Err()
}

func main() {
	sockets, err := readTCPConnections()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Print header
	fmt.Printf("%-15s %-25s %-25s\n", "State", "Local Address", "Remote Address")
	fmt.Println(strings.Repeat("-", 65))

	for _, s := range sockets {
		fmt.Printf("%-15s %-25s %-25s\n",
			s.State,
			fmt.Sprintf("%s:%d", s.LocalIP, s.LocalPort),
			fmt.Sprintf("%s:%d", s.RemoteIP, s.RemotePort),
		)
	}
}
