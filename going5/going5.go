package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
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

var stateColors = map[string]string{
	"ESTABLISHED":  "\033[32m%s\033[0m", // Green
	"LISTEN":       "\033[34m%s\033[0m", // Blue
	"CLOSE":        "\033[31m%s\033[0m", // Red
	"TIME_WAIT":    "\033[33m%s\033[0m", // Yellow
	"SYN_SENT":     "\033[36m%s\033[0m", // Cyan
	"SYN_RECV":     "\033[36m%s\033[0m", // Cyan
	"FIN_WAIT1":    "\033[35m%s\033[0m", // Magenta
	"FIN_WAIT2":    "\033[35m%s\033[0m", // Magenta
	"CLOSE_WAIT":   "\033[31m%s\033[0m", // Red
	"LAST_ACK":     "\033[31m%s\033[0m", // Red
	"CLOSING":      "\033[31m%s\033[0m", // Red
	"NEW_SYN_RECV": "\033[36m%s\033[0m", // Cyan
}

// Socket represents a TCP connection.
type Socket struct {
	LocalIP    string `json:"local_ip"`
	LocalPort  int    `json:"local_port"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort int    `json:"remote_port"`
	State      string `json:"state"`
	Process    string `json:"process"`
}

// parseHexIPPort parses a hex-encoded IP:port string into IP address and port number.
func parseHexIPPort(s string) (string, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid format: %s", s)
	}

	ipBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", 0, fmt.Errorf("failed to decode IP: %v", err)
	}

	var ip string
	if len(ipBytes) == 4 || len(ipBytes) == 16 {
		ip = net.IP(ipBytes).String()
	} else {
		return "", 0, fmt.Errorf("invalid IP length: %d", len(ipBytes))
	}

	port, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return "", 0, fmt.Errorf("failed to parse port: %v", err)
	}
	if port < 0 || port > 65535 {
		return "", 0, fmt.Errorf("port %d out of range (0-65535)", port)
	}

	return ip, int(port), nil
}

// getProcessName finds the process name and PID for a socket inode.
func getProcessName(inode string) string {
	matches, _ := filepath.Glob("/proc/[0-9]*/fd/*")
	for _, fdPath := range matches {
		target, err := os.Readlink(fdPath)
		if err != nil {
			continue
		}
		if strings.HasSuffix(target, fmt.Sprintf("socket:[%s]", inode)) {
			pid := filepath.Base(filepath.Dir(filepath.Dir(fdPath)))
			commPath := fmt.Sprintf("/proc/%s/comm", pid)
			if commData, err := os.ReadFile(commPath); err == nil {
				return fmt.Sprintf("%s (%s)", strings.TrimSpace(string(commData)), pid)
			}
		}
	}
	return "Unknown"
}

// readTCPConnections reads TCP connections from a file like /proc/net/tcp or /proc/net/tcp6.
func readTCPConnections(filePath string, verbose bool) ([]Socket, error) {
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

	sockets := make([]Socket, 0, 100)
	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 { // Need inode field
			if verbose {
				warnLog.Printf("Skipping malformed line in %s: %s", filePath, scanner.Text())
			}
			continue
		}

		localIP, localPort, err := parseHexIPPort(fields[1])
		if err != nil {
			if verbose {
				warnLog.Printf("Skipping line in %s due to local address parse error: %v", filePath, err)
			}
			continue
		}

		remoteIP, remotePort, err := parseHexIPPort(fields[2])
		if err != nil {
			if verbose {
				warnLog.Printf("Skipping line in %s due to remote address parse error: %v", filePath, err)
			}
			continue
		}

		stateCode, err := strconv.ParseInt(fields[3], 16, 32)
		if err != nil {
			if verbose {
				warnLog.Printf("Skipping line in %s due to state parse error: %v", filePath, err)
			}
		 continue
		}
		state := tcpStates[int(stateCode)]
		if state == "" {
			state = fmt.Sprintf("UNKNOWN(%d)", stateCode)
			if verbose {
				warnLog.Printf("Unknown state code in %s: %d", filePath, stateCode)
			}
		}

		sockets = append(sockets, Socket{
			LocalIP:    localIP,
			LocalPort:  localPort,
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
			State:      state,
			Process:    getProcessName(fields[9]),
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading %s: %v", filePath, err)
	}

	return sockets, nil
}

// checkPermissions ensures the program has read access to the specified files.
func checkPermissions(filePaths []string) error {
	if os.Geteuid() != 0 {
		for _, filePath := range filePaths {
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				continue
			} else if err := syscall.Access(filePath, syscall.O_RDONLY); err != nil {
				return fmt.Errorf("need root privileges to read %s: %v", filePath, err)
			}
		}
	}
	return nil
}

// filterSockets filters connections based on command-line flags.
func filterSockets(sockets []Socket, state, localIP, remoteIP, process string, port int) []Socket {
	if state == "" && localIP == "" && remoteIP == "" && port == 0 && process == "" {
		return sockets
	}

	var localNet, remoteNet *net.IPNet
	var err error
	if localIP != "" {
		if _, localNet, err = net.ParseCIDR(localIP); err != nil {
			_, localNet, err = net.ParseCIDR(localIP + "/32")
			if err != nil {
				warnLog.Printf("Invalid local IP/network: %s", localIP)
				return nil
			}
		}
	}
	if remoteIP != "" {
		if _, remoteNet, err = net.ParseCIDR(remoteIP); err != nil {
			_, remoteNet, err = net.ParseCIDR(remoteIP + "/32")
			if err != nil {
				warnLog.Printf("Invalid remote IP/network: %s", remoteIP)
				return nil
			}
		}
	}

	filtered := make([]Socket, 0, len(sockets))
	for _, s := range sockets {
		if state != "" && s.State != strings.ToUpper(state) {
			continue
		}
		if localIP != "" && !localNet.Contains(net.ParseIP(s.LocalIP)) {
			continue
		}
		if remoteIP != "" && !remoteNet.Contains(net.ParseIP(s.RemoteIP)) {
			continue
		}
		if port != 0 && s.LocalPort != port && s.RemotePort != port {
			continue
		}
		if process != "" && !strings.Contains(strings.ToLower(s.Process), strings.ToLower(process)) {
			continue
		}
		filtered = append(filtered, s)
	}
	return filtered
}

// sortSockets sorts connections based on the sort flag.
func sortSockets(sockets []Socket, sortBy string) []Socket {
	switch sortBy {
	case "state":
		for i := 0; i < len(sockets)-1; i++ {
			for j := i + 1; j < len(sockets); j++ {
				if sockets[i].State > sockets[j].State {
					sockets[i], sockets[j] = sockets[j], sockets[i]
				}
			}
		}
	case "local_ip":
		for i := 0; i < len(sockets)-1; i++ {
			for j := i + 1; j < len(sockets); j++ {
				if sockets[i].LocalIP > sockets[j].LocalIP {
					sockets[i], sockets[j] = sockets[j], sockets[i]
				}
			}
		}
	case "remote_ip":
		for i := 0; i < len(sockets)-1; i++ {
			for j := i + 1; j < len(sockets); j++ {
				if sockets[i].RemoteIP > sockets[j].RemoteIP {
					sockets[i], sockets[j] = sockets[j], sockets[i]
				}
			}
		}
	case "port":
		for i := 0; i < len(sockets)-1; i++ {
			for j := i + 1; j < len(sockets); j++ {
				if sockets[i].LocalPort > sockets[j].LocalPort || (sockets[i].LocalPort == sockets[j].LocalPort && sockets[i].RemotePort > sockets[j].RemotePort) {
					sockets[i], sockets[j] = sockets[j], sockets[i]
				}
			}
		}
	case "process":
		for i := 0; i < len(sockets)-1; i++ {
			for j := i + 1; j < len(sockets); j++ {
				if sockets[i].Process > sockets[j].Process {
					sockets[i], sockets[j] = sockets[j], sockets[i]
				}
			}
		}
	}
	return sockets
}

// displayConnections displays connections in the specified format.
func displayConnections(sockets []Socket, format string, noColor, verbose bool) {
	if len(sockets) == 0 {
		fmt.Println("No active TCP connections found")
		return
	}

	if format == "json" {
		data, err := json.MarshalIndent(sockets, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate JSON: %v\n", err)
			return
		}
		fmt.Println(string(data))
		return
	}

	maxStateLen := len("State")
	maxLocalLen := len("Local Address")
	maxRemoteLen := len("Remote Address")
	maxProcessLen := len("Process")
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
		if len(s.Process) > maxProcessLen {
			maxProcessLen = len(s.Process)
		}
	}

	fmt.Printf("\nACTIVE TCP CONNECTIONS:\n")
	fmt.Printf("%-*s %-*s %-*s %-*s\n", maxStateLen, "State", maxLocalLen, "Local Address", maxRemoteLen, "Remote Address", maxProcessLen, "Process")
	fmt.Println(strings.Repeat("-", maxStateLen+maxLocalLen+maxRemoteLen+maxProcessLen+3))
	for _, s := range sockets {
		localAddr := fmt.Sprintf("%s:%d", s.LocalIP, s.LocalPort)
		remoteAddr := fmt.Sprintf("%s:%d", s.RemoteIP, s.RemotePort)
		state := s.State
		if !noColor {
			if colorFormat, exists := stateColors[s.State]; exists {
				state = fmt.Sprintf(colorFormat, s.State)
			}
		}
		fmt.Printf("%-*s %-*s %-*s %-*s\n", maxStateLen, state, maxLocalLen, localAddr, maxRemoteLen, remoteAddr, maxProcessLen, s.Process)
	}
}

func main() {
	if runtime.GOOS != "linux" {
		fmt.Fprintf(os.Stderr, "Error: This program requires Linux with /proc filesystem\n")
		os.Exit(1)
	}

	tcpFile := flag.String("tcp-file", "/proc/net/tcp", "Path to TCP file")
	tcp6File := flag.String("tcp6-file", "/proc/net/tcp6", "Path to TCP6 file")
	watch := flag.Float64("watch", 0, "Refresh interval in seconds (0 for single snapshot)")
	state := flag.String("state", "", "Filter by connection state (e.g., ESTABLISHED)")
	localIP := flag.String("local-ip", "", "Filter by local IP or subnet (e.g., 192.168.1.0/24)")
	remoteIP := flag.String("remote-ip", "", "Filter by remote IP or subnet")
	port := flag.Int("port", 0, "Filter by local or remote port")
	process := flag.String("process", "", "Filter by process name or PID")
	sortBy := flag.String("sort", "state", "Sort by field: state, local_ip, remote_ip, port, process")
	format := flag.String("format", "table", "Output format: table, json")
	noColor := flag.Bool("no-color", false, "Disable colored output")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "Valid states: %s\n", strings.Join(getStateList(), ", "))
		fmt.Fprintf(os.Stderr, "Example: sudo %s -watch 1 -state ESTABLISHED -local-ip 192.168.1.0/24\n", os.Args[0])
	}
	flag.Parse()

	if err := checkPermissions([]string{*tcpFile, *tcp6File}); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *watch > 0 {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c
			fmt.Println("\nStopped monitoring")
			os.Exit(0)
		}()
	}

	for {
		sockets := make([]Socket, 0, 200)
		var errors []string
		for _, filePath := range []string{*tcpFile, *tcp6File} {
			connections, err := readTCPConnections(filePath, *verbose)
			if err != nil {
				if os.IsNotExist(err) {
					if *verbose {
						warnLog.Printf("Skipping %s: %v", filePath, err)
					}
					continue
				}
				errors = append(errors, fmt.Sprintf("Failed to read TCP connections from %s: %v", filePath, err))
				continue
			}
			sockets = append(sockets, connections...)
		}

		if len(errors) > 0 {
			for _, err := range errors {
				fmt.Fprintf(os.Stderr, "%s\n", err)
			}
			if len(sockets) == 0 {
				fmt.Fprintf(os.Stderr, "No connections could be read\n")
				os.Exit(1)
			}
		}

		sockets = filterSockets(sockets, *state, *localIP, *remoteIP, *process, *port)
		sockets = sortSockets(sockets, *sortBy)
		if *watch > 0 {
			fmt.Print("\033[H\033[2J") // Clear terminal
		}
		displayConnections(sockets, *format, *noColor, *verbose)

		if *watch <= 0 {
			break
		}
		time.Sleep(time.Duration(*watch * float64(time.Second)))
	}
}

// getStateList returns a sorted list of valid TCP states.
func getStateList() []string {
	states := make([]string, 0, len(tcpStates))
	for _, state := range tcpStates {
		states = append(states, state)
	}
	for i := 0; i < len(states)-1; i++ {
		for j := i + 1; j < len(states); j++ {
			if states[i] > states[j] {
				states[i], states[j] = states[j], states[i]
			}
		}
	}
	return states
}
