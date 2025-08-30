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
	"sort"
	"strconv"
	"strings"
	"sync"
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

// ProcessCache caches inode to process name lookups
type ProcessCache struct {
	sync.RWMutex
	cache map[string]string
}

// NewProcessCache creates a new process cache
func NewProcessCache() *ProcessCache {
	return &ProcessCache{
		cache: make(map[string]string),
	}
}

// Get retrieves a process name from cache, returns (value, found)
func (pc *ProcessCache) Get(inode string) (string, bool) {
	pc.RLock()
	defer pc.RUnlock()
	val, exists := pc.cache[inode]
	return val, exists
}

// Set stores a process name in cache
func (pc *ProcessCache) Set(inode, process string) {
	pc.Lock()
	defer pc.Unlock()
	pc.cache[inode] = process
}

// Global process cache
var processCache = NewProcessCache()

// parseHexIPPort parses a hex-encoded IP:port string into IP address and port number.
func parseHexIPPort(s string, isIPv6 bool) (string, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid format: %s", s)
	}

	ipBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", 0, fmt.Errorf("failed to decode IP: %v", err)
	}

	expectedLen := 4
	if isIPv6 {
		expectedLen = 16
	}
	if len(ipBytes) != expectedLen {
		return "", 0, fmt.Errorf("invalid IP length: %d, expected %d", len(ipBytes), expectedLen)
	}

	ip := net.IP(ipBytes).String()
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
	// Check cache first
	if cachedName, found := processCache.Get(inode); found {
		return cachedName
	}

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
				processName := fmt.Sprintf("%s (%s)", strings.TrimSpace(string(commData)), pid)
				processCache.Set(inode, processName)
				return processName
			}
		}
	}
	
	// Cache even "Unknown" to avoid repeated lookups
	processCache.Set(inode, "Unknown")
	return "Unknown"
}

// clearProcessCache clears the process cache (useful for long-running processes)
func clearProcessCache() {
	processCache.Lock()
	defer processCache.Unlock()
	// Clear the map but keep the allocated memory
	for k := range processCache.cache {
		delete(processCache.cache, k)
	}
}

// readTCPConnections reads TCP connections from a file like /proc/net/tcp or /proc/net/tcp6.
func readTCPConnections(filePath string, verbose bool, isIPv6 bool) ([]Socket, error) {
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

		localIP, localPort, err := parseHexIPPort(fields[1], isIPv6)
		if err != nil {
			if verbose {
				warnLog.Printf("Skipping line in %s due to local address parse error: %v", filePath, err)
			}
			continue
		}

		remoteIP, remotePort, err := parseHexIPPort(fields[2], isIPv6)
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

// readAllConnections reads TCP and TCP6 connections concurrently.
func readAllConnections(tcpFile, tcp6File string, verbose bool) ([]Socket, []string) {
	sockets := make([]Socket, 0, 200)
	var errors []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, filePath := range []string{tcpFile, tcp6File} {
		wg.Add(1)
		go func(path string, isIPv6 bool) {
			defer wg.Done()
			connections, err := readTCPConnections(path, verbose, isIPv6)
			if err != nil {
				mu.Lock()
				if os.IsNotExist(err) && verbose {
					errors = append(errors, fmt.Sprintf("Skipping %s: %v", path, err))
				} else if err != nil {
					errors = append(errors, fmt.Sprintf("Failed to read TCP connections from %s: %v", path, err))
				}
				mu.Unlock()
				return
			}
			mu.Lock()
			sockets = append(sockets, connections...)
			mu.Unlock()
		}(filePath, filePath == tcp6File)
	}
	wg.Wait()
	return sockets, errors
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
	sort.Slice(sockets, func(i, j int) bool {
		switch sortBy {
		case "state":
			return sockets[i].State < sockets[j].State
		case "local_ip":
			return sockets[i].LocalIP < sockets[j].LocalIP
		case "remote_ip":
			return sockets[i].RemoteIP < sockets[j].RemoteIP
		case "port":
			if sockets[i].LocalPort == sockets[j].LocalPort {
				return sockets[i].RemotePort < sockets[j].RemotePort
			}
			return sockets[i].LocalPort < sockets[j].LocalPort
		case "process":
			return sockets[i].Process < sockets[j].Process
		default:
			return false
		}
	})
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

// getMapKeys returns sorted keys of a map.
func getMapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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
		fmt.Fprintf(os.Stderr, "Valid sort fields: state, local_ip, remote_ip, port, process\n")
		fmt.Fprintf(os.Stderr, "Example: sudo %s -watch 1 -state ESTABLISHED -local-ip 192.168.1.0/24\n", os.Args[0])
	}
	flag.Parse()

	// Validate sort field
	validSortFields := map[string]bool{"state": true, "local_ip": true, "remote_ip": true, "port": true, "process": true}
	if !validSortFields[*sortBy] {
		fmt.Fprintf(os.Stderr, "Error: Invalid sort field '%s'. Valid fields: %s\n", *sortBy, strings.Join(getMapKeys(validSortFields), ", "))
		os.Exit(1)
	}

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
		sockets, errors := readAllConnections(*tcpFile, *tcp6File, *verbose)
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
	sort.Strings(states)
	return states
}
