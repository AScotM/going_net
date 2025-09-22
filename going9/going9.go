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

type Socket struct {
	LocalIP    string `json:"local_ip"`
	LocalPort  int    `json:"local_port"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort int    `json:"remote_port"`
	State      string `json:"state"`
	Process    string `json:"process"`
	Resolved   string `json:"resolved,omitempty"`
}

// ProcessMap: inode → process string (rebuilt each refresh)
type ProcessMap map[string]string

// buildProcessMap scans /proc once and builds inode → process mapping
func buildProcessMap() ProcessMap {
	pm := make(ProcessMap)
	matches, _ := filepath.Glob("/proc/[0-9]*/fd/*")
	for _, fdPath := range matches {
		target, err := os.Readlink(fdPath)
		if err != nil || !strings.HasPrefix(target, "socket:[") {
			continue
		}
		inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
		pid := filepath.Base(filepath.Dir(filepath.Dir(fdPath)))
		commPath := fmt.Sprintf("/proc/%s/comm", pid)
		if commData, err := os.ReadFile(commPath); err == nil {
			pm[inode] = fmt.Sprintf("%s (%s)", strings.TrimSpace(string(commData)), pid)
		}
	}
	return pm
}

// parseHexIPPort decodes /proc hex IP:port (little endian)
func parseHexIPPort(s string, isIPv6 bool) (string, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid format: %s", s)
	}
	ipHex, portHex := parts[0], parts[1]

	ipBytes, err := hex.DecodeString(ipHex)
	if err != nil {
		return "", 0, fmt.Errorf("failed to decode IP: %v", err)
	}

	// reverse byte order (little endian in /proc/net/tcp)
	for i, j := 0, len(ipBytes)-1; i < j; i, j = i+1, j-1 {
		ipBytes[i], ipBytes[j] = ipBytes[j], ipBytes[i]
	}

	expectedLen := 4
	if isIPv6 {
		expectedLen = 16
	}
	if len(ipBytes) != expectedLen {
		return "", 0, fmt.Errorf("invalid IP length: got %d expected %d", len(ipBytes), expectedLen)
	}

	ip := net.IP(ipBytes).String()
	port, err := strconv.ParseInt(portHex, 16, 32)
	if err != nil {
		return "", 0, fmt.Errorf("failed to parse port: %v", err)
	}
	return ip, int(port), nil
}

func readTCPConnections(filePath string, verbose bool, isIPv6 bool, procMap ProcessMap) ([]Socket, error) {
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to open %s: %v", filePath, err)
	}
	defer file.Close()

	var sockets []Socket
	scanner := bufio.NewScanner(file)
	scanner.Scan() // skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			if verbose {
				warnLog.Printf("Skipping malformed line in %s: %s", filePath, scanner.Text())
			}
			continue
		}

		localIP, localPort, err := parseHexIPPort(fields[1], isIPv6)
		if err != nil {
			if verbose {
				warnLog.Printf("Local parse error: %v", err)
			}
			continue
		}
		remoteIP, remotePort, err := parseHexIPPort(fields[2], isIPv6)
		if err != nil {
			if verbose {
				warnLog.Printf("Remote parse error: %v", err)
			}
			continue
		}
		stateCode, err := strconv.ParseInt(fields[3], 16, 32)
		if err != nil {
			continue
		}
		state := tcpStates[int(stateCode)]
		if state == "" {
			state = fmt.Sprintf("UNKNOWN(%d)", stateCode)
		}

		inode := fields[9]
		process := procMap[inode]
		if process == "" {
			process = "Unknown"
		}

		sockets = append(sockets, Socket{
			LocalIP:    localIP,
			LocalPort:  localPort,
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
			State:      state,
			Process:    process,
		})
	}
	return sockets, scanner.Err()
}

func readAllConnections(tcpFile, tcp6File string, verbose bool) ([]Socket, []string) {
	var sockets []Socket
	var errors []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	procMap := buildProcessMap()

	for _, filePath := range []string{tcpFile, tcp6File} {
		wg.Add(1)
		go func(path string, isIPv6 bool) {
			defer wg.Done()
			connections, err := readTCPConnections(path, verbose, isIPv6, procMap)
			if err != nil {
				mu.Lock()
				errors = append(errors, err.Error())
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
				warnLog.Printf("Invalid local filter: %s", localIP)
				return nil
			}
		}
	}
	if remoteIP != "" {
		if _, remoteNet, err = net.ParseCIDR(remoteIP); err != nil {
			_, remoteNet, err = net.ParseCIDR(remoteIP + "/32")
			if err != nil {
				warnLog.Printf("Invalid remote filter: %s", remoteIP)
				return nil
			}
		}
	}

	var filtered []Socket
	for _, s := range sockets {
		if state != "" && s.State != strings.ToUpper(state) {
			continue
		}
		if localNet != nil && !localNet.Contains(net.ParseIP(s.LocalIP)) {
			continue
		}
		if remoteNet != nil && !remoteNet.Contains(net.ParseIP(s.RemoteIP)) {
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

// resolveHosts: optional reverse DNS lookups
func resolveHosts(sockets []Socket, timeout time.Duration) {
	for i := range sockets {
		done := make(chan string, 1)
		go func(ip string) {
			names, err := net.LookupAddr(ip)
			if err == nil && len(names) > 0 {
				done <- strings.TrimRight(names[0], ".")
			} else {
				done <- ""
			}
		}(sockets[i].RemoteIP)

		select {
		case r := <-done:
			if r != "" {
				sockets[i].Resolved = r
				// Append resolved name to process for readability
				sockets[i].Process = fmt.Sprintf("%s [%s]", sockets[i].Process, r)
			}
		case <-time.After(timeout):
			// skip on timeout
		}
	}
}

func displayConnections(sockets []Socket, format string, noColor bool) {
	if len(sockets) == 0 {
		fmt.Println("No active TCP connections found")
		return
	}
	if format == "json" {
		data, _ := json.MarshalIndent(sockets, "", "  ")
		fmt.Println(string(data))
		return
	}

	maxState := len("State")
	maxLocal := len("Local Address")
	maxRemote := len("Remote Address")
	maxProc := len("Process")
	for _, s := range sockets {
		if len(s.State) > maxState {
			maxState = len(s.State)
		}
		l := fmt.Sprintf("%s:%d", s.LocalIP, s.LocalPort)
		r := fmt.Sprintf("%s:%d", s.RemoteIP, s.RemotePort)
		if len(l) > maxLocal {
			maxLocal = len(l)
		}
		if len(r) > maxRemote {
			maxRemote = len(r)
		}
		if len(s.Process) > maxProc {
			maxProc = len(s.Process)
		}
	}

	fmt.Printf("\nACTIVE TCP CONNECTIONS:\n")
	fmt.Printf("%-*s %-*s %-*s %-*s\n", maxState, "State", maxLocal, "Local Address", maxRemote, "Remote Address", maxProc, "Process")
	fmt.Println(strings.Repeat("-", maxState+maxLocal+maxRemote+maxProc+3))
	for _, s := range sockets {
		state := s.State
		if !noColor {
			if cf, ok := stateColors[s.State]; ok {
				state = fmt.Sprintf(cf, s.State)
			}
		}
		localAddr := fmt.Sprintf("%s:%d", s.LocalIP, s.LocalPort)
		remoteAddr := fmt.Sprintf("%s:%d", s.RemoteIP, s.RemotePort)
		fmt.Printf("%-*s %-*s %-*s %-*s\n", maxState, state, maxLocal, localAddr, maxRemote, remoteAddr, maxProc, s.Process)
	}
}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func main() {
	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "This program requires Linux /proc filesystem")
		os.Exit(1)
	}

	tcpFile := flag.String("tcp-file", "/proc/net/tcp", "Path to TCP file")
	tcp6File := flag.String("tcp6-file", "/proc/net/tcp6", "Path to TCP6 file")
	watch := flag.Float64("watch", 0, "Refresh interval seconds (0 = once)")
	state := flag.String("state", "", "Filter by state (ESTABLISHED, LISTEN, ...)")
	localIP := flag.String("local-ip", "", "Filter by local IP or subnet")
	remoteIP := flag.String("remote-ip", "", "Filter by remote IP or subnet")
	port := flag.Int("port", 0, "Filter by local or remote port")
	process := flag.String("process", "", "Filter by process substring")
	sortBy := flag.String("sort", "state", "Sort by: state, local_ip, remote_ip, port, process")
	format := flag.String("format", "table", "Output format: table, json")
	noColor := flag.Bool("no-color", false, "Disable colored output")
	verbose := flag.Bool("verbose", false, "Verbose logging")
	resolve := flag.Bool("resolve", false, "Resolve remote IPs to hostnames")
	resolveTimeout := flag.Duration("resolve-timeout", 200*time.Millisecond, "DNS resolve timeout")
	flag.Parse()

	validSort := map[string]bool{"state": true, "local_ip": true, "remote_ip": true, "port": true, "process": true}
	if !validSort[*sortBy] {
		fmt.Fprintf(os.Stderr, "Invalid sort field: %s\n", *sortBy)
		os.Exit(1)
	}

	// Permission check
	for _, f := range []string{*tcpFile, *tcp6File} {
		if _, err := os.Stat(f); err == nil {
			if _, err := os.Open(f); err != nil {
				fmt.Fprintf(os.Stderr, "Need root to read %s: %v\n", f, err)
				os.Exit(1)
			}
		}
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
		sockets, errs := readAllConnections(*tcpFile, *tcp6File, *verbose)
		if len(errs) > 0 {
			for _, e := range errs {
				fmt.Fprintln(os.Stderr, e)
			}
		}
		sockets = filterSockets(sockets, *state, *localIP, *remoteIP, *process, *port)
		sockets = sortSockets(sockets, *sortBy)

		if *resolve {
			resolveHosts(sockets, *resolveTimeout)
		}

		if *watch > 0 {
			clearScreen()
		}
		displayConnections(sockets, *format, *noColor)

		if *watch <= 0 {
			break
		}
		time.Sleep(time.Duration(*watch * float64(time.Second)))
	}
}
