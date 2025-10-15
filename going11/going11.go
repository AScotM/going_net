package main

import (
	"bufio"
	"context"
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
	"ESTABLISHED":  "\033[32m%s\033[0m",
	"LISTEN":       "\033[34m%s\033[0m",
	"CLOSE":        "\033[31m%s\033[0m",
	"TIME_WAIT":    "\033[33m%s\033[0m",
	"SYN_SENT":     "\033[36m%s\033[0m",
	"SYN_RECV":     "\033[36m%s\033[0m",
	"FIN_WAIT1":    "\033[35m%s\033[0m",
	"FIN_WAIT2":    "\033[35m%s\033[0m",
	"CLOSE_WAIT":   "\033[31m%s\033[0m",
	"LAST_ACK":     "\033[31m%s\033[0m",
	"CLOSING":      "\033[31m%s\033[0m",
	"NEW_SYN_RECV": "\033[36m%s\033[0m",
	"UNKNOWN":      "\033[90m%s\033[0m",
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

type ConnectionStats struct {
	Total      int            `json:"total"`
	ByState    map[string]int `json:"by_state"`
	ByProcess  map[string]int `json:"by_process"`
	Timestamp  time.Time      `json:"timestamp"`
	IPv4Count  int            `json:"ipv4_count"`
	IPv6Count  int            `json:"ipv6_count"`
}

type Config struct {
	TCPFile        string  `json:"tcp_file"`
	TCP6File       string  `json:"tcp6_file"`
	Watch          float64 `json:"watch"`
	State          string  `json:"state"`
	LocalIP        string  `json:"local_ip"`
	RemoteIP       string  `json:"remote_ip"`
	Port           int     `json:"port"`
	Process        string  `json:"process"`
	SortBy         string  `json:"sort"`
	Format         string  `json:"format"`
	NoColor        bool    `json:"no_color"`
	Verbose        bool    `json:"verbose"`
	ShowStats      bool    `json:"show_stats"`
	Resolve        bool    `json:"resolve"`
	ResolveTimeout int     `json:"resolve_timeout_ms"`
	Summary        bool    `json:"summary"`
	MaxProcessAge  int     `json:"max_process_age_sec"`
}

type ProcessMap map[string]string

var (
	procMapCache      ProcessMap
	procMapLastUpdate time.Time
	procMapMutex      sync.RWMutex
)

func getProcessMap(refreshInterval time.Duration) ProcessMap {
	procMapMutex.RLock()
	if procMapCache != nil && time.Since(procMapLastUpdate) <= refreshInterval {
		defer procMapMutex.RUnlock()
		return procMapCache
	}
	procMapMutex.RUnlock()

	procMapMutex.Lock()
	defer procMapMutex.Unlock()

	if procMapCache != nil && time.Since(procMapLastUpdate) <= refreshInterval {
		return procMapCache
	}

	procMapCache = buildProcessMap()
	procMapLastUpdate = time.Now()
	return procMapCache
}

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
		var processName string
		if commData, err := os.ReadFile(commPath); err == nil {
			processName = strings.TrimSpace(string(commData))
		} else {
			cmdlinePath := fmt.Sprintf("/proc/%s/cmdline", pid)
			if cmdlineData, err := os.ReadFile(cmdlinePath); err == nil {
				cmdline := strings.TrimSpace(string(cmdlineData))
				if strings.Contains(cmdline, "\x00") {
					processName = strings.Split(cmdline, "\x00")[0]
				} else {
					processName = cmdline
				}
				processName = filepath.Base(processName)
			}
		}
		
		if processName != "" {
			pm[inode] = fmt.Sprintf("%s (%s)", processName, pid)
		}
	}
	return pm
}

func parseHexIPPort(s string, isIPv6 bool) (string, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) < 2 {
		return "", 0, fmt.Errorf("invalid format: %s", s)
	}

	if isIPv6 && len(parts) > 2 {
		ipHex := strings.Join(parts[:len(parts)-1], "")
		portHex := parts[len(parts)-1]
		parts = []string{ipHex, portHex}
	}

	ipHex, portHex := parts[0], parts[1]

	ipBytes, err := hex.DecodeString(ipHex)
	if err != nil {
		return "", 0, fmt.Errorf("failed to decode IP: %v", err)
	}

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
	scanner.Scan()

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

func readAllConnections(tcpFile, tcp6File string, verbose bool, maxProcessAge time.Duration) ([]Socket, []string) {
	var sockets []Socket
	var errors []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	procMap := getProcessMap(maxProcessAge)

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

func validateFilters(state, localIP, remoteIP string) error {
	if state != "" {
		valid := false
		for _, validState := range tcpStates {
			if strings.EqualFold(state, validState) {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid state filter: %s", state)
		}
	}

	if localIP != "" {
		if _, _, err := net.ParseCIDR(localIP); err != nil {
			if net.ParseIP(localIP) == nil {
				return fmt.Errorf("invalid local IP filter: %s", localIP)
			}
		}
	}

	if remoteIP != "" {
		if _, _, err := net.ParseCIDR(remoteIP); err != nil {
			if net.ParseIP(remoteIP) == nil {
				return fmt.Errorf("invalid remote IP filter: %s", remoteIP)
			}
		}
	}

	return nil
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

func calculateStats(sockets []Socket) ConnectionStats {
	stats := ConnectionStats{
		ByState:   make(map[string]int),
		ByProcess: make(map[string]int),
		Timestamp: time.Now(),
		Total:     len(sockets),
	}

	for _, socket := range sockets {
		stats.ByState[socket.State]++
		stats.ByProcess[socket.Process]++

		if strings.Contains(socket.LocalIP, ":") {
			stats.IPv6Count++
		} else {
			stats.IPv4Count++
		}
	}

	return stats
}

func resolveHosts(sockets []Socket, timeout time.Duration, maxConcurrent int) {
	if maxConcurrent <= 0 {
		maxConcurrent = 10
	}

	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	resolver := &net.Resolver{}

	for i := range sockets {
		wg.Add(1)
		go func(idx int) {
			sem <- struct{}{}
			defer func() {
				<-sem
				wg.Done()
			}()

			ip := sockets[idx].RemoteIP
			if ip == "0.0.0.0" || ip == "::" || ip == "*" {
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			names, err := resolver.LookupAddr(ctx, ip)
			if err == nil && len(names) > 0 {
				sockets[idx].Resolved = strings.TrimRight(names[0], ".")
			}
		}(i)
	}
	wg.Wait()
}

func displayConnections(sockets []Socket, format string, noColor bool, watchMode bool, showStats bool) {
	if len(sockets) == 0 {
		fmt.Println("No active TCP connections found")
		return
	}

	if watchMode && format == "table" {
		stats := calculateStats(sockets)
		fmt.Printf("%s - %d connections", time.Now().Format("2006-01-02 15:04:05"), stats.Total)
		if showStats {
			fmt.Printf(" [EST:%d LISTEN:%d TIME_WAIT:%d]", 
				stats.ByState["ESTABLISHED"], 
				stats.ByState["LISTEN"], 
				stats.ByState["TIME_WAIT"])
		}
		fmt.Println()
		return
	}

	if format == "json" {
		var output interface{}
		if showStats {
			stats := calculateStats(sockets)
			output = map[string]interface{}{
				"connections": sockets,
				"statistics":  stats,
			}
		} else {
			output = sockets
		}
		data, _ := json.MarshalIndent(output, "", "  ")
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
		process := s.Process
		if s.Resolved != "" {
			process = fmt.Sprintf("%s [%s]", process, s.Resolved)
		}
		fmt.Printf("%-*s %-*s %-*s %-*s\n", maxState, state, maxLocal, localAddr, maxRemote, remoteAddr, maxProc, process)
	}
}

func displaySummary(sockets []Socket, noColor bool) {
	stats := calculateStats(sockets)

	fmt.Printf("\nTCP CONNECTION SUMMARY:\n")
	fmt.Printf("Total connections: %d\n", stats.Total)
	fmt.Printf("IPv4 connections: %d\n", stats.IPv4Count)
	fmt.Printf("IPv6 connections: %d\n", stats.IPv6Count)
	fmt.Printf("Timestamp: %s\n", stats.Timestamp.Format("2006-01-02 15:04:05"))

	fmt.Println("\nBy State:")
	type stateCount struct {
		state string
		count int
	}
	stateCounts := make([]stateCount, 0, len(stats.ByState))
	for state, count := range stats.ByState {
		stateCounts = append(stateCounts, stateCount{state, count})
	}
	sort.Slice(stateCounts, func(i, j int) bool {
		return stateCounts[i].count > stateCounts[j].count
	})

	for _, sc := range stateCounts {
		coloredState := sc.state
		if !noColor {
			if cf, ok := stateColors[sc.state]; ok {
				coloredState = fmt.Sprintf(cf, sc.state)
			}
		}
		fmt.Printf("  %-15s: %d\n", coloredState, sc.count)
	}

	fmt.Println("\nTop Processes:")
	processes := make([]struct {
		name  string
		count int
	}, 0, len(stats.ByProcess))

	for name, count := range stats.ByProcess {
		processes = append(processes, struct {
			name  string
			count int
		}{name, count})
	}

	sort.Slice(processes, func(i, j int) bool {
		return processes[i].count > processes[j].count
	})

	for i, p := range processes {
		if i >= 10 {
			break
		}
		fmt.Printf("  %-30s: %d\n", p.name, p.count)
	}
}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func setupSignalHandler() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		sig := <-c
		fmt.Printf("\nReceived signal %v, shutting down...\n", sig)
		cancel()
		time.Sleep(100 * time.Millisecond)
		os.Exit(0)
	}()

	return ctx
}

func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
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
	maxConcurrentDNS := flag.Int("max-dns", 10, "Maximum concurrent DNS lookups")
	showStats := flag.Bool("stats", false, "Show statistics in output")
	summary := flag.Bool("summary", false, "Show summary only")
	configFile := flag.String("config", "", "Configuration file (JSON)")
	maxProcessAge := flag.Duration("max-process-age", 5*time.Second, "Maximum age of process cache")
	flag.Parse()

	var config *Config
	if *configFile != "" {
		var err error
		config, err = loadConfig(*configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config file: %v\n", err)
			os.Exit(1)
		}
		if config.TCPFile != "" {
			tcpFile = &config.TCPFile
		}
		if config.TCP6File != "" {
			tcp6File = &config.TCP6File
		}
		if config.Watch != 0 {
			watch = &config.Watch
		}
		if config.State != "" {
			state = &config.State
		}
		if config.LocalIP != "" {
			localIP = &config.LocalIP
		}
		if config.RemoteIP != "" {
			remoteIP = &config.RemoteIP
		}
		if config.Port != 0 {
			port = &config.Port
		}
		if config.Process != "" {
			process = &config.Process
		}
		if config.SortBy != "" {
			sortBy = &config.SortBy
		}
		if config.Format != "" {
			format = &config.Format
		}
		if config.NoColor {
			noColor = &config.NoColor
		}
		if config.Verbose {
			verbose = &config.Verbose
		}
		if config.ShowStats {
			showStats = &config.ShowStats
		}
		if config.Resolve {
			resolve = &config.Resolve
		}
		if config.ResolveTimeout > 0 {
			timeout := time.Duration(config.ResolveTimeout) * time.Millisecond
			resolveTimeout = &timeout
		}
		if config.Summary {
			summary = &config.Summary
		}
	}

	validSort := map[string]bool{"state": true, "local_ip": true, "remote_ip": true, "port": true, "process": true}
	if !validSort[*sortBy] {
		fmt.Fprintf(os.Stderr, "Invalid sort field: %s. Valid: state, local_ip, remote_ip, port, process\n", *sortBy)
		os.Exit(1)
	}

	if err := validateFilters(*state, *localIP, *remoteIP); err != nil {
		fmt.Fprintf(os.Stderr, "Filter error: %v\n", err)
		os.Exit(1)
	}

	for _, f := range []string{*tcpFile, *tcp6File} {
		if _, err := os.Stat(f); err == nil {
			if _, err := os.Open(f); err != nil {
				fmt.Fprintf(os.Stderr, "Need root to read %s: %v\n", f, err)
				os.Exit(1)
			}
		}
	}

	ctx := setupSignalHandler()

	if *watch > 0 {
		fmt.Printf("Monitoring TCP connections every %.1f seconds. Press Ctrl+C to stop.\n", *watch)
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
			sockets, errs := readAllConnections(*tcpFile, *tcp6File, *verbose, *maxProcessAge)
			if len(errs) > 0 {
				for _, e := range errs {
					fmt.Fprintln(os.Stderr, e)
				}
			}
			sockets = filterSockets(sockets, *state, *localIP, *remoteIP, *process, *port)
			sockets = sortSockets(sockets, *sortBy)

			if *resolve {
				resolveHosts(sockets, *resolveTimeout, *maxConcurrentDNS)
			}

			if *watch > 0 {
				clearScreen()
			}

			if *summary {
				displaySummary(sockets, *noColor)
			} else {
				displayConnections(sockets, *format, *noColor, *watch > 0, *showStats)
			}

			if *watch <= 0 {
				return
			}
			time.Sleep(time.Duration(*watch * float64(time.Second)))
		}
	}
}
