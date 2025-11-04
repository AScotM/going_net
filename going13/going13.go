package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
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

const (
	DefaultTCPFile          = "/proc/net/tcp"
	DefaultTCP6File         = "/proc/net/tcp6"
	DefaultWatchInterval    = 0
	DefaultResolveTimeout   = 200 * time.Millisecond
	DefaultMaxProcessAge    = 5 * time.Second
	DefaultMaxConcurrentDNS = 10
	MinFieldCount           = 10
	MaxConcurrentDNSLimit   = 1000
	MaxResolveTimeout       = 30 * time.Second
	MinWatchInterval        = 100 * time.Millisecond
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

type ConnectionError struct {
	Op   string
	Path string
	Err  error
}

func (e *ConnectionError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("%s %s: %v", e.Op, e.Path, e.Err)
	}
	return fmt.Sprintf("%s: %v", e.Op, e.Err)
}

func (e *ConnectionError) Unwrap() error {
	return e.Err
}

type ParseError struct {
	Field string
	Value string
	Err   error
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("parse error for %s '%s': %v", e.Field, e.Value, e.Err)
}

func (e *ParseError) Unwrap() error {
	return e.Err
}

type ConfigError struct {
	Field string
	Value interface{}
	Err   error
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("config error for %s '%v': %v", e.Field, e.Value, e.Err)
}

func (e *ConfigError) Unwrap() error {
	return e.Err
}

type DNSError struct {
	IP  string
	Err error
}

func (e *DNSError) Error() string {
	return fmt.Sprintf("DNS resolution failed for %s: %v", e.IP, e.Err)
}

func (e *DNSError) Unwrap() error {
	return e.Err
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
	TCPFile          string        `json:"tcp_file"`
	TCP6File         string        `json:"tcp6_file"`
	WatchInterval    time.Duration `json:"watch_interval"`
	State            string        `json:"state"`
	LocalIP          string        `json:"local_ip"`
	RemoteIP         string        `json:"remote_ip"`
	Port             int           `json:"port"`
	Process          string        `json:"process"`
	SortBy           string        `json:"sort"`
	Format           string        `json:"format"`
	NoColor          bool          `json:"no_color"`
	Verbose          bool          `json:"verbose"`
	ShowStats        bool          `json:"show_stats"`
	Resolve          bool          `json:"resolve"`
	ResolveTimeout   time.Duration `json:"resolve_timeout"`
	Summary          bool          `json:"summary"`
	MaxProcessAge    time.Duration `json:"max_process_age"`
	MaxConcurrentDNS int           `json:"max_concurrent_dns"`
}

type ProcessManager struct {
	mu         sync.RWMutex
	cache      map[string]string
	lastUpdate time.Time
}

func NewProcessManager() *ProcessManager {
	return &ProcessManager{
		cache: make(map[string]string),
	}
}

func (pm *ProcessManager) Get(refreshInterval time.Duration) map[string]string {
	pm.mu.RLock()
	if pm.cache != nil && time.Since(pm.lastUpdate) <= refreshInterval {
		defer pm.mu.RUnlock()
		return pm.cache
	}
	pm.mu.RUnlock()

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.cache != nil && time.Since(pm.lastUpdate) <= refreshInterval {
		return pm.cache
	}

	pm.cache = pm.buildProcessMap()
	pm.lastUpdate = time.Now()
	return pm.cache
}

func (pm *ProcessManager) buildProcessMap() map[string]string {
	processMap := make(map[string]string)
	procs, err := os.ReadDir("/proc")
	if err != nil {
		warnLog.Printf("Failed to read /proc: %v", err)
		return processMap
	}

	for _, proc := range procs {
		if !proc.IsDir() {
			continue
		}

		pid := proc.Name()
		if !isPid(pid) {
			continue
		}

		inodes := pm.getSocketInodes(pid)
		processName := pm.getProcessName(pid)

		if processName != "" {
			for inode := range inodes {
				processMap[inode] = fmt.Sprintf("%s (%s)", processName, pid)
			}
		}
	}
	return processMap
}

func (pm *ProcessManager) getSocketInodes(pid string) map[string]bool {
	inodes := make(map[string]bool)
	fdPath := fmt.Sprintf("/proc/%s/fd", pid)

	fds, err := os.ReadDir(fdPath)
	if err != nil {
		return inodes
	}

	for _, fd := range fds {
		fdFullPath := filepath.Join(fdPath, fd.Name())
		target, err := os.Readlink(fdFullPath)
		if err != nil || !strings.HasPrefix(target, "socket:[") {
			continue
		}
		inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
		inodes[inode] = true
	}
	return inodes
}

func (pm *ProcessManager) getProcessName(pid string) string {
	commPath := fmt.Sprintf("/proc/%s/comm", pid)
	if commData, err := os.ReadFile(commPath); err == nil {
		return strings.TrimSpace(string(commData))
	}

	cmdlinePath := fmt.Sprintf("/proc/%s/cmdline", pid)
	if cmdlineData, err := os.ReadFile(cmdlinePath); err == nil {
		cmdline := strings.TrimSpace(string(cmdlineData))
		if strings.Contains(cmdline, "\x00") {
			cmdline = strings.Split(cmdline, "\x00")[0]
		}
		return filepath.Base(cmdline)
	}

	return ""
}

func isPid(name string) bool {
	for _, char := range name {
		if char < '0' || char > '9' {
			return false
		}
	}
	return name != ""
}

func safePath(path string) bool {
	cleaned := filepath.Clean(path)
	return strings.HasPrefix(cleaned, "/proc/net/") && !strings.Contains(cleaned, "..")
}

func parseHexIPPort(s string, isIPv6 bool) (string, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) < 2 {
		return "", 0, &ParseError{Field: "ip:port", Value: s, Err: errors.New("invalid format")}
	}

	if isIPv6 && len(parts) > 2 {
		ipHex := strings.Join(parts[:len(parts)-1], "")
		portHex := parts[len(parts)-1]
		parts = []string{ipHex, portHex}
	}

	ipHex, portHex := parts[0], parts[1]

	ipBytes, err := hex.DecodeString(ipHex)
	if err != nil {
		return "", 0, &ParseError{Field: "IP", Value: ipHex, Err: err}
	}

	for i, j := 0, len(ipBytes)-1; i < j; i, j = i+1, j-1 {
		ipBytes[i], ipBytes[j] = ipBytes[j], ipBytes[i]
	}

	expectedLen := 4
	if isIPv6 {
		expectedLen = 16
	}
	if len(ipBytes) != expectedLen {
		return "", 0, &ParseError{
			Field: "IP",
			Value: ipHex,
			Err:   fmt.Errorf("invalid IP length: got %d expected %d", len(ipBytes), expectedLen),
		}
	}

	ip := net.IP(ipBytes).String()
	port, err := strconv.ParseInt(portHex, 16, 32)
	if err != nil {
		return "", 0, &ParseError{Field: "port", Value: portHex, Err: err}
	}
	return ip, int(port), nil
}

func readTCPConnections(filePath string, verbose bool, isIPv6 bool, procMap map[string]string) ([]Socket, error) {
	if !safePath(filePath) {
		return nil, &ConnectionError{Op: "open", Path: filePath, Err: errors.New("invalid path")}
	}

	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, &ConnectionError{Op: "open", Path: filePath, Err: err}
	}
	defer file.Close()

	var sockets []Socket
	scanner := bufio.NewScanner(file)

	if !scanner.Scan() {
		return nil, nil
	}

	lineNum := 1
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < MinFieldCount {
			if verbose {
				warnLog.Printf("Skipping malformed line %d in %s: %s", lineNum, filePath, line)
			}
			continue
		}

		localIP, localPort, err := parseHexIPPort(fields[1], isIPv6)
		if err != nil {
			if verbose {
				warnLog.Printf("Line %d: local parse error: %v", lineNum, err)
			}
			continue
		}

		remoteIP, remotePort, err := parseHexIPPort(fields[2], isIPv6)
		if err != nil {
			if verbose {
				warnLog.Printf("Line %d: remote parse error: %v", lineNum, err)
			}
			continue
		}

		stateCode, err := strconv.ParseInt(fields[3], 16, 32)
		if err != nil {
			if verbose {
				warnLog.Printf("Line %d: state parse error: %v", lineNum, err)
			}
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

	if err := scanner.Err(); err != nil {
		return sockets, &ConnectionError{Op: "read", Path: filePath, Err: err}
	}

	return sockets, nil
}

func readAllConnections(tcpFile, tcp6File string, verbose bool, maxProcessAge time.Duration, procManager *ProcessManager) ([]Socket, []string) {
	var sockets []Socket
	var errors []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	procMap := procManager.Get(maxProcessAge)

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
			return &ConfigError{Field: "state", Value: state, Err: errors.New("invalid state filter")}
		}
	}

	if localIP != "" {
		if _, _, err := net.ParseCIDR(localIP); err != nil {
			if net.ParseIP(localIP) == nil {
				return &ConfigError{Field: "local_ip", Value: localIP, Err: errors.New("invalid local IP filter")}
			}
		}
	}

	if remoteIP != "" {
		if _, _, err := net.ParseCIDR(remoteIP); err != nil {
			if net.ParseIP(remoteIP) == nil {
				return &ConfigError{Field: "remote_ip", Value: remoteIP, Err: errors.New("invalid remote IP filter")}
			}
		}
	}

	return nil
}

func validateConfig(cfg *Config) error {
	if cfg.WatchInterval < 0 {
		return &ConfigError{Field: "watch_interval", Value: cfg.WatchInterval, Err: errors.New("cannot be negative")}
	}

	if cfg.MaxProcessAge <= 0 {
		return &ConfigError{Field: "max_process_age", Value: cfg.MaxProcessAge, Err: errors.New("must be positive")}
	}

	if cfg.ResolveTimeout < 0 {
		return &ConfigError{Field: "resolve_timeout", Value: cfg.ResolveTimeout, Err: errors.New("cannot be negative")}
	}

	if cfg.ResolveTimeout > MaxResolveTimeout {
		return &ConfigError{Field: "resolve_timeout", Value: cfg.ResolveTimeout, Err: fmt.Errorf("too long, max %v", MaxResolveTimeout)}
	}

	if cfg.MaxConcurrentDNS <= 0 {
		return &ConfigError{Field: "max_concurrent_dns", Value: cfg.MaxConcurrentDNS, Err: errors.New("must be positive")}
	}

	if cfg.MaxConcurrentDNS > MaxConcurrentDNSLimit {
		return &ConfigError{Field: "max_concurrent_dns", Value: cfg.MaxConcurrentDNS, Err: fmt.Errorf("too high, max %d", MaxConcurrentDNSLimit)}
	}

	validSort := map[string]bool{"state": true, "local_ip": true, "remote_ip": true, "port": true, "process": true}
	if !validSort[cfg.SortBy] {
		return &ConfigError{
			Field: "sort",
			Value: cfg.SortBy,
			Err:   errors.New("must be one of: state, local_ip, remote_ip, port, process"),
		}
	}

	validFormats := map[string]bool{"table": true, "json": true}
	if !validFormats[cfg.Format] {
		return &ConfigError{
			Field: "format",
			Value: cfg.Format,
			Err:   errors.New("must be one of: table, json"),
		}
	}

	return validateFilters(cfg.State, cfg.LocalIP, cfg.RemoteIP)
}

func filterSockets(sockets []Socket, state, localIP, remoteIP, process string, port int) ([]Socket, error) {
	if state == "" && localIP == "" && remoteIP == "" && port == 0 && process == "" {
		return sockets, nil
	}

	var localNet, remoteNet *net.IPNet
	var err error

	if localIP != "" {
		if _, localNet, err = net.ParseCIDR(localIP); err != nil {
			_, localNet, err = net.ParseCIDR(localIP + "/32")
			if err != nil {
				return nil, &ConfigError{Field: "local_ip", Value: localIP, Err: err}
			}
		}
	}

	if remoteIP != "" {
		if _, remoteNet, err = net.ParseCIDR(remoteIP); err != nil {
			_, remoteNet, err = net.ParseCIDR(remoteIP + "/32")
			if err != nil {
				return nil, &ConfigError{Field: "remote_ip", Value: remoteIP, Err: err}
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
	return filtered, nil
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
		maxConcurrent = DefaultMaxConcurrentDNS
	}
	if len(sockets) == 0 {
		return
	}

	if maxConcurrent > len(sockets) {
		maxConcurrent = len(sockets)
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
		if len(sockets) > 10000 {
			fmt.Println("[")
			for i, s := range sockets {
				data, err := json.Marshal(s)
				if err != nil {
					continue
				}
				fmt.Printf("  %s", string(data))
				if i < len(sockets)-1 {
					fmt.Println(",")
				}
			}
			fmt.Println("\n]")
			return
		}

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
		data, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			return
		}
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
	if !safePath(filename) {
		return nil, &ConnectionError{Op: "read config", Path: filename, Err: errors.New("invalid config path")}
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, &ConnectionError{Op: "read config", Path: filename, Err: err}
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, &ConnectionError{Op: "parse config", Path: filename, Err: err}
	}

	config.ApplyDefaults()
	return &config, nil
}

func (c *Config) ApplyDefaults() {
	if c.TCPFile == "" {
		c.TCPFile = DefaultTCPFile
	}
	if c.TCP6File == "" {
		c.TCP6File = DefaultTCP6File
	}
	if c.WatchInterval == 0 {
		c.WatchInterval = DefaultWatchInterval
	}
	if c.ResolveTimeout == 0 {
		c.ResolveTimeout = DefaultResolveTimeout
	}
	if c.MaxProcessAge == 0 {
		c.MaxProcessAge = DefaultMaxProcessAge
	}
	if c.MaxConcurrentDNS == 0 {
		c.MaxConcurrentDNS = DefaultMaxConcurrentDNS
	}
	if c.SortBy == "" {
		c.SortBy = "state"
	}
	if c.Format == "" {
		c.Format = "table"
	}
}

func checkFileAccessibility(files ...string) error {
	for _, f := range files {
		if !safePath(f) {
			return &ConnectionError{Op: "access", Path: f, Err: errors.New("invalid path")}
		}
		if _, err := os.Stat(f); err == nil {
			if file, err := os.Open(f); err != nil {
				return &ConnectionError{Op: "access", Path: f, Err: fmt.Errorf("need root privileges: %w", err)}
			} else {
				file.Close()
			}
		}
	}
	return nil
}

func processCycle(cfg *Config, procManager *ProcessManager) error {
	sockets, errs := readAllConnections(cfg.TCPFile, cfg.TCP6File, cfg.Verbose, cfg.MaxProcessAge, procManager)
	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, e)
		}
	}

	filteredSockets, err := filterSockets(sockets, cfg.State, cfg.LocalIP, cfg.RemoteIP, cfg.Process, cfg.Port)
	if err != nil {
		return err
	}

	sortedSockets := sortSockets(filteredSockets, cfg.SortBy)

	if cfg.Resolve {
		resolveHosts(sortedSockets, cfg.ResolveTimeout, cfg.MaxConcurrentDNS)
	}

	if cfg.Summary {
		displaySummary(sortedSockets, cfg.NoColor)
	} else {
		displayConnections(sortedSockets, cfg.Format, cfg.NoColor, cfg.WatchInterval > 0, cfg.ShowStats)
	}

	return nil
}

func runApplication(ctx context.Context, cfg *Config) error {
	procManager := NewProcessManager()

	if cfg.WatchInterval > 0 {
		fmt.Printf("Monitoring TCP connections every %v. Press Ctrl+C to stop.\n", cfg.WatchInterval)
	}

	var lastRun time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			if cfg.WatchInterval > 0 && cfg.WatchInterval < MinWatchInterval {
				if time.Since(lastRun) < MinWatchInterval {
					time.Sleep(MinWatchInterval - time.Since(lastRun))
				}
			}

			if cfg.WatchInterval > 0 {
				clearScreen()
			}

			if err := processCycle(cfg, procManager); err != nil {
				return err
			}

			if cfg.WatchInterval <= 0 {
				return nil
			}

			lastRun = time.Now()
			time.Sleep(cfg.WatchInterval)
		}
	}
}

func main() {
	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "This program requires Linux /proc filesystem")
		os.Exit(1)
	}

	tcpFile := flag.String("tcp-file", DefaultTCPFile, "Path to TCP file")
	tcp6File := flag.String("tcp6-file", DefaultTCP6File, "Path to TCP6 file")
	watchInterval := flag.Duration("watch", DefaultWatchInterval, "Refresh interval")
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
	resolveTimeout := flag.Duration("resolve-timeout", DefaultResolveTimeout, "DNS resolve timeout")
	maxConcurrentDNS := flag.Int("max-dns", DefaultMaxConcurrentDNS, "Maximum concurrent DNS lookups")
	showStats := flag.Bool("stats", false, "Show statistics in output")
	summary := flag.Bool("summary", false, "Show summary only")
	configFile := flag.String("config", "", "Configuration file (JSON)")
	maxProcessAge := flag.Duration("max-process-age", DefaultMaxProcessAge, "Maximum age of process cache")
	flag.Parse()

	var config *Config
	if *configFile != "" {
		var err error
		config, err = loadConfig(*configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config file: %v\n", err)
			os.Exit(1)
		}
	} else {
		config = &Config{
			TCPFile:          *tcpFile,
			TCP6File:         *tcp6File,
			WatchInterval:    *watchInterval,
			State:            *state,
			LocalIP:          *localIP,
			RemoteIP:         *remoteIP,
			Port:             *port,
			Process:          *process,
			SortBy:           *sortBy,
			Format:           *format,
			NoColor:          *noColor,
			Verbose:          *verbose,
			ShowStats:        *showStats,
			Resolve:          *resolve,
			ResolveTimeout:   *resolveTimeout,
			Summary:          *summary,
			MaxProcessAge:    *maxProcessAge,
			MaxConcurrentDNS: *maxConcurrentDNS,
		}
		config.ApplyDefaults()
	}

	if err := validateConfig(config); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	if err := checkFileAccessibility(config.TCPFile, config.TCP6File); err != nil {
		fmt.Fprintf(os.Stderr, "File access error: %v\n", err)
		os.Exit(1)
	}

	ctx := setupSignalHandler()

	if err := runApplication(ctx, config); err != nil {
		fmt.Fprintf(os.Stderr, "Application error: %v\n", err)
		os.Exit(1)
	}
}
