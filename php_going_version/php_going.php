#!/usr/bin/php
<?php
/**
 * TCP Connection Monitor - Improved PHP Version
 * Parses /proc/net/tcp and /proc/net/tcp6 to show active IPv4 and IPv6 connections
 *
 * Only works on Linux systems with access to /proc.
 * Usage: php tcp_monitor.php [--json]
 */

// Define constants if not already defined
defined('AF_INET') || define('AF_INET', 2);
defined('AF_INET6') || define('AF_INET6', 10);

// TCP state mappings (from the Linux kernel)
const TCP_STATES = [
    '01' => "ESTABLISHED",
    '02' => "SYN_SENT",
    '03' => "SYN_RECV",
    '04' => "FIN_WAIT1",
    '05' => "FIN_WAIT2",
    '06' => "TIME_WAIT",
    '07' => "CLOSE",
    '08' => "CLOSE_WAIT",
    '09' => "LAST_ACK",
    '0A' => "LISTEN",
    '0B' => "CLOSING",
    '0C' => "NEW_SYN_RECV",
];

/**
 * Converts a hex representation of an IPv4 or IPv6 address to human-readable format.
 */
function hexToIp($hex, $family) {
    if ($family === AF_INET && strlen($hex) == 8) { // IPv4
        $bytes = str_split($hex, 2);
        $bytes = array_reverse($bytes); // Convert from little-endian
        return implode('.', array_map('hexdec', $bytes));
    } elseif ($family === AF_INET6 && strlen($hex) == 32) { // IPv6
        return inet_ntop(pack("H*", $hex));
    }
    return false;
}

/**
 * Converts a hex port to integer.
 */
function hexToPort($hex) {
    return hexdec($hex);
}

/**
 * Read TCP connections from the specified /proc file and protocol family.
 *
 * @param string $file
 * @param int $family AF_INET or AF_INET6
 * @return array
 */
function readTcpConnections($file, $family) {
    $connections = [];
    if (!file_exists($file)) {
        fwrite(STDERR, "Error: File $file does not exist.\n");
        return $connections;
    } elseif (!is_readable($file)) {
        fwrite(STDERR, "Error: File $file is not readable.\n");
        return $connections;
    }

    $handle = fopen($file, 'r');
    if ($handle === false) {
        fwrite(STDERR, "Error: Unable to open $file.\n");
        return $connections;
    }

    fgets($handle); // Skip header
    while (($line = fgets($handle)) !== false) {
        $fields = preg_split('/\s+/', trim($line));
        if (count($fields) < 10) continue;
        list($localIpHex, $localPortHex) = explode(':', $fields[1]);
        list($remoteIpHex, $remotePortHex) = explode(':', $fields[2]);

        $localIp = hexToIp($localIpHex, $family);
        $localPort = hexToPort($localPortHex);
        $remoteIp = hexToIp($remoteIpHex, $family);
        $remotePort = hexToPort($remotePortHex);
        if (!$localIp || !$remoteIp) continue;

        $stateCode = $fields[3];
        $state = isset(TCP_STATES[$stateCode]) ? TCP_STATES[$stateCode] : "UNKNOWN(0x$stateCode)";
        $proto = $family === AF_INET ? "IPv4" : "IPv6";
        $connections[] = [
            'proto' => $proto,
            'local_ip' => $localIp,
            'local_port' => $localPort,
            'remote_ip' => $remoteIp,
            'remote_port' => $remotePort,
            'state' => $state
        ];
    }
    fclose($handle);
    return $connections;
}

/**
 * Displays all TCP connections, grouped by protocol.
 */
function displayConnections($connections) {
    // Sort connections by protocol then state
    usort($connections, function($a, $b) {
        return strcmp($a['proto'].$a['state'], $b['proto'].$b['state']);
    });

    echo "\nACTIVE TCP CONNECTIONS:\n";
    printf("%-5s %-15s %-25s %-25s\n", "Proto", "State", "Local Address", "Remote Address");
    echo str_repeat("-", 75) . "\n";
    foreach ($connections as $conn) {
        printf("%-5s %-15s %-25s %-25s\n",
            $conn['proto'],
            $conn['state'],
            "{$conn['local_ip']}:{$conn['local_port']}",
            "{$conn['remote_ip']}:{$conn['remote_port']}"
        );
    }

    // Count connections by protocol
    $ipv4_count = count(array_filter($connections, fn($c) => $c['proto'] === 'IPv4'));
    $ipv6_count = count(array_filter($connections, fn($c) => $c['proto'] === 'IPv6'));
    echo "\nFound " . count($connections) . " active connections ($ipv4_count IPv4, $ipv6_count IPv6)\n";
}

/**
 * Outputs connections in JSON format.
 */
function outputJson($connections) {
    echo json_encode($connections, JSON_PRETTY_PRINT) . "\n";
}

// Main
function main() {
    if (php_sapi_name() !== 'cli') {
        fwrite(STDERR, "This script must be run from the command line.\n");
        exit(1);
    }
    if (PHP_OS_FAMILY !== 'Linux') {
        fwrite(STDERR, "Error: This script is only supported on Linux systems.\n");
        exit(1);
    }
    if (posix_geteuid() !== 0) {
        fwrite(STDERR, "Warning: This script may require root privileges to access /proc/net/tcp*.\n");
    }

    // Parse command-line options
    $options = getopt("j", ["json", "help"]);
    if (isset($options['help'])) {
        echo "Usage: php tcp_monitor.php [--json]\n";
        echo "  --json  Output connections in JSON format\n";
        echo "  --help  Show this help message\n";
        exit(0);
    }

    // Read both IPv4 and IPv6 sockets
    $connections = array_merge(
        readTcpConnections('/proc/net/tcp', AF_INET),
        readTcpConnections('/proc/net/tcp6', AF_INET6)
    );
    if (empty($connections)) {
        echo "No active TCP connections found or files not accessible.\n";
        exit(0);
    }

    // Output based on options
    if (isset($options['j']) || isset($options['json'])) {
        outputJson($connections);
    } else {
        displayConnections($connections);
    }
}

main();
?>
