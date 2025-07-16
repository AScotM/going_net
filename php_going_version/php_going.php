#!/usr/bin/php
<?php
/**
 * TCP Connection Monitor - Improved PHP Version
 * Parses /proc/net/tcp and /proc/net/tcp6 to show active IPv4 and IPv6 connections
 * 
 * Only works on Linux systems with access to /proc.
 */

// TCP state mappings (from the Linux kernel)
const TCP_STATES = [
    1  => "ESTABLISHED",
    2  => "SYN_SENT",
    3  => "SYN_RECV",
    4  => "FIN_WAIT1",
    5  => "FIN_WAIT2",
    6  => "TIME_WAIT",
    7  => "CLOSE",
    8  => "CLOSE_WAIT",
    9  => "LAST_ACK",
    10 => "LISTEN",
    11 => "CLOSING",
    12 => "NEW_SYN_RECV",
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
        $ipv6 = '';
        // IPv6 addresses in /proc are in network order (big-endian), but written as a continuous hex string.
        for ($i = 0; $i < 32; $i += 4) {
            $ipv6 .= substr($hex, $i, 4);
            if ($i < 28) $ipv6 .= ':';
        }
        // Optionally compress IPv6:
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
    if (!file_exists($file) || !is_readable($file)) {
        return $connections;
    }

    $lines = @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false || count($lines) < 2) {
        return $connections;
    }

    // Skip headers
    array_shift($lines);

    foreach ($lines as $line) {
        $fields = preg_split('/\s+/', trim($line));
        if (count($fields) < 10) continue;
        list($localIpHex, $localPortHex) = explode(':', $fields[1]);
        list($remoteIpHex, $remotePortHex) = explode(':', $fields[2]);

        $localIp = hexToIp($localIpHex, $family);
        $localPort = hexToPort($localPortHex);
        $remoteIp = hexToIp($remoteIpHex, $family);
        $remotePort = hexToPort($remotePortHex);
        if (!$localIp || !$remoteIp) continue;

        $stateCode = hexdec($fields[3]);
        $state = TCP_STATES[$stateCode] ?? "UNKNOWN($stateCode)";
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

    return $connections;
}

/**
 * Displays all TCP connections, grouped by protocol.
 */
function displayConnections($connections) {
    // Optionally sort connections by protocol then state
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
    echo "\nFound " . count($connections) . " active connections\n";
}

// Main
function main() {
    if (php_sapi_name() !== 'cli') {
        fwrite(STDERR, "This script must be run from the command line.\n");
        exit(1);
    }
    // Read both IPv4 and IPv6 sockets
    $connections = [];
    $connections = array_merge(
        readTcpConnections('/proc/net/tcp', AF_INET),
        readTcpConnections('/proc/net/tcp6', AF_INET6)
    );
    if (empty($connections)) {
        echo "No active TCP connections found or files not accessible.\n";
        exit(0);
    }
    displayConnections($connections);
}

main();
?>
