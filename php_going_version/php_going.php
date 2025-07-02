#!/usr/bin/php
<?php
/**
 * TCP Connection Monitor - PHP Version
 * Parses /proc/net/tcp to show active connections
 */

// TCP state mappings
$tcp_states = [
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

function hexToIp($hex) {
    if (strlen($hex) == 8) { // IPv4
        $bytes = str_split($hex, 2);
        $bytes = array_reverse($bytes); // Convert network byte order
        return implode('.', array_map('hexdec', $bytes));
    } elseif (strlen($hex) == 32) { // IPv6
        $words = str_split($hex, 4);
        return implode(':', array_map(function($w) {
            return dechex(hexdec($w));
        }, $words));
    }
    return false;
}

function hexToPort($hex) {
    return hexdec($hex);
}

function readTcpConnections() {
    global $tcp_states;
    $connections = [];
    
    $lines = file('/proc/net/tcp', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) {
        die("Cannot open /proc/net/tcp\n");
    }
    
    // Skip header line
    array_shift($lines);
    
    foreach ($lines as $line) {
        $fields = preg_split('/\s+/', trim($line));
        if (count($fields) < 10) continue;
        
        list($localIpHex, $localPortHex) = explode(':', $fields[1]);
        list($remoteIpHex, $remotePortHex) = explode(':', $fields[2]);
        
        $localIp = hexToIp($localIpHex);
        $localPort = hexToPort($localPortHex);
        $remoteIp = hexToIp($remoteIpHex);
        $remotePort = hexToPort($remotePortHex);
        
        if (!$localIp || !$remoteIp) continue;
        
        $stateCode = hexdec($fields[3]);
        $state = $tcp_states[$stateCode] ?? "UNKNOWN($stateCode)";
        
        $connections[] = [
            'local_ip' => $localIp,
            'local_port' => $localPort,
            'remote_ip' => $remoteIp,
            'remote_port' => $remotePort,
            'state' => $state
        ];
    }
    
    return $connections;
}

function displayConnections($connections) {
    echo "\nACTIVE TCP CONNECTIONS:\n";
    printf("%-15s %-25s %-25s\n", "State", "Local Address", "Remote Address");
    echo str_repeat("-", 65) . "\n";
    
    foreach ($connections as $conn) {
        printf("%-15s %-25s %-25s\n",
            $conn['state'],
            "{$conn['local_ip']}:{$conn['local_port']}",
            "{$conn['remote_ip']}:{$conn['remote_port']}"
        );
    }
    
    echo "\nFound " . count($connections) . " active connections\n";
}

// Main execution
$connections = readTcpConnections();
displayConnections($connections);
?>
