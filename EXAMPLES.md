/**
 * ════════════════════════════════════════════════════════════════════
 *  🦅 EAGLE AI SCANNER - EXAMPLES & USE CASES
 * ════════════════════════════════════════════════════════════════════
 * 
 * This file contains practical examples of how to use Eagle AI Scanner
 * for various cybersecurity tasks.
 * 
 * Author: Your Name
 * For: GitHub Portfolio Project
 * ════════════════════════════════════════════════════════════════════
 */

#include <iostream>
#include <string>
#include <vector>
#include <chrono>

// Include the main scanner (when integrated)
// #include "eagle_ai.cpp"

// ════════════════════════════════════════════════════════════════════
//  EXAMPLE 1: Basic Port Scan
// ════════════════════════════════════════════════════════════════════

/*
 * SCENARIO: You need to scan a target for open ports
 * 
 * COMMAND:
 *   eagle_v7.exe -t 192....... -p 1-1000
 * 
 * WHAT IT DOES:
 *   - Connects to each port in range 1-1000
 *   - Uses non-blocking sockets for speed
 *   - Reports open ports with service names
 * 
 * EXAMPLE OUTPUT:
 *   [+] Open ports found: 5
 *   [+] Port: 22   (SSH)
 *   [+] Port: 80   (HTTP)
 *   [+] Port: 443  (HTTPS)
 *   [+] Port: 3306 (MySQL)
 *   [+] Port: 8080 (HTTP-ALT)
 */

void example_basic_scan() {
    std::cout << "=== EXAMPLE 1: Basic Port Scan ===" << std::endl;
    std::cout << "Command: eagle_v7.exe -t 192....... -p 1-1000" << std::endl;
    std::cout << std::endl;
}

// ════════════════════════════════════════════════════════════════════
//  EXAMPLE 2: AI OS Fingerprinting
// ════════════════════════════════════════════════════════════════════

/*
 * SCENARIO: Identify the operating system of a target
 * 
 * COMMAND:
 *   eagle_v7.exe -t 192....... --os
 * 
 * WHAT IT DOES:
 *   - Scans common ports first
 *   - Uses Neural Network (24 features → 32 neurons → 8 OS classes)
 *   - Analyzes TTL, window size, port patterns
 *   - Returns OS with confidence percentage
 * 
 * AI FEATURES USED:
 *   - TTL (Time To Live) from ICMP
 *   - TCP Window Size
 *   - Maximum Segment Size (MSS)
 *   - TCP Options presence
 *   - Fragmentation support
 *   - Open ports (21 ports checked)
 *   - Response time
 * 
 * EXAMPLE OUTPUT:
 *   [*] Running AI OS Fingerprinting...
 *   [+] Detected OS: Linux (78.5% AI)
 *   [+] Fingerprints: SSH detected, HTTP detected
 * 
 * OS CLASSES DETECTED:
 *   0 = Windows
 *   1 = Linux
 *   2 = macOS
 *   3 = FreeBSD
 *   4 = Solaris
 *   5 = Network Device (Cisco, etc)
 *   6 = Android
 *   7 = Unknown
 */

void example_ai_os_detection() {
    std::cout << "=== EXAMPLE 2: AI OS Fingerprinting ===" << std::endl;
    std::cout << "Command: eagle_v7.exe -t 192....... --os" << std::endl;
    std::cout << std::endl;
    
    std::cout << "AI Features Analyzed:" << std::endl;
    std::cout << "  - TTL (Time To Live)" << std::endl;
    std::cout << "  - TCP Window Size" << std::endl;
    std::cout << "  - Maximum Segment Size" << std::endl;
    std::cout << "  - TCP Options" << std::endl;
    std::cout << "  - Fragmentation Support" << std::endl;
    std::cout << "  - Port Signatures (22, 80, 443, 445, etc)" << std::endl;
    std::cout << "  - Response Time" << std::endl;
    std::cout << std::endl;
}

// ════════════════════════════════════════════════════════════════════
//  EXAMPLE 3: Export to JSON
// ════════════════════════════════════════════════════════════════════

/*
 * SCENARIO: Generate a report for further analysis
 * 
 * COMMAND:
 *   eagle_v7.exe -t 192....... -p 1-10000 --os --json scan_report.json
 * 
 * WHAT IT DOES:
 *   - Scans ports 1-10000
 *   - Runs AI OS detection
 *   - Exports results to JSON format
 * 
 * JSON OUTPUT:
 *   {
 *     "target": "192.......",
 *     "timestamp": 1699999999,
 *     "duration_ms": 5432,
 *     "open_ports": 8,
 *     "ports": [
 *       {"port": 22, "service": "SSH", "open": true},
 *       {"port": 80, "service": "HTTP", "open": true}
 *     ],
 *     "os": {
 *       "osName": "Linux",
 *       "confidence": 78.5,
 *       "isAI": true
 *     }
 *   }
 */

void example_json_export() {
    std::cout << "=== EXAMPLE 3: JSON Export ===" << std::endl;
    std::cout << "Command: eagle_v7.exe -t 192....... -p 1-10000 --os --json report.json" << std::endl;
    std::cout << std::endl;
}

// ════════════════════════════════════════════════════════════════════
//  EXAMPLE 4: High-Performance Scan
// ════════════════════════════════════════════════════════════════════

/*
 * SCENARIO: Scan all 65535 ports quickly
 * 
 * COMMAND:
 *   eagle_v7.exe -t 192....... -T 128 -p 1-65535
 * 
 * WHAT IT DOES:
 *   - Uses 128 threads (default is 32)
 *   - Scans full port range
 *   - Each thread handles ~512 ports
 * 
 * PERFORMANCE TIPS:
 *   - More threads = faster but more resource usage
 *   - 32-64 threads recommended for most systems
 *   - 128+ may cause network congestion
 */

void example_high_performance() {
    std::cout << "=== EXAMPLE 4: High-Performance Scan ===" << std::endl;
    std::cout << "Command: eagle_v7.exe -t 192.168.1.1 -T 128 -p 1-65535" << std::endl;
    std::cout << std::endl;
    
    std::cout << "Thread Count Guidelines:" << std::endl;
    std::cout << "  32 threads  = Standard (default)" << std::endl;
    std::cout << "  64 threads  = Fast scan" << std::endl;
    std::cout << "  128 threads = Very fast (may lag)" << std::endl;
    std::cout << std::endl;
}

// ════════════════════════════════════════════════════════════════════
//  EXAMPLE 5: Common Service Discovery
// ════════════════════════════════════════════════════════════════════

/*
 * SCENARIO: Quick scan for common services
 * 
 * COMMAND:
 *   eagle_v7.exe -t 192....... -p 21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080
 * 
 * COMMON PORTS:
 *   Port    Service         Description
 *   ----    -------         -----------
 *   21      FTP             File Transfer
 *   22      SSH             Secure Shell
 *   23      TELNET          Unencrypted (avoid)
 *   25      SMTP            Email
 *   53      DNS             Domain Name System
 *   80      HTTP            Web Server
 *   110     POP3            Email (legacy)
 *   143     IMAP            Email
 *   443     HTTPS           Secure Web
 *   445     SMB             Windows File Sharing
 *   3306    MySQL           Database
 *   3389    RDP             Remote Desktop
 *   5432    PostgreSQL      Database
 *   8080    HTTP-ALT        Alternative Web
 */

void example_common_ports() {
    std::cout << "=== EXAMPLE 5: Common Services ===" << std::endl;
    std::cout << "Command: eagle_v7.exe -t 192.168.1.1 -p 21,22,80,443,3306" << std::endl;
    std::cout << std::endl;
    
    std::cout << "Quick Reference - Common Ports:" << std::endl;
    std::cout << "  21  = FTP      (file transfer)" << std::endl;
    std::cout << "  22  = SSH      (secure shell)" << std::endl;
    std::cout << "  80  = HTTP     (web)" << std::endl;
    std::cout << "  443 = HTTPS    (secure web)" << std::endl;
    std::cout << "  445 = SMB      (windows shares)" << std::endl;
    std::cout << "  3306 = MySQL   (database)" << std::endl;
    std::cout << "  3389 = RDP     (remote desktop)" << std::endl;
    std::cout << std::endl;
}

// ════════════════════════════════════════════════════════════════════
//  EXAMPLE 6: Cybersecurity Use Cases
// ════════════════════════════════════════════════════════════════════

/*
 * CYBERSECURITY USE CASES:
 * 
 * 1. NETWORK INVENTORY
 *    - Map your own network
 *    - Find unauthorized services
 *    - Document infrastructure
 * 
 * 2. VULNERABILITY ASSESSMENT
 *    - Find exposed services
 *    - Identify outdated software
 *    - Prioritize patching
 * 
 * 3. PENETRATION TESTING
 *    - Initial reconnaissance
 *    - Service identification
 *    - OS fingerprinting
 * 
 * 4. SECURITY AUDITING
 *    - Verify firewall rules
 *    - Check for misconfigurations
 *    - Compliance checking
 * 
 * 5. INCIDENT RESPONSE
 *    - Identify compromised systems
 *    - Map attacker footprint
 *    - Containment planning
 */

void example_cybersecurity_use_cases() {
    std::cout << "=== EXAMPLE 6: Cybersecurity Use Cases ===" << std::endl;
    std::cout << std::endl;
    
    std::cout << "LEGAL USE CASES:" << std::endl;
    std::cout << "  1. Network Inventory" << std::endl;
    std::cout << "     Scan YOUR network to document services" << std::endl;
    std::cout << std::endl;
    
    std::cout << "  2. Vulnerability Assessment" << std::endl;
    std::cout << "     Find exposed services in YOUR infrastructure" << std::endl;
    std::cout << std::endl;
    
    std::cout << "  3. Penetration Testing (with permission)" << std::endl;
    std::cout << "     Authorized security testing" << std::endl;
    std::cout << std::endl;
    
    std::cout << "  4. Security Auditing" << std::endl;
    std::cout << "     Verify YOUR firewall configurations" << std::endl;
    std::cout << std::endl;
    
    std::cout << "⚠️  WARNING: Only scan systems you own or have permission to test!" << std::endl;
    std::cout << std::endl;
}

// ════════════════════════════════════════════════════════════════════
//  EXAMPLE 7: Understanding AI Neural Network
// ════════════════════════════════════════════════════════════════════

/*
 * HOW THE AI NEURAL NETWORK WORKS:
 * 
 * ARCHITECTURE:
 *   Input Layer (24 neurons)
 *       ↓
 *   Hidden Layer (32 neurons) - LeakyReLU activation
 *       ↓
 *   Output Layer (8 neurons) - Sigmoid activation
 * 
 * INPUT FEATURES (24):
 *   - TTL (0-255)
 *   - Window Size (0-65535)
 *   - MSS (0-1500)
 *   - TCP Options (0 or 1)
 *   - Fragmentation (0 or 1)
 *   - Response Time (0-1000ms)
 *   - 18 port features (binary: present/absent)
 * 
 * TRAINING:
 *   - Hardcoded examples in source code
 *   - 500 training epochs at startup
 *   - Xavier weight initialization
 *   - Learning rate: 0.1
 * 
 * OUTPUT:
 *   - Probability distribution over 8 OS classes
 *   - Confidence percentage
 */

void example_neural_network_info() {
    std::cout << "=== EXAMPLE 7: Neural Network Architecture ===" << std::endl;
    std::cout << std::endl;
    
    std::cout << "Network Architecture:" << std::endl;
    std::cout << "  Input:  24 features" << std::endl;
    std::cout << "  Hidden: 32 neurons (LeakyReLU)" << std::endl;
    std::cout << "  Output: 8 OS classes (Sigmoid)" << std::endl;
    std::cout << std::endl;
    
    std::cout << "Input Features:" << std::endl;
    std::cout << "  - Network: TTL, Window Size, MSS, TCP Options" << std::endl;
    std::cout << "  - Ports: 22, 80, 443, 445, 3389, etc." << std::endl;
    std::cout << "  - Timing: Response time" << std::endl;
    std::cout << std::endl;
    
    std::cout << "This is a simple feedforward neural network (perceptron)." << std::endl;
    std::cout << "For production use, consider deep learning models." << std::endl;
    std::cout << std::endl;
}

// ════════════════════════════════════════════════════════════════════
//  MAIN - Run All Examples
// ════════════════════════════════════════════════════════════════════

int main() {
    std::cout << "╔═══════════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║           🦅 EAGLE AI SCANNER - EXAMPLES GALLERY                ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════════════════╝" << std::endl;
    std::cout << std::endl;
    
    example_basic_scan();
    example_ai_os_detection();
    example_json_export();
    example_high_performance();
    example_common_ports();
    example_cybersecurity_use_cases();
    example_neural_network_info();
    
    std::cout << "═══════════════════════════════════════════════════════════════════" << std::endl;
    std::cout << "For actual scanning, compile eagle_ai.cpp and run:" << std::endl;
    std::cout << "  eagle_v7.exe -t <TARGET_IP> [OPTIONS]" << std::endl;
    std::cout << "═══════════════════════════════════════════════════════════════════" << std::endl;
    
    return 0;
