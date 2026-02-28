# 🦅 Eagle AI Scanner

Modern C++20 port scanner with AI-based OS fingerprinting.

![C++](https://img.shields.io/badge/C++-20-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)

## ✨ Features

- **TCP Port Scanning** - Fast multi-threaded port scanning (1-65535)
- **AI Neural Network OS Detection** - Machine learning based OS fingerprinting
- **Modern C++20 Architecture** - RAII, smart pointers, concepts
- **Thread-Safe** - Concurrent scanning with atomic operations
- **Export Formats** - JSON and CSV output
- **No Dependencies** - Pure C++ with Windows API only

## 🧠 AI Neural Network

Eagle uses a custom neural network for OS detection:

```
Input Layer (24 features)
    ↓
Hidden Layer (32 neurons) - LeakyReLU activation
    ↓
Output Layer (8 neurons) - Sigmoid activation
```

### Input Features:
- TTL (Time To Live)
- TCP Window Size
- Maximum Segment Size (MSS)
- TCP Options presence
- Fragmentation support
- Response time
- Port signatures (22, 80, 443, 445, 3389, etc.)

### Detected OS Classes:
- Windows
- Linux
- macOS
- FreeBSD
- Solaris
- Network Device
- Android
- Unknown

## 📦 Build

### Prerequisites
- Windows OS
- C++20 compatible compiler (MinGW-w64 or MSVC)
- Windows SDK

### Compile with MinGW:
```bash
g++ -std=c++20 -O2 -o eagle_v7.exe eagle_ai.cpp -lws2_32 -liphlpapi -static
```

### Compile with MSVC:
```bash
cl /std:c++20 /O2 eagle_ai.cpp /link ws2_32.lib iphlpapi.lib
```

## 🚀 Usage

### Basic Scan
```bash
eagle_v7.exe -t 192........ -p 1-1000
```

### AI OS Detection
```bash
eagle_v7.exe -t 192........ --os
```

### Export to JSON
```bash
eagle_v7.exe -t 192........ -p 1-10000 --os --json report.json
```

### Export to CSV
```bash
eagle_v7.exe -t 192.......... -p 1-1000 --csv results.csv
```

### High-Performance Scan
```bash
eagle_v7.exe -t 192....... -T 128 -p 1-65535
```

### Quick Service Scan
```bash
eagle_v7.exe -t 192....... -p 21,22,80,443,3306,5432,8080
```

## 📋 Command Line Options

| Option | Description |
|--------|-------------|
| `-t <ip>` | Target IP address (required) |
| `-p <range>` | Port range (e.g., 1-1000 or 22,80,443) |
| `-T <num>` | Number of threads (default: 32, max: 256) |
| `--os` | Enable AI OS detection |
| `--json <file>` | Export results to JSON |
| `--csv <file>` | Export results to CSV |
| `-h, --help` | Show help |

## 🏗️ Architecture

```
eagle::ai/
├── Socket              # RAII socket wrapper
├── WSAInitializer      # RAII WSA wrapper  
├── Result<T, E>        # Error handling (Either pattern)
├── NeuralNetwork      # Template-based NN (24→32→8)
├── OSFingerprinter    # AI OS detection
├── PortScanner        # Multi-threaded scanner
└── EagleScannerApp    # Main application
```

### Key Design Patterns:
- **RAII** - Automatic resource management
- **Rule of Zero** - No manual memory management
- **Concepts** - C++20 type constraints
- **Smart Pointers** - Unique ownership
- **Atomic Operations** - Thread safety

## 📊 Example Output

```
╔═══════════════════════════════════════════════════════════════════╗
║    🦅 EAGLE AI SCANNER v7.0 - NEURAL NETWORK EDITION 🦅        ║
╚═══════════════════════════════════════════════════════════════════╝

[+] Starting scan on 192.......
[+] Port range: 1-1000
[+] Threads: 32

[*] Running AI OS Fingerprinting...
[+] Detected OS: Linux (78.5% AI)

[+] Scan complete!
[+] Open ports found: 5
[+] Port: 22   (SSH)
[+] Port: 80   (HTTP)
[+] Port: 443  (HTTPS)
[+] Port: 3306 (MySQL)
[+] Port: 8080 (HTTP-ALT)
```

## ⚠️ Legal Notice

This tool is for educational purposes and authorized security testing only.

**DO NOT** scan systems you don't own or don't have permission to test.

Unauthorized scanning is illegal in many jurisdictions.

## 📝 License

MIT License - See LICENSE file for details.

## 🤝 Contributing

Contributions welcome! Please read the contributing guidelines first.

---

**Author:** noobsaybot
**For:** Cybersecurity Learning Project  
**Stack:** C++20, Neural Networks, Network Programming
