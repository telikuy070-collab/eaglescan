# 🦅 Eagle AI Scanner

Modern port scanner with AI-based OS fingerprinting.

## Features
- TCP port scanning
- AI Neural Network OS Detection (24-input → 32-neuron → 8-output)
- Thread-safe architecture
- JSON/CSV export

## Build
```bash
g++ -std=c++20 -O2 eagle_ai_v7.exe -.cpp -o eaglelws2_32 -liphlpapi -static
Usage
./eagle_v7.exe -t 192.168.1.1 -p 1-1000 --os --json results.json
