# EAGLE SCANNER

EAGLE SCANNER is a powerful port scanning tool designed to provide detailed information about the services running on networked systems. This documentation outlines its features, installation steps, usage examples, output formats, integration with CVE database, legal notices, and performance metrics.

## Features
- **Fast Scanning**: Ability to scan multiple ports quickly.
- **Comprehensive Results**: Detailed information about the services detected.
- **Customizable Scans**: Options to set timeout and retry limits.
- **Output Formats**: Results can be exported in various formats (JSON, XML, CSV).
- **CVE Database Integration**: Provides information on known vulnerabilities based on the detected services.

## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/telikuy070-collab/eaglescan.git
   cd eaglescan
   ```
2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Run the Tool**:
   ```bash
   python eaglescan.py
   ```

## Usage Examples
- Basic scan on a target:
  ```bash
  python eaglescan.py -t 192.168.1.1
  ```
- Scan specific ports:
  ```bash
  python eaglescan.py -t 192.168.1.1 -p 22,80,443
  ```
- Export results to JSON:
  ```bash
  python eaglescan.py -t 192.168.1.1 -o results.json
  ```

## Output Formats
EAGLE SCANNER supports the following output formats:
- **JSON**: A structured format for easy integration.
- **XML**: Useful for data interchange between systems.
- **CSV**: Simple text format for spreadsheets.

## CVE Database Integration
EAGLE SCANNER leverages the CVE database to provide insights on vulnerabilities associated with the detected services. Users can access vulnerability information through the `--cve` flag:
```bash
python eaglescan.py -t 192.168.1.1 --cve
```

## Legal Notice
This tool is meant for educational and research purposes only. Unauthorized scanning of networks and systems is illegal and may result in severe penalties. Always ensure you have permission to scan a network.

## Performance Metrics
EAGLE SCANNER is tested for performance and can handle:
- Scanning hundreds of ports within seconds.
- Multi-threaded scans to enhance speed without overwhelming the target system.

For more details, refer to the documentation within the repository or reach out through the Issues section.