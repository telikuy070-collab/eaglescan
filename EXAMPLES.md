# Usage Examples for EagleScan

## Example 1: Basic Usage
To get started with EagleScan, simply run the following command:
```bash
$ eaglescan --help
```

## Example 2: Scanning for Issues
To scan a repository for potential issues, use:
```bash
$ eaglescan scan --repository <repository-url>
```

## Example 3: Generating a Report
After scanning, you can generate a report with the following command:
```bash
$ eaglescan report --output report.md
```

## Example 4: Custom Configurations
You can customize your scan settings using a configuration file:
```bash
$ eaglescan --config custom-settings.yaml
```

## Example 5: Integration with CI/CD
Integrate EagleScan into your CI/CD pipeline by adding:
```yaml
- name: EagleScan
  run: eaglescan scan --repository <repository-url>
```

For more detailed information, refer to the [official documentation](https://example.com/docs).