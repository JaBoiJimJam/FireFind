# FireFind

A comprehensive firewall configuration analysis tool that identifies security vulnerabilities and compliance issues in firewall rules.

## Features

- **Multi-vendor Support**: Currently supports Fortinet firewalls with extensible architecture for other vendors
- **CSV/XLSX Input**: Analyzes firewall configurations from exported CSV or Excel files
- **Security Analysis**: Identifies common security issues like overly permissive rules, admin port exposure, and broad CIDR ranges
- **Dual Output**: Generates both CSV reports and PDF summaries
- **CLI Interface**: Easy-to-use command-line interface with flexible configuration options

## Project Structure

```
FireFind/
├── backend/
│   ├── src/
│   │   └── firefind/
│   │       ├── cli.py          # Main CLI module
│   │       ├── loaders/        # Data loading modules
│   │       ├── analyzers/      # Security analysis modules
│   │       └── generators/     # Report generation modules
│   ├── run_backend.py          # Convenient Python wrapper script
│   ├── samples/               # Sample firewall configuration files
│   └── rules/                 # Analysis rules and vendor mappings
├── rules/
│   ├── rules.yaml             # Security analysis rules
│   └── vendor_mappings.yaml   # Vendor-specific column mappings
├── out/                       # Generated reports directory
└── samples/                   # Additional sample files
```

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd FireFind
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Method 1: Using the Python Wrapper Script (Recommended)

The easiest way to run FireFind is using the provided Python wrapper script:

```bash
cd backend
python run_backend.py
```

This script automatically:
- Finds the required directories and files
- Sets up the correct environment variables
- Runs the FireFind CLI with appropriate parameters
- Generates timestamped output files

**Output files will be named with timestamps**:
- `findings_all_HH-MM-SS_DD-MM-YYYY.csv`
- `report_all_HH-MM-SS_DD-MM-YYYY.pdf`

### Method 2: Direct CLI Usage

For advanced users who want more control over the parameters:

```powershell
# Set the Python path
$env:PYTHONPATH = "$PWD\backend\src"

# Run the CLI
python -m firefind.cli `
  --vendor fortinet `
  --input ".\samples" `
  --out-csv ..\out\findings_all.csv `
  --out-pdf ..\out\report_all.pdf `
  --rules ..\rules\rules.yaml `
  --mappings ..\rules\vendor_mappings.yaml
```

### CLI Parameters

- `--vendor`: Firewall vendor (currently supports: `fortinet`)
- `--input`: Directory containing CSV/XLSX firewall configuration files
- `--out-csv`: Output path for CSV findings report
- `--out-pdf`: Output path for PDF summary report
- `--rules`: Path to security analysis rules YAML file
- `--mappings`: Path to vendor column mappings YAML file

## Configuration Files

### Rules Configuration (`rules/rules.yaml`)

Defines security analysis rules:
- **admin_ports**: List of administrative ports to flag
- **broad_cidr_prefix_max**: Maximum CIDR prefix length to consider "broad"

### Vendor Mappings (`rules/vendor_mappings.yaml`)

Maps vendor-specific column names to standardized field names:
- `rule_id`: Rule identifier columns
- `src`: Source address columns
- `dst`: Destination address columns
- `proto`: Protocol columns
- `port`: Port/service columns
- `action`: Action (allow/deny) columns
- `comment`: Comment/description columns

## Input File Format

FireFind accepts CSV or XLSX files with firewall rule data. The tool automatically maps vendor-specific column names to standard fields using the vendor mappings configuration.

**Example Fortinet columns**:
- Rule ID: `Seq #`, `ID`, `Policyid`
- Source: `Source Value`, `Source`, `Address`
- Destination: `Destination Value`, `Destination`, `Address.1`
- Service: `Service`, `Service.1`, `Port`
- Action: `Action`

## Output Reports

### CSV Report
Detailed findings with:
- Rule information
- Security issue descriptions
- Risk levels
- Recommendations

### PDF Report
Executive summary with:
- Analysis overview
- Key statistics
- High-priority findings
- Visual charts and graphs

## Development

### Running Tests
```bash
pytest
```

### Code Formatting
```bash
black .
flake8 .
```

### Project Requirements

- Python 3.8+
- See `requirements.txt` for package dependencies
- Windows/Linux/macOS compatible

## Troubleshooting

### Unicode Encoding Issues
If you encounter Unicode encoding errors on Windows, the `run_backend.py` script automatically handles this by setting appropriate environment variables.

### File Path Issues
The `run_backend.py` script automatically searches for required files and directories in common locations. Ensure your project structure matches the expected layout.

### Missing Dependencies
Install all required packages:
```bash
pip install -r requirements.txt
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and ensure code quality
5. Submit a pull request

## License

[Add your license information here]

## Support

[Add support contact information here]
