# FireFind

A comprehensive firewall configuration analysis tool that identifies security vulnerabilities and compliance issues in firewall rules.

## Features

 **Flexible Column Mapping**: Ingests firewall exports through configurable mapping profiles
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
   git clone https://github.com/JaBoiJimJam/FireFind.git
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
  --vendor generic `
  --input ".\samples" `
  --out-csv ..\out\findings_all.csv `
  --out-pdf ..\out\report_all.pdf `
  --rules ..\rules\rules.yaml `
  --mappings ..\rules\vendor_mappings.yaml
  ```

> **Tip:** Quote every CLI path to guard against spaces or parentheses in
> directory and file names. The Windows backtick line continuations above keep
> the example concise while ensuring each argument is quoted.

To display the application's version:

```bash
python -m firefind.cli --version
```

### Method 3: FastAPI Server

For a web API interface, run the bundled FastAPI application:

```bash
uvicorn firefind.api:app --reload
```

Then send a `POST` request to `http://localhost:8000/scan` with a CSV or XLSX file in the `file` form field. Findings are returned as JSON and optional CSV/PDF reports are saved to the `out/` directory.

#### Configuration API

The FastAPI service also exposes authenticated endpoints for inspecting and updating the active rules configuration:

- `GET /api/config/rules` – returns the merged runtime configuration alongside revision metadata.
- `PATCH /api/config/rules` – accepts a JSON payload with a `changes` object containing partial configuration updates. Optional `message` metadata is recorded with the revision audit trail.
- `GET /api/config/rules/history?limit=<n>` – retrieves the most recent revision entries (defaults to 20).

All configuration endpoints require a bearer token supplied via the `Authorization: Bearer <token>` header. Configure the shared secret with the `FIRE_FIND_API_TOKEN` environment variable before starting the API. Optional user attribution can be provided via the `X-Firefind-Actor` header and is recorded with every revision entry.

Approved updates are persisted to the configured YAML file (defaults to `rules/rules.yaml`) and appended to a JSONL history alongside version numbers, timestamps, and actor details. The analysis service loads configuration from disk for every request, so threshold adjustments take effect immediately without restarting the backend.

### CLI Parameters

- `--vendor`: Column mapping profile name (defaults to `generic`)
- `--input`: Directory containing CSV/XLSX firewall configuration files
- `--out-csv`: Output path for CSV findings report
- `--out-pdf`: Output path for PDF summary report
- `--rules`: Path to security analysis rules YAML file
- `--mappings`: Path to vendor column mappings YAML file
- `--version`: Show the application's version and exit

## Configuration Overview

FireFind ships with sensible defaults, but production deployments should review
the configuration options below to align the analysis engine with internal
policies.

### Core Files

- **Rules Configuration (`rules/rules.yaml`)** – Controls the security analysis
  heuristics. Extend the file or point the backend at a bespoke path to tune
  severity thresholds, CIDR limits, and reusable port collections.
- **Vendor Mappings (`rules/vendor_mappings.yaml`)** – Maps vendor-specific
  column names to the normalized fields the analyzers expect (rule id, source,
  destination, protocol, service, action, and comments).

Copy `rules.config.sample.yaml` to a safe location, tailor the contents, and set
`FIRE_FIND_RULES_CONFIG` to point at the custom file before launching the
service. When the API receives rule updates it persists them alongside a
revision history (`*.history.jsonl`). Override the history location with
`FIRE_FIND_RULES_HISTORY` if you need to store the audit trail elsewhere (for
example on a shared network volume).

### Runtime Environment Variables

| Variable | Purpose |
| --- | --- |
| `FIRE_FIND_API_TOKEN` | Shared bearer token required by the configuration API endpoints. Generate a strong random value and keep it secret. |
| `FIRE_FIND_ALLOW_ORIGINS` | Optional CORS allow-list for the FastAPI server (defaults to `*`). Provide a comma-separated list for production launches. |
| `FIRE_FIND_RULES_CONFIG` | Absolute path to the active rules configuration file. Defaults to `backend/rules/rules.yaml`. |
| `FIRE_FIND_RULES_HISTORY` | Optional override for the JSONL revision log. Defaults to `<rules file name>.history.jsonl` next to the config file. |

Export these variables in your process manager (e.g. systemd, Docker, or a CI
runner) so the CLI and API share a consistent configuration baseline. Remember
to mount the configuration files read/write if you expect operators to patch
rules via the API.

## Input File Format

FireFind accepts CSV or XLSX files with firewall rule data. The tool
automatically maps column names to normalized fields using the mapping profile
selected at runtime. The default `generic` profile recognises common headers
including `Rule ID`, `Source`, `Destination`, `Service`, `Port`, `Protocol`, and
`Action`. Additional profiles can be introduced by extending
`rules/vendor_mappings.yaml` with the column names present in your exports.

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

### Project Requirements

- Python 3.8+
- See `requirements.txt` for package dependencies
- Windows/Linux/macOS compatible

### Testing

Backend and frontend suites ship with unit, integration, and end-to-end
coverage. Common commands:

```bash
# Backend validation helpers and configuration API endpoints
pytest backend/tests/test_config_schema.py
pytest backend/tests/test_config_api.py::test_get_rules_populates_defaults_for_empty_file

# Frontend rule management components (Jest)
npm run test:frontend

# Install Playwright browsers once, then execute UI CRUD flows
npx playwright install --with-deps
npm run test:e2e
```

`npm run test:e2e` automatically launches `./start_dev.sh`, drives the admin
console to create/update/delete a rule, and verifies the configuration persists
across reloads.

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
