# FireFind

Firewall Risk Identification Tool

![My Project Logo](public/firefind_logo.jpg)

## Requirements
- Python 3.8+

## Installation
(Optional) create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # Linux
venv\Scripts\activate     # Windows
```

Install dependencies:

```bash
pip install -r backend/requirements.txt
```

This project relies solely on open-source libraries and runs on Windows or Linux without commercial dependencies.

## Usage
Run the backend via the provided wrapper script:

```bash
cd backend && python run_backend.py
```

Or invoke the CLI directly:

```bash
python -m firefind.cli --vendor fortinet --input samples \
  --out-csv ../out/findings.csv --out-pdf ../out/report.pdf \
  --rules ../rules/rules.yaml --mappings ../rules/vendor_mappings.yaml
```

### Integrated development server
For a combined frontend and API during development, run:

```bash
./start_dev.sh
```

The server will be available at http://localhost:8000 and serves the API under `/api` while hosting the static `frontend/` files at the root path.

## Project Structure
```
backend/
├── src/firefind/   # core logic and CLI
├── rules/          # YAML-based policy rules
└── samples/        # example firewall policies
frontend/           # optional prototype UI
```
For more detailed backend documentation, see [backend/README.md](backend/README.md).
The frontend prototype is described in [frontend/README.md](frontend/README.md).

## Customization
FireFind uses YAML files in the backend to control rule logic and vendor-specific column mappings. These files can be edited to tailor the analysis to your environment:

- `backend/rules/rules.yaml` – defines the security rules applied during analysis.
- `backend/rules/vendor_mappings.yaml` – maps vendor export column names to standardized fields.

Modify these YAML files to implement custom rule logic or adapt the tool to different vendor column names.

## Version Strategy
FireFind uses a sprint-based versioning scheme documented in the Version Strategy file. Versions follow the format `M<cycle>.<patch>` (e.g., `M3.5`).

## Roadmap
### Must-haves
- Core firewall rule parsing and risk scoring
- Minimal UI for uploading firewall configurations
- Documentation for setup and usage

### Nice-to-haves
- Integration with common firewall vendors' configuration formats
- Exporting risk reports in multiple formats
- Basic user authentication

### Optional
- Real-time collaboration features
- Cloud deployment scripts
- Historical trend analysis of risk scores

## Development
Run the test suite with:

```bash
pytest
```

Additional tooling such as flake8 and black can be introduced once the project grows.

## Vendor Support
FireFind currently supports Fortinet firewalls. Support for additional vendors is planned.

