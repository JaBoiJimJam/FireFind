# FireFind
Firewall Risk Identification Tool

![My Project Logo](public/firefind_logo.jpg)

Requirements
Python 3.8+

(Optional) create and activate a virtual environment:

python -m venv venv
source venv/bin/activate  # Linux
venv\Scripts\activate     # Windows
Install dependencies:

pip install -r backend/requirements.txt
This project relies solely on open‑source libraries and runs on Windows or Linux without commercial dependencies.

Version Strategy
FireFind uses a sprint-based versioning scheme documented in the Version Strategy file. Versions follow the format M<cycle>.<patch> (e.g., M3.5).

Roadmap
Must-haves
Core firewall rule parsing and risk scoring

Minimal UI for uploading firewall configurations

Documentation for setup and usage

Nice-to-haves
Integration with common firewall vendors' configuration formats

Exporting risk reports in multiple formats

Basic user authentication

Optional
Real-time collaboration features

Cloud deployment scripts

Historical trend analysis of risk scores

Project Structure
backend/
├── src/firefind/   # core logic and CLI
├── rules/          # YAML-based policy rules
└── samples/        # example firewall policies
frontend/           # optional prototype UI
Development
Tooling such as pytest, flake8, and black is not yet configured. These will be introduced once a proper test suite and configuration are in place.

Customization
FireFind uses YAML files in the backend to control rule logic and vendor-specific column mappings. These files can be edited to tailor the analysis to your environment:

backend/rules/rules.yaml – defines the security rules applied during analysis.

backend/rules/vendor_mappings.yaml – maps vendor export column names to standardized fields.

Modify these YAML files to implement custom rule logic or adapt the tool to different vendor column names.

Usage
Run the backend via the provided wrapper script:

cd backend && python run_backend.py
Or invoke the CLI directly:

python -m firefind.cli --vendor fortinet --input samples \
  --out-csv ../out/findings.csv --out-pdf ../out/report.pdf \
  --rules ../rules/rules.yaml --mappings ../rules/vendor_mappings.yaml
Vendor Support
FireFind currently supports Fortinet firewalls. Support for additional vendors is planned.

Give me this as a copy paste I can put in the readme file
Copy
# FireFind
Firewall Risk Identification Tool  
![My Project Logo](public/firefind_logo.jpg)

## Requirements
- Python 3.8+  
- *(Optional)* create and activate a virtual environment:
  ```bash
  python -m venv venv
  source venv/bin/activate  # Linux
  venv\Scripts\activate     # Windows
Install dependencies:

pip install -r backend/requirements.txt
This project relies solely on open‑source libraries and runs on Windows or Linux without commercial dependencies.

Version Strategy
FireFind uses a sprint-based versioning scheme documented in the Version Strategy file. Versions follow the format M<cycle>.<patch> (e.g., M3.5).

Roadmap
Must-haves
Core firewall rule parsing and risk scoring

Minimal UI for uploading firewall configurations

Documentation for setup and usage

Nice-to-haves
Integration with common firewall vendors' configuration formats

Exporting risk reports in multiple formats

Basic user authentication

Optional
Real-time collaboration features

Cloud deployment scripts

Historical trend analysis of risk scores

Project Structure
backend/
├── src/firefind/   # core logic and CLI
├── rules/          # YAML-based policy rules
└── samples/        # example firewall policies
frontend/           # optional prototype UI
Development
Tooling such as pytest, flake8, and black is not yet configured. These will be introduced once a proper test suite and configuration are in place.

Customization
FireFind uses YAML files in the backend to control rule logic and vendor-specific column mappings. These files can be edited to tailor the analysis to your environment:

backend/rules/rules.yaml – defines the security rules applied during analysis.

backend/rules/vendor_mappings.yaml – maps vendor export column names to standardized fields.

Modify these YAML files to implement custom rule logic or adapt the tool to different vendor column names.

Usage
Run the backend via the provided wrapper script:

cd backend && python run_backend.py
Or invoke the CLI directly:

python -m firefind.cli --vendor fortinet --input samples \
  --out-csv ../out/findings.csv --out-pdf ../out/report.pdf \
  --rules ../rules/rules.yaml --mappings ../rules/vendor_mappings.yaml
Vendor Support
FireFind currently supports Fortinet firewalls. Support for additional vendors is planned.
