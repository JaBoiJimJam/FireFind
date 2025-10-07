# FireFind

Firewall Risk Identification Tool

![My Project Logo](public/firefind_logo.jpg)

## Requirements
- Python 3.8+
- pip
- Git Bash or Windows Subsystem for Linux (WSL) for Windows users

## Installation
(Optional) create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # Linux
venv\Scripts\activate     # Windows
```

Install dependencies:

```bash
python -m pip install -r backend/requirements.txt
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

The `--input` flag accepts individual files or directories containing CSV or XLSX
exports. File extensions are matched case-insensitively, so variants such as
`.CSV` or `.XLSX` are processed without additional configuration.

To view the current application version:

```bash
python -m firefind.cli --version
```

### Integrated development server
For a combined frontend and API during development, run:

```bash
./start_dev.sh
```

Alternatively, use the convenience script to install dependencies, launch the server, and open it in your browser:

```bash
./run_firefind.sh   # Linux
run_firefind.bat    # Windows
```

The server will be available at http://localhost:8000 and serves the API under `/api` while hosting the static `frontend/` files at the root path.

### CORS configuration
The backend's CORS policy can be adjusted by setting the `FIRE_FIND_ALLOW_ORIGINS` environment variable to a comma-separated list of allowed origins. For development, all origins are permitted by default.

```bash
export FIRE_FIND_ALLOW_ORIGINS=http://localhost:5173
uvicorn firefind.api:app --reload
```

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

## Administrative Rule Editor

FireFind ships with an administrative console (`frontend/admin.html`) that exposes the rule logic, CIDR policies, reusable port
groups, and risk thresholds the backend consumes.

### Launch the console

1. Export a bearer token via `FIRE_FIND_API_TOKEN` before starting the server. The development scripts set a default
   `dev-admin-token`, but production deployments must provide a secret value.
2. Start the integrated FastAPI + static frontend host with `./start_dev.sh` (Linux/macOS) or `run_firefind.bat`
   (Windows/Wine). Both scripts place the backend on port `8000` and inject the admin token.
3. Visit `http://localhost:8000/admin.html` to open the console. The UI loads the active configuration on first load and caches
   drafts locally so you can iterate without immediately committing changes.

### Editing workflow

- **Risk Levels** – Adjust identifiers, labels, severity tiers, numeric thresholds, and supporting rationale for every risk
  category.
- **CIDR Limit Sets** – Maintain default and analyzer/vendor specific CIDR policies with validation against IPv4/IPv6 ranges.
- **Reusable Port Groups** – Define port/protocol collections that analyzers can reference when evaluating exposure.
- **Rule Logic** – Author condition trees, analyzer enablement, severity overrides, and metadata for every rule definition. The
  modal editor validates identifiers, comparators, and nesting as you type.
- **Import/Export** – Use the YAML import to seed the editor from an existing snapshot. The export action produces a normalized
  YAML file ready to be committed back to source control.

Validation status is surfaced inline as well as in the top-level summary banner so you can immediately spot schema issues before
persisting changes.

### Publishing updates

1. Export the YAML snapshot once validation passes. This includes the structured `rules` map required by the latest backend.
2. (Optional) Run the migration helper to normalise legacy fields and populate any missing defaults:
   ```bash
   PYTHONPATH=backend/src python -m firefind.config.migrate_cli rules.yaml --output rules.migrated.yaml
   ```
3. Deploy the updated file by copying it to the location referenced by `FIRE_FIND_RULES_CONFIG` or by invoking the
   configuration API from a CI/CD job:
   ```bash
   curl -X PATCH "http://<host>/api/config/rules" \
     -H "Authorization: Bearer $FIRE_FIND_API_TOKEN" \
     -H "Content-Type: application/json" \
     -d @payload.json
   ```
   The payload should include the `rules` collection exported from the UI and any updated thresholds. Each successful request is
   logged to the JSONL history file for audit purposes.

## Migration Notes for Existing Deployments

Upgrades that introduce the rule editor should follow this playbook to safeguard configuration state:

1. **Backup** the YAML file referenced by `FIRE_FIND_RULES_CONFIG` and its companion history log (the `.history.jsonl` file).
2. **Run the migration helper** against the backup copy to populate the new rule logic structure while preserving existing
   values:
   ```bash
   PYTHONPATH=backend/src python -m firefind.config.migrate_cli /path/to/rules.yaml
   ```
   A `.bak` file is created automatically when migrating in-place.
3. **Review diffs** in source control or with your change-management tooling to confirm rationale, thresholds, and analyzer
   settings look correct.
4. **Redeploy** the backend or reload the configuration via the admin console/API.

Refer to `backend/docs/migration-checklist.md` for a detailed, step-by-step validation checklist that pairs with this summary.

## Monitoring and Rollback

- Monitor the FastAPI `/health` endpoint and HTTP 5xx trends after rolling out configuration changes from the admin console.
- Tail the revision history log to confirm each change is captured with actor metadata. Unexpected spikes in revisions should
  trigger investigation.
- If a new rule definition causes issues, restore the `.bak` file created by the migration helper or roll back to a previous
  history entry by copying its `config` payload back into your YAML file and redeploying.
- Keep regular backups of the configuration directory so you can revert quickly if runtime validation begins failing or the
  analyzer output changes unexpectedly.

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

Some integration tests invoke the Windows batch script `run_firefind.bat` using
`cmd.exe`. A Windows runtime or a compatible environment such as Wine is
required to execute these tests; they will be skipped when neither is available.

Additional tooling such as flake8 and black can be introduced once the project grows.

## Testing Strategy

### Backend
- Unit tests covering configuration schema validation and helper functions that transform rule definitions.
- Integration tests for `GET/PUT /config/rules` that exercise both successful updates and validation error handling.

### Frontend
- Component tests (for example, with React Testing Library) validating `RuleList` and `RuleEditor` interactions.
- Cypress or Playwright end-to-end tests for creating, updating, and deleting rule logic while verifying persistence.

### Manual QA Checklist
- Confirm existing rules can be edited, new rules can be created, and YAML import/export maintain parity.
- Verify backward compatibility by loading legacy YAML configurations that omit rule logic.

## Vendor Support
FireFind currently supports Fortinet firewalls. Support for additional vendors is planned.
