# FireFind Frontend

Prototype frontend for the FireFind tool. Serves static files during development and is hosted by the integrated dev server.

To run the combined frontend and backend, use the project launchers:

```bash
../run_firefind.sh   # Linux/macOS
# On Windows, double-click run_firefind.bat from the repository root
```

The server will be available at [http://localhost:8000](http://localhost:8000).

## Scan workflow overview

1. Navigate to the **Scan** page and upload one or more configuration files (CSV/XLS/XLSX). The drop zone now supports drag-and-drop as well as manual file selection.
2. Enter the client name (required). This value is embedded in generated report filenames and the PDF cover.
3. Start the analysis. During the scan the primary action button is disabled and a toast notification highlights progress.
4. When the API responds, headline metrics (critical, high, total issues, and score) animate into view and the detailed findings table becomes interactive.

## Exploring findings

The results card introduces a richer review experience:

- **Dynamic table** – Findings are rendered into a sortable table with severity badges, per-rule context, and quick access to detailed rationales. Selecting “View details” opens an overlay with the full rationale, description, and tag list.
- **Client-side filters** – Filter by severity, rule, tags (multi-select), or free-text search spanning descriptions, rationales, and assets. Filters can be combined and reset in one click.
- **Sorting & pagination** – Click any column header to reorder findings (severity sorts high to low by default). Pagination keeps 10 findings per page with clear navigation controls and stateful page indicators.
- **Download actions** – CSV and JSON exports reflect the filtered result set. Buttons remain disabled until findings are available, with explicit state styling for accessibility.
- **Report cards** – Server-generated PDF/CSV report links now expose enabled/disabled status via `aria-disabled` and styling rather than inline styles.

All user-generated content is passed through DOMPurify before being inserted into the DOM, ensuring the expanded UI remains protected against injection.

## Running tests

Frontend behaviour is exercised via Jest in `frontend/index.test.js`. The suite now covers:

- File upload validation and removal flows.
- Scan submission wiring, including report link state toggling.
- Rendering of findings, filter interactions, and pagination logic.

Run the targeted tests with:

```bash
npm test -- test frontend/index.test.js
```

The command runs quickly and can be used during development to confirm UI logic changes.
