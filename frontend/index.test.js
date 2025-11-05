/**
 * @jest-environment jsdom
 */

const fs = require('fs');
const path = require('path');

let scriptLoaded = false;

function createLocalStorageMock() {
  let store = {};
  return {
    getItem: jest.fn((key) => (key in store ? store[key] : null)),
    setItem: jest.fn((key, value) => {
      store[key] = String(value);
    }),
    removeItem: jest.fn((key) => {
      delete store[key];
    }),
    clear: jest.fn(() => {
      store = {};
    }),
  };
}

function loadApp() {
  document.body.innerHTML = `
    <div id="dropZone"></div>
    <input id="fileInput" />
    <section id="filesSection"><div id="filesGrid"></div></section>
    <section id="results">
      <span id="criticalCount"></span>
      <span id="highCount"></span>
      <span id="totalCount"></span>
      <span id="score"></span>
      <div class="results-toolbar">
        <div class="filters">
          <div class="filter-group">
            <label for="searchFilter">Search</label>
            <div class="filter-input">
              <i class="fas fa-search"></i>
              <input id="searchFilter" type="search" />
            </div>
          </div>
          <div class="filter-group">
            <label for="severityFilter">Severity</label>
            <select id="severityFilter">
              <option value="all">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Informational</option>
            </select>
          </div>
          <div class="filter-group">
            <label for="ruleFilter">Rule</label>
            <select id="ruleFilter">
              <option value="all">All</option>
            </select>
          </div>
          <div class="filter-group">
            <label for="tagFilter">Tags</label>
            <select id="tagFilter" multiple></select>
            <small id="tagFilterHint">Hint</small>
          </div>
        </div>
        <div class="toolbar-actions">
          <button id="resetFilters" type="button">Reset</button>
        </div>
      </div>
      <div class="results-table-card">
        <div class="table-header">
          <div class="table-summary" id="findingsSummary">No findings yet</div>
          <div class="table-actions">
            <button id="downloadFilteredCsv" data-state="disabled" disabled type="button">CSV</button>
            <button id="downloadFilteredJson" data-state="disabled" disabled type="button">JSON</button>
          </div>
        </div>
        <div class="table-responsive">
          <table id="findingsTable">
            <thead>
              <tr>
                <th><button class="sort-button" data-sort="severity" type="button"><span data-sort-indicator="severity"></span></button></th>
                <th><button class="sort-button" data-sort="rule_id" type="button"><span data-sort-indicator="rule_id"></span></button></th>
                <th><button class="sort-button" data-sort="description" type="button"><span data-sort-indicator="description"></span></button></th>
                <th><button class="sort-button" data-sort="rationale" type="button"><span data-sort-indicator="rationale"></span></button></th>
                <th><button class="sort-button" data-sort="tags" type="button"><span data-sort-indicator="tags"></span></button></th>
                <th class="actions-column"></th>
              </tr>
            </thead>
            <tbody id="findingsTableBody"></tbody>
          </table>
          <div id="resultsEmptyState" hidden></div>
        </div>
        <div class="pagination" id="findingsPagination" hidden>
          <button id="prevPage" type="button"></button>
          <span id="pageIndicator"></span>
          <button id="nextPage" type="button"></button>
        </div>
      </div>
      <a id="pdfLink" class="report-card is-disabled" aria-disabled="true"></a>
      <a id="csvLink" class="report-card is-disabled" aria-disabled="true"></a>
    </section>
    <div class="modal-overlay" id="findingModal" aria-hidden="true">
      <div class="modal-backdrop"></div>
      <div class="modal-panel">
        <header class="modal-header">
          <div>
            <p id="findingModalSeverity" class="modal-eyebrow"></p>
            <h3 id="findingModalTitle" class="modal-title"></h3>
          </div>
          <button id="closeFindingModal" type="button">×</button>
        </header>
        <div class="modal-body">
          <dl class="modal-definition">
            <div><dt>Rule</dt><dd id="findingModalRule"></dd></div>
            <div><dt>Description</dt><dd id="findingModalDescription"></dd></div>
            <div><dt>Rationale</dt><dd id="findingModalRationale"></dd></div>
            <div><dt>Tags</dt><dd id="findingModalTags"></dd></div>
          </dl>
        </div>
      </div>
    </div>
  `;
  window.HTMLElement.prototype.scrollIntoView = jest.fn();
  Object.defineProperty(window, 'localStorage', {
    value: createLocalStorageMock(),
    configurable: true,
  });
  window.URL.createObjectURL = jest.fn(() => 'blob:mock');
  window.URL.revokeObjectURL = jest.fn();
  window.showToast = jest.fn();
  if (!scriptLoaded) {
    jest.spyOn(window, 'setInterval').mockImplementation(() => {});
    const script = fs
      .readFileSync(path.resolve(__dirname, 'app.js'), 'utf8');
    const scriptEl = document.createElement('script');
    scriptEl.textContent = script;
    document.body.appendChild(scriptEl);
    scriptLoaded = true;
  } else {
    window.setInterval.mockClear();
    window.eval('uploadedFiles = []');
    window.eval('findingsUiInitialized = false');
    window.initializeFindingsUI();
  }
}

beforeEach(() => {
  jest.clearAllMocks();
  loadApp();
});

test('formatFileSize formats bytes correctly', () => {
  expect(window.formatFileSize(0)).toBe('0 Bytes');
  expect(window.formatFileSize(1024)).toBe('1 KB');
  expect(window.formatFileSize(1048576)).toBe('1 MB');
});

test('displayFiles shows and hides uploaded files', () => {
  const file = new File(['x'], 'file.csv', { type: 'text/csv' });
  window.handleFiles([file]);
  const filesSection = document.getElementById('filesSection');
  const filesGrid = document.getElementById('filesGrid');
  expect(filesSection.classList.contains('active')).toBe(true);
  expect(filesGrid.innerHTML).toContain('file.csv');

  window.eval('uploadedFiles = []');
  window.displayFiles();
  expect(filesSection.classList.contains('active')).toBe(false);
});

test('removeFile removes uploaded entries', () => {
  const file = new File(['x'], 'removable.csv', { type: 'text/csv' });
  window.handleFiles([file]);
  const filesGrid = document.getElementById('filesGrid');
  const uploadedBefore = window.eval('uploadedFiles');
  expect(uploadedBefore).toHaveLength(1);
  expect(filesGrid.innerHTML).toContain('removable.csv');

  const [{ id }] = uploadedBefore;
  window.showToast = jest.fn();
  window.removeFile(id);

  const uploadedAfter = window.eval('uploadedFiles');
  expect(uploadedAfter).toHaveLength(0);
  expect(filesGrid.innerHTML).not.toContain('removable.csv');
});

test('startScan posts files and updates metrics and links', async () => {
  const startButton = document.createElement('button');
  startButton.textContent = 'SCAN';
  document.body.appendChild(startButton);

  const file = new File(['x'], 'file.csv', { type: 'text/csv' });
  window.handleFiles([file]);
  expect(window.eval('uploadedFiles.length')).toBe(1);

  const mockResponse = {
    metrics: { critical: 1, high: 2, total: 3, score: 75 },
    pdf: '/report.pdf',
    csv: '/report.csv',
  };
  window.fetch = jest.fn().mockResolvedValue({
    ok: true,
    json: async () => mockResponse,
  });
  global.fetch = window.fetch;

  await window.startScan({ target: startButton });

  expect(window.fetch).toHaveBeenCalledWith(
    '/api/scan?save_pdf=1&save_csv=1',
    expect.objectContaining({ method: 'POST' })
  );
  expect(document.getElementById('criticalCount').textContent).toBe('1');
  expect(document.getElementById('highCount').textContent).toBe('2');
  expect(document.getElementById('totalCount').textContent).toBe('3');
  expect(document.getElementById('score').textContent).toBe('75%');

  const pdfLink = document.getElementById('pdfLink');
  const csvLink = document.getElementById('csvLink');
  expect(pdfLink.href).toContain('/report.pdf');
  expect(pdfLink.classList.contains('is-disabled')).toBe(false);
  expect(pdfLink.getAttribute('aria-disabled')).toBe('false');
  expect(csvLink.href).toContain('/report.csv');
  expect(csvLink.classList.contains('is-disabled')).toBe(false);
  expect(csvLink.getAttribute('aria-disabled')).toBe('false');

  expect(startButton.disabled).toBe(false);
  expect(startButton.textContent).toBe('SCAN');
});

test('startScan uploads xlsx files correctly', async () => {
  const startButton = document.createElement('button');
  startButton.textContent = 'SCAN';
  document.body.appendChild(startButton);

  const file = new File(['binary'], 'rules.xlsx', {
    type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  });
  window.handleFiles([file]);

  window.fetch = jest.fn().mockResolvedValue({
    ok: true,
    json: async () => ({ metrics: {}, findings: [] }),
  });
  global.fetch = window.fetch;

  await window.startScan({ target: startButton });

  expect(window.fetch).toHaveBeenCalledWith(
    '/api/scan?save_pdf=1&save_csv=1',
    expect.objectContaining({ method: 'POST' })
  );
  const formData = window.fetch.mock.calls[0][1].body;
  const files = formData.getAll('files');
  expect(files).toHaveLength(1);
  expect(files[0].name).toBe('rules.xlsx');
});

test('updateFindingsUI renders findings and enables downloads', () => {
  const findings = [
    {
      severity: 'critical',
      rule_id: 'FF-001',
      description: 'Database exposed to the internet',
      rationale: 'Any source allowed to sensitive port',
      tags: ['database', 'exposure'],
    },
    {
      severity: 'low',
      rule_id: 'FF-002',
      rule_name: 'Allow internal DNS',
      description: 'Internal DNS rule',
      rationale: 'Trusted network segment',
      tags: [],
    },
  ];

  window.updateFindingsUI(findings);

  const rows = document.querySelectorAll('#findingsTableBody tr');
  expect(rows).toHaveLength(2);
  expect(document.getElementById('findingsSummary').textContent).toContain('2');

  const csvButton = document.getElementById('downloadFilteredCsv');
  const jsonButton = document.getElementById('downloadFilteredJson');
  expect(csvButton.disabled).toBe(false);
  expect(jsonButton.disabled).toBe(false);
  expect(csvButton.dataset.state).toBe('enabled');
});

test('filters update the rendered findings', () => {
  const findings = [
    { severity: 'critical', rule_id: 'FF-001', description: 'Database exposure', rationale: 'Any source', tags: ['database'] },
    { severity: 'high', rule_id: 'FF-002', description: 'Open SSH', rationale: 'Legacy access', tags: ['ssh'] },
    { severity: 'low', rule_id: 'FF-003', description: 'Informational notice', rationale: 'Documented exception', tags: [] },
  ];

  window.updateFindingsUI(findings);

  const severityFilter = document.getElementById('severityFilter');
  severityFilter.value = 'high';
  severityFilter.dispatchEvent(new Event('change', { bubbles: true }));

  let rows = document.querySelectorAll('#findingsTableBody tr');
  expect(rows).toHaveLength(1);
  expect(rows[0].textContent).toContain('FF-002');

  const searchInput = document.getElementById('searchFilter');
  searchInput.value = 'database';
  searchInput.dispatchEvent(new Event('input', { bubbles: true }));

  rows = document.querySelectorAll('#findingsTableBody tr');
  expect(rows).toHaveLength(0);
  expect(document.getElementById('resultsEmptyState').hidden).toBe(false);

  document.getElementById('resetFilters').click();
  rows = document.querySelectorAll('#findingsTableBody tr');
  expect(rows).toHaveLength(3);
});

test('pagination navigates between pages of findings', () => {
  const findings = Array.from({ length: 12 }, (_, index) => ({
    severity: index % 2 === 0 ? 'critical' : 'medium',
    rule_id: `FF-${index + 1}`,
    description: `Rule ${index + 1}`,
    rationale: 'Auto generated',
    tags: [],
  }));

  window.updateFindingsUI(findings);

  const indicator = document.getElementById('pageIndicator');
  expect(indicator.textContent).toBe('Page 1 of 2');

  document.getElementById('nextPage').click();
  expect(indicator.textContent).toBe('Page 2 of 2');
  expect(document.querySelectorAll('#findingsTableBody tr')).toHaveLength(2);
  expect(window.__firefind.findingsState.currentPage).toBe(2);

  document.getElementById('prevPage').click();
  expect(indicator.textContent).toBe('Page 1 of 2');
  expect(window.__firefind.findingsState.currentPage).toBe(1);
});