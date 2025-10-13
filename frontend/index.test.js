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
    <div id="results">
      <span id="criticalCount"></span>
      <span id="highCount"></span>
      <span id="mediumCount"></span>
      <span id="cautionaryCount"></span>
      <span id="lowCount"></span>
      <span id="totalCount"></span>
      <span id="score"></span>
      <a id="pdfLink" style="pointer-events:none;opacity:0.5"></a>
      <a id="csvLink" style="pointer-events:none;opacity:0.5"></a>
    </div>
  `;
  window.HTMLElement.prototype.scrollIntoView = jest.fn();
  Object.defineProperty(window, 'localStorage', {
    value: createLocalStorageMock(),
    configurable: true,
  });
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
    metrics: {
      critical: 1,
      high: 2,
      medium: 3,
      cautionary: 4,
      low: 5,
      total: 6,
      score: 75,
    },
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
  expect(document.getElementById('mediumCount').textContent).toBe('3');
  expect(document.getElementById('cautionaryCount').textContent).toBe('4');
  expect(document.getElementById('lowCount').textContent).toBe('5');
  expect(document.getElementById('totalCount').textContent).toBe('6');
  expect(document.getElementById('score').textContent).toBe('75%');

  const pdfLink = document.getElementById('pdfLink');
  const csvLink = document.getElementById('csvLink');
  expect(pdfLink.href).toContain('/report.pdf');
  expect(pdfLink.style.pointerEvents).toBe('auto');
  expect(pdfLink.style.opacity).toBe('1');
  expect(csvLink.href).toContain('/report.csv');
  expect(csvLink.style.pointerEvents).toBe('auto');
  expect(csvLink.style.opacity).toBe('1');

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
