function sanitize(str) {
    if (typeof DOMPurify !== 'undefined' && DOMPurify.sanitize) {
        return DOMPurify.sanitize(str);
    }
    return String(str).replace(/[&<>"']/g, (s) => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[s]);
}

function smoothScroll(event, targetId) {
    if (event && typeof event.preventDefault === 'function') {
        event.preventDefault();
    }
    const element = document.getElementById(targetId);
    if (element) {
        element.scrollIntoView({
            behavior: 'smooth',
            block: 'start'
        });
    }
}

window.addEventListener('scroll', () => {
    const header = document.getElementById('header');
    if (window.scrollY > 50) {
        header.classList.add('scrolled');
    } else {
        header.classList.remove('scrolled');
    }
});

let uploadedFiles = [];

const findingsState = {
    all: [],
    filtered: [],
    currentPage: 1,
    pageSize: 10,
    sortKey: 'severity',
    sortDirection: 'desc',
    filters: {
        search: '',
        severity: 'all',
        rule: 'all',
        tags: []
    }
};

const severityOrder = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
    informational: 4,
    information: 4
};

const severityLabels = {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    info: 'Informational'
};

let findingsUiInitialized = false;
let lastFocusedDetailsTrigger = null;

const asText = (value) => value == null ? '' : String(value);

const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');

if (dropZone) {
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('drag-over');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('drag-over');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('drag-over');
        handleFiles(e.dataTransfer.files);
    });
}

if (fileInput) {
    fileInput.addEventListener('change', (e) => {
        handleFiles(e.target.files);
        e.target.value = '';
    });
}

function loadStoredFiles() {
    try {
        const storedFiles = localStorage.getItem('firefind_uploaded_files');
        if (storedFiles) {
            const fileData = JSON.parse(storedFiles);
            uploadedFiles = fileData.map(fileInfo => ({
                id: fileInfo.id,
                name: fileInfo.name,
                size: fileInfo.size,
                file: new File([fileInfo.content], fileInfo.name, { type: fileInfo.type })
            }));
            displayFiles();
        }
    } catch (error) {
        console.error('Error loading stored files:', error);
        localStorage.removeItem('firefind_uploaded_files');
    }
}

function saveFilesToStorage() {
    try {
        const filePromises = uploadedFiles.map(async (fileObj) => {
            const content = await fileToBase64(fileObj.file);
            return {
                id: fileObj.id,
                name: fileObj.name,
                size: fileObj.size,
                type: fileObj.file.type,
                content: content
            };
        });

        Promise.all(filePromises).then(fileData => {
            localStorage.setItem('firefind_uploaded_files', JSON.stringify(fileData));
        }).catch(error => {
            console.error('Error saving files to storage:', error);
        });
    } catch (error) {
        console.error('Error saving files to storage:', error);
    }
}

function fileToBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.readAsDataURL(file);
        reader.onload = () => resolve(reader.result.split(',')[1]);
        reader.onerror = error => reject(error);
    });
}

function clearStoredFiles() {
    localStorage.removeItem('firefind_uploaded_files');
    uploadedFiles = [];
    displayFiles();
    showToast('All files cleared');
}

const ALLOWED_FILE_TYPES = {
    'text/csv': ['.csv'],
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
    'application/vnd.ms-excel': ['.xls'],
    'text/plain': ['.txt']
};

const ALLOWED_EXTENSIONS = ['.csv', '.xlsx', '.xls'];

function validateFileType(file) {
    const fileName = file.name.toLowerCase();
    const fileExtension = fileName.substring(fileName.lastIndexOf('.'));
    
    if (!ALLOWED_EXTENSIONS.includes(fileExtension)) {
        return {
            valid: false,
            error: `Invalid file type "${fileExtension}". Only CSV (.csv) and Excel (.xlsx, .xls) files are allowed.`
        };
    }
    
    const mimeType = file.type;
    if (mimeType && !Object.keys(ALLOWED_FILE_TYPES).includes(mimeType)) {
        if (!(fileExtension === '.csv' && (mimeType === '' || mimeType === 'application/octet-stream'))) {
            return {
                valid: false,
                error: `Invalid file format detected. Please ensure you're uploading a valid ${fileExtension.toUpperCase()} file.`
            };
        }
    }
    
    return { valid: true };
}

function validateFileSize(file) {
    const maxSize = 50 * 1024 * 1024;
    if (file.size > maxSize) {
        return {
            valid: false,
            error: `File "${file.name}" is too large. Maximum file size is 50MB.`
        };
    }
    return { valid: true };
}

function createFileId() {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
        return crypto.randomUUID();
    }
    return String(Date.now() + Math.random());
}

function handleFiles(files) {
    let validFiles = [];
    let errors = [];

    for (let file of files) {
        if (uploadedFiles.find(f => f.name === file.name)) {
            errors.push(`File "${file.name}" is already uploaded.`);
            continue;
        }

        const typeValidation = validateFileType(file);
        if (!typeValidation.valid) {
            errors.push(typeValidation.error);
            continue;
        }

        const sizeValidation = validateFileSize(file);
        if (!sizeValidation.valid) {
            errors.push(sizeValidation.error);
            continue;
        }

        validFiles.push(file);
    }

    validFiles.forEach(file => {
        uploadedFiles.push({
            id: createFileId(),
            name: file.name,
            size: formatFileSize(file.size),
            file: file
        });
    });
    
    if (errors.length > 0) {
        errors.forEach(error => showToast(error, 'error'));
    }

    if (validFiles.length > 0) {
        const message = validFiles.length === 1
            ? `File "${validFiles[0].name}" uploaded successfully!`
            : `${validFiles.length} files uploaded successfully!`;
        showToast(message, 'success');
    }
    
    if (validFiles.length > 0) {
        displayFiles();
        saveFilesToStorage();
    }
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}
    
function displayFiles() {
    const filesSection = document.getElementById('filesSection');
    const filesGrid = document.getElementById('filesGrid');
    
    if (uploadedFiles.length > 0) {
        filesSection.classList.add('active');

        filesGrid.innerHTML = uploadedFiles.map(file => `
            <div class="file-card">
                <div class="file-header">
                    <div>
                        <div class="file-name">${sanitize(file.name)}</div>
                        <div class="file-size">${sanitize(file.size)}</div>
                    </div>
                    <button class="remove-btn" onclick="removeFile('${sanitize(file.id)}')">Remove</button>
                </div>
            </div>
        `).join('');

        filesGrid.innerHTML += `
            <div class="file-card" style="text-align: center; border: 2px dashed var(--border-color);">
                <button class="btn btn-secondary" onclick="clearStoredFiles()" style="margin: 1rem;">
                    Clear All Files
                </button>
            </div>
        `;

        if (uploadedFiles.length > 0) {
            filesSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    } else {
        filesSection.classList.remove('active');
        filesGrid.innerHTML = '';
    }
}

function removeFile(fileId) {
    const normalizedId = String(fileId);
    uploadedFiles = uploadedFiles.filter(f => String(f.id) !== normalizedId);
    displayFiles();
    saveFilesToStorage();
    showToast('File removed successfully', 'success');
}

function generateDateFilename(baseFilename, extension) {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const seconds = String(now.getSeconds()).padStart(2, '0');
    
    let clientName = '';
    const clientInput = document.getElementById('client-name');
    if (clientInput && clientInput.value.trim() !== '') {
        clientName = '-' + clientInput.value.trim().replace(/\s+/g, '-');
    }
    return `${baseFilename}${clientName}_${year}-${month}-${day}_${hours}-${minutes}-${seconds}.${extension}`;
}

async function startScan(e) {
    if (uploadedFiles.length === 0) {
        showToast('Please upload files first', 'error');
        return;
    }

    const btn = e.target;
    btn.disabled = true;
    const originalText = btn.textContent;
    btn.textContent = 'SCANNING...';
    showToast('Scanning firewall configurations...', 'info');
    const formData = new FormData();
    uploadedFiles.forEach(f => {
        if (f.file) formData.append('files', f.file);
    });
    const clientInput = document.getElementById('client-name');
    if (clientInput && clientInput.value.trim() !== '') {
        formData.append('client_name', clientInput.value.trim());
    }

    try {
        const scanUrl = '/api/scan?save_pdf=1&save_csv=1';
        const response = await fetch(scanUrl, {
            method: 'POST',
            body: formData
        });
        if (!response.ok) throw new Error('Scan failed');
        const data = await response.json();

        const metrics = data.metrics || {};
        document.getElementById('criticalCount').textContent = metrics.critical ?? 0;
        document.getElementById('highCount').textContent = metrics.high ?? 0;
        document.getElementById('totalCount').textContent = metrics.total ?? data.findings?.length ?? 0;
        document.getElementById('score').textContent = metrics.score != null ? metrics.score + '%' : '0%';

        const pdfLink = document.getElementById('pdfLink');
        const csvLink = document.getElementById('csvLink');

        if (pdfLink) {
            if (data.pdf) {
                pdfLink.href = data.pdf;
                const pdfFileName = generateDateFilename('report', 'pdf');
                pdfLink.setAttribute('download', pdfFileName);
                setReportCardState(pdfLink, true);
            } else {
                pdfLink.removeAttribute('href');
                pdfLink.removeAttribute('download');
                setReportCardState(pdfLink, false);
            }        
        }

        if (csvLink) {
            if (data.csv) {
                csvLink.href = data.csv;
                const csvFileName = generateDateFilename('findings', 'csv');
                csvLink.setAttribute('download', csvFileName);
                setReportCardState(csvLink, true);
            } else {
                csvLink.removeAttribute('href');
                csvLink.removeAttribute('download');
                setReportCardState(csvLink, false);
            }
        }

        updateFindingsUI(Array.isArray(data.findings) ? data.findings : []);

        const resultsSection = document.getElementById('results');
        resultsSection.classList.add('active');
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        animateMetrics();
        showToast('Scan completed successfully!', 'success');
    } catch (err) {
        showToast('Scan failed: ' + err.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

function setReportCardState(link, isEnabled) {
    if (!link) return;
    link.classList.toggle('is-disabled', !isEnabled);
    link.dataset.state = isEnabled ? 'enabled' : 'disabled';
    link.setAttribute('aria-disabled', isEnabled ? 'false' : 'true');
    link.style.pointerEvents = isEnabled ? 'auto' : 'none';
    link.style.opacity = isEnabled ? '1' : '0.5';
}

function initializeFindingsUI() {
    if (findingsUiInitialized) return;

    const table = document.getElementById('findingsTable');
    if (!table) return;

    findingsUiInitialized = true;

    const searchFilter = document.getElementById('searchFilter');
    const severityFilter = document.getElementById('severityFilter');
    const ruleFilter = document.getElementById('ruleFilter');
    const tagFilter = document.getElementById('tagFilter');
    const resetFilters = document.getElementById('resetFilters');
    const prevPage = document.getElementById('prevPage');
    const nextPage = document.getElementById('nextPage');
    const downloadCsvBtn = document.getElementById('downloadFilteredCsv');
    const downloadJsonBtn = document.getElementById('downloadFilteredJson');
    const findingsTableBody = document.getElementById('findingsTableBody');
    const closeModalButton = document.getElementById('closeFindingModal');
    const modalBackdrop = document.querySelector('#findingModal .modal-backdrop');

    if (searchFilter) {
        searchFilter.addEventListener('input', (event) => {
            findingsState.filters.search = event.target.value;
            findingsState.currentPage = 1;
            applyFiltersAndRender();
        });
    }

    if (severityFilter) {
        severityFilter.addEventListener('change', (event) => {
            findingsState.filters.severity = event.target.value;
            findingsState.currentPage = 1;
            applyFiltersAndRender();
        });
    }

    if (ruleFilter) {
        ruleFilter.addEventListener('change', (event) => {
            findingsState.filters.rule = event.target.value;
            findingsState.currentPage = 1;
            applyFiltersAndRender();
        });
    }

    if (tagFilter) {
        tagFilter.addEventListener('change', () => {
            const selectedTags = Array.from(tagFilter.selectedOptions || []).map(option => option.value);
            findingsState.filters.tags = selectedTags;
            findingsState.currentPage = 1;
            applyFiltersAndRender();
        });
    }

    if (resetFilters) {
        resetFilters.addEventListener('click', () => {
            findingsState.filters = {
                search: '',
                severity: 'all',
                rule: 'all',
                tags: []
            };
            findingsState.currentPage = 1;
            syncFilterControls();
            applyFiltersAndRender();
        });
    }

    if (prevPage) {
        prevPage.addEventListener('click', () => changePage(-1));
    }

    if (nextPage) {
        nextPage.addEventListener('click', () => changePage(1));
    }

    if (downloadCsvBtn) {
        downloadCsvBtn.addEventListener('click', downloadFilteredCsv);
    }

    if (downloadJsonBtn) {
        downloadJsonBtn.addEventListener('click', downloadFilteredJson);
    }

    if (findingsTableBody) {
        findingsTableBody.addEventListener('click', (event) => {
            const button = event.target.closest('.view-details-btn');
            if (!button) return;
            const index = Number(button.getAttribute('data-finding-index'));
            const finding = findingsState.all.find(item => item.index === index);
            if (finding) {
                lastFocusedDetailsTrigger = button;
                openFindingModal(finding);
            }
        });
    }

    if (closeModalButton) {
        closeModalButton.addEventListener('click', closeFindingModal);
    }

    if (modalBackdrop) {
        modalBackdrop.addEventListener('click', closeFindingModal);
    }

    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
            closeFindingModal();
        }
    });

    const sortButtons = document.querySelectorAll('.sort-button');
    sortButtons.forEach((button) => {
        button.addEventListener('click', () => {
            const sortKey = button.getAttribute('data-sort');
            if (sortKey) {
                changeSort(sortKey);
            }
        });
    });

    updateSortIndicators();
}

function updateFindingsUI(findings) {
    initializeFindingsUI();

    findingsState.all = normalizeFindings(Array.isArray(findings) ? findings : []);
    findingsState.currentPage = 1;
    findingsState.sortKey = 'severity';
    findingsState.sortDirection = 'desc';
    findingsState.filters = {
        search: '',
        severity: 'all',
        rule: 'all',
        tags: []
    };

    updateFilterOptions();
    syncFilterControls();
    applyFiltersAndRender();
}

function normalizeFindings(findings) {
    return findings.map((finding, index) => {
        const severityValue = asText(finding.severity ?? finding.level ?? 'info').toLowerCase();
        const severity = Object.prototype.hasOwnProperty.call(severityOrder, severityValue) ? severityValue : 'info';
        const ruleIdRaw = asText(finding.rule_id ?? finding.ruleId ?? finding.rule ?? finding.id ?? '').trim();
        const ruleName = asText(finding.rule_name ?? finding.ruleName ?? finding.name ?? '').trim();
        const ruleId = ruleIdRaw || `Rule ${index + 1}`;
        const ruleDisplay = ruleName && ruleName !== ruleId ? `${ruleId} – ${ruleName}` : ruleId;
        const description = asText(finding.description ?? finding.message ?? '');
        const rationale = asText(finding.rationale ?? finding.reason ?? '');
        const asset = asText(finding.asset ?? finding.asset_name ?? finding.device ?? '');

        let tags = finding.tags;
        if (Array.isArray(tags)) {
            tags = tags.filter(Boolean).map(tag => asText(tag).trim()).filter(Boolean);
        } else if (typeof tags === 'string') {
            tags = tags.split(/[,;]+/).map(tag => tag.trim()).filter(Boolean);
        } else if (tags != null) {
            tags = [asText(tags).trim()].filter(Boolean);
        } else {
            tags = [];
        }

        const tagsLower = tags.map(tag => tag.toLowerCase());
        const tagsDisplay = tags.join(', ');
        const ruleKey = (ruleId || ruleName).toLowerCase();
        const searchText = [ruleId, ruleName, description, rationale, asset, tagsDisplay].join(' ').toLowerCase();

        return {
            index,
            severity,
            ruleId,
            ruleName,
            ruleDisplay,
            ruleKey,
            description,
            rationale,
            asset,
            tags,
            tagsLower,
            tagsDisplay,
            searchText,
            source: finding
        };
    });
}

function updateFilterOptions() {
    const ruleFilter = document.getElementById('ruleFilter');
    const tagFilter = document.getElementById('tagFilter');

    if (ruleFilter) {
        const selectedRule = findingsState.filters.rule;
        const ruleOptions = new Map();
        findingsState.all.forEach((finding) => {
            if (!ruleOptions.has(finding.ruleKey)) {
                ruleOptions.set(finding.ruleKey, finding.ruleDisplay);
            }
        });

        let optionsHtml = '<option value="all">All rules</option>';
        ruleOptions.forEach((label, value) => {
            optionsHtml += `<option value="${sanitize(value)}">${sanitize(label)}</option>`;
        });
        ruleFilter.innerHTML = optionsHtml;

        if (selectedRule !== 'all' && !ruleOptions.has(selectedRule)) {
            findingsState.filters.rule = 'all';
        }
    }

    if (tagFilter) {
        const selectedTags = new Set(findingsState.filters.tags);
        const tagOptions = new Map();
        findingsState.all.forEach((finding) => {
            finding.tags.forEach((tag, index) => {
                const key = finding.tagsLower[index];
                if (!tagOptions.has(key)) {
                    tagOptions.set(key, tag);
                }
            });
        });

        tagFilter.innerHTML = Array.from(tagOptions.entries()).map(([value, label]) => (
            `<option value="${sanitize(value)}">${sanitize(label)}</option>`
        )).join('');

        Array.from(tagFilter.options).forEach((option) => {
            option.selected = selectedTags.has(option.value);
        });
    }
}

function syncFilterControls() {
    const searchFilter = document.getElementById('searchFilter');
    const severityFilter = document.getElementById('severityFilter');
    const ruleFilter = document.getElementById('ruleFilter');
    const tagFilter = document.getElementById('tagFilter');

    if (searchFilter) {
        searchFilter.value = findingsState.filters.search;
    }

    if (severityFilter) {
        severityFilter.value = findingsState.filters.severity;
    }

    if (ruleFilter) {
        ruleFilter.value = findingsState.filters.rule;
    }

    if (tagFilter) {
        Array.from(tagFilter.options).forEach((option) => {
            option.selected = findingsState.filters.tags.includes(option.value);
        });
    }
}

function applyFiltersAndRender() {
    if (!findingsUiInitialized) return;

    const { search, severity, rule, tags } = findingsState.filters;
    const normalizedSearch = search.trim();

    let items = findingsState.all.slice();

    if (severity && severity !== 'all') {
        items = items.filter(item => item.severity === severity);
    }

    if (rule && rule !== 'all') {
        items = items.filter(item => item.ruleKey === rule);
    }

    if (tags.length > 0) {
        items = items.filter(item => tags.every(tag => item.tagsLower.includes(tag)));
    }

    if (normalizedSearch) {
        const searchTerm = normalizedSearch.toLowerCase();
        items = items.filter(item => item.searchText.includes(searchTerm));
    }

    items = sortFindings(items);
    findingsState.filtered = items;

    const total = items.length;
    const totalPages = total > 0 ? Math.ceil(total / findingsState.pageSize) : 1;

    if (findingsState.currentPage > totalPages) {
        findingsState.currentPage = total > 0 ? totalPages : 1;
    }

    const startIndex = total === 0 ? 0 : (findingsState.currentPage - 1) * findingsState.pageSize;
    const pageItems = items.slice(startIndex, startIndex + findingsState.pageSize);

    renderFindingsTable(pageItems, total, startIndex);
    updatePaginationControls(totalPages, total);
    setDownloadButtonsEnabled(total > 0);
}

function sortFindings(items) {
    const key = findingsState.sortKey;
    const direction = findingsState.sortDirection === 'asc' ? 1 : -1;
    const getComparable = (item) => {
        switch (key) {
            case 'severity':
                return severityOrder[item.severity] ?? Number.MAX_SAFE_INTEGER;
            case 'rule_id':
                return item.ruleDisplay.toLowerCase();
            case 'description':
                return item.description.toLowerCase();
            case 'rationale':
                return item.rationale.toLowerCase();
            case 'tags':
                return item.tagsDisplay.toLowerCase();
            default:
                return item.index;
        }
    };

    return items.slice().sort((a, b) => {
        const valueA = getComparable(a);
        const valueB = getComparable(b);

        if (valueA < valueB) return -1 * direction;
        if (valueA > valueB) return 1 * direction;
        return a.index - b.index;
    });
}

function changePage(offset) {
    const total = findingsState.filtered.length;
    if (total === 0) return;
    const totalPages = Math.ceil(total / findingsState.pageSize);
    const targetPage = Math.min(Math.max(findingsState.currentPage + offset, 1), totalPages);
    if (targetPage !== findingsState.currentPage) {
        findingsState.currentPage = targetPage;
        applyFiltersAndRender();
    }
}

function changeSort(sortKey) {
    if (!sortKey) return;
    if (findingsState.sortKey === sortKey) {
        findingsState.sortDirection = findingsState.sortDirection === 'asc' ? 'desc' : 'asc';
    } else {
        findingsState.sortKey = sortKey;
        findingsState.sortDirection = sortKey === 'severity' ? 'desc' : 'asc';
    }
    findingsState.currentPage = 1;
    updateSortIndicators();
    applyFiltersAndRender();
}

function updateSortIndicators() {
    const indicators = document.querySelectorAll('[data-sort-indicator]');
    indicators.forEach((indicator) => {
        const key = indicator.getAttribute('data-sort-indicator');
        if (key === findingsState.sortKey) {
            indicator.dataset.direction = findingsState.sortDirection;
        } else {
            delete indicator.dataset.direction;
        }
    });
}

function renderFindingsTable(pageItems, total, startIndex) {
    const tbody = document.getElementById('findingsTableBody');
    const emptyState = document.getElementById('resultsEmptyState');
    const summary = document.getElementById('findingsSummary');

    if (!tbody || !emptyState || !summary) {
        return;
    }

    if (total === 0) {
        tbody.innerHTML = '';
        emptyState.hidden = findingsState.all.length === 0;
        summary.textContent = findingsState.all.length === 0
            ? 'No findings yet'
            : 'No findings match the selected filters';
        return;
    }

    emptyState.hidden = pageItems.length > 0;

    const rows = pageItems.map((finding) => {
        const severityKey = Object.prototype.hasOwnProperty.call(severityLabels, finding.severity)
            ? finding.severity
            : 'info';
        const severityClass = `severity-badge severity-${severityKey}`;
        const severityText = severityLabels[severityKey] || severityLabels.info;
        const descriptionText = finding.description || 'No description provided.';
        const rationaleText = finding.rationale || 'No rationale provided.';
        const tagsMarkup = finding.tags.length
            ? finding.tags.map(tag => `<span class="tag">${sanitize(tag)}</span>`).join('')
            : '<span class="tag tag-empty">No tags</span>';

        const assetMarkup = finding.asset
            ? `<span class="table-subtext">${sanitize(finding.asset)}</span>`
            : '';

        return `
            <tr>
                <td>
                    <span class="${severityClass}" data-severity="${sanitize(severityText)}">${sanitize(severityText)}</span>
                </td>
                <td>
                    <span class="table-cell-primary">${sanitize(finding.ruleDisplay)}</span>
                    ${assetMarkup}
                </td>
                <td>
                    <span class="table-cell-primary" title="${sanitize(descriptionText)}">${sanitize(descriptionText)}</span>
                </td>
                <td>
                    <span class="table-cell-primary" title="${sanitize(rationaleText)}">${sanitize(rationaleText)}</span>
                </td>
                <td>
                    <div class="tag-list">${tagsMarkup}</div>
                </td>
                <td class="actions-column">
                    <button type="button" class="btn btn-link view-details-btn" data-finding-index="${finding.index}">
                        View details
                    </button>
                </td>
            </tr>
        `;
    }).join('');

    tbody.innerHTML = rows;

    const endIndex = startIndex + pageItems.length;
    summary.textContent = `Showing ${startIndex + 1}–${endIndex} of ${total} findings`;
}

function updatePaginationControls(totalPages, total) {
    const pagination = document.getElementById('findingsPagination');
    const pageIndicator = document.getElementById('pageIndicator');
    const prevPage = document.getElementById('prevPage');
    const nextPage = document.getElementById('nextPage');

    if (!pagination || !pageIndicator || !prevPage || !nextPage) {
        return;
    }

    if (total <= findingsState.pageSize) {
        pagination.hidden = true;
        prevPage.disabled = true;
        nextPage.disabled = true;
        pageIndicator.textContent = total === 0 ? 'Page 0 of 0' : 'Page 1 of 1';
        return;
    }

    pagination.hidden = false;
    pageIndicator.textContent = `Page ${findingsState.currentPage} of ${totalPages}`;
    prevPage.disabled = findingsState.currentPage <= 1;
    nextPage.disabled = findingsState.currentPage >= totalPages;
}

function setDownloadButtonsEnabled(isEnabled) {
    const buttons = [
        document.getElementById('downloadFilteredCsv'),
        document.getElementById('downloadFilteredJson')
    ];

    buttons.forEach((button) => {
        if (!button) return;
        button.disabled = !isEnabled;
        button.dataset.state = isEnabled ? 'enabled' : 'disabled';
        button.setAttribute('aria-disabled', isEnabled ? 'false' : 'true');
    });
}

function downloadFilteredCsv() {
    if (!findingsState.filtered.length) return;
    const content = createCsvContent(findingsState.filtered);
    const filename = generateDateFilename('firefind-findings', 'csv');
    triggerDownload(content, 'text/csv', filename);
}

function downloadFilteredJson() {
    if (!findingsState.filtered.length) return;
    const payload = findingsState.filtered.map(item => item.source);
    const content = JSON.stringify(payload, null, 2);
    const filename = generateDateFilename('firefind-findings', 'json');
    triggerDownload(content, 'application/json', filename);
}

function createCsvContent(findings) {
    const headers = ['severity', 'rule_id', 'rule_name', 'description', 'rationale', 'asset', 'tags'];
    const headerRow = headers.join(',');

    const rows = findings.map((finding) => {
        const csvRow = {
            severity: severityLabels[finding.severity] || severityLabels.info,
            rule_id: finding.ruleId,
            rule_name: finding.ruleName,
            description: finding.description,
            rationale: finding.rationale,
            asset: finding.asset,
            tags: finding.tags.join('; ')
        };

        return headers.map((key) => csvEscape(csvRow[key] ?? '')).join(',');
    });

    return [headerRow, ...rows].join('\n');
}

function csvEscape(value) {
    const text = asText(value);
    if (/[",\n]/.test(text)) {
        return '"' + text.replace(/"/g, '""') + '"';
    }
    return text;
}

function triggerDownload(content, mimeType, filename) {
    try {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = filename;
        document.body.appendChild(anchor);
        anchor.click();
        document.body.removeChild(anchor);
        URL.revokeObjectURL(url);
    } catch (error) {
        console.error('Download failed', error);
        showToast('Unable to download file. Please try again.', 'error');
    }
}

function openFindingModal(finding) {
    const modal = document.getElementById('findingModal');
    const severityElement = document.getElementById('findingModalSeverity');
    const titleElement = document.getElementById('findingModalTitle');
    const ruleElement = document.getElementById('findingModalRule');
    const descriptionElement = document.getElementById('findingModalDescription');
    const rationaleElement = document.getElementById('findingModalRationale');
    const tagsElement = document.getElementById('findingModalTags');
    const closeButton = document.getElementById('closeFindingModal');

    if (!modal || !severityElement || !titleElement || !ruleElement || !descriptionElement || !rationaleElement || !tagsElement) {
        return;
    }

    const severityKey = Object.prototype.hasOwnProperty.call(severityLabels, finding.severity)
        ? finding.severity
        : 'info';
    const severityText = severityLabels[severityKey] || severityLabels.info;

    severityElement.textContent = severityText;
    severityElement.dataset.severity = severityKey;
    titleElement.textContent = finding.ruleDisplay || 'Finding details';
    ruleElement.textContent = finding.ruleDisplay;
    descriptionElement.textContent = finding.description || 'No description provided.';
    rationaleElement.textContent = finding.rationale || 'No rationale provided.';

    if (finding.tags.length) {
        tagsElement.innerHTML = finding.tags.map(tag => `<span class="tag">${sanitize(tag)}</span>`).join('');
    } else {
        tagsElement.textContent = 'No tags available';
    }

    modal.classList.add('visible');
    modal.setAttribute('aria-hidden', 'false');
    document.body.classList.add('modal-open');

    if (closeButton) {
        closeButton.focus();
    }
}

function closeFindingModal() {
    const modal = document.getElementById('findingModal');
    if (!modal || !modal.classList.contains('visible')) return;
    modal.classList.remove('visible');
    modal.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('modal-open');

    if (lastFocusedDetailsTrigger && typeof lastFocusedDetailsTrigger.focus === 'function') {
        lastFocusedDetailsTrigger.focus();
    }
}

if (document.readyState !== 'loading') {
    initializeFindingsUI();
} else {
    document.addEventListener('DOMContentLoaded', initializeFindingsUI);
}

window.updateFindingsUI = updateFindingsUI;
window.initializeFindingsUI = initializeFindingsUI;
window.__firefind = {
    findingsState,
    applyFiltersAndRender,
    changeSort,
    changePage
};

function animateMetrics() {
    const metrics = document.querySelectorAll('.metric-value');
    metrics.forEach(metric => {
        const finalValue = metric.textContent;
        const isPercentage = finalValue.includes('%');
        const numericValue = parseInt(finalValue);
        let currentValue = 0;

        metric.textContent = '0' + (isPercentage ? '%' : '');

        const increment = numericValue / 30;
        const timer = setInterval(() => {
            currentValue += increment;
            if (currentValue >= numericValue) {
                currentValue = numericValue;
                clearInterval(timer);
            }
            metric.textContent = Math.floor(currentValue) + (isPercentage ? '%' : '');
        }, 50);
    });
}

function showToast(message, type = 'info') {
    const existing = document.querySelector('.toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = sanitize(message);

    document.body.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('show');
    }, 10);

    const duration = type === 'error' ? 5000 : 3000;
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => {
            if (toast.parentElement) {
                toast.remove();
            }
        }, 300);
    }, duration);
}

function createParticle() {
    const particle = document.createElement('div');
    particle.style.cssText = `
        position: fixed;
        width: 3px;
        height: 3px;
        background: var(--primary-green);
        pointer-events: none;
        border-radius: 50%;
        opacity: 0.6;
        z-index: 1;
    `;
    particle.style.left = Math.random() * window.innerWidth + 'px';
    particle.style.top = window.innerHeight + 'px';
    document.body.appendChild(particle);
    
    const duration = 3000 + Math.random() * 4000;
    const animation = particle.animate([
        { transform: 'translateY(0) scale(0)', opacity: 0 },
        { transform: 'translateY(-30vh) scale(1)', opacity: 0.6 },
        { transform: 'translateY(-70vh) scale(1)', opacity: 0.6 },
        { transform: 'translateY(-100vh) scale(0)', opacity: 0 }
    ], {
        duration: duration,
        easing: 'linear'
    });
    
    animation.onfinish = () => particle.remove();
}

setInterval(createParticle, 300);

window.addEventListener('load', () => {
    loadStoredFiles();

    const isDevelopment =
        typeof process !== 'undefined' && process.env.NODE_ENV === 'development';

    if (isDevelopment) {
        console.log('%cFireFind v1.0.0', 'color: #4ECCA3; font-size: 24px; font-weight: bold;');
        console.log('%cDeveloped by Triskele Labs | By team Five guys', 'color: #a0a0a0; font-size: 12px;');
        console.log('%cOpen-Source Firewall Security Scanner', 'color: #00ff88; font-size: 14px;');
    }
});

function handleAboutClick(event) {
    const currentPage = window.location.pathname;
    const isIndexPage = currentPage === '/' ||
                       currentPage.endsWith('/index.html') ||
                       currentPage === '/index.html' ||
                       currentPage === '';

    if (isIndexPage) {
        event.preventDefault();
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
        if (typeof setActiveNavigation === 'function') {
            setActiveNavigation();
        }
    }
}

function initializeRouting() {
    function navigateTo(path, actualFile) {
        history.pushState({ file: actualFile }, '', path);

        setActiveNavigation();

        const currentFile = window.location.pathname.split('/').pop();
        if (actualFile && actualFile !== currentFile && !window.location.pathname.includes(actualFile)) {
            window.location.href = actualFile;
        }
    }

    function setActiveNavigation() {
        const navLinks = document.querySelectorAll('.nav-links a');
        const currentPath = window.location.pathname;
        const currentFile = currentPath.split('/').pop() || 'index.html';

        navLinks.forEach(link => link.classList.remove('active'));

        navLinks.forEach(link => {
            const href = link.getAttribute('href');
            let isActive = false;

            switch(href) {
                case 'index.html':
                    isActive = currentFile === 'index.html' || currentFile === '' || currentPath === '/about' || currentPath === '/';
                    break;
                case 'scan.html':
                    isActive = currentFile === 'scan.html' || currentPath === '/scan';
                    break;
                case 'reports.html':
                    isActive = currentFile === 'reports.html' || currentPath === '/reports';
                    break;
                case 'admin.html':
                    isActive = currentFile === 'admin.html' || currentPath === '/admin';
                    break;
            }

            if (isActive) {
                link.classList.add('active');
            }
        });
    }

    function updateNavLinks() {
        const navLinks = document.querySelectorAll('.nav-links a');
        navLinks.forEach(link => {
            const href = link.getAttribute('href');
            let cleanPath = '';

            switch(href) {
                case 'index.html':
                    cleanPath = '/about';
                    break;
                case 'scan.html':
                    cleanPath = '/scan';
                    break;
                case 'reports.html':
                    cleanPath = '/reports';
                    break;
                case 'admin.html':
                    cleanPath = '/admin';
                    break;
                default:
                    cleanPath = href;
            }

            if (href !== 'index.html') {
                link.removeAttribute('onclick');
                link.addEventListener('click', function(e) {
                    e.preventDefault();
                    navigateTo(cleanPath, href);
                });
            }
        });

        setActiveNavigation();
    }

    function cleanCurrentUrl() {
        const currentFile = window.location.pathname.split('/').pop();
        let cleanPath = window.location.pathname;

        switch(currentFile) {
            case 'index.html':
                cleanPath = '/about';
                break;
            case 'scan.html':
                cleanPath = '/scan';
                break;
            case 'reports.html':
                cleanPath = '/reports';
                break;
            case 'admin.html':
                cleanPath = '/admin';
                break;
        }

        if (cleanPath !== window.location.pathname) {
            history.replaceState({ file: currentFile }, document.title, cleanPath);
        }
    }

    window.addEventListener('popstate', function(e) {
        if (e.state && e.state.file) {
            window.location.href = e.state.file;
        }
    });

    document.addEventListener('DOMContentLoaded', function() {
        cleanCurrentUrl();
        updateNavLinks();
        setActiveNavigation();
    });
}

initializeRouting();
