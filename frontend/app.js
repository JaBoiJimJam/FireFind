// Global sanitize function
function sanitize(str) {
    if (typeof DOMPurify !== 'undefined' && DOMPurify.sanitize) {
        return DOMPurify.sanitize(str);
    }
    // Basic HTML escaping as fallback
    return String(str).replace(/[&<>"']/g, (s) => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[s]);
}

// Smooth scroll function
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

// Header scroll effect
window.addEventListener('scroll', () => {
    const header = document.getElementById('header');
    if (window.scrollY > 50) {
        header.classList.add('scrolled');
    } else {
        header.classList.remove('scrolled');
    }
});

// File handling
let uploadedFiles = [];

// Only set up these elements if they exist on the page
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');

// Only add event listeners if elements exist
if (dropZone) {
    // Drag and drop
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
        // Clear the input so the same file can be selected again if needed
        e.target.value = '';
    });
}

// Load files from localStorage on page load
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

// Save files to localStorage
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

// Convert file to base64 for storage
function fileToBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.readAsDataURL(file);
        reader.onload = () => resolve(reader.result.split(',')[1]);
        reader.onerror = error => reject(error);
    });
}

// Clear stored files
function clearStoredFiles() {
    localStorage.removeItem('firefind_uploaded_files');
    uploadedFiles = [];
    displayFiles();
    showToast('All files cleared');
}

// File type validation
const ALLOWED_FILE_TYPES = {
    'text/csv': ['.csv'],
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
    'application/vnd.ms-excel': ['.xls'],
    'text/plain': ['.txt'] // In case CSV files are detected as plain text
};

const ALLOWED_EXTENSIONS = ['.csv', '.xlsx', '.xls'];

function validateFileType(file) {
    const fileName = file.name.toLowerCase();
    const fileExtension = fileName.substring(fileName.lastIndexOf('.'));
    
    // Check file extension
    if (!ALLOWED_EXTENSIONS.includes(fileExtension)) {
        return {
            valid: false,
            error: `Invalid file type "${fileExtension}". Only CSV (.csv) and Excel (.xlsx, .xls) files are allowed.`
        };
    }
    
    // Check MIME type (additional validation)
    const mimeType = file.type;
    if (mimeType && !Object.keys(ALLOWED_FILE_TYPES).includes(mimeType)) {
        // Some browsers might not detect CSV MIME type correctly, so we allow empty MIME type for CSV files
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
    const maxSize = 50 * 1024 * 1024; // 50MB limit
    if (file.size > maxSize) {
        return {
            valid: false,
            error: `File "${file.name}" is too large. Maximum file size is 50MB.`
        };
    }
    return { valid: true };
}

// File ID creation
function createFileId() {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
        return crypto.randomUUID();
    }
    return String(Date.now() + Math.random());
}

// File handling
function handleFiles(files) {
    let validFiles = [];
    let errors = [];
    
    for (let file of files) {
        // Check if file already exists
        if (uploadedFiles.find(f => f.name === file.name)) {
            errors.push(`File "${file.name}" is already uploaded.`);
            continue;
        }
        
        // Validate file type
        const typeValidation = validateFileType(file);
        if (!typeValidation.valid) {
            errors.push(typeValidation.error);
            continue;
        }
        
        // Validate file size
        const sizeValidation = validateFileSize(file);
        if (!sizeValidation.valid) {
            errors.push(sizeValidation.error);
            continue;
        }
        
        validFiles.push(file);
    }
    
    // Add valid files
    validFiles.forEach(file => {
        uploadedFiles.push({
            id: createFileId(),
            name: file.name,
            size: formatFileSize(file.size),
            file: file
        });
    });
    
    // Show errors if any
    if (errors.length > 0) {
        errors.forEach(error => showToast(error, 'error'));
    }
    
    // Show success message for valid files
    if (validFiles.length > 0) {
        const message = validFiles.length === 1 
            ? `File "${validFiles[0].name}" uploaded successfully!`
            : `${validFiles.length} files uploaded successfully!`;
        showToast(message, 'success');
    }
    
    if (validFiles.length > 0) {
        displayFiles();
        saveFilesToStorage(); // Save to localStorage after adding files
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
        
        // Add a clear all button
        filesGrid.innerHTML += `
            <div class="file-card" style="text-align: center; border: 2px dashed var(--border-color);">
                <button class="btn btn-secondary" onclick="clearStoredFiles()" style="margin: 1rem;">
                    Clear All Files
                </button>
            </div>
        `;
        
        // Smooth scroll to files section only if there are new files
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
    saveFilesToStorage(); // Update localStorage after removing file
    showToast('File removed successfully', 'success');
}

// Add this helper function to generate date-formatted filename
function generateDateFilename(baseFilename, extension) {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const seconds = String(now.getSeconds()).padStart(2, '0');
    
    return `${baseFilename}_${year}-${month}-${day}_${hours}-${minutes}-${seconds}.${extension}`;
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
        showToast('Scanning firewall configurations...', 'info');    const formData = new FormData();
    uploadedFiles.forEach(f => {
        if (f.file) formData.append('files', f.file);
    });

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
        
        if (data.pdf) {
            pdfLink.href = data.pdf;
            // Generate date-formatted filename for PDF
            const pdfFileName = generateDateFilename('firefind_report', 'pdf');
            pdfLink.setAttribute('download', pdfFileName);
            pdfLink.style.pointerEvents = 'auto';
            pdfLink.style.opacity = '1';
        } else {
            pdfLink.removeAttribute('href');
            pdfLink.removeAttribute('download');
            pdfLink.style.pointerEvents = 'none';
            pdfLink.style.opacity = '0.5';
        }
        
        if (data.csv) {
            csvLink.href = data.csv;
            // Generate date-formatted filename for CSV
            const csvFileName = generateDateFilename('firefind_report', 'csv');
            csvLink.setAttribute('download', csvFileName);
            csvLink.style.pointerEvents = 'auto';
            csvLink.style.opacity = '1';
        } else {
            csvLink.removeAttribute('href');
            csvLink.removeAttribute('download');
            csvLink.style.pointerEvents = 'none';
            csvLink.style.opacity = '0.5';
        }

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
    // Remove any existing toasts
    const existing = document.querySelector('.toast');
    if (existing) existing.remove();
    
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = sanitize(message);
    
    document.body.appendChild(toast);
    
    // Trigger animation
    setTimeout(() => {
        toast.classList.add('show');
    }, 10);
    
    // Auto-remove after appropriate duration (longer for errors)
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

// Add floating particles effect
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

// Create particles periodically
setInterval(createParticle, 300);

// Initialize - Load stored files on page load
window.addEventListener('load', () => {
    loadStoredFiles(); // Load files from localStorage
    
    const isDevelopment =
        typeof process !== 'undefined' && process.env.NODE_ENV === 'development';

    if (isDevelopment) {
        console.log('%cFireFind v1.0.0', 'color: #4ECCA3; font-size: 24px; font-weight: bold;');
        console.log('%cDeveloped by Triskele Labs', 'color: #a0a0a0; font-size: 12px;');
        console.log('%cOpen-Source Firewall Security Scanner', 'color: #00ff88; font-size: 14px;');
    }
});

function handleAboutClick(event) {
    // Check if we're already on the index page
    const currentPage = window.location.pathname;
    const isIndexPage = currentPage === '/' || 
                       currentPage.endsWith('/index.html') || 
                       currentPage === '/index.html' ||
                       currentPage === '';
    
    if (isIndexPage) {
        // If on index page, prevent default link behavior and scroll to top
        event.preventDefault();
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
        // Update active navigation state
        if (typeof setActiveNavigation === 'function') {
            setActiveNavigation();
        }
    }
    // If not on index page, let the default link behavior work (go to index.html)
    // The active state will be set automatically when the new page loads
}

// URL Management - Add this to your app.js file
function initializeRouting() {
    // Define route mappings
    const routes = {
        '/': 'index.html',
        '/about': 'index.html',
        '/scan': 'scan.html',
        '/reports': 'reports.html',
        '/admin': 'admin.html'
    };

    // Handle navigation
    function navigateTo(path, actualFile) {
        // Update URL without page reload
        history.pushState({ file: actualFile }, '', path);
        
        // Update active navigation state
        setActiveNavigation();
        
        // Load the actual file if it's different from current
        const currentFile = window.location.pathname.split('/').pop();
        if (actualFile && actualFile !== currentFile && !window.location.pathname.includes(actualFile)) {
            window.location.href = actualFile;
        }
    }

    // Set active navigation state
    function setActiveNavigation() {
        const navLinks = document.querySelectorAll('.nav-links a');
        const currentPath = window.location.pathname;
        const currentFile = currentPath.split('/').pop() || 'index.html';
        
        // Remove active class from all links
        navLinks.forEach(link => link.classList.remove('active'));
        
        // Add active class to current page link
        navLinks.forEach(link => {
            const href = link.getAttribute('href');
            let isActive = false;
            
            // Check if this link corresponds to the current page
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

    // Update all navigation links
    function updateNavLinks() {
        const navLinks = document.querySelectorAll('.nav-links a');
        navLinks.forEach(link => {
            const href = link.getAttribute('href');
            let cleanPath = '';
            
            // Map file names to clean paths
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
            
            // Only modify non-About links, let handleAboutClick handle the About link
            if (href !== 'index.html') {
                // Remove existing click handlers and add new ones for non-About links
                link.removeAttribute('onclick');
                link.addEventListener('click', function(e) {
                    e.preventDefault();
                    navigateTo(cleanPath, href);
                });
            }
            // For index.html (About), keep the existing onclick="handleAboutClick(event)" behavior
        });
        
        // Set active navigation state after updating links
        setActiveNavigation();
    }

    // Clean current URL on page load
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
        
        // Update URL without reload if it needs cleaning
        if (cleanPath !== window.location.pathname) {
            history.replaceState({ file: currentFile }, document.title, cleanPath);
        }
    }

    // Handle browser back/forward buttons
    window.addEventListener('popstate', function(e) {
        if (e.state && e.state.file) {
            window.location.href = e.state.file;
        }
    });

    // Initialize on page load
    document.addEventListener('DOMContentLoaded', function() {
        cleanCurrentUrl();
        updateNavLinks();
        setActiveNavigation();
    });
}

// Initialize routing
initializeRouting();
