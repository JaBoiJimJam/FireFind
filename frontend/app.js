        // Smooth scroll function
        function smoothScroll(targetId) {
            event.preventDefault();
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
        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('fileInput');
        
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

        fileInput.addEventListener('change', (e) => {
            handleFiles(e.target.files);
        });

        function handleFiles(files) {
            for (let file of files) {
                if (!uploadedFiles.find(f => f.name === file.name)) {
                    uploadedFiles.push({
                        id: Date.now() + Math.random(),
                        name: file.name,
                        size: formatFileSize(file.size),
                        file: file
                    });
                }
            }
            displayFiles();
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
                                <div class="file-name">${file.name}</div>
                                <div class="file-size">${file.size}</div>
                            </div>
                            <button class="remove-btn" onclick="removeFile('${file.id}')">Remove</button>
                        </div>
                    </div>
                `).join('');
                
                // Smooth scroll to files section
                filesSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
            } else {
                filesSection.classList.remove('active');
            }
        }

        function removeFile(fileId) {
            uploadedFiles = uploadedFiles.filter(f => f.id !== fileId);
            displayFiles();
            showToast('File removed');
        }

        function startDemo() {
            uploadedFiles = [
                { id: 'demo1', name: 'fortinet_config_2025.csv', size: '245 KB', file: new File(['demo'], 'fortinet_config_2025.csv', { type: 'text/csv' }) },
                { id: 'demo2', name: 'sophos_rules_export.xlsx', size: '1.2 MB', file: new File(['demo'], 'sophos_rules_export.xlsx', { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }) },
                { id: 'demo3', name: 'checkpoint_firewall.csv', size: '567 KB', file: new File(['demo'], 'checkpoint_firewall.csv', { type: 'text/csv' }) }
            ];
            displayFiles();
            showToast('Demo files loaded successfully!');
        }

        async function startScan(e) {
            if (uploadedFiles.length === 0) {
                showToast('Please upload files first');
                return;
            }

            const btn = e.target;
            btn.disabled = true;
            const originalText = btn.textContent;
            btn.textContent = 'SCANNING...';
            showToast('Scanning firewall configurations...');

            const formData = new FormData();
            uploadedFiles.forEach(f => {
                if (f.file) formData.append('files', f.file);
            });

            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    body: formData
                });
                if (!response.ok) throw new Error('Scan failed');
                const data = await response.json();

                document.getElementById('criticalCount').textContent = data.metrics?.critical ?? 0;
                document.getElementById('highCount').textContent = data.metrics?.high ?? 0;
                document.getElementById('totalCount').textContent = data.metrics?.total ?? 0;
                document.getElementById('score').textContent = data.metrics?.score ? data.metrics.score + '%' : '0%';

                const pdfLink = document.getElementById('pdfLink');
                const csvLink = document.getElementById('csvLink');
                if (data.pdf) {
                    pdfLink.href = data.pdf;
                    pdfLink.style.pointerEvents = 'auto';
                    pdfLink.style.opacity = '1';
                }
                if (data.csv) {
                    csvLink.href = data.csv;
                    csvLink.style.pointerEvents = 'auto';
                    csvLink.style.opacity = '1';
                }

                const resultsSection = document.getElementById('results');
                resultsSection.classList.add('active');
                resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
                animateMetrics();
                showToast('Scan complete!');
            } catch (err) {
                showToast('Scan failed: ' + err.message);
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

        function showToast(message) {
            const existing = document.querySelector('.toast');
            if (existing) existing.remove();
            
            const toast = document.createElement('div');
            toast.className = 'toast';
            toast.textContent = message;
            document.body.appendChild(toast);
            
            setTimeout(() => {
                toast.style.animation = 'slideInRight 0.3s ease reverse';
                setTimeout(() => toast.remove(), 300);
            }, 3000);
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

        // Initialize
        window.addEventListener('load', () => {
            console.log('%cFireFind v1.0.0', 'color: #4ECCA3; font-size: 24px; font-weight: bold;');
            console.log('%cDeveloped by Triskele Labs', 'color: #a0a0a0; font-size: 12px;');
            console.log('%cOpen-Source Firewall Security Scanner', 'color: #00ff88; font-size: 14px;');
        });
