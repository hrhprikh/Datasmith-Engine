// ==========================================
// DATASMITH PRO - Professional Client Logic
// Clean & Efficient
// ==========================================

let selectedFile = null;
let currentAnalysisData = null;

// Chart instances
let attackChart = null;
let ipChart = null;
let methodsChart = null;
let logTypesChart = null;

// Chart.js default configuration
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.color = '#525252';
Chart.defaults.plugins.legend.labels.usePointStyle = true;
Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(0, 0, 0, 0.8)';
Chart.defaults.plugins.tooltip.padding = 12;
Chart.defaults.plugins.tooltip.cornerRadius = 8;

// =================== INITIALIZATION ===================
document.addEventListener('DOMContentLoaded', () => {
    console.log('DataSmith Pro initialized');
    
    initClock();
    setupEventListeners();
    setupTableTabs();
    updateHistoryCount();
});

// =================== CLOCK ===================
function initClock() {
    const clockEl = document.getElementById('liveClock');
    if (!clockEl) return;
    
    function updateClock() {
        const now = new Date();
        clockEl.textContent = now.toLocaleTimeString('en-US', { 
            hour: '2-digit', 
            minute: '2-digit', 
            second: '2-digit',
            hour12: false 
        });
    }
    
    updateClock();
    setInterval(updateClock, 1000);
}

// =================== VIEW SWITCHING ===================
function showView(view) {
    const analysisView = document.getElementById('analysisView');
    const historyView = document.getElementById('historyView');
    const navAnalysis = document.getElementById('navAnalysis');
    const navHistory = document.getElementById('navHistory');
    
    if (view === 'analysis') {
        analysisView.style.display = 'block';
        historyView.style.display = 'none';
        navAnalysis.classList.add('active');
        navHistory.classList.remove('active');
    } else if (view === 'history') {
        analysisView.style.display = 'none';
        historyView.style.display = 'block';
        navAnalysis.classList.remove('active');
        navHistory.classList.add('active');
        loadHistory();
    }
}

// =================== EVENT LISTENERS ===================
function setupEventListeners() {
    const fileInput = document.getElementById('fileInput');
    const uploadBox = document.getElementById('uploadBox');
    
    // File input change
    fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) handleFileSelect(file);
    });
    
    // Drag and drop
    uploadBox.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadBox.style.borderColor = 'var(--white)';
    });
    
    uploadBox.addEventListener('dragleave', () => {
        uploadBox.style.borderColor = '';
    });
    
    uploadBox.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadBox.style.borderColor = '';
        
        const file = e.dataTransfer.files[0];
        if (file && (file.name.endsWith('.log') || file.name.endsWith('.txt'))) {
            handleFileSelect(file);
        } else {
            alert('Please upload a .log or .txt file');
        }
    });
}

// =================== FILE HANDLING ===================
function handleFileSelect(file) {
    selectedFile = file;
    
    const fileNameEl = document.getElementById('fileName');
    const analyzeSection = document.getElementById('analyzeSection');
    
    fileNameEl.textContent = file.name;
    fileNameEl.style.display = 'block';
    analyzeSection.style.display = 'block';
}

// Progress polling interval
let progressInterval = null;

// =================== ANALYSIS ===================
async function analyzeFile() {
    if (!selectedFile) {
        alert('Please select a file first');
        return;
    }
    
    const pipelineContainer = document.getElementById('pipelineContainer');
    const results = document.getElementById('results');
    const errorMessage = document.getElementById('errorMessage');
    const analyzeSection = document.getElementById('analyzeSection');
    
    // Show pipeline animation
    pipelineContainer.style.display = 'block';
    results.style.display = 'none';
    errorMessage.style.display = 'none';
    analyzeSection.style.display = 'none';
    
    // Reset pipeline
    resetPipeline();
    
    // Stage 1: File Upload (already completed)
    updatePipelineStage(1, 'completed', 'Completed');
    await sleep(300);
    
    // Stage 2: Parsing - Start
    updatePipelineStage(2, 'active', 'Processing...');
    updateConnector(1, 'active');
    updatePipelineProgress(15);
    
    try {
        const formData = new FormData();
        formData.append('file', selectedFile);
        
        // Start polling for real-time progress
        startProgressPolling();
        
        updatePipelineStage(2, 'completed', 'Completed');
        updateConnector(1, 'completed');
        updatePipelineProgress(25);
        await sleep(200);
        
        // Stage 3: Threat Detection - Active during API call
        updatePipelineStage(3, 'active', 'Scanning...');
        updateConnector(2, 'active');
        updatePipelineProgress(35);
        
        const response = await fetch('/analyze', {
            method: 'POST',
            body: formData
        });
        
        // Stop progress polling
        stopProgressPolling();
        
        if (!response.ok) {
            throw new Error('Analysis failed');
        }
        
        const data = await response.json();
        currentAnalysisData = data;
        
        // Update with final actual data
        updatePipelineStats(data.metrics.total || 0, data.metrics.threats || 0, 50);
        
        updatePipelineStage(3, 'completed', 'Completed');
        updateConnector(2, 'completed');
        updatePipelineProgress(50);
        await sleep(300);
        
        // Stage 4: Pattern Analysis
        updatePipelineStage(4, 'active', 'Analyzing...');
        updateConnector(3, 'active');
        updatePipelineProgress(65);
        updatePipelineStats(data.metrics.total, data.metrics.threats, 65);
        await sleep(400);
        
        updatePipelineStage(4, 'completed', 'Completed');
        updateConnector(3, 'completed');
        updatePipelineProgress(75);
        await sleep(200);
        
        // Stage 5: Generate Insights
        updatePipelineStage(5, 'active', 'Generating...');
        updateConnector(4, 'active');
        updatePipelineProgress(85);
        updatePipelineStats(data.metrics.total, data.metrics.threats, 85);
        await sleep(400);
        
        updatePipelineStage(5, 'completed', 'Completed');
        updateConnector(4, 'completed');
        updatePipelineProgress(92);
        await sleep(200);
        
        // Stage 6: Building Dashboard
        updatePipelineStage(6, 'active', 'Building...');
        updateConnector(5, 'active');
        updatePipelineProgress(95);
        
        // Display results
        displayResults(data);
        
        // Save to history
        saveToHistory(data);
        
        updatePipelineStage(6, 'completed', 'Completed');
        updateConnector(5, 'completed');
        updatePipelineProgress(100);
        updatePipelineStats(data.metrics.total, data.metrics.threats, 100);
        
        // Add complete animation
        pipelineContainer.classList.add('complete');
        
        await sleep(800);
        
        // Hide pipeline, show results with animation
        pipelineContainer.style.display = 'none';
        results.style.display = 'block';
        results.classList.add('reveal');
        
        // Remove reveal class after animation
        setTimeout(() => {
            results.classList.remove('reveal');
        }, 1000);
        
    } catch (error) {
        stopProgressPolling();
        pipelineContainer.style.display = 'none';
        errorMessage.style.display = 'flex';
        document.getElementById('errorText').textContent = error.message;
        analyzeSection.style.display = 'block';
    }
}

// Real-time progress polling functions
function startProgressPolling() {
    // Poll every 500ms for real-time progress updates
    progressInterval = setInterval(async () => {
        try {
            const response = await fetch('/analysis-progress');
            if (response.ok) {
                const progress = await response.json();
                // Update UI with actual lines processed
                updatePipelineStats(
                    progress.lines_processed || 0, 
                    progress.threats_found || 0, 
                    progress.progress_percent || 0
                );
            }
        } catch (e) {
            // Ignore polling errors
        }
    }, 500);
}

function stopProgressPolling() {
    if (progressInterval) {
        clearInterval(progressInterval);
        progressInterval = null;
    }
}

// Pipeline helper functions
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function resetPipeline() {
    // Reset all stages
    for (let i = 1; i <= 6; i++) {
        const stage = document.getElementById(`stage${i}`);
        if (stage) {
            stage.classList.remove('active', 'completed');
            const status = stage.querySelector('.stage-status');
            if (status) status.textContent = 'Waiting...';
        }
        
        if (i < 6) {
            const connector = document.getElementById(`connector${i}`);
            if (connector) {
                connector.classList.remove('active', 'completed');
            }
        }
    }
    
    // Reset progress bar
    const progressBar = document.getElementById('pipelineProgressBar');
    if (progressBar) progressBar.style.width = '0%';
    
    // Reset stats
    updatePipelineStats(0, 0, 0);
    
    // Remove complete class
    const container = document.getElementById('pipelineContainer');
    if (container) container.classList.remove('complete');
}

function updatePipelineStage(stageNum, state, statusText) {
    const stage = document.getElementById(`stage${stageNum}`);
    if (!stage) return;
    
    stage.classList.remove('active', 'completed');
    
    if (state === 'active') {
        stage.classList.add('active');
    } else if (state === 'completed') {
        stage.classList.add('completed');
    }
    
    const status = stage.querySelector('.stage-status');
    if (status) status.textContent = statusText;
    
    // Update indicator
    const indicator = stage.querySelector('.stage-indicator');
    if (indicator && state === 'completed') {
        indicator.classList.add('completed');
        indicator.innerHTML = '<i class="bi bi-check-lg"></i>';
    }
}

function updateConnector(connectorNum, state) {
    const connector = document.getElementById(`connector${connectorNum}`);
    if (!connector) return;
    
    connector.classList.remove('active', 'completed');
    
    if (state === 'active') {
        connector.classList.add('active');
    } else if (state === 'completed') {
        connector.classList.add('completed');
    }
}

function updatePipelineProgress(percent) {
    const progressBar = document.getElementById('pipelineProgressBar');
    if (progressBar) {
        progressBar.style.width = `${percent}%`;
    }
    
    const progressLabel = document.getElementById('pipelineProgress');
    if (progressLabel) {
        progressLabel.textContent = `${percent}%`;
    }
}

function updatePipelineStats(lines, threats, progress) {
    const linesEl = document.getElementById('pipelineLinesProcessed');
    const threatsEl = document.getElementById('pipelineThreatsFound');
    
    if (linesEl) linesEl.textContent = lines.toLocaleString();
    if (threatsEl) threatsEl.textContent = threats.toLocaleString();
}

// =================== DISPLAY RESULTS ===================
function displayResults(data) {
    // Update metrics
    document.getElementById('totalLogs').textContent = (data.metrics.total || 0).toLocaleString();
    document.getElementById('parsedLogs').textContent = (data.metrics.parsed || 0).toLocaleString();
    document.getElementById('uniqueIps').textContent = (data.metrics.unique_ips || 0).toLocaleString();
    document.getElementById('threatsDetected').textContent = (data.metrics.threats || 0).toLocaleString();
    
    // Create interactive charts
    createAttackChart(data.attack_types || {});
    createIpChart(data.top_ips || {});
    createMethodsChart(data.methods || {});
    createLogTypesChart(data.log_types || {});
    
    // Update tables
    updateAttackTypesTable(data.attack_types || {});
    updateTopIpsTable(data.top_ips || {});
    updateLogDataTable(data.log_data || []);
}

// =================== CHART.JS INTERACTIVE CHARTS ===================

// Professional color palette
const chartColors = {
    primary: ['#000000', '#1a1a1a', '#333333', '#4d4d4d', '#666666', '#808080', '#999999', '#b3b3b3'],
    accent: ['#2563eb', '#3b82f6', '#60a5fa', '#93c5fd'],
    danger: ['#ef4444', '#f87171', '#fca5a5'],
    success: ['#10b981', '#34d399', '#6ee7b7'],
    warning: ['#f59e0b', '#fbbf24', '#fcd34d'],
    gradient: ['#000000', '#1e3a5f', '#2563eb', '#3b82f6', '#60a5fa']
};

function createAttackChart(attackTypes) {
    const ctx = document.getElementById('attackChart');
    if (!ctx) return;
    
    // Destroy existing chart
    if (attackChart) {
        attackChart.destroy();
    }
    
    const labels = Object.keys(attackTypes);
    const values = Object.values(attackTypes);
    
    // Unique colors for each attack type
    const attackColorMap = {
        'Normal': '#10b981',              // Green
        'SQL Injection': '#ef4444',       // Red
        'XSS Attempt': '#f97316',         // Orange
        'LFI / Path Traversal': '#8b5cf6', // Purple
        'Remote Code Execution': '#dc2626', // Dark Red
        'Sensitive File Scan': '#0ea5e9',  // Sky Blue
        'Automated Scanner': '#6366f1',    // Indigo
        'Auth Brute Force': '#ec4899',     // Pink
        'SSH Brute Force': '#14b8a6',      // Teal
        'DDoS Attack': '#f43f5e',          // Rose
        'Directory Traversal': '#a855f7',  // Violet
        'Command Injection': '#ea580c'     // Deep Orange
    };
    
    // Fallback colors for unknown types
    const fallbackColors = ['#3b82f6', '#22c55e', '#eab308', '#06b6d4', '#d946ef', '#84cc16', '#f472b6', '#38bdf8'];
    let colorIndex = 0;
    
    const colors = labels.map(label => {
        if (attackColorMap[label]) {
            return attackColorMap[label];
        }
        return fallbackColors[colorIndex++ % fallbackColors.length];
    });
    
    attackChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: colors,
                borderColor: '#ffffff',
                borderWidth: 2,
                hoverBorderWidth: 3,
                hoverOffset: 10
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '60%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 20,
                        font: { size: 12, weight: '500' }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((context.raw / total) * 100).toFixed(1);
                            return `${context.label}: ${context.raw.toLocaleString()} (${percentage}%)`;
                        }
                    }
                }
            },
            animation: {
                animateRotate: true,
                animateScale: true,
                duration: 1000,
                easing: 'easeOutQuart'
            }
        }
    });
}

function createIpChart(topIps) {
    const ctx = document.getElementById('ipChart');
    if (!ctx) return;
    
    // Destroy existing chart
    if (ipChart) {
        ipChart.destroy();
    }
    
    const labels = Object.keys(topIps).slice(0, 10);
    const values = Object.values(topIps).slice(0, 10);
    
    ipChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Requests',
                data: values,
                backgroundColor: 'rgba(0, 0, 0, 0.8)',
                borderColor: '#000000',
                borderWidth: 1,
                borderRadius: 6,
                hoverBackgroundColor: '#2563eb'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `Requests: ${context.raw.toLocaleString()}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(0, 0, 0, 0.05)' },
                    ticks: { font: { size: 11 } }
                },
                y: {
                    grid: { display: false },
                    ticks: { 
                        font: { size: 11, family: "'JetBrains Mono', monospace" }
                    }
                }
            },
            animation: {
                duration: 1000,
                easing: 'easeOutQuart'
            }
        }
    });
}

function createMethodsChart(methods) {
    const ctx = document.getElementById('methodsChart');
    if (!ctx) return;
    
    // Destroy existing chart
    if (methodsChart) {
        methodsChart.destroy();
    }
    
    const labels = Object.keys(methods);
    const values = Object.values(methods);
    
    // Method-specific colors
    const methodColors = {
        'GET': '#10b981',
        'POST': '#2563eb',
        'PUT': '#f59e0b',
        'DELETE': '#ef4444',
        'PATCH': '#8b5cf6',
        'HEAD': '#6b7280',
        'OPTIONS': '#06b6d4'
    };
    
    const colors = labels.map(label => methodColors[label] || '#000000');
    
    methodsChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Count',
                data: values,
                backgroundColor: colors,
                borderColor: colors,
                borderWidth: 1,
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `Count: ${context.raw.toLocaleString()}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { font: { size: 12, weight: '600' } }
                },
                y: {
                    grid: { color: 'rgba(0, 0, 0, 0.05)' },
                    ticks: { font: { size: 11 } }
                }
            },
            animation: {
                duration: 1000,
                easing: 'easeOutQuart'
            }
        }
    });
}

function createLogTypesChart(logTypes) {
    const ctx = document.getElementById('logTypesChart');
    if (!ctx) return;
    
    // Destroy existing chart
    if (logTypesChart) {
        logTypesChart.destroy();
    }
    
    const labels = Object.keys(logTypes);
    const values = Object.values(logTypes);
    
    logTypesChart = new Chart(ctx, {
        type: 'polarArea',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: [
                    'rgba(0, 0, 0, 0.7)',
                    'rgba(37, 99, 235, 0.7)',
                    'rgba(16, 185, 129, 0.7)',
                    'rgba(245, 158, 11, 0.7)',
                    'rgba(239, 68, 68, 0.7)'
                ],
                borderColor: '#ffffff',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 15,
                        font: { size: 11 }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `${context.label}: ${context.raw.toLocaleString()}`;
                        }
                    }
                }
            },
            scales: {
                r: {
                    grid: { color: 'rgba(0, 0, 0, 0.05)' },
                    ticks: { display: false }
                }
            },
            animation: {
                duration: 1000,
                easing: 'easeOutQuart'
            }
        }
    });
}

// =================== TABLES ===================
function updateAttackTypesTable(attackTypes) {
    const tbody = document.getElementById('attackTypesBody');
    tbody.innerHTML = '';
    
    for (const [type, count] of Object.entries(attackTypes)) {
        const isDanger = type !== 'Normal';
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${type}</td>
            <td><span class="count-badge ${isDanger ? 'danger' : ''}">${count.toLocaleString()}</span></td>
        `;
        tbody.appendChild(row);
    }
}

function updateTopIpsTable(topIps) {
    const tbody = document.getElementById('topIpsBody');
    tbody.innerHTML = '';
    
    for (const [ip, count] of Object.entries(topIps)) {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td style="font-family: var(--font-mono);">${ip}</td>
            <td><span class="count-badge">${count.toLocaleString()}</span></td>
        `;
        tbody.appendChild(row);
    }
}

// Global variable to store all log data for filtering
let allLogData = [];

function updateLogDataTable(logData) {
    // Store all data for filtering
    allLogData = logData;
    
    // Populate filter dropdowns
    populateFilterDropdowns(logData);
    
    // Render the table
    renderLogDataTable(logData);
}

function populateFilterDropdowns(logData) {
    // Get unique classifications
    const classifications = [...new Set(logData.map(entry => entry.attack_type || 'Normal'))].sort();
    const classificationFilter = document.getElementById('classificationFilter');
    if (classificationFilter) {
        classificationFilter.innerHTML = '<option value="all">All Classifications</option>';
        classifications.forEach(cls => {
            const option = document.createElement('option');
            option.value = cls;
            option.textContent = cls;
            classificationFilter.appendChild(option);
        });
    }
    
    // Get unique methods
    const methods = [...new Set(logData.map(entry => entry.method).filter(m => m))].sort();
    const methodFilter = document.getElementById('methodFilter');
    if (methodFilter) {
        methodFilter.innerHTML = '<option value="all">All Methods</option>';
        methods.forEach(method => {
            const option = document.createElement('option');
            option.value = method;
            option.textContent = method;
            methodFilter.appendChild(option);
        });
    }
    
    // Get unique statuses
    const statuses = [...new Set(logData.map(entry => entry.status).filter(s => s))].sort();
    const statusFilter = document.getElementById('statusFilter');
    if (statusFilter) {
        statusFilter.innerHTML = '<option value="all">All Statuses</option>';
        statuses.forEach(status => {
            const option = document.createElement('option');
            option.value = status;
            option.textContent = status;
            statusFilter.appendChild(option);
        });
    }
}

function filterLogData() {
    const classificationValue = document.getElementById('classificationFilter')?.value || 'all';
    const methodValue = document.getElementById('methodFilter')?.value || 'all';
    const statusValue = document.getElementById('statusFilter')?.value || 'all';
    
    let filteredData = allLogData;
    
    // Apply classification filter
    if (classificationValue !== 'all') {
        filteredData = filteredData.filter(entry => 
            (entry.attack_type || 'Normal') === classificationValue
        );
    }
    
    // Apply method filter
    if (methodValue !== 'all') {
        filteredData = filteredData.filter(entry => entry.method === methodValue);
    }
    
    // Apply status filter
    if (statusValue !== 'all') {
        filteredData = filteredData.filter(entry => entry.status === statusValue);
    }
    
    renderLogDataTable(filteredData);
    
    // Update filtered count
    const countEl = document.getElementById('filteredCount');
    if (countEl) {
        if (filteredData.length !== allLogData.length) {
            countEl.textContent = `Showing ${Math.min(filteredData.length, 100)} of ${filteredData.length} filtered (${allLogData.length} total)`;
        } else {
            countEl.textContent = `Showing ${Math.min(allLogData.length, 100)} of ${allLogData.length} entries`;
        }
    }
}

function resetFilters() {
    const classificationFilter = document.getElementById('classificationFilter');
    const methodFilter = document.getElementById('methodFilter');
    const statusFilter = document.getElementById('statusFilter');
    
    if (classificationFilter) classificationFilter.value = 'all';
    if (methodFilter) methodFilter.value = 'all';
    if (statusFilter) statusFilter.value = 'all';
    
    renderLogDataTable(allLogData);
    
    const countEl = document.getElementById('filteredCount');
    if (countEl) {
        countEl.textContent = `Showing ${Math.min(allLogData.length, 100)} of ${allLogData.length} entries`;
    }
}

function renderLogDataTable(logData) {
    const tbody = document.getElementById('logDataBody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    
    // Limit to 100 entries
    const entries = logData.slice(0, 100);
    
    if (entries.length === 0) {
        const row = document.createElement('tr');
        row.innerHTML = `<td colspan="5" style="text-align: center; padding: 30px; color: #888;">No entries match the selected filters</td>`;
        tbody.appendChild(row);
        return;
    }
    
    for (const entry of entries) {
        const attackType = entry.attack_type || 'Normal';
        const isDanger = attackType !== 'Normal';
        const row = document.createElement('tr');
        row.innerHTML = `
            <td style="font-family: var(--font-mono);">${entry.ip || '-'}</td>
            <td>${entry.method || '-'}</td>
            <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${entry.endpoint || ''}">${entry.endpoint || '-'}</td>
            <td>${entry.status || '-'}</td>
            <td><span class="count-badge ${isDanger ? 'danger' : ''}">${attackType}</span></td>
        `;
        tbody.appendChild(row);
    }
}

// =================== TABLE TABS ===================
function setupTableTabs() {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const tab = btn.dataset.tab;
            
            // Update active states
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            
            btn.classList.add('active');
            document.getElementById(tab).classList.add('active');
        });
    });
}

// =================== EXPORTS ===================
async function exportCSV() {
    if (!currentAnalysisData) {
        alert('No data to export. Please run an analysis first.');
        return;
    }
    
    try {
        const response = await fetch('/export-csv', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                columns: ['ip', 'method', 'endpoint', 'status', 'attack_type'],
                data: currentAnalysisData.log_data || []
            })
        });
        
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `datasmith_export_${Date.now()}.csv`;
        a.click();
    } catch (error) {
        alert('Export failed: ' + error.message);
    }
}

async function exportJSON() {
    if (!currentAnalysisData) {
        alert('No data to export. Please run an analysis first.');
        return;
    }
    
    const dataStr = JSON.stringify(currentAnalysisData, null, 2);
    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `datasmith_export_${Date.now()}.json`;
    a.click();
}

async function generatePDF() {
    if (!currentAnalysisData) {
        alert('No data to export. Please run an analysis first.');
        return;
    }
    
    try {
        const response = await fetch('/generate-report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(currentAnalysisData)
        });
        
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `DataSmith_Report_${Date.now()}.pdf`;
        a.click();
    } catch (error) {
        alert('PDF generation failed: ' + error.message);
    }
}

// =================== HISTORY ===================
async function saveToHistory(data) {
    try {
        await fetch('/history', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                filename: selectedFile ? selectedFile.name : 'Unknown',
                metrics: data.metrics,
                attack_types: data.attack_types,
                top_ips: data.top_ips,
                charts: data.charts
            })
        });
        updateHistoryCount();
    } catch (error) {
        console.error('Failed to save to history:', error);
    }
}

async function updateHistoryCount() {
    try {
        const response = await fetch('/history');
        const history = await response.json();
        document.getElementById('historyCount').textContent = history.length || 0;
    } catch (error) {
        console.error('Failed to update history count:', error);
    }
}

async function loadHistory() {
    const loading = document.getElementById('historyLoading');
    const error = document.getElementById('historyError');
    const empty = document.getElementById('historyEmpty');
    const list = document.getElementById('historyList');
    
    // Show loading
    loading.style.display = 'block';
    error.style.display = 'none';
    empty.style.display = 'none';
    list.innerHTML = '';
    
    try {
        const response = await fetch('/history');
        
        if (!response.ok) {
            throw new Error('Failed to load history');
        }
        
        const history = await response.json();
        
        loading.style.display = 'none';
        
        if (history.length === 0) {
            empty.style.display = 'block';
            return;
        }
        
        // Render history cards
        history.forEach(item => {
            const card = document.createElement('div');
            card.className = 'card history-card';
            card.onclick = () => viewHistoryDetail(item.id);
            
            const metrics = item.metrics || {};
            const threatCount = metrics.threats || 0;
            
            card.innerHTML = `
                <div class="history-card-header">
                    <div>
                        <div class="history-filename">${item.filename}</div>
                        <div class="history-date">${item.date}</div>
                    </div>
                    <button class="history-delete" onclick="event.stopPropagation(); deleteHistory('${item.id}')">
                        <i class="bi bi-trash"></i>
                    </button>
                </div>
                <div class="history-metrics">
                    <div class="history-metric">
                        <div class="history-metric-value">${(metrics.total || 0).toLocaleString()}</div>
                        <div class="history-metric-label">Total</div>
                    </div>
                    <div class="history-metric">
                        <div class="history-metric-value">${(metrics.parsed || 0).toLocaleString()}</div>
                        <div class="history-metric-label">Parsed</div>
                    </div>
                    <div class="history-metric">
                        <div class="history-metric-value">${(metrics.unique_ips || 0).toLocaleString()}</div>
                        <div class="history-metric-label">IPs</div>
                    </div>
                    <div class="history-metric">
                        <div class="history-metric-value ${threatCount > 0 ? 'threat' : ''}">${threatCount.toLocaleString()}</div>
                        <div class="history-metric-label">Threats</div>
                    </div>
                </div>
            `;
            
            list.appendChild(card);
        });
        
    } catch (err) {
        loading.style.display = 'none';
        error.style.display = 'flex';
        console.error('Error loading history:', err);
    }
}

async function viewHistoryDetail(id) {
    try {
        const response = await fetch(`/history/${id}`);
        
        if (!response.ok) {
            throw new Error('Failed to load analysis');
        }
        
        const data = await response.json();
        
        // Update modal content
        document.getElementById('historyDetailTitle').innerHTML = `
            <i class="bi bi-file-text"></i> ${data.filename || 'Analysis Details'}
        `;
        
        const metrics = data.metrics || {};
        const attackTypes = data.attack_types || {};
        
        let attacksList = '';
        for (const [type, count] of Object.entries(attackTypes)) {
            const isDanger = type !== 'Normal';
            attacksList += `<tr>
                <td>${type}</td>
                <td><span class="count-badge ${isDanger ? 'danger' : ''}">${count.toLocaleString()}</span></td>
            </tr>`;
        }
        
        document.getElementById('historyDetailBody').innerHTML = `
            <div class="quick-stats" style="margin-top: 0; padding-top: 0; border-top: none;">
                <div class="quick-stat">
                    <div class="quick-stat-value">${(metrics.total || 0).toLocaleString()}</div>
                    <div class="quick-stat-label">Total Logs</div>
                </div>
                <div class="quick-stat">
                    <div class="quick-stat-value">${(metrics.unique_ips || 0).toLocaleString()}</div>
                    <div class="quick-stat-label">Unique IPs</div>
                </div>
                <div class="quick-stat">
                    <div class="quick-stat-value" style="color: var(--danger);">${(metrics.threats || 0).toLocaleString()}</div>
                    <div class="quick-stat-label">Threats</div>
                </div>
            </div>
            <h6 style="margin-top: 1.5rem; color: var(--text-secondary); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1px;">Attack Types Detected</h6>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Attack Type</th>
                        <th>Count</th>
                    </tr>
                </thead>
                <tbody>${attacksList}</tbody>
            </table>
            <p style="margin-top: 1rem; font-size: 0.85rem; color: var(--text-secondary);">
                <i class="bi bi-calendar3"></i> Analyzed on: ${data.date || 'Unknown'}
            </p>
        `;
        
        // Set up delete button
        document.getElementById('deleteHistoryBtn').onclick = () => deleteHistory(id);
        
        // Show modal
        const modal = new bootstrap.Modal(document.getElementById('historyDetailModal'));
        modal.show();
        
    } catch (error) {
        alert('Failed to load analysis: ' + error.message);
    }
}

async function deleteHistory(id) {
    if (!confirm('Are you sure you want to delete this analysis?')) {
        return;
    }
    
    try {
        const response = await fetch(`/history/${id}`, { method: 'DELETE' });
        
        if (!response.ok) {
            throw new Error('Failed to delete');
        }
        
        // Close modal if open
        const modal = bootstrap.Modal.getInstance(document.getElementById('historyDetailModal'));
        if (modal) modal.hide();
        
        // Reload history
        loadHistory();
        updateHistoryCount();
        
    } catch (error) {
        alert('Failed to delete: ' + error.message);
    }
}

// =================== ATTACK REPORT MODAL ===================
let availableAttacks = [];
let attackReportModal = null;

async function openReportModal() {
    if (!currentAnalysisData) {
        alert('No data to export. Please run an analysis first.');
        return;
    }
    
    // Initialize modal
    if (!attackReportModal) {
        attackReportModal = new bootstrap.Modal(document.getElementById('attackReportModal'));
    }
    
    // Load available attacks
    await loadAvailableAttacks();
    
    // Show modal
    attackReportModal.show();
}

async function loadAvailableAttacks() {
    try {
        const response = await fetch('/available-attacks');
        availableAttacks = await response.json();
        
        renderAttackTypesList();
    } catch (error) {
        console.error('Failed to load attacks:', error);
    }
}

function renderAttackTypesList() {
    const container = document.getElementById('attackTypesList');
    const detectedAttacks = currentAnalysisData?.attack_types || {};
    
    // Group by severity
    const severityGroups = {
        'CRITICAL': { label: 'Critical', color: '#dc2626', bgColor: '#fef2f2', icon: 'exclamation-triangle-fill' },
        'HIGH': { label: 'High', color: '#ea580c', bgColor: '#fff7ed', icon: 'exclamation-circle-fill' },
        'MEDIUM': { label: 'Medium', color: '#ca8a04', bgColor: '#fefce8', icon: 'info-circle-fill' },
        'LOW': { label: 'Low', color: '#2563eb', bgColor: '#eff6ff', icon: 'shield-check' },
        'INFO': { label: 'Info', color: '#6b7280', bgColor: '#f9fafb', icon: 'info-circle' }
    };
    
    let html = '';
    
    // Group attacks by severity
    const grouped = {};
    availableAttacks.forEach(attack => {
        const sev = attack.severity;
        if (!grouped[sev]) grouped[sev] = [];
        grouped[sev].push(attack);
    });
    
    // Render each severity group
    Object.keys(severityGroups).forEach(severity => {
        const attacks = grouped[severity] || [];
        if (attacks.length === 0) return;
        
        const group = severityGroups[severity];
        
        html += `
            <div style="margin-bottom: 0.75rem;">
                <div style="display: flex; align-items: center; gap: 6px; padding: 0.5rem 0.75rem; background: ${group.bgColor}; border-radius: 8px; margin-bottom: 0.5rem;">
                    <i class="bi bi-${group.icon}" style="color: ${group.color};"></i>
                    <span style="font-weight: 600; font-size: 0.85rem; color: ${group.color};">${group.label}</span>
                </div>
                <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 0.5rem; padding: 0 0.5rem;">
        `;
        
        attacks.forEach(attack => {
            const count = detectedAttacks[attack.name] || 0;
            const isDetected = count > 0;
            const checkboxId = `attack_${attack.name.replace(/[^a-zA-Z0-9]/g, '_')}`;
            
            html += `
                <label style="display: flex; align-items: center; gap: 8px; padding: 0.5rem 0.75rem; 
                       background: ${isDetected ? '#f0fdf4' : '#fff'}; 
                       border: 1px solid ${isDetected ? '#86efac' : '#e5e7eb'}; 
                       border-radius: 8px; cursor: pointer; transition: all 0.15s;"
                       onmouseover="this.style.borderColor='#000'" 
                       onmouseout="this.style.borderColor='${isDetected ? '#86efac' : '#e5e7eb'}'">
                    <input type="checkbox" 
                           id="${checkboxId}"
                           class="attack-checkbox" 
                           data-attack="${attack.name}" 
                           data-severity="${attack.severity}"
                           data-count="${count}"
                           ${isDetected ? 'checked' : ''}
                           onchange="updateSelectedCount()"
                           style="width: 16px; height: 16px; accent-color: ${attack.color};">
                    <div style="flex: 1; min-width: 0;">
                        <div style="font-size: 0.85rem; font-weight: 500; color: #111; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                            ${attack.name}
                        </div>
                        ${isDetected ? `<div style="font-size: 0.75rem; color: #16a34a; font-weight: 600;">${count.toLocaleString()} detected</div>` : 
                                       `<div style="font-size: 0.75rem; color: #9ca3af;">Not detected</div>`}
                    </div>
                </label>
            `;
        });
        
        html += '</div></div>';
    });
    
    container.innerHTML = html;
    updateSelectedCount();
}

function selectAttacksBySeverity(severity) {
    const checkboxes = document.querySelectorAll('.attack-checkbox');
    
    checkboxes.forEach(cb => {
        if (severity === 'all') {
            cb.checked = true;
        } else if (severity === 'none') {
            cb.checked = false;
        } else {
            if (cb.dataset.severity === severity) {
                cb.checked = true;
            }
        }
    });
    
    updateSelectedCount();
}

function updateSelectedCount() {
    const checkboxes = document.querySelectorAll('.attack-checkbox:checked');
    let totalThreats = 0;
    
    checkboxes.forEach(cb => {
        totalThreats += parseInt(cb.dataset.count) || 0;
    });
    
    document.getElementById('selectedAttackCount').textContent = checkboxes.length;
    document.getElementById('selectedThreatCount').textContent = `${totalThreats.toLocaleString()} threats`;
    
    // Enable/disable generate button
    const btn = document.getElementById('generateReportBtn');
    if (checkboxes.length === 0) {
        btn.disabled = true;
        btn.style.opacity = '0.5';
    } else {
        btn.disabled = false;
        btn.style.opacity = '1';
    }
}

async function generateAttackReport() {
    const checkboxes = document.querySelectorAll('.attack-checkbox:checked');
    const selectedAttacks = Array.from(checkboxes).map(cb => cb.dataset.attack);
    
    if (selectedAttacks.length === 0) {
        alert('Please select at least one attack type');
        return;
    }
    
    const includeCharts = document.getElementById('includeCharts').checked;
    const includeDetails = document.getElementById('includeDetails').checked;
    
    // Show loading state
    const btn = document.getElementById('generateReportBtn');
    const originalText = btn.innerHTML;
    btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Generating...';
    btn.disabled = true;
    
    try {
        const response = await fetch('/generate-attack-report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                selected_attacks: selectedAttacks,
                metrics: currentAnalysisData.metrics,
                attack_types: currentAnalysisData.attack_types,
                top_ips: currentAnalysisData.top_ips,
                log_data: currentAnalysisData.log_data || [],
                include_charts: includeCharts,
                include_details: includeDetails
            })
        });
        
        if (!response.ok) {
            throw new Error('Failed to generate report');
        }
        
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `DataSmith_Attack_Report_${Date.now()}.pdf`;
        a.click();
        
        // Close modal
        attackReportModal.hide();
        
    } catch (error) {
        alert('Report generation failed: ' + error.message);
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

// Keep the old generatePDF function as fallback
async function generatePDF() {
    openReportModal();
}
