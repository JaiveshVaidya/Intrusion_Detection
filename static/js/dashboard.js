// Global application state
let trafficChartInstance = null;
let attackChartInstance = null;
let lastAttackId = null;
let isPollingActive = true;

document.addEventListener('DOMContentLoaded', () => {
    // Initialize Dashboard Component Charts
    initCharts();
    
    // Perform initial fetch and start polling loop
    fetchStats();
    setInterval(fetchStats, 2000);

    // Register button event handlers
    setupEventHandlers();
});

// ----- Chart Configuration & Initialization -----
function initCharts() {
    // 1. Traffic Trend Line Chart
    const ctxTrend = document.getElementById('trafficTrendChart').getContext('2d');
    trafficChartInstance = new Chart(ctxTrend, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Legitimate Requests',
                    borderColor: '#06b6d4',
                    backgroundColor: 'rgba(6, 182, 212, 0.05)',
                    fill: true,
                    data: [],
                    tension: 0.35,
                    borderWidth: 2
                },
                {
                    label: 'Attacks / Blocked',
                    borderColor: '#f43f5e',
                    backgroundColor: 'rgba(244, 63, 94, 0.05)',
                    fill: true,
                    data: [],
                    tension: 0.35,
                    borderWidth: 2
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: '#f3f4f6', font: { family: 'Outfit' } }
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.03)' },
                    ticks: { color: '#9ca3af', font: { family: 'Outfit' } }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255, 255, 255, 0.03)' },
                    ticks: { 
                        color: '#9ca3af', 
                        font: { family: 'Outfit' },
                        precision: 0 
                    }
                }
            }
        }
    });

    // 2. Attack Distribution Doughnut Chart
    const ctxPie = document.getElementById('attackPieChart').getContext('2d');
    attackChartInstance = new Chart(ctxPie, {
        type: 'doughnut',
        data: {
            labels: ['SQL Injection', 'XSS Attack', 'Path Traversal', 'Command Injection', 'Brute-force'],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                backgroundColor: [
                    '#f43f5e', // Rose
                    '#9333ea', // Purple
                    '#eab308', // Amber
                    '#06b6d4', // Cyan
                    '#6b7280'  // Gray (Brute-force)
                ],
                borderWidth: 1,
                borderColor: 'rgba(255, 255, 255, 0.05)'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#f3f4f6', font: { family: 'Outfit', size: 11 } }
                }
            },
            cutout: '65%'
        }
    });
}

// ----- AJAX Data Pull Loop -----
function fetchStats() {
    if (!isPollingActive) return;

    fetch('/api/dashboard/stats')
        .then(response => response.json())
        .then(data => {
            updateMetrics(data);
            updateSimulatorUI(data.simulator_active);
            updateTelemetry(data.system_stats);
            updateCharts(data);
            updateIncidentTable(data.recent_attacks);
            updateBlocklistTable(data.blocked_ips);
            
            // Check for new attacks to launch alerts
            if (data.recent_attacks.length > 0) {
                const newestAttack = data.recent_attacks[0];
                if (lastAttackId !== null && newestAttack.id > lastAttackId) {
                    showToastAlert(newestAttack);
                }
                lastAttackId = newestAttack.id;
            } else {
                lastAttackId = 0;
            }
        })
        .catch(err => console.error("Error loading dashboard metrics: ", err));
}

// ----- Update UI Elements -----
function updateMetrics(data) {
    document.getElementById('metric-attacks').innerText = data.total_attacks.toLocaleString();
    document.getElementById('metric-requests').innerText = data.total_requests.toLocaleString();
    document.getElementById('metric-blocked-ips').innerText = data.total_blocked.toLocaleString();
    
    const threatEl = document.getElementById('metric-threat-level');
    threatEl.innerText = data.threat_level;
    
    // Style threat level dynamically
    threatEl.className = 'value'; // Reset
    if (data.threat_level === 'Low') {
        threatEl.classList.add('purple-text');
    } else if (data.threat_level === 'Medium') {
        threatEl.classList.add('amber-text');
    } else if (data.threat_level === 'High') {
        threatEl.style.color = '#f97316'; // Orange accent
    } else {
        threatEl.classList.add('rose-text');
        threatEl.style.animation = 'flash 1s infinite';
    }
}

function updateSimulatorUI(isActive) {
    const badge = document.getElementById('sim-badge');
    const badgeText = badge.querySelector('.badge-text');
    const startBtn = document.getElementById('btn-start-sim');
    const stopBtn = document.getElementById('btn-stop-sim');

    if (isActive) {
        badge.className = 'simulation-badge active';
        badgeText.innerText = 'Simulator Active';
        startBtn.disabled = true;
        stopBtn.disabled = false;
    } else {
        badge.className = 'simulation-badge';
        badgeText.innerText = 'Simulator Idle';
        startBtn.disabled = false;
        stopBtn.disabled = true;
    }
}

function updateTelemetry(stats) {
    document.getElementById('cpu-value').innerText = `${stats.cpu}%`;
    document.getElementById('cpu-bar').style.width = `${stats.cpu}%`;
    document.getElementById('ram-value').innerText = `${stats.ram}%`;
    document.getElementById('ram-bar').style.width = `${stats.ram}%`;
}

function updateCharts(data) {
    // 1. Update Traffic Trend Chart
    const trend = data.traffic_trend;
    const labels = trend.map(t => t.label);
    const normals = trend.map(t => t.normal);
    const attacks = trend.map(t => t.attack);

    trafficChartInstance.data.labels = labels;
    trafficChartInstance.data.datasets[0].data = normals;
    trafficChartInstance.data.datasets[1].data = attacks;
    trafficChartInstance.update('none'); // Update without full redraw animation for smoothness

    // 2. Update Attack Pie Chart
    const types = data.attack_types;
    attackChartInstance.data.datasets[0].data = [
        types["SQL Injection"] || 0,
        types["XSS Attack"] || 0,
        types["Path Traversal"] || 0,
        types["Command Injection"] || 0,
        types["Brute-force"] || 0
    ];
    attackChartInstance.update();
}

function getAttackBadgeClass(type) {
    switch (type) {
        case 'SQL Injection': return 'tag-sqli';
        case 'XSS Attack': return 'tag-xss';
        case 'Path Traversal': return 'tag-path';
        case 'Command Injection': return 'tag-cmd';
        default: return 'tag-brute';
    }
}

function updateIncidentTable(attacks) {
    const tbody = document.querySelector('#attacks-table tbody');
    if (attacks.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="loading-placeholder">No security incidents detected.</td></tr>';
        return;
    }

    let html = '';
    attacks.forEach(att => {
        const badgeClass = getAttackBadgeClass(att.type);
        const escapedPayload = escapeHtml(att.payload);
        html += `
            <tr>
                <td>${att.time}</td>
                <td><strong style="color:#06b6d4;">${att.ip}</strong></td>
                <td><span class="tag ${badgeClass}">${att.type}</span></td>
                <td class="payload-cell" title="${escapedPayload}">${escapedPayload}</td>
                <td>
                    <button class="btn btn-outline" style="padding:4px 10px; font-size:11px;" onclick="blacklistIP('${att.ip}')">
                        <i class="fa-solid fa-ban"></i> Block
                    </button>
                </td>
            </tr>
        `;
    });
    tbody.innerHTML = html;
}

function updateBlocklistTable(blockedIps) {
    const tbody = document.querySelector('#blocked-ips-table tbody');
    if (blockedIps.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" class="loading-placeholder">No IP bans active.</td></tr>';
        return;
    }

    let html = '';
    blockedIps.forEach(item => {
        html += `
            <tr>
                <td><strong style="color:#f43f5e;">${item.ip}</strong></td>
                <td>${item.blocked_at}</td>
                <td>
                    <button class="btn btn-warning" style="padding:4px 10px; font-size:11px;" onclick="unblacklistIP('${item.ip}')">
                        <i class="fa-solid fa-unlock"></i> Unblock
                    </button>
                </td>
            </tr>
        `;
    });
    tbody.innerHTML = html;
}

// ----- Event Handlers & API Triggers -----
function setupEventHandlers() {
    // Simulator Control: Start
    document.getElementById('btn-start-sim').addEventListener('click', () => {
        fetch('/api/dashboard/simulate/start', { method: 'POST' })
            .then(res => res.json())
            .then(data => {
                if (data.status === 'success') fetchStats();
            });
    });

    // Simulator Control: Stop
    document.getElementById('btn-stop-sim').addEventListener('click', () => {
        fetch('/api/dashboard/simulate/stop', { method: 'POST' })
            .then(res => res.json())
            .then(data => {
                if (data.status === 'success') fetchStats();
            });
    });

    // Send single manual test payloads
    const attackBtns = document.querySelectorAll('.attack-shortcuts .btn');
    attackBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
            const attackType = btn.getAttribute('data-attack');
            btn.disabled = true;
            
            fetch('/api/dashboard/test-attack', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ type: attackType })
            })
            .then(res => res.json())
            .then(data => {
                setTimeout(() => { btn.disabled = false; }, 800);
            })
            .catch(() => { btn.disabled = false; });
        });
    });

    // Manual blacklist form submission
    document.getElementById('manual-block-form').addEventListener('submit', (e) => {
        e.preventDefault();
        const ipInput = document.getElementById('manual-ip-input');
        const ipVal = ipInput.value.trim();
        if (!ipVal) return;

        blacklistIP(ipVal);
        ipInput.value = '';
    });

    // System Maintenance: Clear all DB records
    document.getElementById('btn-clear-logs').addEventListener('click', () => {
        if (confirm("Are you sure you want to purge all security database records and reset the requests/attacks logs? This cannot be undone.")) {
            fetch('/api/dashboard/clear-logs', { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    if (data.status === 'success') {
                        // Soft clean arrays
                        lastAttackId = 0;
                        fetchStats();
                        showToastAlert({
                            type: 'System Notification',
                            ip: 'SYSTEM',
                            payload: 'Databases and local logs flushed successfully.'
                        });
                    }
                });
        }
    });
}

function blacklistIP(ip) {
    fetch('/api/dashboard/block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
    })
    .then(res => res.json())
    .then(data => {
        fetchStats();
        if (data.status === 'error') {
            alert(data.message);
        }
    });
}

function unblacklistIP(ip) {
    fetch('/api/dashboard/unblock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
    })
    .then(res => res.json())
    .then(data => {
        fetchStats();
        if (data.status === 'error') {
            alert(data.message);
        }
    });
}

// ----- UI Notification Components -----
function showToastAlert(attack) {
    const container = document.getElementById('toast-container');
    
    // Create element
    const toast = document.createElement('div');
    toast.className = 'toast';
    
    toast.innerHTML = `
        <div class="toast-icon">
            <i class="fa-solid fa-triangle-exclamation"></i>
        </div>
        <div class="toast-content">
            <div class="toast-title">${attack.type} Blocked</div>
            <div class="toast-desc">
                Source IP: <strong>${attack.ip}</strong><br>
                Payload: <code>${escapeHtml(attack.payload.slice(0, 80))}</code>
            </div>
        </div>
    `;
    
    container.appendChild(toast);
    
    // Try to trigger a notification beep
    try {
        const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioCtx.createOscillator();
        const gainNode = audioCtx.createGain();
        oscillator.type = 'sine';
        oscillator.frequency.setValueAtTime(350, audioCtx.currentTime); // Low warning sound
        gainNode.gain.setValueAtTime(0.08, audioCtx.currentTime);
        oscillator.connect(gainNode);
        gainNode.connect(audioCtx.destination);
        oscillator.start();
        oscillator.stop(audioCtx.currentTime + 0.15);
    } catch(e) {
        // Safe catch for modern browser autoplay blocks
    }

    // Auto-remove toast after 4 seconds
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(-10px)';
        setTimeout(() => {
            toast.remove();
        }, 300);
    }, 4000);
}

// Helper to escape HTML tags to display raw scripts safely in dashboard
function escapeHtml(text) {
    if (!text) return '';
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
