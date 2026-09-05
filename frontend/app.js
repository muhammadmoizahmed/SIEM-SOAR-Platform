const API = 'http://localhost:8000';
let authToken = localStorage.getItem('blueshield_token');
let currentUser = null;

// ========== AUTH ==========
async function handleLogin(e) {
    e.preventDefault();
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    const errorEl = document.getElementById('login-error');

    try {
        const res = await fetch(`${API}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
        });
        const data = await res.json();
        if (!res.ok) {
            errorEl.textContent = data.detail || 'Login failed';
            errorEl.style.display = 'block';
            return;
        }
        authToken = data.access_token;
        currentUser = data.user;
        localStorage.setItem('blueshield_token', authToken);
        localStorage.setItem('blueshield_user', JSON.stringify(currentUser));
        showApp();
    } catch (err) {
        errorEl.textContent = 'Connection error. Is the backend running?';
        errorEl.style.display = 'block';
    }
}

function handleLogout() {
    authToken = null;
    currentUser = null;
    localStorage.removeItem('blueshield_token');
    localStorage.removeItem('blueshield_user');
    document.getElementById('app-container').style.display = 'none';
    document.getElementById('login-page').style.display = 'flex';
    document.body.classList.remove('logged-in');
}

function showApp() {
    document.getElementById('login-page').style.display = 'none';
    document.getElementById('app-container').style.display = 'flex';
    document.body.classList.add('logged-in');
    if (currentUser) {
        document.getElementById('user-role-badge').textContent = currentUser.role;
        document.getElementById('user-info').innerHTML = `<span class="user-name">${currentUser.username}</span> (${currentUser.role})`;
    }
    loadDashboard();
}

function authHeaders() {
    return { 'Authorization': `Bearer ${authToken}`, 'Content-Type': 'application/json' };
}

async function authFetch(url, options = {}) {
    options.headers = { ...authHeaders(), ...options.headers };
    const res = await fetch(url, options);
    if (res.status === 401) { handleLogout(); return null; }
    return res;
}

// ========== NAVIGATION ==========
function showPage(page, el) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-links li').forEach(li => li.classList.remove('active'));
    document.getElementById('page-' + page).classList.add('active');
    if (el) el.classList.add('active');

    if (page === 'dashboard') loadDashboard();
    else if (page === 'alerts') loadAlerts();
    else if (page === 'incidents') loadIncidents();
    else if (page === 'metrics') loadMetrics();
    else if (page === 'playbooks') loadPlaybooks();
    else if (page === 'threat-intel') loadThreatIntel();
    else if (page === 'audit-logs') loadAuditLogs();
}

// ========== DASHBOARD ==========
async function loadDashboard() {
    try {
        const res = await authFetch(`${API}/api/dashboard/`);
        if (!res) return;
        const data = await res.json();

        document.getElementById('stat-events').textContent = data.summary.total_events.toLocaleString();
        document.getElementById('stat-alerts').textContent = data.summary.total_alerts.toLocaleString();
        document.getElementById('stat-incidents').textContent = data.summary.total_incidents.toLocaleString();
        document.getElementById('stat-iocs').textContent = data.threat_intel.total_iocs;

        renderSeverityChart(data.alert_stats.by_severity);
        renderRulesChart(data.top_detection_rules);
        renderTopIPs(data.top_source_ips);
        renderMitreChart(data.mitre_techniques);

        const alertsRes = await authFetch(`${API}/api/alerts/?limit=10`);
        if (alertsRes) {
            const alerts = await alertsRes.json();
            renderRecentAlerts(alerts);
        }
    } catch (e) { console.error('Dashboard error:', e); }
}

function renderSeverityChart(severity) {
    const el = document.getElementById('severity-chart');
    if (!severity) return;
    const max = Math.max(...Object.values(severity), 1);
    el.innerHTML = Object.entries(severity).map(([sev, count]) =>
        `<div class="bar-row"><span class="bar-label">${sev}</span><div class="bar-container"><div class="bar-fill sev-${sev}" style="width:${(count/max)*100}%"></div></div><span class="bar-count">${count}</span></div>`
    ).join('');
}

function renderRulesChart(rules) {
    const el = document.getElementById('rules-chart');
    if (!rules || !rules.length) { el.innerHTML = '<p style="color:#6b7280">No data</p>'; return; }
    const max = Math.max(...rules.map(r => r.count), 1);
    el.innerHTML = rules.map(r =>
        `<div class="bar-row"><span class="bar-label">${r.rule || 'N/A'}</span><div class="bar-container"><div class="bar-fill rule" style="width:${(r.count/max)*100}%"></div></div><span class="bar-count">${r.count}</span></div>`
    ).join('');
}

function renderTopIPs(ips) {
    const el = document.getElementById('top-ips');
    if (!ips || !ips.length) { el.innerHTML = '<p style="color:#6b7280">No data</p>'; return; }
    const max = Math.max(...ips.map(i => i.count), 1);
    el.innerHTML = ips.slice(0, 8).map(i =>
        `<div class="bar-row"><span class="bar-label">${i.ip}</span><div class="bar-container"><div class="bar-fill ip" style="width:${(i.count/max)*100}%"></div></div><span class="bar-count">${i.count}</span></div>`
    ).join('');
}

function renderMitreChart(techniques) {
    const el = document.getElementById('mitre-chart');
    if (!techniques || !Object.keys(techniques).length) { el.innerHTML = '<p style="color:#6b7280">No data</p>'; return; }
    const entries = Object.entries(techniques);
    const max = Math.max(...entries.map(([, v]) => v.count), 1);
    el.innerHTML = entries.map(([tech, info]) =>
        `<div class="bar-row"><span class="bar-label">${tech} (${info.tactic || ''})</span><div class="bar-container"><div class="bar-fill mitre" style="width:${(info.count/max)*100}%"></div></div><span class="bar-count">${info.count}</span></div>`
    ).join('');
}

function renderRecentAlerts(alerts) {
    const tbody = document.querySelector('#recent-alerts-table tbody');
    tbody.innerHTML = alerts.slice(0, 10).map(a => `
        <tr>
            <td>${a.alert_id || a.id}</td>
            <td>${a.title}</td>
            <td><span class="sev-badge sev-${a.severity}">${a.severity}</span></td>
            <td>${a.source_ip || '-'}</td>
            <td>${a.mitre_technique || '-'}</td>
            <td><span class="risk-badge risk-${getRiskLevel(a.risk_score)}">${a.risk_score || 0}</span></td>
            <td>${formatTime(a.created_at)}</td>
        </tr>
    `).join('');
}

// ========== ALERTS ==========
async function loadAlerts() {
    const sev = document.getElementById('filter-severity').value;
    const status = document.getElementById('filter-status').value;
    const rule = document.getElementById('filter-rule').value;
    let url = `${API}/api/alerts/?limit=100`;
    if (sev) url += `&severity=${sev}`;
    if (status) url += `&status=${status}`;
    if (rule) url += `&rule_name=${rule}`;

    const res = await authFetch(url);
    if (!res) return;
    const alerts = await res.json();
    const tbody = document.querySelector('#alerts-table tbody');
    tbody.innerHTML = alerts.map(a => `
        <tr>
            <td>${a.alert_id || a.id}</td>
            <td>${a.title}</td>
            <td><span class="sev-badge sev-${a.severity}">${a.severity}</span></td>
            <td><span class="status-badge status-${a.status}">${a.status}</span></td>
            <td>${a.source_ip || '-'}</td>
            <td>${a.username || '-'}</td>
            <td>${a.rule_name || '-'}</td>
            <td>${a.mitre_technique || '-'}</td>
            <td><span class="risk-badge risk-${getRiskLevel(a.risk_score)}">${a.risk_score || 0}</span></td>
            <td>${a.event_count || 0}</td>
            <td>
                <button class="btn-sm btn-investigate" onclick="showAlertDetail(${a.id})">Investigate</button>
                <button class="btn-sm btn-respond" onclick="respondToAlert(${a.id}, '${a.rule_name}')">Respond</button>
            </td>
        </tr>
    `).join('');
}

async function showAlertDetail(id) {
    const res = await authFetch(`${API}/api/alerts/${id}`);
    if (!res) return;
    const a = await res.json();
    document.getElementById('alert-detail').innerHTML = `
        <div class="detail-section"><h4>${a.alert_id} — ${a.title}</h4></div>
        <div class="detail-section">
            <div class="detail-row"><span class="label">Severity</span><span class="sev-badge sev-${a.severity}">${a.severity}</span></div>
            <div class="detail-row"><span class="label">Status</span><span class="status-badge status-${a.status}">${a.status}</span></div>
            <div class="detail-row"><span class="label">Risk Score</span><span class="risk-badge risk-${getRiskLevel(a.risk_score)}">${a.risk_score}/100</span></div>
            <div class="detail-row"><span class="label">Source IP</span><span class="value">${a.source_ip || '-'}</span></div>
            <div class="detail-row"><span class="label">Username</span><span class="value">${a.username || '-'}</span></div>
            <div class="detail-row"><span class="label">MITRE</span><span class="value">${a.mitre_technique || '-'} (${a.mitre_tactic || '-'})</span></div>
            <div class="detail-row"><span class="label">Event Count</span><span class="value">${a.event_count}</span></div>
        </div>
        <div class="detail-section"><h4>Description</h4><p style="color:#d1d5db;font-size:0.85em">${a.description || 'No description'}</p></div>
        <div style="display:flex;gap:10px;margin-top:16px">
            <button class="btn-sm btn-investigate" onclick="updateAlertStatus(${a.id}, 'investigating')">Investigating</button>
            <button class="btn-sm btn-resolve" onclick="updateAlertStatus(${a.id}, 'resolved')">Resolve</button>
            <button class="btn-sm btn-false-pos" onclick="updateAlertStatus(${a.id}, 'false_positive')">False Positive</button>
            <button class="btn-sm btn-respond" onclick="respondToAlert(${a.id}, '${a.rule_name}')">Run Playbook</button>
        </div>
    `;
    document.getElementById('alert-modal').classList.remove('hidden');
}

async function updateAlertStatus(id, status) {
    await authFetch(`${API}/api/alerts/${id}/status?status=${status}`, { method: 'PUT' });
    closeModal('alert-modal');
    loadAlerts();
}

async function respondToAlert(id, ruleName) {
    const playbookMap = { 'brute_force': 'brute_force', 'suspicious_authentication': 'suspicious_ip', 'password_spray': 'brute_force', 'impossible_login': 'suspicious_ip', 'suspicious_process': 'malware', 'malware_detection': 'malware' };
    const playbook = playbookMap[ruleName] || 'suspicious_ip';
    const res = await authFetch(`${API}/api/alerts/${id}/respond?playbook_name=${playbook}`, { method: 'POST' });
    if (!res) return;
    const result = await res.json();
    alert(`Playbook executed! Incident: ${result.incident_id}\nRisk Score: ${result.risk_score}`);
    loadAlerts();
}

// ========== INCIDENTS ==========
async function loadIncidents() {
    const res = await authFetch(`${API}/api/incidents/`);
    if (!res) return;
    const incidents = await res.json();
    const tbody = document.querySelector('#incidents-table tbody');
    tbody.innerHTML = incidents.map(i => `
        <tr>
            <td>${i.incident_id || i.id}</td>
            <td>${i.title}</td>
            <td><span class="sev-badge sev-${(i.severity || 'medium').toLowerCase()}">${i.priority}</span></td>
            <td><span class="status-badge status-${i.status}">${i.status}</span></td>
            <td>${i.source_ip || '-'}</td>
            <td>${i.mitre_technique || '-'}</td>
            <td><span class="risk-badge risk-${getRiskLevel(i.risk_score)}">${i.risk_score || 0}</span></td>
            <td>${i.assigned_to || '-'}</td>
            <td><button class="btn-sm btn-investigate" onclick="showIncidentDetail(${i.id})">View</button></td>
        </tr>
    `).join('');

    const statsRes = await authFetch(`${API}/api/incidents/stats`);
    if (statsRes) {
        const stats = await statsRes.json();
        document.getElementById('inc-new').textContent = stats.by_status.new || 0;
        document.getElementById('inc-investigating').textContent = stats.by_status.investigating || 0;
        document.getElementById('inc-contained').textContent = stats.by_status.contained || 0;
        document.getElementById('inc-closed').textContent = stats.by_status.closed || 0;
    }
}

async function showIncidentDetail(id) {
    const res = await authFetch(`${API}/api/incidents/${id}`);
    if (!res) return;
    const i = await res.json();
    let timeline = [];
    try { timeline = JSON.parse(i.timeline || '[]'); } catch(e) {}
    document.getElementById('incident-detail').innerHTML = `
        <div class="detail-section"><h4>${i.incident_id} — ${i.title}</h4></div>
        <div class="detail-section">
            <div class="detail-row"><span class="label">Priority</span><span class="sev-badge sev-${(i.severity || 'medium').toLowerCase()}">${i.priority}</span></div>
            <div class="detail-row"><span class="label">Status</span><span class="status-badge status-${i.status}">${i.status}</span></div>
            <div class="detail-row"><span class="label">Risk</span><span class="risk-badge risk-${getRiskLevel(i.risk_score)}">${i.risk_score}/100</span></div>
            <div class="detail-row"><span class="label">Source IP</span><span class="value">${i.source_ip || '-'}</span></div>
            <div class="detail-row"><span class="label">MITRE</span><span class="value">${i.mitre_technique || '-'}</span></div>
            <div class="detail-row"><span class="label">Assigned</span><span class="value">${i.assigned_to || '-'}</span></div>
        </div>
        <div class="detail-section"><h4>Description</h4><p style="color:#d1d5db;font-size:0.85em">${i.description || ''}</p></div>
        ${timeline.length ? `<div class="detail-section"><h4>Timeline</h4><div class="timeline">${timeline.map(t => `<div class="timeline-entry"><span class="timeline-time">${formatTime(t.time)}</span><span class="timeline-event">${t.event}</span></div>`).join('')}</div></div>` : ''}
        <div style="display:flex;gap:10px;margin-top:16px">
            <button class="btn-sm btn-investigate" onclick="updateIncidentStatus(${i.id}, 'investigating')">Investigating</button>
            <button class="btn-sm btn-resolve" onclick="updateIncidentStatus(${i.id}, 'contained')">Contained</button>
            <button class="btn-sm btn-resolve" onclick="updateIncidentStatus(${i.id}, 'closed')">Close</button>
        </div>
    `;
    document.getElementById('incident-modal').classList.remove('hidden');
}

async function updateIncidentStatus(id, status) {
    await authFetch(`${API}/api/incidents/${id}/status?status=${status}`, { method: 'PUT' });
    closeModal('incident-modal');
    loadIncidents();
}

// ========== METRICS ==========
async function loadMetrics() {
    const res = await authFetch(`${API}/api/metrics/`);
    if (!res) return;
    const data = await res.json();
    document.getElementById('mttd-value').textContent = data.mttd.formatted;
    document.getElementById('mttr-value').textContent = data.mttr.formatted;

    renderBarChart('events-by-type', data.event_stats.by_type, 'rule');
    renderBarChart('events-by-source', data.event_stats.by_source, 'ip');
    renderBarChart('incidents-by-priority', data.incident_stats.by_priority, 'sev-medium');
}

function renderBarChart(elId, data, cssClass) {
    const el = document.getElementById(elId);
    if (!data || !Object.keys(data).length) { el.innerHTML = '<p style="color:#6b7280">No data</p>'; return; }
    const max = Math.max(...Object.values(data), 1);
    el.innerHTML = Object.entries(data).map(([key, count]) =>
        `<div class="bar-row"><span class="bar-label">${key}</span><div class="bar-container"><div class="bar-fill ${cssClass}" style="width:${(count/max)*100}%"></div></div><span class="bar-count">${count}</span></div>`
    ).join('');
}

// ========== PLAYBOOKS ==========
async function loadPlaybooks() {
    const res = await authFetch(`${API}/api/playbooks/`);
    if (!res) return;
    const playbooks = await res.json();
    const details = {
        'brute_force': { color: '#ef4444', steps: ['Receive alert', 'Extract IP', 'Count failed attempts', 'Risk Score', 'Create Incident', 'Notify Analyst', 'Simulate Block', 'Audit Log'] },
        'suspicious_ip': { color: '#f97316', steps: ['Extract IP', 'Threat Intel', 'Risk Score', 'Create Incident', 'Analyst Decision', 'Simulated Response'] },
        'malware': { color: '#8b5cf6', steps: ['Extract SHA256', 'Threat Intelligence', 'IOC Record', 'Risk Score', 'Create Incident', 'Simulate Quarantine', 'Audit Log'] },
        'phishing': { color: '#eab308', steps: ['Extract URL/Domain/Hash', 'Enrichment', 'Risk Score', 'Incident', 'Simulated URL Block'] },
    };
    document.getElementById('playbooks-grid').innerHTML = playbooks.map(p => {
        const d = details[p.name] || { color: '#3b82f6', steps: [] };
        return `<div class="playbook-card" style="border-top:3px solid ${d.color}"><h4>${p.name}</h4><p>${p.description}</p><div class="playbook-steps">${d.steps.map((s, i) => `<div class="playbook-step"><span class="step-num">${i+1}</span>${s}</div>`).join('')}</div></div>`;
    }).join('');
}

// ========== THREAT INTEL ==========
async function loadThreatIntel() {
    const res = await authFetch(`${API}/api/threat-intel/iocs`);
    if (!res) return;
    const data = await res.json();
    document.getElementById('ti-ips').textContent = data.malicious_ips;
    document.getElementById('ti-hashes').textContent = data.malicious_hashes;
    document.getElementById('ti-urls').textContent = data.suspicious_urls;
    document.getElementById('ti-total').textContent = data.total_iocs;
}

async function lookupIP() {
    const ip = document.getElementById('ip-lookup-input').value.trim();
    if (!ip) return;
    const res = await authFetch(`${API}/api/threat-intel/ip/${ip}`);
    if (!res) return;
    const data = await res.json();
    const el = document.getElementById('ip-lookup-result');
    el.style.display = 'block';
    el.innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
}

// ========== AUDIT LOGS ==========
async function loadAuditLogs() {
    const res = await authFetch(`${API}/api/audit-logs/?limit=100`);
    if (!res) return;
    const logs = await res.json();
    const tbody = document.querySelector('#audit-table tbody');
    tbody.innerHTML = logs.map(l => `
        <tr>
            <td>${formatTime(l.timestamp)}</td>
            <td>${l.analyst}</td>
            <td>${l.action}</td>
            <td>${l.target_type ? l.target_type + '#' + (l.target_id || '') : '-'}</td>
            <td>${l.details || '-'}</td>
            <td><span class="status-badge status-${l.result === 'success' ? 'resolved' : 'open'}">${l.result}</span></td>
        </tr>
    `).join('');
}

// ========== UPLOAD ==========
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
if (dropZone) {
    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.style.borderColor = '#3b82f6'; });
    dropZone.addEventListener('dragleave', () => { dropZone.style.borderColor = '#374151'; });
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = '#374151';
        fileInput.files = e.dataTransfer.files;
    });
}

async function uploadFile() {
    const file = fileInput.files[0];
    if (!file) { alert('Please select a file'); return; }
    const sourceType = document.getElementById('upload-source-type').value;
    const formData = new FormData();
    formData.append('file', file);
    const res = await authFetch(`${API}/api/logs/upload?source_type=${sourceType}`, { method: 'POST', headers: { 'Authorization': `Bearer ${authToken}` }, body: formData });
    if (!res) return;
    const data = await res.json();
    const el = document.getElementById('upload-result');
    el.style.display = 'block';
    el.innerHTML = `
        <h4 style="color:#10b981;margin-bottom:10px">Upload Complete</h4>
        <div class="detail-row"><span class="label">File</span><span class="value">${data.filename}</span></div>
        <div class="detail-row"><span class="label">Events Parsed</span><span class="value">${data.events_parsed}</span></div>
        <div class="detail-row"><span class="label">Events Saved</span><span class="value">${data.events_saved}</span></div>
        <div class="detail-row"><span class="label">Alerts Generated</span><span class="value" style="color:#ef4444">${data.alerts_generated}</span></div>
        ${data.alerts.length ? `<h4 style="margin-top:12px;color:#f59e0b">Alerts:</h4>${data.alerts.map(a => `<div style="padding:4px 0;color:#d1d5db;font-size:0.85em">• ${a.title || JSON.stringify(a)}</div>`).join('')}` : ''}
    `;
}

// ========== UTILITIES ==========
function getRiskLevel(score) {
    if (score >= 81) return 'critical';
    if (score >= 51) return 'high';
    if (score >= 21) return 'medium';
    return 'low';
}

function formatTime(iso) {
    if (!iso) return '-';
    try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

function closeModal(id) { document.getElementById(id).classList.add('hidden'); }

// ========== INIT ==========
document.addEventListener('DOMContentLoaded', () => {
    if (authToken && localStorage.getItem('blueshield_user')) {
        currentUser = JSON.parse(localStorage.getItem('blueshield_user'));
        showApp();
    }
});
