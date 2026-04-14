// ============================================
// AI Network Guardian - Frontend Application
// ============================================

// --- Load AI Mode Status ---
fetch('/api/status').then(r => r.json()).then(data => {
    const badge = document.getElementById('ai-mode-badge');
    if (data.ai_mode === 'gemini-api') {
        badge.textContent = 'Gemini API';
        badge.className = 'ai-mode-badge claude';
    } else {
        badge.textContent = 'Rule-Based Fallback';
        badge.className = 'ai-mode-badge fallback';
    }
}).catch(() => {
    document.getElementById('ai-mode-badge').textContent = 'offline';
});

// --- Tab Navigation ---
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
    });
});

// --- Utility Functions ---
function showLoading(module) {
    document.getElementById(module + '-loading').classList.remove('hidden');
    document.getElementById(module + '-results').innerHTML = '';
}

function hideLoading(module) {
    document.getElementById(module + '-loading').classList.add('hidden');
}

function showError(module, message) {
    document.getElementById(module + '-results').innerHTML =
        `<div class="error-card">Error: ${escapeHtml(message)}</div>`;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatTimestamp(ts) {
    return new Date(ts * 1000).toLocaleString();
}

// --- Diagnosis Card Renderer ---
function renderDiagnosis(d) {
    const evidenceItems = (d.evidence || [])
        .map(e => `<li>${escapeHtml(e)}</li>`).join('');

    return `
        <div class="diagnosis-card severity-${d.severity}">
            <div class="diagnosis-header">
                <span class="diagnosis-title">${escapeHtml(d.title)}</span>
                <div class="diagnosis-badges">
                    <span class="badge badge-layer" data-layer="${d.layer}">${escapeHtml(d.layer)} Layer</span>
                    <span class="badge badge-severity ${d.severity}">${d.severity.toUpperCase()}</span>
                    <span class="badge badge-confidence">${Math.round(d.confidence * 100)}% confidence</span>
                </div>
            </div>
            <div class="diagnosis-section">
                <div class="diagnosis-section-label">Explanation</div>
                <div class="diagnosis-explanation">${escapeHtml(d.explanation)}</div>
            </div>
            <div class="diagnosis-section">
                <div class="diagnosis-section-label">Supporting Evidence</div>
                <ul class="diagnosis-evidence">${evidenceItems}</ul>
            </div>
            <div class="diagnosis-section">
                <div class="diagnosis-section-label">Recommendation</div>
                <div class="diagnosis-recommendation">${escapeHtml(d.recommendation)}</div>
            </div>
        </div>
    `;
}

function renderDiagnoses(diagnoses) {
    if (!diagnoses || diagnoses.length === 0) {
        return '<div class="diagnosis-card severity-info"><div class="diagnosis-title">No issues detected</div></div>';
    }
    return diagnoses.map(renderDiagnosis).join('');
}


// ============================================
// Network Detective
// ============================================

async function runDetectiveScan() {
    const btn = document.getElementById('btn-scan-network');
    btn.disabled = true;
    showLoading('detective');

    try {
        const res = await fetch('/api/detective/scan', { method: 'POST' });
        const data = await res.json();
        hideLoading('detective');

        if (data.error) {
            showError('detective', data.error);
            return;
        }

        const scan = data.scan;
        const devices = scan.devices || [];

        // Summary cards
        let html = `<div class="summary-grid">
            <div class="summary-card">
                <div class="summary-value">${scan.total_found}</div>
                <div class="summary-label">Devices Found</div>
            </div>
            <div class="summary-card">
                <div class="summary-value good">${scan.responsive}</div>
                <div class="summary-label">Responsive</div>
            </div>
            <div class="summary-card">
                <div class="summary-value ${scan.unknown_count > 0 ? 'warn' : ''}">${scan.unknown_count}</div>
                <div class="summary-label">Unknown Devices</div>
            </div>
            <div class="summary-card">
                <div class="summary-value">${scan.subnet}.0/24</div>
                <div class="summary-label">Subnet</div>
            </div>
        </div>`;

        // Device table
        if (devices.length > 0) {
            html += `<div class="section-title">Discovered Devices</div>
            <div style="overflow-x:auto">
            <table class="device-table">
                <thead><tr>
                    <th>Status</th><th>IP Address</th><th>MAC Address</th>
                    <th>Vendor</th><th>Device Type</th><th>Hostname</th>
                </tr></thead><tbody>`;

            for (const d of devices) {
                const statusClass = d.is_responsive === true ? 'online' :
                                   d.is_responsive === false ? 'offline' : 'unknown';
                const vendorClass = d.vendor === 'Unknown Vendor' ? 'vendor-unknown' : '';
                html += `<tr>
                    <td><span class="status-dot ${statusClass}"></span>${statusClass}</td>
                    <td>${escapeHtml(d.ip)}</td>
                    <td><code>${escapeHtml(d.mac)}</code></td>
                    <td class="${vendorClass}">${escapeHtml(d.vendor)}</td>
                    <td>${escapeHtml(d.device_type)}</td>
                    <td>${d.hostname ? escapeHtml(d.hostname) : '<span style="color:var(--text-muted)">-</span>'}</td>
                </tr>`;
            }
            html += `</tbody></table></div>`;
        }

        // AI Diagnoses
        html += `<div class="section-title">AI Diagnosis</div>`;
        html += renderDiagnoses(data.diagnoses);

        document.getElementById('detective-results').innerHTML = html;
    } catch (err) {
        hideLoading('detective');
        showError('detective', err.message);
    } finally {
        btn.disabled = false;
    }
}


// ============================================
// Security Hunter
// ============================================

async function runSecurityAnalysis() {
    const urlInput = document.getElementById('url-input');
    const url = urlInput.value.trim();
    if (!url) {
        urlInput.focus();
        return;
    }

    showLoading('security');

    try {
        const res = await fetch('/api/security/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const data = await res.json();
        hideLoading('security');

        if (data.error) {
            showError('security', data.error);
            return;
        }

        const analysis = data.analysis;
        const cert = analysis.certificate || {};
        const wh = analysis.whois || {};
        const phishing = analysis.phishing_assessment || {};
        const urlInfo = analysis.url || {};

        // Risk meter
        const riskScore = phishing.risk_score || 0;
        const riskLevel = phishing.risk_level || 'safe';
        let html = `
        <div class="risk-meter">
            <div class="risk-label">
                <span>Phishing Risk Assessment</span>
                <span><strong>${riskScore}/100</strong> (${riskLevel.toUpperCase()})</span>
            </div>
            <div class="risk-bar-container">
                <div class="risk-bar ${riskLevel}" style="width:${Math.max(riskScore, 3)}%"></div>
            </div>
        </div>`;

        // Summary cards
        html += `<div class="summary-grid">
            <div class="summary-card">
                <div class="summary-value ${cert.valid ? 'good' : 'warn'}">${cert.valid ? 'Valid' : 'Invalid'}</div>
                <div class="summary-label">SSL Certificate</div>
            </div>
            <div class="summary-card">
                <div class="summary-value">${cert.protocol_version || 'N/A'}</div>
                <div class="summary-label">TLS Version</div>
            </div>
            <div class="summary-card">
                <div class="summary-value ${cert.days_until_expiry > 30 ? 'good' : 'warn'}">
                    ${cert.days_until_expiry !== null ? cert.days_until_expiry + 'd' : 'N/A'}
                </div>
                <div class="summary-label">Cert Expiry</div>
            </div>
            <div class="summary-card">
                <div class="summary-value">${wh.domain_age_days !== null ? Math.floor(wh.domain_age_days / 365) + 'y' : 'N/A'}</div>
                <div class="summary-label">Domain Age</div>
            </div>
        </div>`;

        // Certificate details
        html += `<div class="section-title">Certificate Details</div>
        <div class="diagnosis-card severity-info">
            <table class="device-table" style="margin:0">
                <tr><td style="width:140px;color:var(--text-muted)">Hostname</td><td>${escapeHtml(urlInfo.hostname || '')}</td></tr>
                <tr><td style="color:var(--text-muted)">Issuer</td><td>${escapeHtml(cert.issuer?.organizationName || cert.issuer?.commonName || 'N/A')}</td></tr>
                <tr><td style="color:var(--text-muted)">Subject</td><td>${escapeHtml(cert.subject?.commonName || 'N/A')}</td></tr>
                <tr><td style="color:var(--text-muted)">Valid From</td><td>${cert.not_before || 'N/A'}</td></tr>
                <tr><td style="color:var(--text-muted)">Valid Until</td><td>${cert.not_after || 'N/A'}</td></tr>
                <tr><td style="color:var(--text-muted)">Cipher</td><td>${escapeHtml(cert.cipher || 'N/A')}</td></tr>
                <tr><td style="color:var(--text-muted)">SAN Domains</td><td>${(cert.san_domains || []).slice(0, 5).map(escapeHtml).join(', ') || 'N/A'}</td></tr>
                ${cert.error ? `<tr><td style="color:var(--accent-red)">Error</td><td style="color:var(--accent-red)">${escapeHtml(cert.error)}</td></tr>` : ''}
            </table>
        </div>`;

        // WHOIS details
        if (wh.available) {
            html += `<div class="section-title" style="margin-top:1rem">WHOIS Information</div>
            <div class="diagnosis-card severity-info">
                <table class="device-table" style="margin:0">
                    <tr><td style="width:140px;color:var(--text-muted)">Registrar</td><td>${escapeHtml(wh.registrar || 'N/A')}</td></tr>
                    <tr><td style="color:var(--text-muted)">Created</td><td>${wh.creation_date || 'N/A'}</td></tr>
                    <tr><td style="color:var(--text-muted)">Expires</td><td>${wh.expiration_date || 'N/A'}</td></tr>
                    <tr><td style="color:var(--text-muted)">Domain Age</td><td>${wh.domain_age_days !== null ? wh.domain_age_days + ' days' : 'N/A'}</td></tr>
                    <tr><td style="color:var(--text-muted)">Name Servers</td><td>${(wh.name_servers || []).slice(0, 4).map(escapeHtml).join(', ') || 'N/A'}</td></tr>
                </table>
            </div>`;
        }

        // AI Diagnoses
        html += `<div class="section-title" style="margin-top:1rem">AI Diagnosis</div>`;
        html += renderDiagnoses(data.diagnoses);

        document.getElementById('security-results').innerHTML = html;
    } catch (err) {
        hideLoading('security');
        showError('security', err.message);
    }
}


// ============================================
// Performance & Lag Monitor
// ============================================

async function runPerformanceDiag() {
    const host = document.getElementById('perf-host').value.trim() || '8.8.8.8';
    const pingCount = parseInt(document.getElementById('perf-count').value) || 10;

    showLoading('performance');

    try {
        const res = await fetch('/api/performance/diagnose', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ host, ping_count: pingCount })
        });
        const data = await res.json();
        hideLoading('performance');

        if (data.error) {
            showError('performance', data.error);
            return;
        }

        const perf = data.performance;
        const lat = perf.latency || {};
        const conn = perf.connections || {};
        const dns = perf.dns || {};

        // Summary cards
        const avgClass = (lat.avg_ms || 0) <= 50 ? 'good' : (lat.avg_ms || 0) <= 100 ? '' : 'warn';
        const lossClass = (lat.packet_loss_pct || 0) === 0 ? 'good' : 'warn';

        let html = `<div class="summary-grid">
            <div class="summary-card">
                <div class="summary-value ${avgClass}">${lat.avg_ms !== null ? lat.avg_ms.toFixed(1) : 'N/A'}</div>
                <div class="summary-label">Avg Latency (ms)</div>
            </div>
            <div class="summary-card">
                <div class="summary-value ${lossClass}">${lat.packet_loss_pct !== null ? lat.packet_loss_pct + '%' : 'N/A'}</div>
                <div class="summary-label">Packet Loss</div>
            </div>
            <div class="summary-card">
                <div class="summary-value">${lat.jitter_ms !== null ? lat.jitter_ms : 'N/A'}</div>
                <div class="summary-label">Jitter (ms)</div>
            </div>
            <div class="summary-card">
                <div class="summary-value">${dns.resolution_time_ms !== null ? dns.resolution_time_ms.toFixed(0) : 'N/A'}</div>
                <div class="summary-label">DNS (ms)</div>
            </div>
        </div>`;

        // Latency visualization
        const packets = lat.packets || [];
        if (packets.length > 0) {
            const maxPkt = Math.max(...packets);
            html += `<div class="section-title">Latency Per Packet (${escapeHtml(lat.host)})</div>
            <div class="latency-bars">`;
            for (const p of packets) {
                const height = Math.max((p / maxPkt) * 100, 5);
                const color = p <= 50 ? 'var(--accent-green)' :
                             p <= 100 ? 'var(--accent-yellow)' :
                             p <= 200 ? 'var(--accent-orange)' : 'var(--accent-red)';
                html += `<div class="latency-bar" style="height:${height}%;background:${color}" title="${p.toFixed(1)} ms"></div>`;
            }
            html += `</div>
            <div style="display:flex;justify-content:space-between;font-size:0.7rem;color:var(--text-muted);padding:0 0.5rem;margin-bottom:1rem">
                <span>Min: ${lat.min_ms?.toFixed(1)} ms</span>
                <span>Avg: ${lat.avg_ms?.toFixed(1)} ms</span>
                <span>Max: ${lat.max_ms?.toFixed(1)} ms</span>
            </div>`;
        }

        // Connection states
        const states = conn.states || {};
        const stateKeys = Object.keys(states);
        if (stateKeys.length > 0) {
            html += `<div class="section-title">Connection States (TCP: ${conn.tcp_count}, UDP: ${conn.udp_count})</div>
            <div class="conn-states">`;
            for (const [state, count] of Object.entries(states)) {
                html += `<span class="conn-state-chip">${escapeHtml(state)}<span class="count">${count}</span></span>`;
            }
            html += `</div>`;
        }

        // Top remote hosts
        const topHosts = conn.top_remote_hosts || {};
        const hostKeys = Object.keys(topHosts);
        if (hostKeys.length > 0) {
            html += `<div class="section-title">Top Remote Hosts</div>
            <table class="device-table"><thead><tr><th>Host</th><th>Connections</th></tr></thead><tbody>`;
            for (const [h, c] of Object.entries(topHosts)) {
                html += `<tr><td><code>${escapeHtml(h)}</code></td><td>${c}</td></tr>`;
            }
            html += `</tbody></table>`;
        }

        // AI Diagnoses
        html += `<div class="section-title">AI Diagnosis</div>`;
        html += renderDiagnoses(data.diagnoses);

        document.getElementById('performance-results').innerHTML = html;
    } catch (err) {
        hideLoading('performance');
        showError('performance', err.message);
    }
}


// ============================================
// History
// ============================================

async function loadHistory(module) {
    const modal = document.getElementById('history-modal');
    const body = document.getElementById('history-body');
    modal.classList.remove('hidden');
    body.innerHTML = '<div class="loading"><div class="spinner"></div><p>Loading history...</p></div>';

    try {
        const res = await fetch(`/api/history/${module}?limit=15`);
        const data = await res.json();
        const history = data.history || [];

        if (history.length === 0) {
            body.innerHTML = '<p style="text-align:center;padding:2rem;color:var(--text-muted)">No history yet. Run a scan first.</p>';
            return;
        }

        let html = '';
        for (const entry of history) {
            const diagnoses = entry.diagnoses || [];
            const sevCounts = {};
            diagnoses.forEach(d => {
                sevCounts[d.severity] = (sevCounts[d.severity] || 0) + 1;
            });
            const sevSummary = Object.entries(sevCounts)
                .map(([s, c]) => `<span class="badge badge-severity ${s}" style="margin-right:4px">${c} ${s}</span>`)
                .join('');

            html += `<div class="history-entry">
                <div class="timestamp">${formatTimestamp(entry.timestamp)}</div>
                <div class="diagnosis-count">${diagnoses.length} diagnosis(es) ${sevSummary}</div>
                <div style="margin-top:0.4rem;font-size:0.8rem;color:var(--text-muted)">
                    ${diagnoses.map(d => d.title).join(' &bull; ')}
                </div>
            </div>`;
        }
        body.innerHTML = html;
    } catch (err) {
        body.innerHTML = `<div class="error-card">Failed to load history: ${escapeHtml(err.message)}</div>`;
    }
}

function closeHistory() {
    document.getElementById('history-modal').classList.add('hidden');
}

// Close modal on backdrop click
document.getElementById('history-modal').addEventListener('click', function(e) {
    if (e.target === this) closeHistory();
});

// Close modal on Escape
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeHistory();
});
