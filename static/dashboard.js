/**
 * WazuhBoard Dashboard JavaScript
 * Based on SOC-AI dashboard.js but simplified without API keys
 */

document.addEventListener('DOMContentLoaded', function() {
    initializeDashboard();
});

// Chart instances (kept global so we can destroy on refresh)
let alertsChartInstance = null;
let severityChartInstance = null;

function initializeDashboard() {
    // Init dashboard
    loadClients();

    // Set up refresh button
    const refreshBtn = document.getElementById('refresh-stats');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => fetchDashboardStats());
    }

    // Set up client selector
    const clientSelector = document.getElementById('client-selector');
    if (clientSelector) {
        clientSelector.addEventListener('change', handleClientChange);
    }
}

async function loadClients() {
    const response = await fetch('/api/clients');
    const data = await response.json();

    if (data.clients && data.clients.length > 0) {
        populateClientSelector(data.clients, data.default_client);
        // Load stats for default client
        fetchDashboardStats();
    } else {
        showError('No clients configured');
    }
}

function populateClientSelector(clients, defaultClient) {
    const selector = document.getElementById('client-selector');
    if (!selector) return;

    selector.innerHTML = '';

    clients.forEach(client => {
        const option = document.createElement('option');
        option.value = client.name;
        option.textContent = `${client.name} - ${client.description}`;
        if (client.name === defaultClient) {
            option.selected = true;
        }
        selector.appendChild(option);
    });
}

function handleClientChange() {
    // Reload stats when client changes
    fetchDashboardStats();
}

async function fetchDashboardStats() {
    const clientSelector = document.getElementById('client-selector');
    const selectedClient = clientSelector ? clientSelector.value : null;

    try {
        const requestBody = selectedClient ? { client: selectedClient } : {};

        const response = await fetch('/api/stats/dashboard', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestBody)
        });

        const data = await response.json();

        if (data.error) {
            showError(`Failed to fetch dashboard stats: ${data.error}`);
        } else {
            updateDashboardWidgets(data);
        }
    } catch (error) {
        console.error('Error fetching dashboard stats:', error);
        showError('Failed to load dashboard statistics');
    }
}

function updateDashboardWidgets(stats) {
    const statsContainer = document.getElementById('stats-container');
    if (!statsContainer) {
        console.error('Stats container not found!');
        return;
    }

    // Update top summary if present
    const clientLabel = document.getElementById('summary-client');
    const alerts24 = document.getElementById('summary-24h');
    const criticalLabel = document.getElementById('summary-critical');
    const agentsLabel = document.getElementById('summary-agents');

    if (clientLabel) clientLabel.textContent = document.getElementById('client-selector') ? document.getElementById('client-selector').value || 'â€”' : 'â€”';

    let total24 = 0;
    if (stats.alerts_per_hour && stats.alerts_per_hour.length > 0) {
        total24 = stats.alerts_per_hour.reduce((s, h) => s + (h.count || 0), 0);
    }
    if (alerts24) alerts24.textContent = total24;

    // Use server-side severity summary when present; otherwise derive critical counts locally
    let criticalCount = 0;
    if (stats.severity_summary) {
        criticalCount = stats.severity_summary.critical || 0;
    } else if (stats.severity_breakdown && stats.severity_breakdown.length > 0) {
        stats.severity_breakdown.forEach(b => { if (parseInt(b.level) >= 15) criticalCount += b.count || 0; });
    }
    if (criticalLabel) criticalLabel.textContent = criticalCount;

    if (agentsLabel) agentsLabel.textContent = stats.agent_health && stats.agent_health.total !== undefined ? stats.agent_health.total : 'â€”';

    let html = '<h3>Security Dashboard</h3>';

    if (stats.error) {
        html += `<div class="error">Error: ${stats.error}</div>`;
        if (stats.note) html += `<div class="warning">${stats.note}</div>`;
        statsContainer.innerHTML = html;
        return;
    }

    html += '<div class="stats-grid">';

    // Total agents
    html += `<div class="stat-card">
                <h4>Total Agents</h4>
                <div class="stat-value">${stats.agent_health && stats.agent_health.total !== undefined ? stats.agent_health.total : 'â€”'}</div>
            </div>`;

    // Alerts per hour chart
    html += '<div class="stat-card">';
    html += '<h4>Alerts Per Hour (24h)</h4>';
    if (stats.alerts_per_hour && stats.alerts_per_hour.length > 0) {
        html += '<div class="chart-placeholder"><canvas id="alertsChart"></canvas></div>';
    } else {
        html += '<div class="no-data">No alert data available</div>';
    }
    html += '</div>';

    // Severity donut
    html += '<div class="stat-card">';
    html += '<h4>Alert Severity</h4>';
    if (stats.severity_breakdown && stats.severity_breakdown.length > 0) {
        html += '<div class="severity-chart"><canvas id="severityChart"></canvas></div>';
    } else {
        html += '<div class="no-data">No severity data available</div>';
    }
    html += '</div>';

    // Agent Health card (progress + online/offline tiles)
    html += '<div class="stat-card">';
    html += '<h4>Agent Health</h4>';
    const online = stats.agent_health && stats.agent_health.online !== undefined ? stats.agent_health.online : null;
    const offline = stats.agent_health && stats.agent_health.offline !== undefined ? stats.agent_health.offline : null;
    const total = stats.agent_health && stats.agent_health.total !== undefined ? stats.agent_health.total : (online !== null && offline !== null ? online + offline : null);

    if (total !== null) {
        const pctOnline = total > 0 ? Math.round((online / total) * 100) : 0;
        html += `<div class="agent-health">
            <div class="agent-health-bar" role="progressbar" aria-valuenow="${pctOnline}" aria-valuemin="0" aria-valuemax="100">
                <div class="agent-health-fill" style="width:${pctOnline}%;"></div>
            </div>
            <div class="agent-tiles">
                <div class="tile online"><div class="tile-num">${online}</div><div class="tile-label">ONLINE</div></div>
                <div class="tile offline"><div class="tile-num">${offline}</div><div class="tile-label">OFFLINE</div></div>
            </div>
        </div>`;
    } else {
        html += '<div class="no-data">No agent status available</div>';
    }
    html += '</div>';

    // Top rules
    html += '<div class="stat-card">';
    html += '<h4>Top Rules</h4>';
    if (stats.top_rules && stats.top_rules.length > 0) {
        html += '<ul class="top-list">';
        stats.top_rules.slice(0, 8).forEach(rule => {
            const desc = rule.description ? ` - ${rule.description.substring(0, 80)}...` : '';
            html += `<li>Rule ${rule.rule_id}${desc}: ${rule.count} alerts</li>`;
        });
        html += '</ul>';
    } else {
        html += '<div class="no-data">No rule data available</div>';
    }
    html += '</div>';

    // Top agents
    html += '<div class="stat-card">';
    html += '<h4>Top Agents</h4>';
    if (stats.top_agents && stats.top_agents.length > 0) {
        html += '<ul class="top-list">';
        stats.top_agents.slice(0, 8).forEach(agent => {
            html += `<li>${agent.agent_name}: ${agent.count} alerts</li>`;
        });
        html += '</ul>';
    } else {
        html += '<div class="no-data">No agent data available</div>';
    }
    html += '</div>';

    // Top source IPs
    html += '<div class="stat-card">';
    html += '<h4>Top Source IPs</h4>';
    if (stats.top_source_ips && stats.top_source_ips.length > 0) {
        html += '<ul class="top-list">';
        stats.top_source_ips.slice(0, 8).forEach(ip => {
            html += `<li>${ip.ip}: ${ip.count} alerts</li>`;
        });
        html += '</ul>';
    } else {
        html += '<div class="no-data">No IP data available</div>';
    }
    html += '</div>';

    // Alert trends (7 days)
    html += '<div class="stat-card">';
    html += '<h4>Alert Trends (7 days)</h4>';
    if (stats.alert_trends && stats.alert_trends.length > 0) {
        html += '<div class="trends-chart">';
        stats.alert_trends.forEach(trend => {
            const dateStr = new Date(trend.date).toLocaleDateString();
            html += `<div class="trend-item"><span class="trend-date">${dateStr}</span><span class="trend-count">${trend.count}</span></div>`;
        });
        html += '</div>';
    } else {
        html += '<div class="no-data">No trend data available</div>';
    }
    html += '</div>';

    html += '</div>'; // end stats-grid

    statsContainer.innerHTML = html;
    // Show informational note if returned
    if (stats.note) {
        showError(stats.note); // reuse showError to show a transient warning; could create dedicated UI later
    }

    // Initialize charts after DOM update
    try {
        // Alerts line chart
        const alertsCanvas = document.getElementById('alertsChart');
        if (alertsCanvas && stats.alerts_per_hour && typeof Chart !== 'undefined') {
            const slice = stats.alerts_per_hour.slice(-24);
            const labels = slice.map(h => new Date(h.timestamp).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'}));
            const data = slice.map(h => h.count || 0);
            if (alertsChartInstance) alertsChartInstance.destroy();
            alertsChartInstance = new Chart(alertsCanvas.getContext('2d'), {
                type: 'line',
                data: { labels: labels, datasets: [{ label: 'Alerts', data: data, borderColor: '#4da6ff', backgroundColor: 'rgba(77,166,255,0.08)', fill: true, tension: 0.25 }] },
                options: { maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
            });
        }

        // Severity donut (favor server-side summary for counts/labels)
    const severityCanvas = document.getElementById('severityChart');
    if (severityCanvas && (stats.severity_breakdown || stats.severity_summary) && typeof Chart !== 'undefined') {
            let buckets = [];
            if (stats.severity_breakdown && stats.severity_breakdown.length > 0) {
                buckets = stats.severity_breakdown.slice().sort((a,b)=>parseInt(b.level)-parseInt(a.level));
            } else if (stats.severity_summary) {
                const s = stats.severity_summary;
                buckets = [
                    { level: 15, count: s.critical || 0 },
                    { level: 13, count: s.high || 0 },
                    { level: 9, count: s.medium || 0 },
                    { level: 3, count: s.low || 0 }
                ];
            }
            const labels = buckets.map(b => `L${b.level}`);
            const values = buckets.map(b => b.count || 0);
            const colors = ['#e74c3c','#e67e22','#f39c12','#27ae60','#3498db','#9b59b6','#2ecc71','#1abc9c'];
            if (severityChartInstance) severityChartInstance.destroy();
            severityChartInstance = new Chart(severityCanvas.getContext('2d'), {
                type: 'doughnut',
                data: {
                    labels: labels,
                    datasets: [{ data: values, backgroundColor: colors.slice(0, labels.length) }]
                },
                options: {
                    maintainAspectRatio: false,
                    plugins: { legend: { position: 'right' } }
                }
            });

            // Update summary text labels when server provided summary
            if (stats.severity_summary) {
                const s = stats.severity_summary;
                const elCrit = document.getElementById('sev-critical');
                const elHigh = document.getElementById('sev-high');
                const elMed = document.getElementById('sev-medium');
                const elLow = document.getElementById('sev-low');
                if (elCrit) elCrit.textContent = s.critical || 0;
                if (elHigh) elHigh.textContent = s.high || 0;
                if (elMed) elMed.textContent = s.medium || 0;
                if (elLow) elLow.textContent = s.low || 0;
            }
        }
    } catch (e) {
        console.warn('Chart initialization failed:', e);
    }
}

function getSeverityClass(level) {
    // Match server-side mapping: critical >=15, high >=12, medium >=7, low <7
    if (level >= 15) return 'critical';
    if (level >= 12) return 'high';
    if (level >= 7) return 'medium';
    return 'low';
}
// Query functionality removed to keep the UI focused on dashboard widgets only.

function showError(message) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error';
    errorDiv.textContent = message;

    // Remove existing errors
    const existingErrors = document.querySelectorAll('.error');
    existingErrors.forEach(err => err.remove());

    // Add new error
    document.body.insertBefore(errorDiv, document.body.firstChild);

    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (errorDiv.parentNode) {
            errorDiv.remove();
        }
    }, 5000);
}