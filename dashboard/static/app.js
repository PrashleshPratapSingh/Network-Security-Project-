/* ── NIDS Dashboard — Client-Side Application Logic ───────────────────────
   Handles:
     - Clock
     - SSE (Server-Sent Events) real-time alert streaming
     - Approach switching (A1 / A2)
     - Mode toggling (Simulator / CSV / Live)
     - Start / Stop calls to Flask API
     - Alert table rendering + filtering
     - Metrics card updates
     - Chart.js chart initialization & live updates
     - Compare tab auto-population
───────────────────────────────────────────────────────────────────────── */

'use strict';

// ── State ──────────────────────────────────────────────────────────────────
const state = {
  currentApproach: 'approach1',
  currentMode:     'simulator',
  alertFilters:    new Set(['HIGH', 'MEDIUM', 'LOW']),
  alerts:          [],
  metrics:         { approach1: {}, approach2: {} },
  status:          { approach1: 'stopped', approach2: 'stopped' },
  attackCounts:    {},
  charts:          {},
  maxAlerts:       500,   // cap UI table rows
};

// ── Clock ──────────────────────────────────────────────────────────────────
function updateClock() {
  const now = new Date();
  document.getElementById('clock').textContent =
    now.toLocaleTimeString('en-GB', { hour12: false });
}
setInterval(updateClock, 1000);
updateClock();

// ── SSE Connection ─────────────────────────────────────────────────────────
let sse = null;

function connectSSE() {
  sse = new EventSource('/api/stream/alerts');

  sse.onopen = () => {
    setConnectionStatus('connected');
    addLog('Connected to alert stream', 'ok');
  };

  sse.onerror = () => {
    setConnectionStatus('disconnected');
    addLog('Stream disconnected — retrying…', 'warn');
  };

  sse.onmessage = (evt) => {
    try {
      const msg = JSON.parse(evt.data);
      handleSSEMessage(msg);
    } catch (e) { /* ignore parse errors */ }
  };
}

function handleSSEMessage(msg) {
  switch (msg.type) {

    case 'connected':
      setConnectionStatus('connected');
      break;

    case 'ping':
      break;   // keepalive, ignore

    case 'alert':
      onAlert(msg.alert, msg.approach);
      break;

    case 'metrics':
      onMetricsUpdate(msg.approach, msg.metrics);
      break;

    case 'status':
      onStatusUpdate(msg.approach, msg.status, msg.metrics);
      break;

    case 'log':
      addLog(msg.message, 'info');
      break;
  }
}

// ── Alert Handling ─────────────────────────────────────────────────────────
function onAlert(alert, approach) {
  state.alerts.unshift(alert);            // newest first
  if (state.alerts.length > state.maxAlerts) {
    state.alerts.length = state.maxAlerts;
  }

  // Count attack types for chart
  const rule = alert.rule || 'Unknown';
  state.attackCounts[rule] = (state.attackCounts[rule] || 0) + 1;

  // Update sidebar alert counter
  const totalAlerts = state.alerts.length;
  document.getElementById('statAlerts').textContent = totalAlerts;
  document.getElementById('alertCountBadge').textContent = `${totalAlerts} alerts`;

  // Remove empty-state row if present
  const emptyRow = document.querySelector('.empty-row');
  if (emptyRow) emptyRow.remove();

  // Only render in table if matches current filter
  if (state.alertFilters.has(alert.severity)) {
    prependAlertRow(alert, approach);
  }

  // Periodically update charts
  if (totalAlerts % 20 === 0) updateCharts();
}

function prependAlertRow(alert, approach) {
  const tbody = document.getElementById('alertTableBody');
  const tr = document.createElement('tr');
  tr.className = `sev-${alert.severity.toLowerCase()} alert-row-new`;
  tr.dataset.severity = alert.severity;

  tr.innerHTML = `
    <td class="font-mono">${escHtml(alert.timestamp || '')}</td>
    <td><span class="sev-chip ${alert.severity}">${alert.severity}</span></td>
    <td>${escHtml(alert.rule || '')}</td>
    <td class="font-mono">${escHtml(alert.src_dst || '')}</td>
    <td class="font-mono">${escHtml(alert.protocol || '')}</td>
    <td><span class="approach-chip ${approach === 'approach1' ? 'a1' : 'a2'}">${approach === 'approach1' ? 'A1·Sig' : 'A2·ML'}</span></td>
  `;

  tbody.insertBefore(tr, tbody.firstChild);

  // Keep DOM trim (max 200 rows visible)
  while (tbody.rows.length > 200) {
    tbody.deleteRow(tbody.rows.length - 1);
  }
}

function clearAlerts() {
  state.alerts = [];
  state.attackCounts = {};
  document.getElementById('alertTableBody').innerHTML =
    `<tr class="empty-row"><td colspan="6">
      <div class="empty-state">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.3"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <p>Start detection to see live alerts</p>
      </div>
    </td></tr>`;
  document.getElementById('statAlerts').textContent = '0';
  document.getElementById('alertCountBadge').textContent = '0 alerts';
}

// ── Severity Filter ────────────────────────────────────────────────────────
function toggleFilter(sev, btn) {
  if (state.alertFilters.has(sev)) {
    state.alertFilters.delete(sev);
    btn.classList.remove('active');
  } else {
    state.alertFilters.add(sev);
    btn.classList.add('active');
  }
  rebuildAlertTable();
}

function rebuildAlertTable() {
  const tbody = document.getElementById('alertTableBody');
  tbody.innerHTML = '';

  const visible = state.alerts.filter(a => state.alertFilters.has(a.severity));
  if (visible.length === 0) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="6"><div class="empty-state"><p>No alerts match the current filter</p></div></td></tr>`;
    return;
  }

  visible.slice(0, 200).forEach(alert => {
    prependAlertRow(alert, alert.approach || state.currentApproach);
  });
}

// ── Metrics Updates ────────────────────────────────────────────────────────
function onMetricsUpdate(approach, metrics) {
  state.metrics[approach] = { ...state.metrics[approach], ...metrics };
  renderMetricsCards();
  updateCompareTable();
}

function renderMetricsCards() {
  for (const ap of ['approach1', 'approach2']) {
    const m   = state.metrics[ap];
    const pfx = ap === 'approach1' ? 'a1' : 'a2';
    const pct = v => v != null ? `${Number(v).toFixed(1)}%` : '—';
    const num = v => v != null ? Number(v).toFixed(4) : '—';

    setTextSafe(`${pfx}Accuracy`,  pct(m.accuracy));
    setTextSafe(`${pfx}Precision`, pct(m.precision));
    setTextSafe(`${pfx}Recall`,    pct(m.recall_detection_rate ?? m.recall));
    setTextSafe(`${pfx}F1`,        num(m.f1_score));
    setTextSafe(`${pfx}FPR`,       pct(m.false_positive_rate ?? m.fpr));

    setTextSafe(`${pfx}TPv`, m.true_positives  ?? m.tp ?? '—');
    setTextSafe(`${pfx}FPv`, m.false_positives ?? m.fp ?? '—');
    setTextSafe(`${pfx}TNv`, m.true_negatives  ?? m.tn ?? '—');
    setTextSafe(`${pfx}FNv`, m.false_negatives ?? m.fn ?? '—');

    // Sidebar accuracy
    if (ap === state.currentApproach) {
      const acc = m.accuracy ?? m.recall_detection_rate;
      document.getElementById('statAccuracy').textContent =
        acc != null ? `${Number(acc).toFixed(1)}%` : '—';
      document.getElementById('statPackets').textContent =
        m.total_packets ?? '—';
    }
  }
}

// ── Status Updates ─────────────────────────────────────────────────────────
function onStatusUpdate(approach, status, metrics) {
  state.status[approach] = status;

  const badge = document.getElementById(approach === 'approach1' ? 'a1StatusBadge' : 'a2StatusBadge');
  if (badge) {
    badge.textContent = status.charAt(0).toUpperCase() + status.slice(1);
    badge.className   = `status-badge ${status}`;
  }

  if (status === 'done' || status === 'stopped') {
    // If this is the active approach, re-enable start button
    if (approach === state.currentApproach) {
      setRunningState(false);
    }
    addLog(`${approach} ${status}.`, status === 'done' ? 'ok' : 'warn');
  }

  if (metrics && Object.keys(metrics).length > 0) {
    onMetricsUpdate(approach, metrics);
  }

  // Auto-update charts on completion
  updateCharts();
  updateCompareTable();
}

// ── Start / Stop ───────────────────────────────────────────────────────────
async function startApproach() {
  const approach = state.currentApproach;
  const mode     = state.currentMode;

  const body = { mode };

  if (mode === 'simulator') {
    body.packets      = parseInt(document.getElementById('inputPackets').value) || 300;
    body.attack_ratio = parseFloat(document.getElementById('attackRatio').value) || 0.4;
  } else if (mode === 'csv') {
    body.input    = document.getElementById('csvPath').value.trim();
    body.max_rows = parseInt(document.getElementById('maxRows').value) || 0;
  } else if (mode === 'live') {
    body.input = document.getElementById('ifaceInput').value.trim() || 'eth0';
  }

  addLog(`Starting ${approach} in ${mode} mode…`, 'info');
  setRunningState(true);
  clearAlerts();
  state.attackCounts = {};

  try {
    const res = await fetch(`/api/${approach}/start`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
    });
    const data = await res.json();

    if (!res.ok) {
      addLog(`Error: ${data.error}`, 'warn');
      setRunningState(false);
    } else {
      addLog(`Started — PID ${data.pid}`, 'ok');
      setConnectionStatus('running');
    }
  } catch (err) {
    addLog(`Failed to start: ${err.message}`, 'warn');
    setRunningState(false);
  }
}

async function stopApproach() {
  const approach = state.currentApproach;
  addLog(`Stopping ${approach}…`, 'warn');

  try {
    await fetch(`/api/${approach}/stop`, { method: 'POST' });
    setRunningState(false);
    setConnectionStatus('connected');
    addLog('Stopped.', 'ok');

    // Reload final metrics
    await refreshMetrics();
  } catch (err) {
    addLog(`Stop failed: ${err.message}`, 'warn');
  }
}

function setRunningState(running) {
  document.getElementById('startBtn').disabled = running;
  document.getElementById('stopBtn').disabled  = !running;
}

// ── Metrics Refresh (polling) ──────────────────────────────────────────────
async function refreshMetrics() {
  try {
    const res  = await fetch('/api/metrics');
    const data = await res.json();

    for (const ap of ['approach1', 'approach2']) {
      if (data[ap] && Object.keys(data[ap]).length > 0) {
        state.metrics[ap] = data[ap];
      }
    }

    renderMetricsCards();
    updateCharts();
    updateCompareTable();
  } catch (e) { /* server may not be ready */ }
}

// Poll metrics every 5s
setInterval(refreshMetrics, 5000);

// ── Approach Switching ─────────────────────────────────────────────────────
function switchApproach(approach) {
  state.currentApproach = approach;

  document.getElementById('tabA1').classList.toggle('active', approach === 'approach1');
  document.getElementById('tabA2').classList.toggle('active', approach === 'approach2');

  renderMetricsCards();
  addLog(`Switched to ${approach}`, 'info');
}

// ── Mode Toggle ────────────────────────────────────────────────────────────
function setMode(mode) {
  state.currentMode = mode;

  ['modeSimulator', 'modeCSV', 'modeLive'].forEach(id => {
    document.getElementById(id).classList.remove('active');
  });

  const idMap = { simulator: 'modeSimulator', csv: 'modeCSV', live: 'modeLive' };
  document.getElementById(idMap[mode]).classList.add('active');

  // Show/hide input groups
  const simInputs = document.getElementById('inputPackets').closest('div') || document.getElementById('inputGroup');
  const isSimulator = mode === 'simulator';
  const isCSV       = mode === 'csv';
  const isLive      = mode === 'live';

  document.getElementById('inputPackets').closest('div,section,label')?.parentElement;

  // Simple show/hide
  const simEls  = [document.getElementById('inputPackets'), document.getElementById('attackRatio')?.parentElement?.parentElement];
  const labelPackets = document.getElementById('inputLabel');

  if (labelPackets) labelPackets.textContent = 'Packets to Simulate';

  document.getElementById('csvInputGroup').style.display  = isCSV  ? 'block' : 'none';
  document.getElementById('liveInputGroup').style.display = isLive ? 'block' : 'none';

  // Show/hide simulator-specific controls
  const simSpecific = document.getElementById('inputPackets').parentNode;
  if (simSpecific) simSpecific.style.display = isSimulator ? 'block' : 'none';

  const sliderRow = document.getElementById('attackRatio').closest('.slider-row');
  const sliderLabel = sliderRow?.previousElementSibling;
  if (sliderRow)  sliderRow.style.display  = isSimulator ? 'flex' : 'none';
  if (sliderLabel) sliderLabel.style.display = isSimulator ? 'block' : 'none';
}

// ── Section Navigation ─────────────────────────────────────────────────────
function showSection(name, btn) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.content-tab').forEach(b => b.classList.remove('active'));

  document.getElementById(`section-${name}`).classList.add('active');
  btn.classList.add('active');

  if (name === 'charts') { updateCharts(); }
  if (name === 'compare') { updateCompareTable(); }
  if (name === 'metrics') { refreshMetrics(); }
}

// ── Chart.js Charts ────────────────────────────────────────────────────────
const CHART_DEFAULTS = {
  color: '#e6edf3',
  plugins: {
    legend: { labels: { color: '#8b949e', font: { family: 'Inter', size: 11 } } },
    tooltip: { bodyFont: { family: 'JetBrains Mono' } },
  },
};

function initCharts() {
  Chart.defaults.color = '#8b949e';
  Chart.defaults.font.family = 'Inter';

  // Chart 1: Metrics comparison bar
  state.charts.metrics = new Chart(document.getElementById('chartMetrics'), {
    type: 'bar',
    data: {
      labels: ['Accuracy', 'Precision', 'Recall', 'F1×100'],
      datasets: [
        { label: 'A1 Signature', data: [0, 0, 0, 0], backgroundColor: 'rgba(139,92,246,0.7)', borderColor: '#8b5cf6', borderWidth: 1 },
        { label: 'A2 ML',        data: [0, 0, 0, 0], backgroundColor: 'rgba(6,182,212,0.7)',  borderColor: '#06b6d4', borderWidth: 1 },
      ],
    },
    options: {
      responsive: true,
      scales: {
        y: { max: 100, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#8b949e', callback: v => v + '%' } },
        x: { grid: { display: false }, ticks: { color: '#8b949e' } },
      },
      plugins: { ...CHART_DEFAULTS.plugins },
    },
  });

  // Chart 2: Severity doughnut
  state.charts.severity = new Chart(document.getElementById('chartSeverity'), {
    type: 'doughnut',
    data: {
      labels: ['HIGH', 'MEDIUM', 'LOW'],
      datasets: [{
        data: [0, 0, 0],
        backgroundColor: ['rgba(248,81,73,0.8)', 'rgba(227,179,65,0.8)', 'rgba(88,166,255,0.8)'],
        borderColor: ['#f85149', '#e3b341', '#58a6ff'],
        borderWidth: 2,
      }],
    },
    options: {
      responsive: true,
      cutout: '65%',
      plugins: { ...CHART_DEFAULTS.plugins },
    },
  });

  // Chart 3: Top attacks horizontal bar
  state.charts.attacks = new Chart(document.getElementById('chartAttacks'), {
    type: 'bar',
    data: {
      labels: [],
      datasets: [{
        label: 'Detections',
        data: [],
        backgroundColor: 'rgba(63,185,80,0.7)',
        borderColor: '#3fb950',
        borderWidth: 1,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      scales: {
        x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#8b949e' } },
        y: { grid: { display: false }, ticks: { color: '#8b949e', font: { size: 11 } } },
      },
      plugins: { ...CHART_DEFAULTS.plugins, legend: { display: false } },
    },
  });

  // Chart 4: DR vs FPR comparison
  state.charts.drFpr = new Chart(document.getElementById('chartDRvsFPR'), {
    type: 'bar',
    data: {
      labels: ['A1 Detection Rate', 'A1 FPR', 'A2 Detection Rate', 'A2 FPR'],
      datasets: [{
        label: 'Percentage',
        data: [0, 0, 0, 0],
        backgroundColor: [
          'rgba(63,185,80,0.7)',
          'rgba(248,81,73,0.7)',
          'rgba(63,185,80,0.5)',
          'rgba(248,81,73,0.5)',
        ],
        borderColor: ['#3fb950', '#f85149', '#3fb950', '#f85149'],
        borderWidth: 1,
      }],
    },
    options: {
      responsive: true,
      scales: {
        y: { max: 100, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#8b949e', callback: v => v + '%' } },
        x: { grid: { display: false }, ticks: { color: '#8b949e', font: { size: 11 } } },
      },
      plugins: { ...CHART_DEFAULTS.plugins, legend: { display: false } },
    },
  });
}

function updateCharts() {
  const m1 = state.metrics.approach1;
  const m2 = state.metrics.approach2;

  // Metrics comparison
  if (state.charts.metrics) {
    state.charts.metrics.data.datasets[0].data = [
      m1.accuracy  || 0,
      m1.precision || 0,
      m1.recall_detection_rate || m1.recall || 0,
      (m1.f1_score || 0) * 100,
    ];
    state.charts.metrics.data.datasets[1].data = [
      m2.accuracy  || 0,
      m2.precision || 0,
      m2.recall_detection_rate || m2.recall || 0,
      (m2.f1_score || 0) * 100,
    ];
    state.charts.metrics.update('none');
  }

  // Severity distribution
  if (state.charts.severity) {
    const m = state.metrics[state.currentApproach];
    const sc = m.severity_counts || {};
    state.charts.severity.data.datasets[0].data = [
      sc.HIGH || 0, sc.MEDIUM || 0, sc.LOW || 0,
    ];
    state.charts.severity.update('none');
  }

  // Top attacks
  if (state.charts.attacks) {
    const sorted = Object.entries(state.attackCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);

    state.charts.attacks.data.labels = sorted.map(e => e[0]);
    state.charts.attacks.data.datasets[0].data = sorted.map(e => e[1]);
    state.charts.attacks.update('none');
  }

  // DR vs FPR
  if (state.charts.drFpr) {
    state.charts.drFpr.data.datasets[0].data = [
      m1.recall_detection_rate || m1.recall || 0,
      m1.false_positive_rate || m1.fpr || 0,
      m2.recall_detection_rate || m2.recall || 0,
      m2.false_positive_rate || m2.fpr || 0,
    ];
    state.charts.drFpr.update('none');
  }
}

// ── Comparison Table ───────────────────────────────────────────────────────
function updateCompareTable() {
  const m1 = state.metrics.approach1;
  const m2 = state.metrics.approach2;
  const pct = v => v != null ? `${Number(v).toFixed(1)}%` : '—';
  const num = v => v != null ? Number(v).toFixed(3) : '—';

  const a1Acc = m1.accuracy || 0;
  const a2Acc = m2.accuracy || 0;
  const a1DR  = m1.recall_detection_rate || m1.recall || 0;
  const a2DR  = m2.recall_detection_rate || m2.recall || 0;
  const a1F1  = m1.f1_score || 0;
  const a2F1  = m2.f1_score || 0;
  const a1FPR = m1.false_positive_rate || m1.fpr || 0;
  const a2FPR = m2.false_positive_rate || m2.fpr || 0;

  const winner = (a, b, higherBetter = true) => {
    if (!a && !b) return '—';
    if (higherBetter) return a >= b ? '<span class="yes">✅ A1·Sig</span>' : '<span class="yes">✅ A2·ML</span>';
    else              return a <= b ? '<span class="yes">✅ A1·Sig</span>' : '<span class="yes">✅ A2·ML</span>';
  };

  setHTML('cA1Acc', pct(a1Acc)); setHTML('cA2Acc', pct(a2Acc)); setHTML('cWinAcc', winner(a1Acc, a2Acc));
  setHTML('cA1DR',  pct(a1DR));  setHTML('cA2DR',  pct(a2DR));  setHTML('cWinDR',  winner(a1DR, a2DR));
  setHTML('cA1F1',  num(a1F1));  setHTML('cA2F1',  num(a2F1));  setHTML('cWinF1',  winner(a1F1, a2F1));
  setHTML('cA1FPR', pct(a1FPR)); setHTML('cA2FPR', pct(a2FPR)); setHTML('cWinFPR', winner(a1FPR, a2FPR, false));

  // Auto-conclusion if both have data
  if (a1Acc > 0 && a2Acc > 0) {
    const betterML = a2F1 > a1F1;
    const winner_name = betterML ? 'Approach 2 (ML Anomaly Detection)' : 'Approach 1 (Signature-Based Detection)';
    const box = document.getElementById('conclusionBox');
    const txt = document.getElementById('conclusionText');
    const badge = document.getElementById('winnerBadge');

    box.style.display = 'block';
    badge.style.display = 'inline-block';
    badge.textContent = `🏆 Winner: ${betterML ? 'ML Anomaly' : 'Signature-Based'}`;

    txt.textContent =
      `Based on the experimental results, ${winner_name} performs better overall. ` +
      `A1 achieved ${pct(a1Acc)} accuracy with ${pct(a1FPR)} false positive rate, ` +
      `while A2 achieved ${pct(a2Acc)} accuracy with ${pct(a2FPR)} false positive rate. ` +
      (betterML
        ? `The ML approach demonstrates superior detection capability, particularly against novel attack patterns not covered by the signature database.`
        : `The signature-based approach achieves higher precision with lower false positives, making it more reliable in this evaluation.`);
  }
}

// ── Log Box ────────────────────────────────────────────────────────────────
function addLog(msg, type = 'info') {
  const box = document.getElementById('logBox');
  const placeholder = box.querySelector('.log-placeholder');
  if (placeholder) placeholder.remove();

  const entry = document.createElement('div');
  entry.className = `log-entry ${type}`;
  const time = new Date().toLocaleTimeString('en-GB', { hour12: false });
  entry.textContent = `[${time}] ${msg}`;
  box.insertBefore(entry, box.firstChild);

  // Keep max 50 log lines
  while (box.children.length > 50) box.removeChild(box.lastChild);
}

// ── Connection Status ──────────────────────────────────────────────────────
function setConnectionStatus(status) {
  const dot   = document.querySelector('.status-dot');
  const label = document.querySelector('.status-label');
  dot.className   = `status-dot ${status}`;
  label.textContent = status === 'connected' ? 'Connected'
                    : status === 'running'   ? 'Running…'
                    : 'Disconnected';
}

// ── Utilities ──────────────────────────────────────────────────────────────
function setTextSafe(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function setHTML(id, html) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = html;
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Init ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  connectSSE();
  refreshMetrics();
  setMode('simulator');   // default mode
  addLog('Dashboard initialized.', 'ok');
});
