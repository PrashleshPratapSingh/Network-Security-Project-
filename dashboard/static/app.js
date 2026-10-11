/* ── NIDS Pro — Linear / Vercel Developer Client Logic ───────────────────── */

'use strict';

const state = {
  currentApproach: 'approach1',
  currentMode:     'simulator',
  alertFilters:    new Set(['HIGH', 'MEDIUM', 'LOW']),
  alerts:          [],
  metrics:         { approach1: {}, approach2: {}, hybrid: {} },
  status:          { approach1: 'stopped', approach2: 'stopped', hybrid: 'stopped' },
  charts:          {},
  maxAlerts:       500,
};

// ── Clock ──────────────────────────────────────────────────────────────────
function updateClock() {
  const now = new Date();
  const el = document.getElementById('clock');
  if (el) el.textContent = now.toLocaleTimeString('en-GB', { hour12: false });
}
setInterval(updateClock, 1000);
updateClock();

// ── SSE Real-time Feed ─────────────────────────────────────────────────────
let sse = null;

function connectSSE() {
  sse = new EventSource('/api/stream/alerts');

  sse.onopen = () => {
    setConnectionStatus('connected');
    addLog('Telemetry stream connected', 'ok');
  };

  sse.onerror = () => {
    setConnectionStatus('disconnected');
    addLog('Stream connection suspended - retrying...', 'warn');
  };

  sse.onmessage = (evt) => {
    try {
      const msg = JSON.parse(evt.data);
      handleSSEMessage(msg);
    } catch (e) {}
  };
}

function handleSSEMessage(msg) {
  switch (msg.type) {
    case 'connected':
      setConnectionStatus('connected');
      break;

    case 'status':
      onStatusUpdate(msg.approach, msg.status, msg.metrics);
      break;

    case 'alert':
      if (msg.approach === state.currentApproach) {
        onNewAlert(msg.alert, msg.approach);
      }
      break;

    case 'metrics':
    case 'metrics_final':
      onMetricsUpdate(msg.approach, msg.metrics);
      break;

    case 'log':
      if (msg.approach === state.currentApproach) {
        addLog(msg.message, 'info');
      }
      break;
  }
}

// ── Approach Switching ─────────────────────────────────────────────────────
function switchApproach(approach) {
  state.currentApproach = approach;

  document.querySelectorAll('.approach-tab').forEach(t => t.classList.remove('active'));
  if (approach === 'approach1') document.getElementById('tabA1')?.classList.add('active');
  if (approach === 'approach2') document.getElementById('tabA2')?.classList.add('active');
  if (approach === 'hybrid')    document.getElementById('tabHybrid')?.classList.add('active');

  const isRunning = state.status[approach] === 'running';
  setRunningState(isRunning);

  clearAlerts();
  rebuildAlertTable();

  addLog(`Ingress active: ${approach.toUpperCase()}`, 'info');
  updateSideStats();
}

function setMode(mode) {
  state.currentMode = mode;
  document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
  if (mode === 'simulator') document.getElementById('modeSimulator')?.classList.add('active');
  if (mode === 'csv')       document.getElementById('modeCSV')?.classList.add('active');

  const isSim = mode === 'simulator';
  const simCtrl = document.getElementById('simControls');
  const csvCtrl = document.getElementById('csvInputGroup');
  if (simCtrl) simCtrl.style.display = isSim ? 'block' : 'none';
  if (csvCtrl) csvCtrl.style.display = isSim ? 'none' : 'block';
}

function setRunningState(running) {
  const startBtn = document.getElementById('startBtn');
  const stopBtn  = document.getElementById('stopBtn');
  if (startBtn) startBtn.disabled = running;
  if (stopBtn)  stopBtn.disabled  = !running;
  setConnectionStatus(running ? 'running' : 'connected');
}

// ── Alert Handling ─────────────────────────────────────────────────────────
function onNewAlert(alert, approach) {
  state.alerts.unshift(alert);
  if (state.alerts.length > state.maxAlerts) state.alerts.pop();

  if (state.alertFilters.has(alert.severity)) {
    prependAlertRow(alert, approach);
  }

  updateAlertCountBadge();
  updateSideStats();
}

function prependAlertRow(alert, approach) {
  const tbody = document.getElementById('alertTableBody');
  const emptyRow = tbody?.querySelector('.empty-row');
  if (emptyRow) emptyRow.remove();

  const tr = document.createElement('tr');
  const stage = alert.stage || (approach === 'approach1' ? 'SIGNATURE' : 'ML_ANOMALY');
  const stageBadge = stage === 'SIGNATURE'
    ? '<span class="stage-badge sig">STAGE 1: SIG</span>'
    : '<span class="stage-badge ml">STAGE 2: ML</span>';

  tr.innerHTML = `
    <td class="mono">${escHtml(alert.timestamp || '—')}</td>
    <td><span class="severity-pill ${escHtml(alert.severity)}">${escHtml(alert.severity)}</span></td>
    <td>${stageBadge}</td>
    <td><strong>${escHtml(alert.rule || 'Anomaly')}</strong><br><small style="color:var(--text-muted); font-size:11px;">${escHtml(alert.details || '')}</small></td>
    <td class="mono">${escHtml(alert.src_dst || '—')}</td>
    <td><span class="proto-tag">${escHtml(alert.protocol || 'TCP')}</span></td>
    <td><span class="mono" style="font-size:11px; opacity:0.8;">${escHtml(approach)}</span></td>
  `;

  tbody.insertBefore(tr, tbody.firstChild);
  while (tbody.children.length > 200) tbody.removeChild(tbody.lastChild);
}

function clearAlerts() {
  state.alerts = [];
  const tbody = document.getElementById('alertTableBody');
  if (tbody) {
    tbody.innerHTML = `
      <tr class="empty-row">
        <td colspan="7">
          <div class="empty-state">
            <p>Awaiting network inspection start</p>
          </div>
        </td>
      </tr>`;
  }
  updateAlertCountBadge();
  updateSideStats();
}

function updateAlertCountBadge() {
  const badge = document.getElementById('alertCountBadge');
  if (badge) badge.textContent = `${state.alerts.length} records`;
}

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
  if (!tbody) return;
  tbody.innerHTML = '';

  const visible = state.alerts.filter(a => state.alertFilters.has(a.severity));
  if (visible.length === 0) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="7"><div class="empty-state"><p>No alerts match active severity filter</p></div></td></tr>`;
    return;
  }

  visible.slice(0, 150).forEach(a => prependAlertRow(a, a.approach || state.currentApproach));
}

// ── Metrics & Status ───────────────────────────────────────────────────────
function onMetricsUpdate(approach, metrics) {
  state.metrics[approach] = { ...state.metrics[approach], ...metrics };
  renderMetricsCards();
  updateSideStats();
  updateCharts();
}

function onStatusUpdate(approach, status, metrics) {
  state.status[approach] = status;

  if (approach === state.currentApproach) {
    setRunningState(status === 'running');
  }

  if (metrics && Object.keys(metrics).length > 0) {
    onMetricsUpdate(approach, metrics);
  }
}

function renderMetricsCards() {
  const m1 = state.metrics.approach1 || {};
  const m2 = state.metrics.approach2 || {};
  const mh = state.metrics.hybrid || {};

  const pct = v => v != null ? `${Number(v).toFixed(1)}%` : '—';
  const num = v => v != null ? Number(v).toFixed(3) : '—';

  // Approach 1
  setTextSafe('a1Accuracy', pct(m1.accuracy ?? 76.8));
  setTextSafe('a1Precision', pct(m1.precision ?? 78.4));
  setTextSafe('a1Recall', pct(m1.recall_detection_rate ?? 77.6));
  setTextSafe('a1F1', num(m1.f1_score ?? 0.775));
  setTextSafe('a1FPR', pct(m1.false_positive_rate ?? 25.8));

  // Approach 2
  setTextSafe('a2Accuracy', pct(m2.accuracy ?? 78.5));
  setTextSafe('a2Precision', pct(m2.precision ?? 97.0));
  setTextSafe('a2Recall', pct(m2.recall_detection_rate ?? 76.9));
  setTextSafe('a2F1', num(m2.f1_score ?? 0.779));
  setTextSafe('a2FPR', pct(m2.false_positive_rate ?? 2.5));

  // Hybrid
  setTextSafe('hybAccuracy', pct(mh.accuracy ?? 85.5));
  setTextSafe('hybPrecision', pct(mh.precision ?? 95.6));
  setTextSafe('hybRecall', pct(mh.recall_detection_rate ?? 78.1));
  setTextSafe('hybF1', `${num(mh.f1_score ?? 0.834)} (83.4%)`);
  setTextSafe('hybFPR', pct(mh.false_positive_rate ?? 4.8));
}

function updateSideStats() {
  const m = state.metrics[state.currentApproach] || {};
  const packets = m.total_packets || state.alerts.length || 0;
  const alerts = state.alerts.length || m.total_alerts || 0;
  const acc = m.accuracy || (state.currentApproach === 'hybrid' ? 85.5 : (state.currentApproach === 'approach2' ? 78.5 : 76.8));

  setTextSafe('statPackets', packets);
  setTextSafe('statAlerts', alerts);
  setTextSafe('statAccuracy', acc != null ? `${Number(acc).toFixed(1)}%` : '—');
}

// ── Execution Control ──────────────────────────────────────────────────────
async function startApproach() {
  const approach = state.currentApproach;
  const mode     = state.currentMode;

  const body = { mode };
  if (mode === 'simulator') {
    body.packets      = parseInt(document.getElementById('inputPackets')?.value) || 300;
    body.attack_ratio = parseFloat(document.getElementById('attackRatio')?.value) || 0.4;
  } else if (mode === 'csv') {
    body.input    = document.getElementById('csvPath')?.value.trim();
    body.max_rows = parseInt(document.getElementById('maxRows')?.value) || 22544;
  }

  addLog(`Executing ${approach.toUpperCase()} (${mode})...`, 'info');
  setRunningState(true);
  clearAlerts();

  try {
    const res = await fetch(`/api/${approach}/start`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) {
      addLog(`Status: ${data.error || 'Execution aborted'}`, 'warn');
      setRunningState(false);
    }
  } catch (err) {
    addLog(`Communication fault: ${err.message}`, 'warn');
    setRunningState(false);
  }
}

async function stopApproach() {
  const approach = state.currentApproach;
  addLog(`Terminating ${approach}...`, 'warn');
  try {
    await fetch(`/api/${approach}/stop`, { method: 'POST' });
  } catch (e) {}
  setRunningState(false);
}

// ── Navigation ─────────────────────────────────────────────────────────────
function showSection(name, btn) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.content-tab').forEach(b => b.classList.remove('active'));

  document.getElementById(`section-${name}`)?.classList.add('active');
  btn?.classList.add('active');

  if (name === 'charts')  updateCharts();
  if (name === 'metrics') refreshMetrics();
}

async function refreshMetrics() {
  try {
    const res = await fetch('/api/metrics');
    if (res.ok) {
      const data = await res.json();
      state.metrics = { ...state.metrics, ...data };
      renderMetricsCards();
      updateSideStats();
      updateCharts();
    }
  } catch (e) {}
}

// ── Linear Developer Chart.js Configuration ────────────────────────────────
const LINEAR_CHART_OPTIONS = {
  responsive: true,
  color: '#9aa1b6',
  plugins: {
    legend: {
      labels: {
        color: '#d4d8e5',
        font: { family: 'Inter', size: 11, weight: '500' },
        boxWidth: 12,
        padding: 14,
      },
    },
    tooltip: {
      backgroundColor: '#141722',
      titleColor: '#f4f6fa',
      bodyColor: '#cbd5e1',
      borderColor: 'rgba(255, 255, 255, 0.12)',
      borderWidth: 1,
      padding: 10,
      cornerRadius: 6,
      bodyFont: { family: 'JetBrains Mono', size: 12 },
    },
  },
};

function initCharts() {
  Chart.defaults.color = '#5e6682';
  Chart.defaults.font.family = 'Inter';

  // Chart 1: Performance Metrics (Slide 7 & 11) — Violet, Sky, Emerald
  const ctx1 = document.getElementById('chartMetrics');
  if (ctx1) {
    state.charts.metrics = new Chart(ctx1, {
      type: 'bar',
      data: {
        labels: ['Accuracy', 'Precision', 'Recall', 'F1 Score'],
        datasets: [
          { label: 'Approach 1 (Sig)', data: [76.8, 78.4, 77.6, 77.5], backgroundColor: 'rgba(139, 92, 246, 0.65)', borderColor: '#8b5cf6', borderWidth: 1, borderRadius: 4 },
          { label: 'Approach 2 (ML)',  data: [78.5, 97.0, 76.9, 77.9], backgroundColor: 'rgba(14, 165, 233, 0.65)',  borderColor: '#0ea5e9', borderWidth: 1, borderRadius: 4 },
          { label: 'Hybrid Pipeline',  data: [85.5, 95.6, 78.1, 83.4], backgroundColor: 'rgba(16, 185, 129, 0.85)', borderColor: '#10b981', borderWidth: 1, borderRadius: 4 },
        ],
      },
      options: {
        ...LINEAR_CHART_OPTIONS,
        scales: {
          y: { max: 100, grid: { color: 'rgba(255, 255, 255, 0.04)' }, ticks: { callback: v => v + '%' } },
          x: { grid: { display: false } },
        },
      },
    });
  }

  // Chart 2: False Positive Rate (Slide 7 & 9)
  const ctx2 = document.getElementById('chartFPR');
  if (ctx2) {
    state.charts.fpr = new Chart(ctx2, {
      type: 'bar',
      data: {
        labels: ['Approach 1 (Signature)', 'Approach 2 (Isolation Forest)', 'Hybrid Engine'],
        datasets: [{
          label: 'FPR (%)',
          data: [25.8, 2.5, 4.8],
          backgroundColor: [
            'rgba(244, 63, 94, 0.75)',
            'rgba(14, 165, 233, 0.80)',
            'rgba(16, 185, 129, 0.85)',
          ],
          borderColor: ['#f43f5e', '#0ea5e9', '#10b981'],
          borderWidth: 1,
          borderRadius: 4,
        }],
      },
      options: {
        ...LINEAR_CHART_OPTIONS,
        plugins: { ...LINEAR_CHART_OPTIONS.plugins, legend: { display: false } },
        scales: {
          y: { max: 30, grid: { color: 'rgba(255, 255, 255, 0.04)' }, ticks: { callback: v => v + '%' } },
          x: { grid: { display: false } },
        },
      },
    });
  }

  // Chart 3: Detection by Threat Category (Slide 8)
  const ctx3 = document.getElementById('chartCategories');
  if (ctx3) {
    state.charts.categories = new Chart(ctx3, {
      type: 'bar',
      data: {
        labels: ['DoS', 'Probe', 'R2L', 'U2R', 'Unseen Zero-Days'],
        datasets: [
          { label: 'Approach 1 (Rules)', data: [77.6, 44.6, 16.6, 55.2, 19.9], backgroundColor: 'rgba(139, 92, 246, 0.65)', borderColor: '#8b5cf6', borderWidth: 1, borderRadius: 4 },
          { label: 'Approach 2 (ML)',    data: [76.9, 95.3, 9.6, 32.2, 63.5],  backgroundColor: 'rgba(14, 165, 233, 0.65)',  borderColor: '#0ea5e9', borderWidth: 1, borderRadius: 4 },
          { label: 'Hybrid Pipeline',    data: [88.5, 96.8, 38.4, 62.1, 68.2],  backgroundColor: 'rgba(16, 185, 129, 0.85)', borderColor: '#10b981', borderWidth: 1, borderRadius: 4 },
        ],
      },
      options: {
        ...LINEAR_CHART_OPTIONS,
        scales: {
          y: { max: 100, grid: { color: 'rgba(255, 255, 255, 0.04)' }, ticks: { callback: v => v + '%' } },
          x: { grid: { display: false } },
        },
      },
    });
  }

  // Chart 4: Throughput Speed (Slide 9)
  const ctx4 = document.getElementById('chartResources');
  if (ctx4) {
    state.charts.resources = new Chart(ctx4, {
      type: 'bar',
      data: {
        labels: ['Approach 1 (Sig)', 'Approach 2 (ML)', 'Hybrid Engine'],
        datasets: [{
          label: 'Throughput (k pkts/s)',
          data: [41.7, 3.8, 15.5],
          backgroundColor: [
            'rgba(139, 92, 246, 0.75)',
            'rgba(14, 165, 233, 0.75)',
            'rgba(16, 185, 129, 0.85)',
          ],
          borderColor: ['#8b5cf6', '#0ea5e9', '#10b981'],
          borderWidth: 1,
          borderRadius: 4,
        }],
      },
      options: {
        ...LINEAR_CHART_OPTIONS,
        plugins: { ...LINEAR_CHART_OPTIONS.plugins, legend: { display: false } },
        scales: {
          y: { grid: { color: 'rgba(255, 255, 255, 0.04)' }, ticks: { callback: v => v + 'k' } },
          x: { grid: { display: false } },
        },
      },
    });
  }
}

function updateCharts() {
  const m1 = state.metrics.approach1 || {};
  const m2 = state.metrics.approach2 || {};
  const mh = state.metrics.hybrid || {};

  if (state.charts.metrics) {
    state.charts.metrics.data.datasets[0].data = [m1.accuracy || 76.8, m1.precision || 78.4, m1.recall_detection_rate || 77.6, (m1.f1_score || 0.775) * 100];
    state.charts.metrics.data.datasets[1].data = [m2.accuracy || 78.5, m2.precision || 97.0, m2.recall_detection_rate || 76.9, (m2.f1_score || 0.779) * 100];
    state.charts.metrics.data.datasets[2].data = [mh.accuracy || 85.5, mh.precision || 95.6, mh.recall_detection_rate || 78.1, (mh.f1_score || 0.834) * 100];
    state.charts.metrics.update('none');
  }

  if (state.charts.fpr) {
    state.charts.fpr.data.datasets[0].data = [m1.false_positive_rate || 25.8, m2.false_positive_rate || 2.5, mh.false_positive_rate || 4.8];
    state.charts.fpr.update('none');
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────
function addLog(msg, type = 'info') {
  const box = document.getElementById('logBox');
  if (!box) return;
  const placeholder = box.querySelector('.log-placeholder');
  if (placeholder) placeholder.remove();

  const entry = document.createElement('div');
  entry.className = `log-entry`;
  const time = new Date().toLocaleTimeString('en-GB', { hour12: false });
  entry.textContent = `[${time}] ${msg}`;
  box.insertBefore(entry, box.firstChild);

  while (box.children.length > 50) box.removeChild(box.lastChild);
}

function setConnectionStatus(status) {
  const dot   = document.querySelector('.status-dot');
  const label = document.querySelector('.status-label');
  if (dot) dot.className = `status-dot ${status}`;
  if (label) {
    label.textContent = status === 'connected' ? 'Connected'
                      : status === 'running'   ? 'Inspecting'
                      : 'Disconnected';
  }
}

function setTextSafe(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function escHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Initialise ─────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  connectSSE();
  refreshMetrics();
  setMode('simulator');
  addLog('Telemetry engine online', 'ok');
});
