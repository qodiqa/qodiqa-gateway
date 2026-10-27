'use strict';

// shared infrastructure lives in public/js/common/ (see that
// directory for the canonical implementations). Re-exported here with `var`
// (not `const`) so each stays a property of this script's global object,
// matching how test/helpers/dashboardScriptSandbox.js exposes every other
// top-level binding in this file.
var esc = window.QodiqaCommon.esc;
var sharedRenderPager = window.QodiqaCommon.renderPager;
var createClickDispatcher = window.QodiqaCommon.createClickDispatcher;

// ── State ──────────────────────────────────────────────────────────────────
const _pages = { executions: 1, blocked: 1, replays: 1, anomalies: 1 };
let _activePanel = 'overview';
let _evtSource   = null;

// ── Navigation ─────────────────────────────────────────────────────────────
function showPanel(name) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('nav button[data-panel]').forEach((b) => {
    b.classList.toggle('active', b.dataset.panel === name);
  });
  document.getElementById('panel-' + name).classList.add('active');
  _activePanel = name;
  loadPanel(name);
}

// ── Data loaders ───────────────────────────────────────────────────────────
async function fetchJSON(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(r.status);
  return r.json();
}

async function loadPanel(name) {
  try {
    switch (name) {
      case 'overview':   await loadOverview();   break;
      case 'executions': await loadExecutions(); break;
      case 'blocked':    await loadBlocked();    break;
      case 'replays':    await loadReplays();    break;
      case 'anomalies':  await loadAnomalies();  break;
      case 'status':     await loadStatus();     break;
      case 'activity':   await loadActivity();   break;
    }
  } catch { /* silently retry on next SSE tick */ }
}

async function loadOverview() {
  const d = await fetchJSON('/dashboard/overview');
  document.getElementById('ov-total').textContent    = d.totalRequests    ?? 0;
  document.getElementById('ov-allowed').textContent  = d.allowedRequests  ?? 0;
  document.getElementById('ov-blocked').textContent  = d.blockedRequests  ?? 0;
  document.getElementById('ov-replays').textContent  = d.replayAttempts   ?? 0;
  document.getElementById('ov-anomalies').textContent= d.anomaliesDetected ?? 0;
  const intEl = document.getElementById('ov-integrity');
  intEl.textContent = d.executionIntegrity ?? '—';
  intEl.className   = 'value ' + (d.executionIntegrity === 'FULL' ? 'green' : 'red');
  document.getElementById('ov-uptime').textContent   = fmtUptime(d.uptime);
  renderReasonBars(d.byReason || {});
  document.getElementById('last-updated').textContent = 'Updated ' + fmtTime(d.timestamp);
}

function renderReasonBars(byReason) {
  const el  = document.getElementById('reason-bars');
  const entries = Object.entries(byReason).sort((a,b) => b[1]-a[1]);
  if (!entries.length) { el.innerHTML = '<div class="empty">No blocked requests.</div>'; return; }
  const max = entries[0][1] || 1;
  el.innerHTML = entries.map(([reason, count]) =>
    `<div class="reason-row">
      <div class="reason-label">${esc(reason)}</div>
      <div class="reason-bar-bg"><div class="reason-bar-fill" style="width:${(count/max*100).toFixed(1)}%"></div></div>
      <div class="reason-count">${count}</div>
    </div>`
  ).join('');
}

function renderTable(wrapId, columns, rows, emptyMsg) {
  const wrap = document.getElementById(wrapId);
  if (!rows.length) { wrap.innerHTML = `<div class="empty">${emptyMsg}</div>`; return; }
  const thead = `<tr>${columns.map(c=>`<th>${c.label}</th>`).join('')}</tr>`;
  const tbody = rows.map(r => `<tr>${columns.map(c=>`<td title="${esc(String(r[c.key]??''))}">${esc(String(r[c.key]??'—'))}</td>`).join('')}</tr>`).join('');
  wrap.innerHTML = `<table><thead>${thead}</thead><tbody>${tbody}</tbody></table>`;
}

// Pagination buttons carry data-action/data-arg (the same scheme as
// audit-viewer.js's dispatcher, via the shared createClickDispatcher below)
// instead of an inline onclick string.  This keeps script-src free of
// 'unsafe-inline' without losing per-panel pagination behaviour.
function renderPager(pagerId, total, pageSize, current, fnName) {
  document.getElementById(pagerId).innerHTML = sharedRenderPager({
    total, pageSize, page: current, actionName: fnName,
    prevLabel: '← Prev', nextLabel: 'Next →', totalWord: 'total',
  });
}

const EXEC_COLS  = [{key:'timestamp',label:'Timestamp'},{key:'artifactId',label:'Artifact ID'},{key:'provider',label:'Provider'},{key:'model',label:'Model'},{key:'tenantId',label:'Tenant'}];
const BLOCK_COLS = [{key:'timestamp',label:'Timestamp'},{key:'artifactId',label:'Artifact ID'},{key:'reason',label:'Reason'},{key:'stage',label:'Stage'},{key:'tenantId',label:'Tenant'}];
const RPL_COLS   = [{key:'timestamp',label:'Timestamp'},{key:'artifactId',label:'Artifact ID'},{key:'replayOf',label:'Original ID'},{key:'tenantId',label:'Tenant'}];
const ANO_COLS   = [{key:'timestamp',label:'Timestamp'},{key:'artifactId',label:'Artifact ID'},{key:'anomalyType',label:'Type'},{key:'tenantId',label:'Tenant'}];

async function loadExecutions(page) {
  page = page || _pages.executions;
  const d = await fetchJSON(`/dashboard/executions?page=${page}&pageSize=50`);
  _pages.executions = page;
  document.getElementById('exec-total').textContent = d.total;
  renderTable('exec-table-wrap', EXEC_COLS, d.entries, 'No executions recorded.');
  renderPager('exec-pager', d.total, d.pageSize, page, 'loadExecutions');
}

async function loadBlocked(page) {
  page = page || _pages.blocked;
  const d = await fetchJSON(`/dashboard/blocked?page=${page}&pageSize=50`);
  _pages.blocked = page;
  document.getElementById('blk-total').textContent = d.total;
  renderTable('blk-table-wrap', BLOCK_COLS, d.entries, 'No blocked requests recorded.');
  renderPager('blk-pager', d.total, d.pageSize, page, 'loadBlocked');
}

async function loadReplays(page) {
  page = page || _pages.replays;
  const d = await fetchJSON(`/dashboard/replays?page=${page}&pageSize=50`);
  _pages.replays = page;
  document.getElementById('rpl-total').textContent = d.total;
  renderTable('rpl-table-wrap', RPL_COLS, d.entries, 'No replay attempts recorded.');
  renderPager('rpl-pager', d.total, d.pageSize, page, 'loadReplays');
}

async function loadAnomalies(page) {
  page = page || _pages.anomalies;
  const d = await fetchJSON(`/dashboard/anomalies?page=${page}&pageSize=50`);
  _pages.anomalies = page;
  document.getElementById('ano-total').textContent = d.total;
  renderTable('ano-table-wrap', ANO_COLS, d.entries, 'No anomaly events recorded.');
  renderPager('ano-pager', d.total, d.pageSize, page, 'loadAnomalies');
}

async function loadStatus() {
  const d = await fetchJSON('/dashboard/status');
  document.getElementById('st-service').textContent = d.service  ?? '—';
  document.getElementById('st-version').textContent = d.version  ?? '—';
  document.getElementById('st-status').textContent  = d.status   ?? '—';
  document.getElementById('st-mem').textContent     = (d.memoryMb ?? '—') + ' MB';
  document.getElementById('st-pid').textContent     = d.pid      ?? '—';
  document.getElementById('st-node').textContent    = d.nodeVersion ?? '—';
  const grid = document.getElementById('comp-grid');
  const comps = Object.entries(d.components || {});
  if (!comps.length) { grid.innerHTML = '<div class="empty">No components.</div>'; return; }
  grid.innerHTML = comps.map(([, c]) => `
    <div class="comp-card">
      <div class="comp-dot ${c.ready?'ready':'degraded'}"></div>
      <div>
        <div class="comp-name">${esc(c.name)}</div>
        <div class="comp-sub">${c.ready ? 'Operational' : 'DEGRADED — fail-closed'}</div>
      </div>
    </div>`).join('');
}

async function loadActivity() {
  const d = await fetchJSON('/dashboard/activity?windowMinutes=60');
  renderActivityChart(d.series || []);
}

function renderActivityChart(series) {
  const el = document.getElementById('activity-chart');
  if (!series.length) { el.innerHTML = '<div class="empty">No activity data.</div>'; return; }
  const W = 900, H = 160, PL = 40, PB = 30;
  const maxVal = Math.max(1, ...series.map(s => s.allowed + s.blocked));
  const n = series.length;
  const bw = Math.max(2, (W - PL) / n - 2);
  const bars = series.map((s, i) => {
    const x   = PL + i * ((W - PL) / n);
    const tot = s.allowed + s.blocked;
    const ah  = ((s.allowed / maxVal) * (H - PB)).toFixed(1);
    const bh  = ((s.blocked / maxVal) * (H - PB)).toFixed(1);
    const ay  = (H - PB - parseFloat(ah)).toFixed(1);
    const by  = (parseFloat(ay) - parseFloat(bh)).toFixed(1);
    return `<rect x="${x.toFixed(1)}" y="${ay}" width="${bw}" height="${ah}" fill="#22c55e" opacity=".8"/>
            <rect x="${x.toFixed(1)}" y="${by}" width="${bw}" height="${bh}" fill="#ef4444" opacity=".8"/>
            <title>${s.minute}: ${s.allowed} allowed, ${s.blocked} blocked</title>`;
  }).join('');
  el.innerHTML = `<svg class="chart-svg" viewBox="0 0 ${W} ${H}" width="100%" height="${H}">
    <text x="4" y="14" font-size="10" fill="#64748b">Req</text>
    <line x1="${PL}" y1="0" x2="${PL}" y2="${H-PB}" stroke="#2e3147" stroke-width="1"/>
    <line x1="${PL}" y1="${H-PB}" x2="${W}" y2="${H-PB}" stroke="#2e3147" stroke-width="1"/>
    ${bars}
    <rect x="${PL+20}" y="${H-20}" width="10" height="8" fill="#22c55e" opacity=".8"/>
    <text x="${PL+34}" y="${H-13}" font-size="10" fill="#e2e8f0">Allowed</text>
    <rect x="${PL+100}" y="${H-20}" width="10" height="8" fill="#ef4444" opacity=".8"/>
    <text x="${PL+114}" y="${H-13}" font-size="10" fill="#e2e8f0">Blocked</text>
  </svg>`;
}

// ── SSE stream ─────────────────────────────────────────────────────────────
function connectStream() {
  if (_evtSource) { _evtSource.close(); _evtSource = null; }
  try {
    _evtSource = new (window.QodiqaAuthEventSource || EventSource)('/dashboard/stream');
    _evtSource.addEventListener('snapshot', (e) => {
      const d = JSON.parse(e.data);
      setSseStatus(true);
      if (d.overview) applyOverviewSnapshot(d.overview, d.status);
      if (_activePanel === 'status' && d.status) applyStatusSnapshot(d.status);
    });
    _evtSource.onerror = () => {
      setSseStatus(false);
      setTimeout(connectStream, 5000);
    };
  } catch { setSseStatus(false); }
}

function setSseStatus(live) {
  document.getElementById('stream-dot').className   = live ? 'live' : '';
  document.getElementById('stream-label').textContent = live ? 'Live' : 'Reconnecting…';
}

function applyOverviewSnapshot(ov, st) {
  if (_activePanel !== 'overview') return;
  if (ov.totalRequests    !== undefined) document.getElementById('ov-total').textContent    = ov.totalRequests;
  if (ov.allowedRequests  !== undefined) document.getElementById('ov-allowed').textContent  = ov.allowedRequests;
  if (ov.blockedRequests  !== undefined) document.getElementById('ov-blocked').textContent  = ov.blockedRequests;
  if (ov.replayAttempts   !== undefined) document.getElementById('ov-replays').textContent  = ov.replayAttempts;
  if (ov.anomaliesDetected!== undefined) document.getElementById('ov-anomalies').textContent= ov.anomaliesDetected;
  if (ov.byReason)                       renderReasonBars(ov.byReason);
  if (st) {
    const intEl = document.getElementById('ov-integrity');
    intEl.textContent = st.executionIntegrity ?? '—';
    intEl.className   = 'value ' + (st.executionIntegrity === 'FULL' ? 'green' : 'red');
    document.getElementById('ov-uptime').textContent = fmtUptime(st.uptime);
  }
}

function applyStatusSnapshot(st) {
  document.getElementById('st-mem').textContent = (st.memoryMb ?? '—') + ' MB';
  document.getElementById('ov-uptime').textContent = fmtUptime(st.uptime);
}

// ── Helpers ────────────────────────────────────────────────────────────────
function fmtUptime(s) {
  if (s == null) return '—';
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = Math.floor(s % 60);
  return `${h}h ${m}m ${sec}s`;
}
function fmtTime(iso) { return iso ? new Date(iso).toLocaleTimeString() : '—'; }

// ── Delegated event handlers ─────────────
const PAGE_FNS = { loadExecutions, loadBlocked, loadReplays, loadAnomalies };

document.querySelector('nav').addEventListener('click', (e) => {
  const btn = e.target.closest('button[data-panel]');
  if (btn) showPanel(btn.dataset.panel);
});

document.addEventListener('click', createClickDispatcher(PAGE_FNS));

// ── Init ───────────────────────────────────────────────────────────────────
loadPanel('overview');
connectStream();
