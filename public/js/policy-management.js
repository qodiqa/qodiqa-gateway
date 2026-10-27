// shared infrastructure lives in public/js/common/ (see that
// directory for the canonical implementations). Re-exported here with `var`
// (not `const`) so each stays a property of this script's global object,
// matching how test/helpers/dashboardScriptSandbox.js exposes every other
// top-level binding in this file.
var esc = window.QodiqaCommon.esc;
var attrJs = window.QodiqaCommon.attrJs;
var sharedPaginate = window.QodiqaCommon.paginate;
var badge = window.QodiqaCommon.badge;
var createClickDispatcher = window.QodiqaCommon.createClickDispatcher;

/* ─────────────────────────────────────────────────────────────
   STATE
───────────────────────────────────────────────────────────────*/
const S = {
  activeTab: 'dashboard',
  policies: { page: 1, pageSize: 20, total: 0, status: '', search: '' },
  editor:   { mode: 'CREATE', policyId: null, timeWindows: [] },
  versions: { policyId: null },
  diff:     { policyId: null },
  rollback: { policyId: null, toVersion: null, versions: [] },
  history:  { policyId: null },
  details:  { policyId: null, fromTab: 'policies' },
};

let _modalCallback = null;
let _debounceTimer = null;

/* ─────────────────────────────────────────────────────────────
   UTILITIES
───────────────────────────────────────────────────────────────*/
function short(s, n = 40) {
  s = String(s ?? '');
  return s.length > n ? s.slice(0, n) + '…' : s;
}

function fmt(ts) {
  if (!ts) return '—';
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

function fmtType(t) {
  const m = { REQUIRE_CONSENT: 'Require Consent', BLOCK_IP: 'Block IP', TIME_WINDOW: 'Time Window', RATE_LIMIT: 'Rate Limit' };
  return m[t] || t;
}

function statusBadge(s) {
  if (s === 'ACTIVE')   return badge('ACTIVE', 'green');
  if (s === 'DISABLED') return badge('DISABLED', 'red');
  return badge(s, '');
}

function typeBadge(t) {
  return badge(fmtType(t), 'accent');
}

function histBadge(ev) {
  const m = {
    POLICY_CREATED:     'blue',
    POLICY_UPDATED:     'yellow',
    POLICY_ENABLED:     'green',
    POLICY_DISABLED:    'red',
    POLICY_ROLLED_BACK: 'orange',
    POLICY_IMPORTED:    '',
  };
  return badge(ev, m[ev] || '');
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).catch(() => {});
}

function copyBtn(text) {
  return `<button class="copy-btn" title="Copy" data-action="copyToClipboard" data-arg="${attrJs(text)}">⧉</button>`;
}

/* ─────────────────────────────────────────────────────────────
   API HELPER
───────────────────────────────────────────────────────────────*/
async function api(path, options) {
  const r = await fetch(path, options);
  if (!r.ok) {
    const err = await r.json().catch(() => ({ reason: r.statusText }));
    throw Object.assign(new Error(err.reason || r.statusText), { status: r.status, body: err });
  }
  const json = await r.json();
  // Unwrap the standard { status, timestamp, requestId, data } envelope
  return (json && typeof json === 'object' && 'data' in json) ? json.data : json;
}

/* ─────────────────────────────────────────────────────────────
   TAB SWITCHING
───────────────────────────────────────────────────────────────*/
function switchTab(name, skipLoad) {
  S.activeTab = name;
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  const panel = document.getElementById('tab-' + name);
  if (panel) panel.classList.add('active');
  const btn = document.querySelector(`.tab-btn[data-tab="${name}"]`);
  if (btn) btn.classList.add('active');

  if (!skipLoad) {
    if (name === 'dashboard') loadDashboard();
    if (name === 'policies')  loadPolicies();
  }
}

document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => switchTab(btn.dataset.tab));
});

/* ─────────────────────────────────────────────────────────────
   MODAL
───────────────────────────────────────────────────────────────*/
function openModal(title, body, confirmLabel, cls, cb) {
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-body').textContent = body;
  const confirmBtn = document.getElementById('modal-confirm-btn');
  confirmBtn.textContent = confirmLabel || 'Confirm';
  confirmBtn.className = 'btn ' + (cls || 'danger');
  _modalCallback = cb;
  document.getElementById('confirm-modal').classList.add('open');
}

function closeModal() {
  document.getElementById('confirm-modal').classList.remove('open');
  _modalCallback = null;
}

document.getElementById('modal-confirm-btn').addEventListener('click', () => {
  if (_modalCallback) { _modalCallback(); }
  closeModal();
});

document.getElementById('confirm-modal').addEventListener('click', e => {
  if (e.target === e.currentTarget) closeModal();
});

/* ─────────────────────────────────────────────────────────────
   INLINE MESSAGE HELPERS
───────────────────────────────────────────────────────────────*/
function showMsg(elId, html, type = 'info') {
  const el = document.getElementById(elId);
  if (!el) return;
  const cls = type === 'error' ? 'error-box' : type === 'success' ? 'success-box' : 'info-box';
  el.innerHTML = `<div class="${cls}">${html}</div>`;
}

function clearMsg(elId) {
  const el = document.getElementById(elId);
  if (el) el.innerHTML = '';
}

/* ─────────────────────────────────────────────────────────────
   TAB 1 — DASHBOARD
───────────────────────────────────────────────────────────────*/
async function loadDashboard() {
  document.getElementById('dash-recent-wrap').innerHTML = '<div class="loading"></div>';
  try {
    const data = await api('/policy-ui/dashboard');
    document.getElementById('dc-total').textContent    = data.total    ?? '—';
    document.getElementById('dc-active').textContent   = data.active   ?? '—';
    document.getElementById('dc-disabled').textContent = data.disabled ?? '—';
    document.getElementById('dc-versions').textContent = data.versionCount ?? '—';
    document.getElementById('dc-valfails').textContent = data.validationFailures ?? '—';

    const rows = (data.recentChanges || []);
    if (!rows.length) {
      document.getElementById('dash-recent-wrap').innerHTML = '<div class="empty">No recent changes.</div>';
      return;
    }
    let html = `<table>
      <thead><tr>
        <th>Event</th><th>Policy</th><th>Actor</th><th>Version</th><th>Timestamp</th>
      </tr></thead><tbody>`;
    for (const r of rows) {
      html += `<tr>
        <td>${histBadge(r.event)}</td>
        <td style="color:var(--accent);cursor:pointer" data-action="viewPolicy" data-arg="${attrJs(r.policyId || '')}">${esc(short(r.policyId, 30))}</td>
        <td>${esc(r.actor || '—')}</td>
        <td>${esc(r.version ?? '—')}</td>
        <td>${fmt(r.timestamp)}</td>
      </tr>`;
    }
    html += '</tbody></table>';
    document.getElementById('dash-recent-wrap').innerHTML = html;
  } catch (e) {
    document.getElementById('dash-recent-wrap').innerHTML = `<div class="error-box">${esc(e.message)}</div>`;
  }
}

/* ─────────────────────────────────────────────────────────────
   TAB 2 — POLICIES
───────────────────────────────────────────────────────────────*/
function setPolicyFilter(btn, status) {
  document.querySelectorAll('.filter-toggle').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  S.policies.status = status;
  S.policies.page = 1;
  loadPolicies();
}

function debouncedPoliciesLoad() {
  clearTimeout(_debounceTimer);
  _debounceTimer = setTimeout(() => {
    S.policies.search = document.getElementById('pol-search').value.trim();
    S.policies.page = 1;
    loadPolicies();
  }, 350);
}

function policiesPage(dir) {
  const { totalPages } = sharedPaginate(S.policies.total, S.policies.pageSize, S.policies.page);
  const newPage = S.policies.page + dir;
  if (newPage < 1 || newPage > totalPages) return;
  S.policies.page = newPage;
  loadPolicies();
}

async function loadPolicies() {
  const wrap = document.getElementById('pol-table-wrap');
  wrap.innerHTML = '<div class="loading"></div>';
  document.getElementById('pol-pagination').style.display = 'none';

  const params = new URLSearchParams({
    page: S.policies.page,
    pageSize: S.policies.pageSize,
  });
  if (S.policies.status) params.set('status', S.policies.status);
  if (S.policies.search) params.set('search', S.policies.search);

  try {
    const data = await api(`/policy-ui/policies?${params}`);
    const items = data.policies || data.items || [];
    S.policies.total = data.total || items.length;

    if (!items.length) {
      wrap.innerHTML = '<div class="empty">No policies found.</div>';
      return;
    }

    let html = `<table>
      <thead><tr>
        <th>ID</th><th>Name</th><th>Type</th><th>Status</th>
        <th>Version</th><th>Last Modified</th><th>Modified By</th><th>Actions</th>
      </tr></thead><tbody>`;

    for (const p of items) {
      const pid = p.policyId || p.id || '';
      html += `<tr class="clickable-row" data-action="viewPolicy" data-arg="${attrJs(pid)}">
        <td style="color:var(--accent)">${esc(pid)}</td>
        <td style="max-width:160px">${esc(short(p.name, 30))}</td>
        <td>${typeBadge(p.type)}</td>
        <td>${statusBadge(p.status)}</td>
        <td>${esc(p.version ?? '—')}</td>
        <td>${fmt(p.updatedAt || p.lastModified)}</td>
        <td>${esc(p.updatedBy || p.modifiedBy || '—')}</td>
        <td data-action="stopPropagation" style="white-space:nowrap">
          <button class="btn xs secondary" data-action="viewPolicy" data-arg="${attrJs(pid)}">View</button>
          <button class="btn xs ${p.status === 'ACTIVE' ? 'danger' : 'success'}"
            data-action="togglePolicy" data-args="${attrJs([pid, p.status])}">
            ${p.status === 'ACTIVE' ? 'Disable' : 'Enable'}
          </button>
          <button class="btn xs secondary" data-action="editPolicy" data-arg="${attrJs(pid)}">Edit</button>
        </td>
      </tr>`;
    }
    html += '</tbody></table>';
    wrap.innerHTML = html;

    const { totalPages } = sharedPaginate(S.policies.total, S.policies.pageSize, S.policies.page);
    if (totalPages > 1) {
      document.getElementById('pol-pagination').style.display = 'flex';
      document.getElementById('pol-page-info').textContent =
        `Page ${S.policies.page} of ${totalPages} (${S.policies.total} total)`;
      document.getElementById('pol-prev').disabled = S.policies.page <= 1;
      document.getElementById('pol-next').disabled = S.policies.page >= totalPages;
    }
  } catch (e) {
    wrap.innerHTML = `<div class="error-box">${esc(e.message)}</div>`;
  }
}

async function togglePolicy(policyId, currentStatus) {
  if (currentStatus === 'ACTIVE') {
    openModal(
      'Disable Policy',
      `Are you sure you want to disable policy "${policyId}"? It will stop being enforced immediately.`,
      'Disable',
      'danger',
      () => doToggle(policyId, 'disable')
    );
  } else {
    await doToggle(policyId, 'enable');
  }
}

async function doToggle(policyId, action) {
  try {
    await api(`/policy-ui/policies/${encodeURIComponent(policyId)}/${action}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    loadPolicies();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

function viewPolicy(policyId) {
  S.details.policyId = policyId;
  S.details.fromTab = S.activeTab;
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  switchTab('details', true);
  loadDetails(policyId);
}

async function editPolicy(policyId) {
  try {
    const res = await api(`/policy-ui/policies/${encodeURIComponent(policyId)}`);
    startEdit(res.policy || res);
    switchTab('editor', true);
  } catch (e) {
    alert('Error loading policy: ' + e.message);
  }
}

/* ─────────────────────────────────────────────────────────────
   TAB 3 — EDITOR
───────────────────────────────────────────────────────────────*/
function startCreate() {
  S.editor.mode = 'CREATE';
  S.editor.policyId = null;
  S.editor.timeWindows = [];
  document.getElementById('editor-title').textContent = 'New Policy';
  document.getElementById('editor-save-btn').textContent = 'Save Policy';
  document.getElementById('ed-id').readOnly = false;
  document.getElementById('ed-id').value = '';
  document.getElementById('ed-name').value = '';
  document.getElementById('ed-desc').value = '';
  document.getElementById('ed-type').value = 'REQUIRE_CONSENT';
  document.getElementById('ed-priority').value = 100;
  document.getElementById('ed-enabled').checked = true;
  document.getElementById('ed-comment').value = '';
  clearMsg('editor-msg');
  onTypeChange();
}

function startEdit(p) {
  S.editor.mode = 'EDIT';
  S.editor.policyId = p.policyId || p.id;
  S.editor.timeWindows = [];
  document.getElementById('editor-title').textContent = `Edit Policy: ${S.editor.policyId}`;
  document.getElementById('editor-save-btn').textContent = 'Update Policy';
  document.getElementById('ed-id').readOnly = true;
  document.getElementById('ed-id').value = S.editor.policyId || '';
  document.getElementById('ed-name').value = p.name || '';
  document.getElementById('ed-desc').value = p.description || '';
  document.getElementById('ed-type').value = p.type || 'REQUIRE_CONSENT';
  document.getElementById('ed-priority').value = p.priority ?? 100;
  document.getElementById('ed-enabled').checked = p.enabled !== false;
  document.getElementById('ed-comment').value = '';
  clearMsg('editor-msg');
  onTypeChange();

  // Populate config
  const cfg = p.config || {};
  const type = p.type;
  if (type === 'BLOCK_IP') {
    document.getElementById('cfg-blocklist').value = (cfg.blocklist || []).join('\n');
    document.getElementById('cfg-cidrs').value = (cfg.cidrs || []).join('\n');
  } else if (type === 'TIME_WINDOW') {
    S.editor.timeWindows = (cfg.allowedWindows || []).map(w => ({ days: w.days || [], startTime: w.start || w.startTime || '09:00', endTime: w.end || w.endTime || '17:00' }));
    renderTimeWindows();
  } else if (type === 'RATE_LIMIT') {
    document.getElementById('cfg-ws').value = cfg.windowSeconds ?? 60;
    document.getElementById('cfg-mr').value = cfg.maxRequests ?? 100;
    document.getElementById('cfg-kb').value = cfg.keyBy || 'userId';
  }
}

function cancelEditor() {
  switchTab('policies');
}

function onTypeChange() {
  const type = document.getElementById('ed-type').value;
  ['REQUIRE_CONSENT', 'BLOCK_IP', 'TIME_WINDOW', 'RATE_LIMIT'].forEach(t => {
    document.getElementById('cfg-' + t).style.display = (t === type) ? '' : 'none';
  });
}

/* Time windows */
function addTimeWindow() {
  S.editor.timeWindows.push({ days: [], startTime: '09:00', endTime: '17:00' });
  renderTimeWindows();
}

function removeTimeWindow(idx) {
  S.editor.timeWindows.splice(idx, 1);
  renderTimeWindows();
}

function renderTimeWindows() {
  const container = document.getElementById('tw-list');
  const DAYS = ['MON','TUE','WED','THU','FRI','SAT','SUN'];
  let html = '';
  S.editor.timeWindows.forEach((w, i) => {
    html += `<div class="time-window-item" id="tw-item-${i}">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <span style="font-size:11px;color:var(--muted)">Window ${i + 1}</span>
        <button class="btn danger xs" data-action="removeTimeWindow" data-arg="${i}">Remove</button>
      </div>
      <div class="time-window-days">`;
    DAYS.forEach(d => {
      const active = (w.days || []).includes(d) ? 'active' : '';
      html += `<button class="day-toggle ${active}" data-action="toggleDay" data-args="${attrJs([i, d])}">${d}</button>`;
    });
    html += `</div>
      <div class="time-window-times">
        <label for="tw-start-${i}">Start</label>
        <input type="time" id="tw-start-${i}" value="${esc(w.startTime || '09:00')}" data-onchange-action="updateTWTime" data-args="${attrJs([i, 'startTime'])}">
        <label for="tw-end-${i}">End</label>
        <input type="time" id="tw-end-${i}" value="${esc(w.endTime || '17:00')}" data-onchange-action="updateTWTime" data-args="${attrJs([i, 'endTime'])}">
      </div>
    </div>`;
  });
  container.innerHTML = html;
}

function toggleDay(idx, day, btn) {
  const w = S.editor.timeWindows[idx];
  if (!w.days) w.days = [];
  const pos = w.days.indexOf(day);
  if (pos === -1) { w.days.push(day); btn.classList.add('active'); }
  else { w.days.splice(pos, 1); btn.classList.remove('active'); }
}

function updateTWTime(idx, field, val) {
  S.editor.timeWindows[idx][field] = val;
}

/* Build config from form */
function buildConfigFromForm(type) {
  if (type === 'REQUIRE_CONSENT') return { requireValidArtifact: true };
  if (type === 'BLOCK_IP') return {
    blocklist: document.getElementById('cfg-blocklist').value.split('\n').map(s => s.trim()).filter(Boolean),
    cidrs:     document.getElementById('cfg-cidrs').value.split('\n').map(s => s.trim()).filter(Boolean),
  };
  if (type === 'TIME_WINDOW') return { allowedWindows: S.editor.timeWindows.map(w => ({ days: w.days || [], start: w.startTime || '09:00', end: w.endTime || '17:00' })) };
  if (type === 'RATE_LIMIT') return {
    windowSeconds: parseInt(document.getElementById('cfg-ws').value, 10),
    maxRequests:   parseInt(document.getElementById('cfg-mr').value, 10),
    keyBy:         document.getElementById('cfg-kb').value,
  };
}

function buildPayload() {
  const type = document.getElementById('ed-type').value;
  return {
    id:          document.getElementById('ed-id').value.trim(),
    name:        document.getElementById('ed-name').value.trim(),
    description: document.getElementById('ed-desc').value.trim(),
    type,
    priority:    parseInt(document.getElementById('ed-priority').value, 10) || 0,
    enabled:     document.getElementById('ed-enabled').checked,
    comment:     document.getElementById('ed-comment').value.trim(),
    config:      buildConfigFromForm(type),
  };
}

function validateEditorInputs(payload) {
  const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
  if (!ID_RE.test(payload.id)) {
    showMsg('editor-msg', 'Policy ID must match <code>[A-Za-z0-9_-]{1,64}</code>', 'error');
    return false;
  }
  if (!payload.name) {
    showMsg('editor-msg', 'Policy Name is required.', 'error');
    return false;
  }
  return true;
}

async function validateFromEditor() {
  clearMsg('editor-msg');
  const payload = buildPayload();
  if (!validateEditorInputs(payload)) return;
  try {
    const res = await api('/policy-ui/policies/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const valid = res.valid !== false;
    const errs = (res.errors || []).map(e => `<li>${esc(e)}</li>`).join('');
    const warns = (res.warnings || []).map(w => `<li>${esc(w)}</li>`).join('');
    showMsg('editor-msg',
      `<strong>${valid ? '✓ Valid' : '✗ Invalid'}</strong> — Score: ${res.score ?? 'N/A'}
       ${errs ? `<ul style="margin-top:6px;padding-left:16px">${errs}</ul>` : ''}
       ${warns ? `<ul style="margin-top:4px;padding-left:16px;color:var(--yellow)">${warns}</ul>` : ''}`,
      valid ? 'success' : 'error'
    );
  } catch (e) {
    showMsg('editor-msg', esc(e.message), 'error');
  }
}

async function savePolicy() {
  clearMsg('editor-msg');
  const payload = buildPayload();
  if (!validateEditorInputs(payload)) return;

  const isCreate = S.editor.mode === 'CREATE';
  try {
    if (isCreate) {
      await api('/policy-ui/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      showMsg('editor-msg', `Policy <strong>${esc(payload.id)}</strong> created successfully.`, 'success');
    } else {
      await api(`/policy-ui/policies/${encodeURIComponent(S.editor.policyId)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      showMsg('editor-msg', `Policy <strong>${esc(S.editor.policyId)}</strong> updated successfully.`, 'success');
    }
    setTimeout(() => { switchTab('policies'); }, 900);
  } catch (e) {
    showMsg('editor-msg', esc(e.message), 'error');
  }
}

/* ─────────────────────────────────────────────────────────────
   TAB 4 — VALIDATION
───────────────────────────────────────────────────────────────*/
async function validateById() {
  const pid = document.getElementById('val-pid').value.trim();
  if (!pid) { alert('Enter a Policy ID.'); return; }
  await runValidation({ policyId: pid });
}

async function validateAdHoc() {
  const raw = document.getElementById('val-json').value.trim();
  let payload;
  try { payload = JSON.parse(raw); }
  catch { alert('Invalid JSON.'); return; }
  await runValidation(payload);
}

async function runValidation(payload) {
  const section = document.getElementById('val-result-section');
  const body    = document.getElementById('val-result-body');
  section.style.display = '';
  body.innerHTML = '<div class="loading"></div>';
  try {
    const res = await api('/policy-ui/policies/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    renderValidationResult(body, res);
  } catch (e) {
    body.innerHTML = `<div class="error-box">${esc(e.message)}</div>`;
  }
}

function renderValidationResult(el, res) {
  const valid = res.valid !== false;
  const score = res.score ?? null;
  let scoreCls = 'good';
  if (score !== null) { if (score < 70) scoreCls = 'warn'; if (score < 40) scoreCls = 'bad'; }
  const errors   = res.errors   || [];
  const warnings = res.warnings || [];

  let html = `<div class="val-result">
    <div class="score-row">
      ${score !== null ? `<div class="score-big ${scoreCls}">${score}</div>` : ''}
      <div>
        <div style="margin-bottom:6px">${valid
          ? '<span class="badge green" style="font-size:13px;padding:4px 12px">✓ Valid</span>'
          : '<span class="badge red" style="font-size:13px;padding:4px 12px">✗ Invalid</span>'}</div>
        ${score !== null ? `<div style="font-size:11px;color:var(--muted)">Validation score out of 100</div>` : ''}
      </div>
    </div>`;

  if (errors.length) {
    html += `<div style="margin-bottom:10px">
      <div style="font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--red);margin-bottom:6px">Errors (${errors.length})</div>
      <ul class="val-list errors">${errors.map(e => `<li>${esc(e)}</li>`).join('')}</ul>
    </div>`;
  }
  if (warnings.length) {
    html += `<div>
      <div style="font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--yellow);margin-bottom:6px">Warnings (${warnings.length})</div>
      <ul class="val-list warnings">${warnings.map(w => `<li>${esc(w)}</li>`).join('')}</ul>
    </div>`;
  }
  if (!errors.length && !warnings.length) {
    html += `<div class="empty">No errors or warnings.</div>`;
  }
  html += '</div>';
  el.innerHTML = html;
}

/* ─────────────────────────────────────────────────────────────
   TAB 5 — VERSIONS
───────────────────────────────────────────────────────────────*/
async function loadVersions() {
  const pid = document.getElementById('ver-pid').value.trim();
  if (!pid) { alert('Enter a Policy ID.'); return; }
  S.versions.policyId = pid;
  const wrap = document.getElementById('ver-table-wrap');
  wrap.innerHTML = '<div class="loading"></div>';
  document.getElementById('ver-snapshot-section').style.display = 'none';

  try {
    const data = await api(`/policy-ui/policies/${encodeURIComponent(pid)}/versions`);
    const versions = data.versions || data || [];
    if (!versions.length) { wrap.innerHTML = '<div class="empty">No versions found.</div>'; return; }

    let html = `<table>
      <thead><tr>
        <th>Version</th><th>Created At</th><th>Created By</th><th>Summary</th><th>Validation</th><th>Actions</th>
      </tr></thead><tbody>`;
    versions.forEach((v, idx) => {
      const vnum = v.v ?? v.version ?? v.versionNumber ?? idx + 1;
      const prevNum = idx > 0 ? (versions[idx-1].v ?? versions[idx-1].version ?? idx) : null;
      html += `<tr class="clickable-row" data-action="loadVersionSnapshot" data-args="${attrJs([pid, vnum])}">
        <td><strong>v${esc(vnum)}</strong></td>
        <td>${fmt(v.createdAt)}</td>
        <td>${esc(v.createdBy || '—')}</td>
        <td style="max-width:240px">${esc(short(v.summary || v.comment || '', 50))}</td>
        <td>${v.validationStatus === 'VALID' ? '<span class="badge green">VALID</span>' : v.validationStatus ? `<span class="badge red">${esc(v.validationStatus)}</span>` : '<span class="badge">—</span>'}</td>
        <td data-action="stopPropagation">
          ${idx > 0 ? `<button class="btn xs secondary" data-action="goDiff" data-args="${attrJs([pid, prevNum, vnum])}">View Diff</button>` : ''}
        </td>
      </tr>`;
    });
    html += '</tbody></table>';
    wrap.innerHTML = html;
  } catch (e) {
    wrap.innerHTML = `<div class="error-box">${esc(e.message)}</div>`;
  }
}

async function loadVersionSnapshot(policyId, version) {
  const section = document.getElementById('ver-snapshot-section');
  const title   = document.getElementById('ver-snapshot-title');
  const body    = document.getElementById('ver-snapshot-body');
  section.style.display = '';
  title.textContent = `Snapshot — v${version}`;
  body.innerHTML = '<div class="loading"></div>';
  try {
    const data = await api(`/policy-ui/policies/${encodeURIComponent(policyId)}/versions/${encodeURIComponent(version)}`);
    const vobj = data.version || data;
    const snap = vobj.snapshot || vobj;
    body.innerHTML = `<pre class="raw-json">${esc(JSON.stringify(snap, null, 2))}</pre>`;
  } catch (e) {
    body.innerHTML = `<div class="error-box">${esc(e.message)}</div>`;
  }
}

function goDiff(pid, from, to) {
  document.getElementById('diff-pid').value  = pid;
  document.getElementById('diff-from').value = from;
  document.getElementById('diff-to').value   = to;
  switchTab('diff', true);
  loadDiff();
}

/* ─────────────────────────────────────────────────────────────
   TAB 6 — DIFF VIEWER
───────────────────────────────────────────────────────────────*/
async function loadDiff() {
  const pid  = document.getElementById('diff-pid').value.trim();
  const from = document.getElementById('diff-from').value.trim();
  const to   = document.getElementById('diff-to').value.trim();
  if (!pid || !from || !to) { alert('Enter Policy ID, From version, and To version.'); return; }

  const wrap = document.getElementById('diff-result-wrap');
  wrap.innerHTML = '<div class="loading"></div>';
  try {
    const data = await api(`/policy-ui/policies/${encodeURIComponent(pid)}/diff?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`);
    renderDiff(wrap, data, from, to);
  } catch (e) {
    wrap.innerHTML = `<div class="error-box">${esc(e.message)}</div>`;
  }
}

function renderDiff(wrap, data, from, to) {
  const changes = data.changes || [];
  const summary = data.summary || `${changes.length} change(s)`;

  let html = `<div class="section-body">
    <div class="diff-summary">${esc(summary)}</div>`;

  if (!changes.length) {
    html += '<div class="empty">No differences found.</div>';
  } else {
    changes.forEach(c => {
      const kind = (c.type || c.kind || 'MODIFIED').toUpperCase();
      html += `<div class="diff-change ${kind}">
        <div class="diff-change-label">${kind} — ${esc(c.field || c.path || '')}</div>`;
      if (kind === 'MODIFIED') {
        html += `<div>Before: <span style="color:var(--red)">${esc(JSON.stringify(c.from ?? c.oldValue))}</span></div>
                 <div>After:  <span style="color:var(--green)">${esc(JSON.stringify(c.to ?? c.newValue))}</span></div>`;
      } else if (kind === 'ADDED') {
        html += `<div>Value: <span style="color:var(--green)">${esc(JSON.stringify(c.value ?? c.to))}</span></div>`;
      } else {
        html += `<div>Value: <span style="color:var(--red)">${esc(JSON.stringify(c.value ?? c.from))}</span></div>`;
      }
      html += `</div>`;
    });
  }

  if (data.fromSnapshot || data.toSnapshot) {
    html += `<div class="diff-side-by-side">
      <div>
        <div class="diff-pane-label">Version ${esc(from)} (before)</div>
        <pre class="raw-json">${esc(JSON.stringify(data.fromSnapshot || {}, null, 2))}</pre>
      </div>
      <div>
        <div class="diff-pane-label">Version ${esc(to)} (after)</div>
        <pre class="raw-json">${esc(JSON.stringify(data.toSnapshot || {}, null, 2))}</pre>
      </div>
    </div>`;
  }

  html += '</div>';
  wrap.innerHTML = html;
}

/* ─────────────────────────────────────────────────────────────
   TAB 7 — ROLLBACK
───────────────────────────────────────────────────────────────*/
async function loadRollbackVersions() {
  const pid = document.getElementById('rb-pid').value.trim();
  if (!pid) { alert('Enter a Policy ID.'); return; }
  S.rollback.policyId = pid;
  S.rollback.toVersion = null;
  S.rollback.versions = [];
  const wrap = document.getElementById('rb-versions-wrap');
  wrap.innerHTML = '<div class="loading"></div>';
  document.getElementById('rb-snapshot-section').style.display = 'none';
  document.getElementById('rb-confirm-section').style.display = 'none';
  clearMsg('rb-msg');

  try {
    const data = await api(`/policy-ui/policies/${encodeURIComponent(pid)}/versions`);
    S.rollback.versions = data.versions || data || [];
    renderRollbackVersions();
  } catch (e) {
    wrap.innerHTML = `<div class="error-box">${esc(e.message)}</div>`;
  }
}

function renderRollbackVersions() {
  const wrap = document.getElementById('rb-versions-wrap');
  if (!S.rollback.versions.length) {
    wrap.innerHTML = '<div class="empty">No versions found.</div>';
    return;
  }
  let html = '';
  S.rollback.versions.forEach((v, idx) => {
    const vnum = v.v ?? v.version ?? v.versionNumber ?? idx + 1;
    const isLatest = idx === S.rollback.versions.length - 1;
    html += `<div class="rollback-ver-item ${S.rollback.toVersion === vnum ? 'selected' : ''}"
              data-action="selectRollbackVersion" data-arg="${attrJs(vnum)}">
      <input type="radio" name="rb-ver" aria-label="${esc('Restore version v' + vnum)}" ${S.rollback.toVersion === vnum ? 'checked' : ''}>
      <div style="flex:1">
        <div style="font-size:12px;font-weight:600">v${esc(vnum)} ${isLatest ? '<span class="badge accent">current</span>' : ''}</div>
        <div style="font-size:10px;color:var(--muted)">${fmt(v.createdAt)} · ${esc(v.createdBy || '—')}</div>
        ${v.summary || v.comment ? `<div style="font-size:10px;color:var(--muted);margin-top:2px">${esc(short(v.summary || v.comment, 60))}</div>` : ''}
      </div>
    </div>`;
  });
  wrap.innerHTML = html;
}

async function selectRollbackVersion(vnum) {
  S.rollback.toVersion = vnum;
  renderRollbackVersions();

  const section = document.getElementById('rb-snapshot-section');
  const title   = document.getElementById('rb-snapshot-title');
  const body    = document.getElementById('rb-snapshot-body');
  section.style.display = '';
  title.textContent = `Snapshot — v${vnum}`;
  body.innerHTML = '<div class="loading"></div>';

  try {
    const data = await api(`/policy-ui/policies/${encodeURIComponent(S.rollback.policyId)}/versions/${encodeURIComponent(vnum)}`);
    const vobj = data.version || data;
    const snap = vobj.snapshot || vobj;
    body.innerHTML = `<pre class="raw-json">${esc(JSON.stringify(snap, null, 2))}</pre>`;
    document.getElementById('rb-confirm-section').style.display = '';
    clearMsg('rb-msg');
  } catch (e) {
    body.innerHTML = `<div class="error-box">${esc(e.message)}</div>`;
  }
}

function confirmRollback() {
  const comment = document.getElementById('rb-comment').value.trim();
  if (!comment) { showMsg('rb-msg', 'A rollback reason/comment is required.', 'error'); return; }
  if (!S.rollback.toVersion) { showMsg('rb-msg', 'Select a version to roll back to.', 'error'); return; }

  openModal(
    'Confirm Rollback',
    `Roll back policy "${S.rollback.policyId}" to version ${S.rollback.toVersion}? This will create a new version restoring that state.`,
    'Execute Rollback',
    'danger',
    () => executeRollback(comment)
  );
}

async function executeRollback(comment) {
  clearMsg('rb-msg');
  try {
    const res = await api(`/policy-ui/policies/${encodeURIComponent(S.rollback.policyId)}/rollback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ toVersion: S.rollback.toVersion, comment }),
    });
    const newVer = (res.policy && res.policy.currentVersion) || res.newVersion || res.version || '?';
    showMsg('rb-msg', `Rollback successful. New version created: <strong>v${esc(String(newVer))}</strong>`, 'success');
    S.rollback.toVersion = null;
    document.getElementById('rb-confirm-section').style.display = 'none';
    await loadRollbackVersions();
  } catch (e) {
    showMsg('rb-msg', esc(e.message), 'error');
  }
}

/* ─────────────────────────────────────────────────────────────
   TAB 8 — HISTORY
───────────────────────────────────────────────────────────────*/
async function loadHistory() {
  const pid = document.getElementById('hist-pid').value.trim();
  if (!pid) { alert('Enter a Policy ID.'); return; }
  S.history.policyId = pid;
  const wrap = document.getElementById('hist-table-wrap');
  wrap.innerHTML = '<div class="loading"></div>';

  try {
    const data = await api(`/policy-ui/policies/${encodeURIComponent(pid)}/history`);
    const events = data.events || data.history || data || [];
    if (!events.length) { wrap.innerHTML = '<div class="empty">No history events found.</div>'; return; }

    let html = `<table>
      <thead><tr>
        <th>Event</th><th>Actor</th><th>Version</th><th>Timestamp</th><th>Comment</th>
      </tr></thead><tbody>`;
    events.forEach(ev => {
      html += `<tr>
        <td>${histBadge(ev.event || ev.type)}</td>
        <td>${esc(ev.actor || ev.createdBy || '—')}</td>
        <td>${esc(ev.version ?? '—')}</td>
        <td>${fmt(ev.timestamp || ev.createdAt)}</td>
        <td style="max-width:300px;white-space:normal">${esc(short(ev.comment || '', 80))}</td>
      </tr>`;
    });
    html += '</tbody></table>';
    wrap.innerHTML = html;
  } catch (e) {
    wrap.innerHTML = `<div class="error-box">${esc(e.message)}</div>`;
  }
}

/* ─────────────────────────────────────────────────────────────
   TAB 9 — DETAILS
───────────────────────────────────────────────────────────────*/
function backFromDetails() {
  switchTab(S.details.fromTab || 'policies');
}

async function loadDetails(policyId) {
  const body = document.getElementById('det-body');
  body.innerHTML = '<div class="loading"></div>';
  try {
    const res = await api(`/policy-ui/policies/${encodeURIComponent(policyId)}`);
    renderDetails(body, res.policy || res);
  } catch (e) {
    body.innerHTML = `<div class="error-box">${esc(e.message)}</div>`;
  }
}

function renderConfigHuman(type, cfg) {
  if (!cfg) return '—';
  if (type === 'REQUIRE_CONSENT') {
    return `<span class="badge green">Require Valid Artifact: ${cfg.requireValidArtifact ? 'Yes' : 'No'}</span>`;
  }
  if (type === 'BLOCK_IP') {
    const ips   = (cfg.blocklist || []).length;
    const cidrs = (cfg.cidrs || []).length;
    return `<span class="badge accent">${ips} blocked IP${ips !== 1 ? 's' : ''}</span> <span class="badge accent">${cidrs} CIDR range${cidrs !== 1 ? 's' : ''}</span>`;
  }
  if (type === 'TIME_WINDOW') {
    const wins = (cfg.allowedWindows || []).length;
    return `<span class="badge accent">${wins} time window${wins !== 1 ? 's' : ''}</span>`;
  }
  if (type === 'RATE_LIMIT') {
    return `<span class="badge accent">${cfg.maxRequests} req / ${cfg.windowSeconds}s</span> keyed by <span class="badge">${esc(cfg.keyBy)}</span>`;
  }
  return '—';
}

function renderDetails(el, p) {
  const pid    = p.policyId || p.id || '';
  const type   = p.type || '';
  const cfg    = p.config || {};
  const valSt  = p.validationStatus;

  let cfgHuman = renderConfigHuman(type, cfg);

  // Time windows detail
  let cfgExtra = '';
  if (type === 'TIME_WINDOW' && cfg.allowedWindows) {
    cfgExtra = '<div style="margin-top:10px">';
    cfg.allowedWindows.forEach((w, i) => {
      cfgExtra += `<div style="margin-bottom:6px;font-size:11px;font-family:var(--mono)">
        Window ${i+1}: ${esc((w.days||[]).join(', '))} &bull; ${esc(w.start||w.startTime||'?')}–${esc(w.end||w.endTime||'?')}
      </div>`;
    });
    cfgExtra += '</div>';
  }
  if (type === 'BLOCK_IP') {
    const ips = cfg.blocklist || [];
    const cidrs = cfg.cidrs || [];
    if (ips.length) cfgExtra += `<div style="margin-top:8px"><div style="font-size:10px;color:var(--muted);margin-bottom:4px">BLOCKED IPs</div><pre class="raw-json" style="max-height:120px">${esc(ips.join('\n'))}</pre></div>`;
    if (cidrs.length) cfgExtra += `<div style="margin-top:8px"><div style="font-size:10px;color:var(--muted);margin-bottom:4px">CIDR RANGES</div><pre class="raw-json" style="max-height:80px">${esc(cidrs.join('\n'))}</pre></div>`;
  }

  const rawJsonId = 'det-raw-json-' + Math.random().toString(36).slice(2);
  const rawTogId  = 'det-raw-tog-' + Math.random().toString(36).slice(2);

  el.innerHTML = `
    <div class="two-col">
      <div>
        <div class="detail-section">
          <h3>Identity</h3>
          <div class="kv-list">
            <div class="kv-row">
              <span class="kv-key">Policy ID</span>
              <span class="kv-value">${esc(pid)} ${copyBtn(pid)}</span>
            </div>
            <div class="kv-row">
              <span class="kv-key">Name</span>
              <span class="kv-value">${esc(p.name || '—')}</span>
            </div>
            <div class="kv-row">
              <span class="kv-key">Type</span>
              <span class="kv-value">${typeBadge(type)}</span>
            </div>
            <div class="kv-row">
              <span class="kv-key">Status</span>
              <span class="kv-value">${statusBadge(p.status || '—')}</span>
            </div>
            <div class="kv-row">
              <span class="kv-key">Version</span>
              <span class="kv-value">v${esc(p.version ?? '—')}</span>
            </div>
            <div class="kv-row">
              <span class="kv-key">Priority</span>
              <span class="kv-value">${esc(p.priority ?? '—')}</span>
            </div>
            <div class="kv-row">
              <span class="kv-key">Description</span>
              <span class="kv-value" style="white-space:normal">${esc(p.description || '—')}</span>
            </div>
            <div class="kv-row">
              <span class="kv-key">Created At</span>
              <span class="kv-value">${fmt(p.createdAt)}</span>
            </div>
            <div class="kv-row">
              <span class="kv-key">Created By</span>
              <span class="kv-value">${esc(p.createdBy || '—')}</span>
            </div>
            <div class="kv-row">
              <span class="kv-key">Last Modified</span>
              <span class="kv-value">${fmt(p.updatedAt || p.lastModified)}</span>
            </div>
            <div class="kv-row">
              <span class="kv-key">Modified By</span>
              <span class="kv-value">${esc(p.updatedBy || p.modifiedBy || '—')}</span>
            </div>
          </div>
        </div>

        <div class="detail-section">
          <h3>Validation Status</h3>
          ${valSt === 'VALID'   ? '<span class="badge green" style="font-size:12px;padding:4px 10px">✓ VALID</span>' :
            valSt === 'INVALID' ? '<span class="badge red" style="font-size:12px;padding:4px 10px">✗ INVALID</span>' :
            '<span class="badge" style="font-size:12px;padding:4px 10px">—</span>'}
          ${p.validationScore != null ? `<span style="font-size:11px;color:var(--muted);margin-left:8px">Score: ${p.validationScore}</span>` : ''}
        </div>
      </div>

      <div>
        <div class="detail-section">
          <h3>Configuration</h3>
          <div style="margin-bottom:8px">${cfgHuman}</div>
          ${cfgExtra}
          <div style="margin-top:12px;display:flex;align-items:center;gap:8px">
            <span style="font-size:10px;color:var(--muted)">Raw JSON</span>
            <button class="toggle-link" id="${rawTogId}" data-action="toggleRawJson" data-args="${attrJs([rawJsonId, rawTogId])}">Show</button>
          </div>
          <pre class="raw-json" id="${rawJsonId}" style="display:none;margin-top:6px">${esc(JSON.stringify(cfg, null, 2))}</pre>
        </div>

        <div class="detail-section">
          <h3>Links</h3>
          <div style="display:flex;flex-wrap:wrap;gap:8px">
            <button class="btn secondary sm" data-action="loadVersionsForPolicy" data-arg="${attrJs(pid)}">View Versions</button>
            <button class="btn secondary sm" data-action="loadHistoryForPolicy" data-arg="${attrJs(pid)}">View History</button>
            <button class="btn sm" data-action="editPolicy" data-arg="${attrJs(pid)}">Edit</button>
            <button class="btn ${p.status === 'ACTIVE' ? 'danger' : 'success'} sm"
              data-action="togglePolicy" data-args="${attrJs([pid, p.status])}">
              ${p.status === 'ACTIVE' ? 'Disable' : 'Enable'}
            </button>
          </div>
        </div>
      </div>
    </div>`;
}

function loadVersionsForPolicy(pid) {
  document.getElementById('ver-pid').value = pid;
  switchTab('versions', true);
  loadVersions();
}

function loadHistoryForPolicy(pid) {
  document.getElementById('hist-pid').value = pid;
  switchTab('history', true);
  loadHistory();
}

/* Show/hide the raw JSON block in the policy details view. This was
   previously an inline onclick containing raw JS statements (not a call to
   a named function); it is extracted here verbatim as its own function so
   it can be dispatched like every other action below. */
function toggleRawJson(jsonId, togId) {
  const el  = document.getElementById(jsonId);
  const tog = document.getElementById(togId);
  if (el.style.display === 'none') { el.style.display = ''; tog.textContent = 'Hide'; }
  else { el.style.display = 'none'; tog.textContent = 'Show'; }
}

/* ─────────────────────────────────────────────────────────────
   DELEGATED EVENT HANDLERS
   Elements carry data-action / data-onchange-action / data-oninput-action
   plus data-arg (single value) or data-args (JSON array of values, for
   multi-argument or this/event-derived calls) instead of inline handler
   attributes. Each dispatch map below resolves the action name to the
   real function and invokes it, passing the matched DOM element through
   wherever the original handler relied on `this` or `event`.
───────────────────────────────────────────────────────────────*/
function newPolicy() {
  switchTab('editor');
  startCreate();
}

const CLICK_FNS = {
  loadDashboard,
  newPolicy,
  addTimeWindow,
  validateFromEditor,
  savePolicy,
  cancelEditor,
  validateById,
  validateAdHoc,
  loadVersions,
  loadDiff,
  loadRollbackVersions,
  confirmRollback,
  loadHistory,
  backFromDetails,
  closeModal,
  stopPropagation: (el, e) => e.stopPropagation(),
  setPolicyFilter: (el) => setPolicyFilter(el, el.dataset.arg),
  policiesPage: (el) => policiesPage(parseInt(el.dataset.arg, 10)),
  copyToClipboard: (el) => copyToClipboard(JSON.parse(el.dataset.arg)),
  viewPolicy: (el) => viewPolicy(JSON.parse(el.dataset.arg)),
  editPolicy: (el) => editPolicy(JSON.parse(el.dataset.arg)),
  togglePolicy: (el) => {
    const [policyId, status] = JSON.parse(el.dataset.args);
    togglePolicy(policyId, status);
  },
  removeTimeWindow: (el) => removeTimeWindow(parseInt(el.dataset.arg, 10)),
  toggleDay: (el) => {
    const [idx, day] = JSON.parse(el.dataset.args);
    toggleDay(idx, day, el);
  },
  loadVersionSnapshot: (el) => {
    const [policyId, version] = JSON.parse(el.dataset.args);
    loadVersionSnapshot(policyId, version);
  },
  goDiff: (el) => {
    const [policyId, from, to] = JSON.parse(el.dataset.args);
    goDiff(policyId, from, to);
  },
  selectRollbackVersion: (el) => selectRollbackVersion(JSON.parse(el.dataset.arg)),
  toggleRawJson: (el) => {
    const [jsonId, togId] = JSON.parse(el.dataset.args);
    toggleRawJson(jsonId, togId);
  },
  loadVersionsForPolicy: (el) => loadVersionsForPolicy(JSON.parse(el.dataset.arg)),
  loadHistoryForPolicy: (el) => loadHistoryForPolicy(JSON.parse(el.dataset.arg)),
};

const CHANGE_FNS = {
  onTypeChange,
  updateTWTime: (el) => {
    const [idx, field] = JSON.parse(el.dataset.args);
    updateTWTime(idx, field, el.value);
  },
};

const INPUT_FNS = {
  debouncedPoliciesLoad,
};

document.addEventListener('click', createClickDispatcher(CLICK_FNS, { style: 'element' }));

document.addEventListener('change', (e) => {
  const el = e.target.closest('[data-onchange-action]');
  if (!el) return;
  const fn = CHANGE_FNS[el.dataset.onchangeAction];
  if (fn) fn(el, e);
});

document.addEventListener('input', (e) => {
  const el = e.target.closest('[data-oninput-action]');
  if (!el) return;
  const fn = INPUT_FNS[el.dataset.oninputAction];
  if (fn) fn(el, e);
});

/* ─────────────────────────────────────────────────────────────
   INIT
───────────────────────────────────────────────────────────────*/
loadDashboard();
