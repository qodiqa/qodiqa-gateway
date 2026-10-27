'use strict';

// shared infrastructure lives in public/js/common/ (see that
// directory for the canonical implementations). Re-exported here with `var`
// (not `const`) so each stays a property of this script's global object,
// matching how test/helpers/dashboardScriptSandbox.js exposes every other
// top-level binding in this file.
var esc = window.QodiqaCommon.esc;
var attrJs = window.QodiqaCommon.attrJs;
var sharedRenderPager = window.QodiqaCommon.renderPager;
var badge = window.QodiqaCommon.badge;
var createClickDispatcher = window.QodiqaCommon.createClickDispatcher;

// ── State ─────────────────────────────────────────────────────────────────────
const S = {
  activePanel:   'dashboard',
  search:        { page: 1, pageSize: 25, total: 0 },
  timeline:      { page: 1, pageSize: 30, total: 0 },
  investigation: { page: 1, pageSize: 20, total: 0 },
  sseConnected:  false,
  realtimeFired: false,
};

// ── Utilities ─────────────────────────────────────────────────────────────────
async function api(path) {
  const r = await fetch(path);
  if (!r.ok) {
    const err = await r.json().catch(() => ({ reason: r.statusText }));
    throw Object.assign(new Error(err.reason || r.statusText), { status: r.status, body: err });
  }
  return r.json();
}

function fmt(ts) {
  if (!ts) return '—';
  try { return new Date(ts).toLocaleString(undefined, { year:'numeric', month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit' }); }
  catch { return ts; }
}

function short(s, n) {
  if (!s) return '—';
  s = String(s);
  return s.length > n ? s.slice(0, n) + '…' : s;
}

function copyText(text) {
  if (!text) return;
  navigator.clipboard?.writeText(text).catch(() => {
    const el = document.createElement('textarea');
    el.value = text; document.body.appendChild(el); el.select();
    document.execCommand('copy'); document.body.removeChild(el);
  });
}

function copyBtn(text, label) {
  return `<button class="copy-btn tooltip" data-tip="Copy" data-action="copyText" data-arg="${attrJs(text)}">${label || '⧉'}</button>`;
}

function decisionClass(d) { return d === 'ALLOW' ? 'green' : d === 'BLOCK' ? 'red' : 'muted'; }
function decisionBadge(d) { return badge(d || '—', decisionClass(d)); }

// Not migrated to the shared badge() primitive — different markup shape
// (sig-badge/sig-X classes plus an icon prefix), not the same component.
function sigBadge(status) {
  const icons = { VALID:'✓', INVALID:'✗', EXPIRED:'⏱', REVOKED:'⊘', MISSING:'–', UNKNOWN:'?' };
  return `<span class="sig-badge sig-${esc(status)}">${icons[status] || '?'} ${esc(status)}</span>`;
}

function chainStatusBadge(s) {
  const cls = { FULLY_VERIFIED:'green', PARTIALLY_VERIFIED:'yellow', FAILED:'red', NO_REPLAY:'green', CONFIRMED_REPLAY:'red', SUSPECTED_REPLAY:'yellow' };
  return badge(s || '—', cls[s] || '');
}

function kvRow(k, v, raw) {
  const display = v === null || v === undefined ? '<span class="muted">—</span>' : `<span class="kv-value">${esc(short(String(v), 80))}</span>`;
  const copy    = (raw !== undefined && raw !== null) ? copyBtn(String(raw)) : (v ? copyBtn(String(v)) : '');
  return `<div class="kv-row"><span class="kv-key">${esc(k)}</span>${display}${copy}</div>`;
}

function showError(containerId, msg) {
  document.getElementById(containerId).innerHTML = `<div class="error-box">${esc(msg)}</div>`;
}

function showLoading(containerId) {
  document.getElementById(containerId).innerHTML = '<div class="loading">Loading</div>';
}

function pagerHtml(currentPage, total, pageSize, onClickName) {
  return sharedRenderPager({
    total, pageSize, page: currentPage, actionName: onClickName,
    prevLabel: '◀ Prev', nextLabel: 'Next ▶', totalWord: 'records', infoClass: 'info',
  });
}

// ── Navigation ────────────────────────────────────────────────────────────────
function showPanel(name) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(b => b.classList.toggle('active', b.dataset.panel === name));
  const el = document.getElementById('panel-' + name);
  if (el) el.classList.add('active');
  S.activePanel = name;
  if (name === 'dashboard')   loadDashboard();
  if (name === 'timeline')    loadTimeline(1);
  if (name === 'investigate') loadInvestigationList();
}

document.getElementById('main-nav').addEventListener('click', e => {
  const btn = e.target.closest('button[data-panel]');
  if (btn) showPanel(btn.dataset.panel);
});

// ── Dashboard ─────────────────────────────────────────────────────────────────
async function loadDashboard() {
  try {
    const r = await api('/audit-viewer/chain-summary');
    const d = r.data;

    document.getElementById('dc-total').textContent   = d.modernLength ?? d.chainLength ?? '—';
    document.getElementById('dc-allows').textContent  = d.allows  ?? '—';
    document.getElementById('dc-blocks').textContent  = d.blocks  ?? '—';
    document.getElementById('dc-replays').textContent = d.replays ?? '—';

    const validEl  = document.getElementById('dc-valid');
    const tamperEl = document.getElementById('dc-tamper');
    validEl.textContent  = d.chainValid ? 'YES' : 'NO';
    validEl.className    = 'value ' + (d.chainValid ? 'green' : 'red');
    tamperEl.textContent = d.tamperingDetected ? 'YES' : 'NO';
    tamperEl.className   = 'value ' + (d.tamperingDetected ? 'red' : 'green');

    const banner = document.getElementById('dash-banner');
    if (!d.chainValid) {
      banner.style.display = '';
      banner.className = 'status-banner invalid';
      banner.textContent = `⚠ Chain integrity violation detected: ${d.validationReason || 'unknown reason'}. Immediate investigation required.`;
    } else if (d.tamperingDetected) {
      banner.style.display = '';
      banner.className = 'status-banner invalid';
      banner.textContent = '⚠ Tampering detected in audit chain. Escalate immediately.';
    } else if (d.replays > 0) {
      banner.style.display = '';
      banner.className = 'status-banner warn';
      banner.textContent = `${d.replays} replay attempt(s) detected in audit chain.`;
    } else {
      banner.style.display = 'none';
    }

    const reasonsEl = document.getElementById('dash-reasons');
    if (d.byReason && Object.keys(d.byReason).length > 0) {
      const max = Math.max(...Object.values(d.byReason));
      reasonsEl.innerHTML = Object.entries(d.byReason).sort((a,b) => b[1]-a[1]).map(([k, v]) => `
        <div class="reason-bar-row">
          <div class="reason-bar-label">${esc(short(k, 28))}</div>
          <div class="reason-bar-bg"><div class="reason-bar-fill" style="width:${Math.round(v/max*100)}%"></div></div>
          <div class="reason-bar-count">${v}</div>
        </div>`).join('');
    } else {
      reasonsEl.innerHTML = '<div class="empty">No blocked requests.</div>';
    }
  } catch (e) {
    console.error(e);
  }

  try {
    const t = await api('/audit-viewer/timeline?pageSize=15');
    const events = t.data?.events ?? [];
    document.getElementById('dash-tl-count').textContent = t.data?.total ?? 0;
    const tlEl = document.getElementById('dash-timeline');
    if (!events.length) { tlEl.innerHTML = '<li class="empty">No events.</li>'; return; }
    tlEl.innerHTML = events.map(ev => renderTimelineItem(ev, true)).join('');
  } catch (e) {
    document.getElementById('dash-timeline').innerHTML = '<li class="error-box" style="margin:8px">Failed to load timeline.</li>';
  }
}

// ── Search ────────────────────────────────────────────────────────────────────
function _searchParams() {
  const p = new URLSearchParams();
  const a  = document.getElementById('sf-artifact').value.trim();
  const d  = document.getElementById('sf-decision').value;
  const sg = document.getElementById('sf-sig').value;
  const vf = document.getElementById('sf-verify').value;
  const st = document.getElementById('sf-stage').value.trim();
  const s  = document.getElementById('sf-start').value;
  const e  = document.getElementById('sf-end').value;
  const rp = document.getElementById('sf-replay').checked;
  const fl = document.getElementById('sf-failed').checked;
  if (a)  p.set('artifactId', a);
  if (d)  p.set('decision', d);
  if (sg) p.set('signatureStatus', sg);
  if (vf) p.set('verificationStatus', vf);
  if (st) p.set('stage', st);
  if (s)  p.set('startDate', s + 'T00:00:00.000Z');
  if (e)  p.set('endDate',   e + 'T23:59:59.999Z');
  if (rp) p.set('replayOnly', 'true');
  if (fl) p.set('failedOnly', 'true');
  return p;
}

async function runSearch(page) {
  S.search.page = page || 1;
  const wrap = document.getElementById('search-results-wrap');
  wrap.innerHTML = '<div class="loading">Searching</div>';
  document.getElementById('search-pager').style.display = 'none';

  const p = _searchParams();
  p.set('page', S.search.page);
  p.set('pageSize', S.search.pageSize);

  try {
    const r = await api('/audit-viewer/search?' + p);
    const { total, results } = r.data;
    S.search.total = total;

    if (!results.length) {
      wrap.innerHTML = '<div class="empty">No records match your filters.</div>';
      return;
    }

    wrap.innerHTML = `<table>
      <thead><tr>
        <th>Artifact ID</th><th>Timestamp</th><th>Decision</th>
        <th>Signature</th><th>Stage</th><th>Reason</th><th>Provider</th><th>Actions</th>
      </tr></thead>
      <tbody>${results.map(r => `<tr>
        <td class="tooltip" data-tip="${esc(r.artifactId)}">${esc(short(r.artifactId, 20))}</td>
        <td>${esc(fmt(r.timestamp))}</td>
        <td class="${decisionClass(r.decision)}">${esc(r.decision||'—')}</td>
        <td>${sigBadge(r.signatureStatus || 'UNKNOWN')}</td>
        <td>${esc(r.stage||'—')}</td>
        <td>${esc(short(r.reason||'—', 24))}</td>
        <td>${esc(r.provider||'—')}</td>
        <td style="white-space:nowrap">
          <button class="btn sm" data-action="openArtifact" data-arg="${attrJs(r.artifactId)}">Inspect</button>
          <button class="btn sm secondary" data-action="addToInvestigationLocal" data-arg="${attrJs(r.artifactId)}">+Inv</button>
        </td>
      </tr>`).join('')}</tbody>
    </table>`;

    const pager = document.getElementById('search-pager');
    pager.style.display = '';
    pager.innerHTML = pagerHtml(S.search.page, total, S.search.pageSize, 'runSearch');
  } catch (e) {
    showError('search-results-wrap', e.message);
  }
}

function clearSearch() {
  ['sf-artifact','sf-stage'].forEach(id => document.getElementById(id).value = '');
  ['sf-decision','sf-sig','sf-verify'].forEach(id => document.getElementById(id).value = '');
  ['sf-start','sf-end'].forEach(id => document.getElementById(id).value = '');
  ['sf-replay','sf-failed'].forEach(id => document.getElementById(id).checked = false);
  document.getElementById('search-results-wrap').innerHTML = '';
  document.getElementById('search-pager').style.display = 'none';
}

// ── Artifact ──────────────────────────────────────────────────────────────────
function openArtifact(id) {
  showPanel('artifact');
  document.getElementById('art-id-input').value = id;
  loadArtifact();
}

async function loadArtifact() {
  const id = document.getElementById('art-id-input').value.trim();
  if (!id) return;
  showLoading('artifact-result');
  try {
    const r = await api('/audit-viewer/artifact/' + encodeURIComponent(id));
    document.getElementById('artifact-result').innerHTML = renderArtifactDetail(r.data);
  } catch (e) {
    showError('artifact-result', e.status === 404 ? `Artifact not found: ${id}` : e.message);
  }
}

function renderArtifactDetail(d) {
  const exec = d.execution;
  const sig  = d.signature;
  const ver  = d.verification;
  const pol  = d.policy;
  const con  = d.consent;
  const rpl  = d.replay;
  const ch   = d.chain;
  const lin  = d.lineageCompleteness ?? d.auditReferences;

  return `
  <div class="status-banner ${d.decision==='ALLOW'?'valid':d.decision==='BLOCK'?'invalid':'info'}">
    ${decisionBadge(d.decision)} &nbsp; ${esc(d.artifactId)} &nbsp;
    <span style="margin-left:auto;font-size:11px;color:var(--muted)">Resolved at ${esc(fmt(d.resolvedAt))}</span>
    <button class="btn sm secondary" style="margin-left:12px" data-action="addToInvestigationLocal" data-arg="${attrJs(d.artifactId)}">+ Add to Investigation</button>
  </div>

  <div class="detail-grid">
    <div class="section">
      <div class="section-header collapsible" data-action="toggleCollapse">Execution Details</div>
      <div class="collapse-body section-body kv-list">
        ${kvRow('Artifact ID',   d.artifactId)}
        ${kvRow('Timestamp',     fmt(d.timestamp), d.timestamp)}
        ${kvRow('Decision',      d.decision)}
        ${kvRow('Stage',         exec?.stage)}
        ${kvRow('Reason',        exec?.reason)}
        ${kvRow('Provider',      exec?.provider)}
        ${kvRow('Replay Of',     exec?.replayOf)}
        ${kvRow('Verified',      exec?.verificationResult)}
        ${kvRow('Lineage State', d.lineageState)}
      </div>
    </div>

    <div class="section">
      <div class="section-header collapsible" data-action="toggleCollapse">Signature &amp; Verification</div>
      <div class="collapse-body section-body">
        <div style="margin-bottom:12px">${sigBadge(sig?.status || 'UNKNOWN')}</div>
        <div class="kv-list">
          ${kvRow('Algorithm',     sig?.algorithm || 'Ed25519')}
          ${kvRow('Status',        sig?.status)}
          ${kvRow('Verified At',   fmt(sig?.verifiedAt), sig?.verifiedAt)}
          ${kvRow('Failure Reason',sig?.failureReason)}
          ${kvRow('Sig Value',     short(sig?.value, 32), sig?.value)}
          ${kvRow('Verification',  ver?.outcome)}
          ${kvRow('Input Hash',    short(ver?.inputHash, 32), ver?.inputHash)}
          ${kvRow('Request Hash',  short(ver?.requestHash, 32), ver?.requestHash)}
          ${kvRow('Policy Hash',   short(ver?.policyHash, 32), ver?.policyHash)}
        </div>
      </div>
    </div>

    <div class="section">
      <div class="section-header collapsible" data-action="toggleCollapse">Policy &amp; Consent</div>
      <div class="collapse-body section-body kv-list">
        ${kvRow('Policy Outcome',  pol?.outcome)}
        ${kvRow('Policy Hash',     short(pol?.hash, 32), pol?.hash)}
        ${kvRow('Matches Current', pol?.matchesCurrent === null ? 'N/A' : pol?.matchesCurrent)}
        ${kvRow('Policy Reason',   pol?.reason)}
        ${kvRow('Consent Outcome', con?.outcome)}
      </div>
    </div>

    <div class="section">
      <div class="section-header collapsible" data-action="toggleCollapse">
        Replay Detection
        <span class="badge ${rpl?.replayDetected ? 'red' : 'green'}">${rpl?.replayDetected ? 'REPLAYS DETECTED' : 'CLEAN'}</span>
      </div>
      <div class="collapse-body section-body">
        <div class="kv-list">
          ${kvRow('Replay Detected', rpl?.replayDetected)}
          ${kvRow('Replay Count',    rpl?.replayCount)}
        </div>
        ${rpl?.attempts?.length ? `<div style="margin-top:12px">
          ${rpl.attempts.map(a => `<div class="rpl-event replay" style="margin-bottom:6px">
            <div class="rpl-time">${esc(fmt(a.replayAttemptTimestamp))}</div>
            <div class="rpl-body"><strong>${esc(short(a.replayArtifactId, 24))}</strong> — ${esc(a.reason||'REPLAY_DETECTED')}</div>
          </div>`).join('')}
        </div>` : ''}
      </div>
    </div>

    <div class="section">
      <div class="section-header collapsible" data-action="toggleCollapse">Chain Position</div>
      <div class="collapse-body section-body kv-list">
        ${kvRow('Position',        ch?.position)}
        ${kvRow('Chain Valid',     ch?.valid)}
        ${kvRow('Tampered',        ch?.tamperingDetected)}
        ${kvRow('Entries Verified', ch?.entriesVerified)}
        ${kvRow('Entry Hash',      short(d.hashes?.artifact, 32), d.hashes?.artifact)}
        ${kvRow('Prev Hash',       short(d.hashes?.chainPrev, 32), d.hashes?.chainPrev)}
        ${kvRow('Prev Artifact',   ch?.prevArtifactId ? `<a href="#" data-action="openArtifact" data-arg="${attrJs(ch.prevArtifactId)}">${esc(short(ch.prevArtifactId, 20))}</a>` : '—')}
        ${kvRow('Next Artifact',   ch?.nextArtifactId ? `<a href="#" data-action="openArtifact" data-arg="${attrJs(ch.nextArtifactId)}">${esc(short(ch.nextArtifactId, 20))}</a>` : '—')}
      </div>
    </div>

    <div class="section">
      <div class="section-header collapsible" data-action="toggleCollapse">Hashes</div>
      <div class="collapse-body section-body kv-list">
        ${kvRow('Artifact Hash',  short(d.hashes?.artifact, 40),  d.hashes?.artifact)}
        ${kvRow('Input Hash',     short(d.hashes?.input, 40),     d.hashes?.input)}
        ${kvRow('Policy Hash',    short(d.hashes?.policy, 40),    d.hashes?.policy)}
        ${kvRow('Request Hash',   short(d.hashes?.request, 40),   d.hashes?.request)}
        ${kvRow('Chain Prev',     short(d.hashes?.chainPrev, 40), d.hashes?.chainPrev)}
      </div>
    </div>
  </div>

  <div class="section" style="margin-top:0">
    <div class="section-header collapsible collapsed" data-action="toggleCollapse">Raw Audit Record</div>
    <div class="collapse-body collapsed">
      <div class="raw-json">${esc(JSON.stringify(d.raw, null, 2))}</div>
    </div>
  </div>

  <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
    <button class="btn secondary" data-action="gotoSignature" data-arg="${attrJs(d.artifactId)}">View Signature</button>
    <button class="btn secondary" data-action="gotoReplay" data-arg="${attrJs(d.artifactId)}">Replay Analysis</button>
    <button class="btn secondary" data-action="gotoLineage" data-arg="${attrJs(d.artifactId)}">Trace Lineage</button>
    <button class="btn secondary" data-action="gotoChain" data-arg="${attrJs(d.artifactId)}">Verify Chain</button>
  </div>`;
}

// Small named wrappers for the "jump to another panel, seed its input,
// run its loader" combos that used to live as multi-statement inline
// onclick="" strings (e.g. onclick="showPanel('signature');document
// .getElementById('sig-id-input').value=...;loadSignature()"). Each does
// exactly what the original inline statement sequence did — no logic
// change — but is now a single named function so it can be referenced
// from a data-action attribute and invoked by the delegated listener.
function gotoSignature(id) { showPanel('signature'); document.getElementById('sig-id-input').value = id; loadSignature(); }
function gotoReplay(id)    { showPanel('replay');    document.getElementById('rpl-id-input').value = id; loadReplay(); }
function gotoLineage(id)   { showPanel('lineage');   document.getElementById('lin-id-input').value = id; loadLineage(); }
function gotoChain(id)     { showPanel('chain');     document.getElementById('chn-id-input').value = id; loadChain(); }

// ── Signature ─────────────────────────────────────────────────────────────────
function openSignature(id) {
  showPanel('signature');
  document.getElementById('sig-id-input').value = id;
  loadSignature();
}

async function loadSignature() {
  const id = document.getElementById('sig-id-input').value.trim();
  if (!id) return;
  showLoading('signature-result');
  try {
    const r = await api('/audit-viewer/signature/' + encodeURIComponent(id));
    document.getElementById('signature-result').innerHTML = renderSignatureDetail(r.data);
  } catch (e) {
    showError('signature-result', e.status === 404 ? `Artifact not found: ${id}` : e.message);
  }
}

function renderSignatureDetail(d) {
  const status = d.signature?.status || 'UNKNOWN';
  const bannerClass = status === 'VALID' ? 'valid' : status === 'MISSING' ? 'info' : 'invalid';

  return `
  <div class="status-banner ${bannerClass}">
    ${sigBadge(status)} &nbsp; <span>${esc(d.stateExplanation || '')}</span>
  </div>
  <div class="detail-grid">
    <div class="section">
      <div class="section-header">Signature Record</div>
      <div class="section-body kv-list">
        ${kvRow('Artifact ID',   d.artifactId)}
        ${kvRow('Status',        d.signature?.status)}
        ${kvRow('Algorithm',     d.signature?.algorithm || 'Ed25519')}
        ${kvRow('Encoding',      d.signature?.encoding || 'hex')}
        ${kvRow('Verified At',   fmt(d.signature?.verifiedAt), d.signature?.verifiedAt)}
        ${kvRow('Value',         short(d.signature?.value, 40), d.signature?.value)}
      </div>
    </div>
    <div class="section">
      <div class="section-header">Validation Result</div>
      <div class="section-body kv-list">
        ${kvRow('Outcome',        d.validation?.outcome)}
        ${kvRow('Result',         d.validation?.result)}
        ${kvRow('Failure Reason', d.validation?.failureReason)}
        ${kvRow('Failure Stage',  d.validation?.failureStage)}
        ${kvRow('Recorded At',    fmt(d.validation?.recordedAt), d.validation?.recordedAt)}
      </div>
    </div>
    <div class="section">
      <div class="section-header">Enforcement Context</div>
      <div class="section-body kv-list">
        ${kvRow('Decision',      d.signingContext?.decision)}
        ${kvRow('Stage',         d.signingContext?.stage)}
        ${kvRow('Reason',        d.signingContext?.reason)}
        ${kvRow('Policy Hash',   short(d.signingContext?.policyHash, 32), d.signingContext?.policyHash)}
        ${kvRow('Request Hash',  short(d.signingContext?.requestHash, 32), d.signingContext?.requestHash)}
        ${kvRow('Input Hash',    short(d.signingContext?.inputHash, 32), d.signingContext?.inputHash)}
      </div>
    </div>
    <div class="section">
      <div class="section-header">Known Keys <span class="badge">${d.keys?.length || 0}</span></div>
      <div class="section-body">
        ${d.keys?.length ? `<table>
          <thead><tr><th>Key ID</th><th>Client</th><th>Status</th><th>Algorithm</th><th>Created</th></tr></thead>
          <tbody>${d.keys.map(k => `<tr>
            <td>${esc(short(k.keyId, 24))}</td>
            <td>${esc(k.clientId)}</td>
            <td><span class="badge ${k.status==='active'?'green':k.status==='revoked'?'red':'yellow'}">${esc(k.status)}</span></td>
            <td>${esc(k.algorithm||'Ed25519')}</td>
            <td>${esc(fmt(k.createdAt))}</td>
          </tr>`).join('')}</tbody>
        </table>` : '<div class="empty">No keys available.</div>'}
      </div>
    </div>
  </div>`;
}

// ── Replay ────────────────────────────────────────────────────────────────────
async function loadReplay() {
  const id = document.getElementById('rpl-id-input').value.trim();
  if (!id) return;
  showLoading('replay-result');
  try {
    const r = await api('/audit-viewer/replay/' + encodeURIComponent(id));
    document.getElementById('replay-result').innerHTML = renderReplayDetail(r.data);
  } catch (e) {
    showError('replay-result', e.status === 404 ? `Artifact not found: ${id}` : e.message);
  }
}

function renderReplayDetail(d) {
  const bannerClass = d.status === 'NO_REPLAY' ? 'valid' : d.status === 'CONFIRMED_REPLAY' ? 'invalid' : 'warn';

  return `
  <div class="status-banner ${bannerClass}">
    ${chainStatusBadge(d.status)}
    &nbsp; ${d.replayCount} replay attempt(s) detected
    <span style="margin-left:auto;font-size:11px">${esc(fmt(d.resolvedAt))}</span>
  </div>
  <div class="two-col">
    <div class="section">
      <div class="section-header">Replay Analysis</div>
      <div class="section-body kv-list">
        ${kvRow('Artifact ID',         d.artifactId)}
        ${kvRow('Status',              d.status)}
        ${kvRow('Replay Count',        d.replayCount)}
        ${kvRow('Nonce',               d.nonce)}
        ${kvRow('Request Fingerprint', short(d.requestFingerprint, 32), d.requestFingerprint)}
        ${kvRow('First Seen',          fmt(d.firstSeen), d.firstSeen)}
        ${kvRow('Last Seen',           fmt(d.lastSeen),  d.lastSeen)}
        ${kvRow('Detection Source',    d.detectionSource)}
      </div>
    </div>
    <div class="section">
      <div class="section-header">Evidence</div>
      <div class="section-body kv-list">
        ${kvRow('Original Decision',   d.evidence?.originalDecision)}
        ${kvRow('Original Timestamp',  fmt(d.evidence?.originalTimestamp), d.evidence?.originalTimestamp)}
        ${kvRow('Nonce Consumed At',   fmt(d.evidence?.nonceConsumedAt), d.evidence?.nonceConsumedAt)}
        ${kvRow('Subsequent Blocked',  d.evidence?.subsequentBlocked)}
      </div>
    </div>
  </div>
  ${d.forensics ? `<div class="section">
    <div class="section-header">Forensic Analysis</div>
    <div class="section-body kv-list">
      ${kvRow('Pattern',             d.forensics.clusterPattern)}
      ${kvRow('Risk Level',          d.forensics.riskLevel)}
      ${kvRow('Window Duration',     d.forensics.windowHuman)}
      ${kvRow('Frequency (per hr)',  d.forensics.replayFreqPerHour !== null ? d.forensics.replayFreqPerHour : '—')}
      ${kvRow('Avg Inter-attempt',   d.forensics.avgInterAttemptMs !== null ? d.forensics.avgInterAttemptMs + ' ms' : '—')}
    </div>
  </div>` : ''}

  <div class="section">
    <div class="section-header">Detection Timeline</div>
    <div class="section-body replay-timeline">
      ${d.detectionTimeline?.length ? d.detectionTimeline.map(ev => `
        <div class="rpl-event ${ev.event === 'ORIGINAL_EXECUTION' ? 'original' : 'replay'}">
          <div class="rpl-time">${esc(fmt(ev.timestamp))}</div>
          <div class="rpl-body">
            <strong>${esc(ev.event.replace(/_/g,' '))}</strong>
            ${ev.decision ? ` — ${esc(ev.decision)}` : ''}
            ${ev.reason   ? ` (${esc(ev.reason)})`   : ''}
            <br><span class="muted">${esc(short(ev.artifactId, 36))}</span>
          </div>
        </div>`).join('') : '<div class="empty">No timeline events.</div>'}
    </div>
  </div>

  ${d.relatedRequests?.length ? `<div class="section">
    <div class="section-header">Related Requests (same request hash) <span class="badge">${d.relatedRequests.length}</span></div>
    <table>
      <thead><tr><th>Artifact ID</th><th>Timestamp</th><th>Decision</th><th>Request Hash</th></tr></thead>
      <tbody>${d.relatedRequests.map(r => `<tr>
        <td><a href="#" data-action="openArtifact" data-arg="${attrJs(r.artifactId)}">${esc(short(r.artifactId, 20))}</a></td>
        <td>${esc(fmt(r.timestamp))}</td>
        <td class="${decisionClass(r.decision)}">${esc(r.decision)}</td>
        <td>${esc(short(r.requestHash, 24))}</td>
      </tr>`).join('')}</tbody>
    </table>
  </div>` : ''}`;
}

// ── Lineage ───────────────────────────────────────────────────────────────────
async function loadLineage() {
  const id = document.getElementById('lin-id-input').value.trim();
  if (!id) return;
  showLoading('lineage-result');
  try {
    const r = await api('/audit-viewer/lineage/' + encodeURIComponent(id));
    document.getElementById('lineage-result').innerHTML = renderLineageDetail(r.data);
  } catch (e) {
    showError('lineage-result', e.status === 404 ? `Artifact not found: ${id}` : e.message);
  }
}

function renderLineageDetail(d) {
  const nodeColors = {
    FOUND:'green', PRESENT:'green', VERIFIED:'green', VALID:'green', CURRENT:'green', LINKED:'green', AVAILABLE:'green',
    FAILED:'red', INVALID:'red', REVOKED:'red',
    MISSING:'muted', NOT_FOUND:'muted',
    CHANGED:'yellow', EXPIRED:'yellow', PARTIAL:'yellow', UNKNOWN:'muted',
  };

  const graphHtml = d.nodes.map((node, i) => {
    const next = d.edges.find(e => e.from === node.id);
    const color = nodeColors[node.status] || 'muted';
    const detail = node.data ? Object.entries(node.data).filter(([,v]) => v !== null && v !== undefined && typeof v !== 'object').map(([k,v]) => `${k}: ${short(String(v), 20)}`).join(' · ') : '';
    return `<div class="lg-node" data-action="toggleNodeDetail" data-arg="${attrJs('lg-detail-' + i)}">
      <div class="lg-node-box status-${esc(node.status)}">
        <div class="lg-node-type">${esc(node.type)}</div>
        <div class="lg-node-label">${esc(node.label)}</div>
        <div class="lg-node-status ${color}">${esc(node.status)}</div>
        ${detail ? `<div class="lg-node-detail">${esc(detail)}</div>` : ''}
      </div>
    </div>
    ${next ? `<div class="lg-arrow ${next.status === 'LINKED' ? 'linked' : next.status === 'FAILED' ? 'failed' : 'missing'}">→</div>` : ''}
    <div id="lg-detail-${i}" class="collapse-body collapsed" style="position:absolute;display:none"></div>`;
  }).join('');

  const lifecycleHtml = d.lifecycle?.length ? d.lifecycle.map(step => `
    <div style="display:flex;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)">
      <div style="width:24px;height:24px;background:var(--accent);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;flex-shrink:0">${step.step}</div>
      <div>
        <div style="font-size:11px;font-weight:600">${esc(step.event?.replace(/_/g,' '))}</div>
        <div style="font-size:10px;color:var(--muted)">${esc(fmt(step.timestamp))} — ${esc(step.description)}</div>
      </div>
    </div>`).join('') : '<div class="empty">No lifecycle events.</div>';

  return `
  <div class="section">
    <div class="section-header">Lineage Graph
      <span class="badge ${d.summary?.completeLineage ? 'green' : 'yellow'}">${d.summary?.completeLineage ? 'COMPLETE' : 'INCOMPLETE'}</span>
      <span class="muted" style="font-size:10px;margin-left:8px">${d.summary?.linkedNodes}/${d.summary?.totalNodes} nodes linked · ${d.summary?.failedLinks} failed links</span>
    </div>
    <div class="section-body">
      <div class="lineage-graph">${graphHtml}</div>
    </div>
  </div>
  <div class="section">
    <div class="section-header collapsible" data-action="toggleCollapse">Artifact Lifecycle</div>
    <div class="collapse-body section-body">${lifecycleHtml}</div>
  </div>
  <div class="section">
    <div class="section-header collapsible collapsed" data-action="toggleCollapse">Node Details</div>
    <div class="collapse-body collapsed section-body">
      ${d.nodes.map(n => `<div style="margin-bottom:12px">
        <div style="font-weight:600;margin-bottom:6px">${esc(n.label)} (${esc(n.type)})</div>
        <div class="kv-list">${Object.entries(n.data || {}).map(([k,v]) => typeof v !== 'object' ? kvRow(k, v) : kvRow(k, JSON.stringify(v))).join('')}</div>
      </div>`).join('')}
    </div>
  </div>`;
}

// ── Chain Verify ──────────────────────────────────────────────────────────────
async function loadChain() {
  const id = document.getElementById('chn-id-input').value.trim();
  if (!id) return;
  showLoading('chain-result');
  try {
    const r = await api('/audit-viewer/chain/' + encodeURIComponent(id));
    document.getElementById('chain-result').innerHTML = renderChainDetail(r.data);
  } catch (e) {
    showError('chain-result', e.status === 404 ? `Artifact not found: ${id}` : e.message);
  }
}

async function loadFullChainIntegrity() {
  showLoading('chain-result');
  try {
    const r = await api('/audit/chain/integrity');
    const d = r.data;
    document.getElementById('chain-result').innerHTML = `
      <div class="status-banner ${d.chainValid ? 'valid' : 'invalid'}">
        ${d.chainValid ? '✓ Full Chain Integrity: VALID' : '✗ Full Chain Integrity: INVALID'}
        <span class="muted" style="font-size:11px;margin-left:12px">${d.chainLength} total entries · ${d.modernLength} modern · ${d.integrityFailures?.length || 0} failures</span>
      </div>
      <div class="two-col">
        <div class="section">
          <div class="section-header">Chain Statistics</div>
          <div class="section-body kv-list">
            ${kvRow('Chain Length',      d.chainLength)}
            ${kvRow('Modern Length',     d.modernLength)}
            ${kvRow('Chain Valid',       d.chainValid)}
            ${kvRow('Tampering',         d.tamperingDetected)}
            ${kvRow('Validation Reason', d.validationReason)}
            ${kvRow('Allow Count',       d.allowCount)}
            ${kvRow('Block Count',       d.blockCount)}
            ${kvRow('Lineage',           d.lineageCompleteness)}
            ${kvRow('First Event',       fmt(d.firstTimestamp), d.firstTimestamp)}
            ${kvRow('Last Event',        fmt(d.lastTimestamp), d.lastTimestamp)}
          </div>
        </div>
        <div class="section">
          <div class="section-header">Replay Correlation</div>
          <div class="section-body kv-list">
            ${kvRow('Replays Detected', d.replayCorrelationState?.replaysDetected)}
            ${kvRow('Replays Linked',   d.replayCorrelationState?.replaysLinked)}
            ${kvRow('Replays Unlinked', d.replayCorrelationState?.replaysUnlinked)}
          </div>
        </div>
      </div>
      ${d.integrityFailures?.length ? `<div class="section">
        <div class="section-header">Integrity Failures <span class="badge red">${d.integrityFailures.length}</span></div>
        <div class="section-body">${d.integrityFailures.map(f => `
          <div class="error-box" style="margin-bottom:8px">${esc(f.reason)} at index ${esc(f.atIndex)} (${esc(f.entriesVerified)} verified)</div>`).join('')}</div>
      </div>` : ''}`;
  } catch (e) {
    showError('chain-result', e.message);
  }
}

function renderChainDetail(d) {
  const bannerClass = d.status === 'FULLY_VERIFIED' ? 'valid' : d.status === 'FAILED' ? 'invalid' : 'warn';

  const linkIcon = l => l.verified ? '✓' : '✗';
  const linkClass = l => l.verified ? 'verified' : (l.status === 'MISSING' ? 'partial' : 'failed');

  return `
  <div class="status-banner ${bannerClass}">
    ${chainStatusBadge(d.status)}
    <span style="margin-left:12px">${d.failures?.length || 0} failure(s) · ${d.findings?.length || 0} finding(s)</span>
    <span style="margin-left:auto;font-size:11px;color:var(--muted)">Verified at ${esc(fmt(d.verifiedAt))}</span>
  </div>

  <div class="section">
    <div class="section-header">Evidence Chain Links</div>
    <div class="section-body chain-links">
      ${d.links?.map(l => `<div class="chain-link ${linkClass(l)}">
        <span class="chain-link-icon ${l.verified ? 'green' : 'red'}">${linkIcon(l)}</span>
        <div class="chain-link-body">
          <div class="chain-link-label">${esc(l.label)}</div>
          <div class="chain-link-detail">${esc(l.status)}${l.details ? ' — ' + Object.entries(l.details).filter(([,v]) => v !== null && v !== undefined && typeof v !== 'object').map(([k,v]) => `${esc(k)}: ${esc(short(String(v), 24))}`).join(' · ') : ''}</div>
        </div>
        <span class="chain-link-status ${l.verified ? 'green' : 'red'}">${esc(l.status)}</span>
      </div>`).join('') || '<div class="empty">No links.</div>'}
    </div>
  </div>

  <div class="two-col">
    <div class="section">
      <div class="section-header">Chain Integrity</div>
      <div class="section-body kv-list">
        ${kvRow('Integrity Score',   d.integrity?.integrityScore !== undefined ? d.integrity.integrityScore + '/100 (' + d.integrity.integritySeverity + ')' : null)}
        ${kvRow('Chain Valid',       d.integrity?.chainValid)}
        ${kvRow('Entries Verified',  d.integrity?.entriesVerified)}
        ${kvRow('Tampering',         d.integrity?.tamperingDetected)}
        ${kvRow('Failure Reason',    d.integrity?.validationReason)}
        ${kvRow('Position',          d.integrity?.position)}
        ${kvRow('Entry Hash',        short(d.integrity?.entryHash, 32), d.integrity?.entryHash)}
        ${kvRow('Prev Hash',         short(d.integrity?.prevHash, 32), d.integrity?.prevHash)}
      </div>
    </div>
    ${d.failures?.length || d.findings?.length ? `<div class="section">
      <div class="section-header">Failures &amp; Findings</div>
      <div class="section-body">
        ${d.failures?.map(f => `<div class="error-box" style="margin-bottom:6px"><strong>${esc(f.link)}:</strong> ${esc(f.reason)} <span class="badge red">${esc(f.severity)}</span></div>`).join('') || ''}
        ${d.findings?.map(f => `<div class="status-banner info" style="margin-bottom:6px"><strong>${esc(f.link)}:</strong> ${esc(f.finding)} <span class="badge">${esc(f.severity)}</span></div>`).join('') || ''}
      </div>
    </div>` : ''}
  </div>`;
}

// ── Timeline ──────────────────────────────────────────────────────────────────
async function loadTimeline(page) {
  S.timeline.page = page || 1;
  const el = document.getElementById('timeline-list');
  if (el) el.innerHTML = '<li class="loading">Loading</li>';

  const p = new URLSearchParams({ page: S.timeline.page, pageSize: S.timeline.pageSize });
  const s = document.getElementById('tl-start')?.value;
  const e = document.getElementById('tl-end')?.value;
  const t = document.getElementById('tl-type')?.value;
  if (s) p.set('startDate', s + 'T00:00:00.000Z');
  if (e) p.set('endDate',   e + 'T23:59:59.999Z');
  if (t) p.set('eventType', t);

  try {
    const r = await api('/audit-viewer/timeline?' + p);
    const { total, events } = r.data;
    S.timeline.total = total;
    document.getElementById('tl-total').textContent = total;

    if (!events.length) {
      el.innerHTML = '<li class="empty">No events match filters.</li>';
      document.getElementById('tl-pager').innerHTML = '';
      return;
    }

    el.innerHTML = events.map(ev => renderTimelineItem(ev, false)).join('');
    document.getElementById('tl-pager').innerHTML = pagerHtml(S.timeline.page, total, S.timeline.pageSize, 'loadTimeline');
  } catch (e) {
    el.innerHTML = `<li class="error-box" style="margin:8px">${esc(e.message)}</li>`;
  }
}

function renderTimelineItem(ev, compact) {
  const typeColors = {
    ARTIFACT_ALLOWED: 'green', POLICY_BLOCKED: 'red', VALIDATION_FAILED: 'orange',
    REPLAY_DETECTED: 'yellow', ARTIFACT_BLOCKED: 'red', SIGNATURE_FAILED: 'orange',
    CONSENT_DENIED: 'purple', ANOMALY_DETECTED: 'cyan',
  };
  const color = typeColors[ev.eventType] || 'muted';
  const meta  = [ev.stage, ev.reason, ev.provider].filter(Boolean).join(' · ');
  const id    = `tl-${ev.artifactId?.replace(/-/g,'').slice(0,8)}-${Math.random().toString(36).slice(2,6)}`;
  return `<li class="tl-item">
    <div class="tl-dot ${esc(ev.eventType)}"></div>
    <div class="tl-content">
      <div class="tl-header">
        <span class="tl-type ${color}">${esc(ev.eventType?.replace(/_/g,' '))}</span>
        <span class="tl-time">${esc(fmt(ev.timestamp))}</span>
        ${ev.artifactId ? `<a class="tl-id" data-action="openArtifact" data-arg="${attrJs(ev.artifactId)}">${esc(short(ev.artifactId, 20))}</a>` : ''}
        ${ev.replayOf   ? `<span class="badge yellow">REPLAY</span>` : ''}
        ${!compact      ? `<button class="btn sm secondary" style="margin-left:auto" data-action="toggleTlDetail" data-arg="${attrJs(id)}">Details</button>` : ''}
      </div>
      ${meta ? `<div class="tl-meta">${esc(meta)}</div>` : ''}
      ${!compact ? `<div class="tl-expand" id="${id}">
        <div class="kv-list" style="font-size:10px">
          ${kvRow('Decision',   ev.decision)}
          ${kvRow('Stage',      ev.stage)}
          ${kvRow('Reason',     ev.reason)}
          ${kvRow('Provider',   ev.provider)}
          ${ev.replayOf ? kvRow('Replay Of', ev.replayOf) : ''}
          ${kvRow('Chain Hash', short(ev.chainHash, 32), ev.chainHash)}
        </div>
      </div>` : ''}
    </div>
  </li>`;
}

// ── Investigation ─────────────────────────────────────────────────────────────
const _localInv = { ids: new Set() };

function addToInvestigationLocal(artifactId) {
  if (!artifactId) return;
  _localInv.ids.add(artifactId);
  updateInvBadge();
  const el = document.getElementById('inv-artifacts');
  if (el) {
    const current = el.value.split('\n').map(s => s.trim()).filter(Boolean);
    if (!current.includes(artifactId)) {
      el.value = [...current, artifactId].join('\n');
    }
  }
}

function updateInvBadge() {
  const b = document.getElementById('inv-badge');
  const n = _localInv.ids.size;
  if (n > 0) {
    b.style.display = '';
    b.textContent = `${n} in investigation`;
  } else {
    b.style.display = 'none';
  }
}

async function createInvestigation() {
  const title  = document.getElementById('inv-title').value.trim();
  const name   = document.getElementById('inv-name').value.trim();
  const notes  = document.getElementById('inv-notes').value.trim();
  const rawIds = document.getElementById('inv-artifacts').value;
  const ids    = rawIds.split('\n').map(s => s.trim()).filter(Boolean);

  if (!title) { alert('Please enter an investigation title.'); return; }
  if (!ids.length) { alert('Please enter at least one artifact ID.'); return; }

  try {
    const r = await fetch('/audit-viewer/investigation', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title, investigator: name, notes, artifactIds: ids }),
    });
    if (!r.ok) { const e = await r.json(); throw new Error(e.reason || r.statusText); }
    const resp = await r.json();

    ['inv-title','inv-name','inv-notes','inv-artifacts'].forEach(id => document.getElementById(id).value = '');
    _localInv.ids.clear();
    updateInvBadge();

    await loadInvestigationList();
    await openInvestigationDetail(resp.data.id);
  } catch (e) {
    alert('Failed to create investigation: ' + e.message);
  }
}

async function loadInvestigationList(page) {
  S.investigation.page = page || 1;
  const wrap = document.getElementById('inv-list-wrap');

  try {
    const r = await api(`/audit-viewer/investigation?page=${S.investigation.page}&pageSize=${S.investigation.pageSize}`);
    const { total, investigations } = r.data;
    S.investigation.total = total;
    document.getElementById('inv-list-count').textContent = total;

    if (!investigations?.length) {
      wrap.innerHTML = '<div class="empty">No investigations.</div>';
      document.getElementById('inv-pager').style.display = 'none';
      return;
    }

    wrap.innerHTML = investigations.map(inv => `
      <div style="padding:10px;border-bottom:1px solid var(--border)">
        <div style="display:flex;align-items:center;gap:8px">
          <span style="font-size:12px;font-weight:600">${esc(inv.title)}</span>
          <span class="badge">${esc(inv.status)}</span>
          <button class="btn sm" style="margin-left:auto" data-action="openInvestigationDetail" data-arg="${attrJs(inv.id)}">Open</button>
        </div>
        <div style="font-size:10px;color:var(--muted);margin-top:4px">
          ${esc(inv.id)} · ${esc(inv.investigator)} · ${esc(inv.artifactIds?.length || 0)} artifacts · ${esc(fmt(inv.createdAt))}
        </div>
      </div>`).join('');

    const pager = document.getElementById('inv-pager');
    pager.style.display = '';
    pager.innerHTML = pagerHtml(S.investigation.page, total, S.investigation.pageSize, 'loadInvestigationList');
  } catch (e) {
    wrap.innerHTML = `<div class="error-box">${esc(e.message)}</div>`;
  }
}

async function openInvestigationDetail(id) {
  const wrap = document.getElementById('inv-detail-wrap');
  wrap.innerHTML = '<div class="loading">Loading investigation</div>';
  try {
    const r = await api('/audit-viewer/investigation/' + encodeURIComponent(id));
    const d = r.data;

    wrap.innerHTML = `
    <div class="section" style="margin-top:16px">
      <div class="section-header">
        Investigation: ${esc(d.title)}
        <span class="badge">${esc(d.status)}</span>
        <span class="muted" style="font-size:10px;margin-left:auto">${esc(d.id)} · ${esc(d.investigator)} · ${esc(fmt(d.createdAt))}</span>
      </div>
      <div class="section-body">
        ${d.notes ? `<div style="margin-bottom:12px;font-size:12px;background:var(--surface2);padding:10px;border-radius:4px">${esc(d.notes)}</div>` : ''}
        <div class="cards" style="margin-bottom:16px">
          <div class="card"><div class="label">Total Artifacts</div><div class="value">${d.summary.totalArtifacts}</div></div>
          <div class="card"><div class="label">Found</div><div class="value">${d.summary.found}</div></div>
          <div class="card"><div class="label">Allowed</div><div class="value green">${d.summary.allowed}</div></div>
          <div class="card"><div class="label">Blocked</div><div class="value red">${d.summary.blocked}</div></div>
          <div class="card"><div class="label">Replays</div><div class="value yellow">${d.summary.replaysDetected}</div></div>
          <div class="card"><div class="label">Verify Failures</div><div class="value red">${d.summary.verificationFailures}</div></div>
        </div>
        <table>
          <thead><tr><th>Artifact ID</th><th>Decision</th><th>Signature</th><th>Replays</th><th>Timestamp</th><th>Actions</th></tr></thead>
          <tbody>${d.artifacts.map(a => `<tr>
            <td class="tooltip" data-tip="${esc(a.artifactId)}">${esc(short(a.artifactId, 22))}</td>
            <td class="${decisionClass(a.decision)}">${esc(a.decision || '—')}</td>
            <td>${sigBadge(a.signatureStatus || 'UNKNOWN')}</td>
            <td>${a.replayCount > 0 ? `<span class="badge yellow">${a.replayCount}</span>` : '—'}</td>
            <td>${esc(fmt(a.timestamp))}</td>
            <td style="white-space:nowrap">
              <button class="btn sm" data-action="openArtifact" data-arg="${attrJs(a.artifactId)}">Inspect</button>
            </td>
          </tr>`).join('')}
          </tbody>
        </table>
        <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn secondary" data-action="exportInvestigation" data-args="${attrJs([d.id, d.title, d.artifactIds])}">Export Investigation</button>
        </div>
      </div>
    </div>`;
  } catch (e) {
    wrap.innerHTML = `<div class="error-box">${esc(e.message)}</div>`;
  }
}

function exportInvestigation(id, title, artifactIds) {
  const ids = Array.isArray(artifactIds) ? artifactIds : JSON.parse(artifactIds);
  const payload = { investigationId: id, title, exportedAt: new Date().toISOString(), artifactIds: ids };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = `qodiqa-investigation-${id}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ── Export ────────────────────────────────────────────────────────────────────
function _exportParams() {
  const p = new URLSearchParams();
  const a  = document.getElementById('ex-artifact').value.trim();
  const d  = document.getElementById('ex-decision').value;
  const s  = document.getElementById('ex-start').value;
  const e  = document.getElementById('ex-end').value;
  const rp = document.getElementById('ex-replay').checked;
  const fl = document.getElementById('ex-failed').checked;
  if (a)  p.set('artifactId', a);
  if (d)  p.set('decision', d);
  if (s)  p.set('startDate', s + 'T00:00:00.000Z');
  if (e)  p.set('endDate',   e + 'T23:59:59.999Z');
  if (rp) p.set('replayOnly', 'true');
  if (fl) p.set('failedOnly', 'true');
  return p;
}

function runExport(format) {
  const p = _exportParams();
  p.set('format', format);
  const url = '/audit-viewer/export?' + p;
  const status = document.getElementById('export-status');

  if (format === 'pdf') {
    window.open(url, '_blank');
    status.textContent = 'PDF report opened in new tab. Use File → Print → Save as PDF to save.';
  } else {
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `qodiqa-audit-export.${format}`;
    a.click();
    status.textContent = `${format.toUpperCase()} export started.`;
  }
  setTimeout(() => { status.textContent = ''; }, 5000);
}

// ── Collapse helpers ──────────────────────────────────────────────────────────
function toggleCollapse(header) {
  header.classList.toggle('collapsed');
  const body = header.nextElementSibling;
  if (body?.classList.contains('collapse-body')) {
    body.classList.toggle('collapsed');
  }
}

function toggleNodeDetail(id) {
  const el = document.getElementById(id);
  if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}

// Wrapper for the old inline onclick="document.getElementById('${id}')
// .classList.toggle('open')" on timeline "Details" buttons — same single
// statement, just named so it can be dispatched via data-action.
function toggleTlDetail(id) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle('open');
}

// ── SSE ───────────────────────────────────────────────────────────────────────
function connectSSE() {
  const dot   = document.getElementById('stream-dot');
  const label = document.getElementById('stream-label');

  const src = new (window.QodiqaAuthEventSource || EventSource)('/dashboard/stream');

  src.onopen = () => {
    S.sseConnected = true;
    dot.className  = 'live';
    label.textContent = 'Live';
  };

  src.onerror = () => {
    S.sseConnected = false;
    dot.className  = '';
    label.textContent = 'Disconnected';
    setTimeout(connectSSE, 5000);
    src.close();
  };

  src.addEventListener('audit', e => {
    try {
      const ev = JSON.parse(e.data);
      if (S.activePanel === 'dashboard' && !S.realtimeFired) {
        S.realtimeFired = true;
        setTimeout(() => { loadDashboard(); S.realtimeFired = false; }, 2000);
      }
      if (S.activePanel === 'timeline' && !S.realtimeFired) {
        S.realtimeFired = true;
        setTimeout(() => { loadTimeline(1); S.realtimeFired = false; }, 2000);
      }
    } catch {}
  });
}

// ── Delegated click handling ────────────────
// Elements now carry data-action="fnName" plus either data-arg (a single
// JSON-encoded argument) or data-args (a JSON-encoded array of arguments)
// instead of an inline onclick="fnName(...)" attribute. One delegated
// listener on document resolves data-action against ACTIONS and invokes
// the real function with the parsed argument(s) — this also catches
// elements injected later via innerHTML, since delegation is on document.
// Mirrors the PAGE_FNS + delegated-listener pattern in public/js/dashboard.js.
const ACTIONS = {
  runSearch, clearSearch, loadArtifact, loadSignature, loadReplay, loadLineage,
  loadChain, loadFullChainIntegrity, loadTimeline, createInvestigation,
  loadInvestigationList, runExport, copyText, openArtifact,
  addToInvestigationLocal, toggleCollapse, toggleNodeDetail, toggleTlDetail,
  openInvestigationDetail, exportInvestigation,
  gotoSignature, gotoReplay, gotoLineage, gotoChain,
};

// toggleCollapse's original inline call was onclick="toggleCollapse(this)" —
// it operates on the clicked element itself, not a JSON-encoded value, hence
// the rawElementActions escape hatch below.
document.addEventListener('click', createClickDispatcher(ACTIONS, { rawElementActions: ['toggleCollapse'] }));

// ── Init ──────────────────────────────────────────────────────────────────────
(function init() {
  loadDashboard();
  connectSSE();
  updateInvBadge();
})();
