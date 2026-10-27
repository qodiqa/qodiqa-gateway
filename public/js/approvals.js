/*
 * Operator console: human approval of agent actions.
 *
 * The page lists the approval requests of a tenant (GET /v1/approvals) and shows ONE request with the exact tool and arguments the approver is asked to approve
 * (GET /v1/approvals/:id); Approve / Deny post the decision (POST /v1/approvals/:id/decision) with the operator's one-time code in X-QODIQA-OTP (MFA step-up).
 * Operator authentication (the API key bar) is public/js/common/adminAuth.js. Everything that comes from the server is put into the page with textContent - never as markup.
 */
(function () {
  'use strict';

  var selected = null;

  function $(id) { return document.getElementById(id); }
  function el(tag, props, text) {
    var e = document.createElement(tag);
    if (props) Object.keys(props).forEach(function (k) { e.setAttribute(k, props[k]); });
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function fmt(ts) { if (!ts) return '—'; try { return new Date(ts).toLocaleString(); } catch (e) { return String(ts); } }
  function say(id, text, kind) { var m = $(id); m.textContent = text || ''; m.className = 'msg' + (kind ? ' ' + kind : ''); }
  function tenant() { return $('tenant').value.trim(); }

  function api(path, options) {
    return fetch(path, options).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (body) {
        if (!r.ok) {
          var code = (body && body.error && body.error.code) || (body && body.reason) || r.statusText;
          var err = new Error(code); err.status = r.status; err.body = body; throw err;
        }
        return body && body.data !== undefined ? body.data : body;
      });
    });
  }

  function statusBadge(status) { return el('span', { 'class': 'badge ' + status }, status); }

  function renderRows(list) {
    var tbody = $('rows');
    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
    list.forEach(function (a) {
      var tr = el('tr', { 'class': 'pick' + (selected === a.approvalId ? ' sel' : ''), tabindex: '0', 'data-id': a.approvalId, role: 'button', 'aria-label': 'Open request ' + a.tool.server + '/' + a.tool.name });
      tr.appendChild(el('td', null, fmt(a.requestedAt)));
      tr.appendChild(el('td', null, a.tool.server + '/' + a.tool.name));
      tr.appendChild(el('td', null, a.actionClass));
      tr.appendChild(el('td', null, a.requesterId));
      var st = el('td'); st.appendChild(statusBadge(a.status)); tr.appendChild(st);
      tr.appendChild(el('td', null, fmt(a.status === 'APPROVED' ? a.approvalExpiresAt : a.expiresAt)));
      function open() { openRequest(a.approvalId); }
      tr.addEventListener('click', open);
      tr.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); open(); } });
      tbody.appendChild(tr);
    });
    $('list-caption').textContent = list.length ? (list.length + ' request' + (list.length === 1 ? '' : 's')) : 'No requests';
  }

  function load() {
    if (!tenant()) { say('list-msg', 'Enter a tenant.', 'err'); return Promise.resolve(); }
    var q = '/v1/approvals?tenantId=' + encodeURIComponent(tenant()) + ($('status').value ? '&status=' + encodeURIComponent($('status').value) : '');
    say('list-msg', 'Loading…');
    return api(q).then(function (d) { renderRows(d.approvals || []); say('list-msg', ''); }).catch(function (e) { say('list-msg', 'Could not load: ' + e.message, 'err'); });
  }

  function renderDetail(a) {
    $('nothing').hidden = true; $('detail').hidden = false;
    var facts = $('facts');
    while (facts.firstChild) facts.removeChild(facts.firstChild);
    [['Status', a.status], ['Tool', a.tool.server + '/' + a.tool.name], ['Class', a.actionClass], ['Agent', a.agentId], ['Session / position', a.sessionId + ' / #' + a.seq], ['Action hash', a.actionHash],
      ['Requested by', a.requesterId + (a.requesterUserId ? ' (for ' + a.requesterUserId + ')' : '')], ['Requested', fmt(a.requestedAt)], ['Decide before', fmt(a.expiresAt)],
      ['Decided by', a.approverId ? (a.approverId + ' at ' + fmt(a.decidedAt)) : '—'], ['Valid', a.notBefore ? (fmt(a.notBefore) + ' → ' + fmt(a.approvalExpiresAt)) : '—'], ['Reason', a.decisionReason || '—']]
      .forEach(function (p) { facts.appendChild(el('dt', null, p[0])); facts.appendChild(el('dd', null, p[1])); });
    $('args').textContent = JSON.stringify(a.args, null, 2);
    var open = a.status === 'PENDING';
    $('approve').disabled = !open; $('deny').disabled = !open;
    say('decision-msg', open ? '' : 'This request is ' + a.status.toLowerCase() + '; nothing more to decide.');
  }

  function openRequest(id) {
    selected = id;
    return api('/v1/approvals/' + encodeURIComponent(id) + '?tenantId=' + encodeURIComponent(tenant())).then(renderDetail).then(load)
      .catch(function (e) { say('decision-msg', 'Could not open the request: ' + e.message, 'err'); });
  }

  function decide(decision) {
    if (!selected) return;
    var reason = $('reason').value.trim();
    if (decision === 'DENY' && !reason) { say('decision-msg', 'A reason is required to deny.', 'err'); return; }
    var otp = $('otp').value.trim();
    if (!otp) { say('decision-msg', 'Enter your one-time code.', 'err'); return; }
    $('approve').disabled = true; $('deny').disabled = true;
    say('decision-msg', 'Sending…');
    var body = { tenantId: tenant(), decision: decision };
    if (reason) body.reason = reason;
    api('/v1/approvals/' + encodeURIComponent(selected) + '/decision', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-QODIQA-OTP': otp }, body: JSON.stringify(body) })
      .then(function (a) { $('otp').value = ''; renderDetail(a); say('decision-msg', decision === 'APPROVE' ? 'Approved. The agent can now ask for its artifact.' : 'Denied.', 'ok'); return load(); })
      .catch(function (e) {
        say('decision-msg', 'Not recorded: ' + e.message + (e.message === 'APPROVAL_NOT_INDEPENDENT' ? ' — you cannot decide a request made by you or for you.' : ''), 'err');
        $('approve').disabled = false; $('deny').disabled = false;
      });
  }

  $('refresh').addEventListener('click', load);
  $('status').addEventListener('change', load);
  $('approve').addEventListener('click', function () { decide('APPROVE'); });
  $('deny').addEventListener('click', function () { decide('DENY'); });
  load();
}());
