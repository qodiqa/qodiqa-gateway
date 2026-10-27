/*
 * Operator authentication for the admin pages.
 *
 * The admin API (/audit-viewer, /dashboard, /v1/policy/*, ...) accepts an operator API key ONLY in an `Authorization: Bearer` (or
 * `x-ops-token`) header. The pages sent no credentials at all, and EventSource cannot set headers, so they could not be used from a
 * browser. This script, loaded BEFORE a page's own script:
 *   1. shows a small sign-in bar (operator API key, kept in sessionStorage — tab-scoped, never in a URL or cookie);
 *   2. wraps window.fetch so every SAME-ORIGIN request carries `Authorization: Bearer <key>`, and shows the bar again on 401/403;
 *   3. provides window.QodiqaAuthEventSource, a fetch-based EventSource replacement that can send the header.
 * No inline script / style is used (the pages run under script-src 'self'); the bar is built with DOM + CSSOM calls.
 */
(function () {
  'use strict';

  var STORAGE_KEY = 'qodiqa.operatorKey';

  function getKey() { try { return window.sessionStorage.getItem(STORAGE_KEY) || ''; } catch (e) { return ''; } }
  function setKey(v) {
    try { if (v) window.sessionStorage.setItem(STORAGE_KEY, v); else window.sessionStorage.removeItem(STORAGE_KEY); } catch (e) { /* storage blocked: key lives for this page only */ memoryKey = v || ''; }
  }
  var memoryKey = '';
  function currentKey() { return getKey() || memoryKey; }

  function sameOrigin(url) {
    try { return new URL(url, window.location.href).origin === window.location.origin; } catch (e) { return false; }
  }

  // ── sign-in bar ──────────────────────────────────────────────────────────────────────────────────────────────────
  var bar = null; var statusEl = null; var input = null;

  function css(el, props) { Object.keys(props).forEach(function (k) { el.style[k] = props[k]; }); }

  function buildBar() {
    if (bar || !document.body) return;
    bar = document.createElement('div');
    bar.id = 'qodiqa-auth-bar';
    css(bar, { position: 'fixed', top: '8px', right: '8px', zIndex: '2147483000', background: '#111827', color: '#e5e7eb', border: '1px solid #374151',
      borderRadius: '6px', padding: '6px 8px', font: '12px system-ui, sans-serif', display: 'flex', gap: '6px', alignItems: 'center', boxShadow: '0 2px 8px rgba(0,0,0,.4)' });

    var label = document.createElement('span');
    label.textContent = 'Operator API key';
    input = document.createElement('input');
    input.type = 'password';
    input.autocomplete = 'off';
    input.placeholder = 'paste key';
    input.setAttribute('aria-label', 'Operator API key');
    css(input, { width: '170px', background: '#0b1220', color: '#e5e7eb', border: '1px solid #374151', borderRadius: '4px', padding: '3px 6px' });
    var btnIn = document.createElement('button');
    btnIn.type = 'button'; btnIn.textContent = 'Sign in';
    var btnOut = document.createElement('button');
    btnOut.type = 'button'; btnOut.textContent = 'Sign out';
    [btnIn, btnOut].forEach(function (b) { css(b, { background: '#1f2937', color: '#e5e7eb', border: '1px solid #4b5563', borderRadius: '4px', padding: '3px 8px', cursor: 'pointer' }); });
    statusEl = document.createElement('span');
    css(statusEl, { minWidth: '90px' });

    btnIn.addEventListener('click', function () {
      var v = (input.value || '').trim();
      if (!v) { setStatus('enter a key', true); return; }
      setKey(v); input.value = ''; setStatus('signed in — reloading', false);
      window.location.reload();
    });
    input.addEventListener('keydown', function (e) { if (e.key === 'Enter') btnIn.click(); });
    btnOut.addEventListener('click', function () { setKey(''); memoryKey = ''; window.location.reload(); });

    bar.appendChild(label); bar.appendChild(input); bar.appendChild(btnIn); bar.appendChild(btnOut); bar.appendChild(statusEl);
    document.body.appendChild(bar);
    setStatus(currentKey() ? 'key set' : 'not signed in', !currentKey());
  }

  function setStatus(text, warn) {
    if (!statusEl) return;
    statusEl.textContent = text;
    statusEl.style.color = warn ? '#fca5a5' : '#86efac';
  }

  function needLogin(status) {
    buildBar();
    setStatus(status === 403 ? 'forbidden for this key' : 'sign in (401)', true);
    if (bar && !currentKey() && input) { try { input.focus(); } catch (e) { /* ignore */ } }
  }

  // ── fetch wrapper ────────────────────────────────────────────────────────────────────────────────────────────────
  var originalFetch = window.fetch ? window.fetch.bind(window) : null;
  if (originalFetch) {
    window.fetch = function (input_, init) {
      var url = typeof input_ === 'string' ? input_ : (input_ && input_.url) || '';
      var key = currentKey();
      var opts = init;
      if (key && sameOrigin(url)) {
        var headers = new Headers((init && init.headers) || (input_ && typeof input_ !== 'string' ? input_.headers : undefined) || {});
        if (!headers.has('Authorization')) headers.set('Authorization', 'Bearer ' + key);
        opts = Object.assign({}, init || {}, { headers: headers });
      }
      return originalFetch(input_, opts).then(function (res) {
        if (sameOrigin(url) && (res.status === 401 || res.status === 403)) needLogin(res.status);
        return res;
      });
    };
  }

  // ── EventSource replacement (fetch streaming, header-capable) ───────────────────────────────────────────────────
  function AuthEventSource(url) {
    var self = this;
    self.url = url; self.readyState = 0; self.onopen = null; self.onmessage = null; self.onerror = null;
    self._listeners = {}; self._abort = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    var headers = { Accept: 'text/event-stream' };
    var key = currentKey();
    if (key) headers.Authorization = 'Bearer ' + key;

    fetch(url, { headers: headers, signal: self._abort ? self._abort.signal : undefined, cache: 'no-store' }).then(function (res) {
      if (!res.ok || !res.body) { self._fail(res.status); return; }
      self.readyState = 1;
      if (typeof self.onopen === 'function') self.onopen({ type: 'open' });
      var reader = res.body.getReader(); var decoder = new TextDecoder(); var buf = '';
      var evt = 'message'; var data = [];
      function dispatch() {
        if (!data.length) { evt = 'message'; return; }
        var e = { type: evt, data: data.join('\n'), lastEventId: '' };
        data = []; var t = evt; evt = 'message';
        var ls = self._listeners[t] || [];
        for (var i = 0; i < ls.length; i++) { try { ls[i](e); } catch (err) { /* a listener must not break the stream */ } }
        if (t === 'message' && typeof self.onmessage === 'function') { try { self.onmessage(e); } catch (err) { /* ignore */ } }
      }
      function pump() {
        return reader.read().then(function (r) {
          if (r.done) { self._fail(0); return undefined; }
          buf += decoder.decode(r.value, { stream: true });
          var lines = buf.split(/\r\n|\n|\r/); buf = lines.pop();
          lines.forEach(function (line) {
            if (line === '') { dispatch(); return; }
            if (line.charAt(0) === ':') return;
            var i = line.indexOf(':'); var field = i < 0 ? line : line.slice(0, i); var val = i < 0 ? '' : line.slice(i + 1);
            if (val.charAt(0) === ' ') val = val.slice(1);
            if (field === 'event') evt = val; else if (field === 'data') data.push(val);
          });
          return pump();
        });
      }
      return pump();
    }).catch(function () { if (self.readyState !== 2) self._fail(0); });
  }
  AuthEventSource.prototype.addEventListener = function (type, fn) { (this._listeners[type] = this._listeners[type] || []).push(fn); };
  AuthEventSource.prototype.removeEventListener = function (type, fn) { this._listeners[type] = (this._listeners[type] || []).filter(function (f) { return f !== fn; }); };
  AuthEventSource.prototype.close = function () { this.readyState = 2; if (this._abort) { try { this._abort.abort(); } catch (e) { /* ignore */ } } };
  AuthEventSource.prototype._fail = function (status) {
    if (this.readyState === 2) return;
    this.readyState = 0;
    if (status === 401 || status === 403) needLogin(status);
    if (typeof this.onerror === 'function') this.onerror({ type: 'error', status: status });
  };
  window.QodiqaAuthEventSource = AuthEventSource;

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', buildBar); else buildBar();
  window.QodiqaAdminAuth = { getKey: currentKey, setKey: setKey };
})();
