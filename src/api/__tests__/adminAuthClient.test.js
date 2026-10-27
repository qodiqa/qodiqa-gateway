'use strict';

/**
 * public/js/common/adminAuth.js must (a) add the operator key to same-origin fetches only,
 * (b) never send it cross-origin, (c) show the sign-in bar on 401, (d) give SSE streams the header (EventSource cannot).
 */
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const SRC = fs.readFileSync(path.join(__dirname, '../../../public/js/common/adminAuth.js'), 'utf8');

function boot(fetchImpl) {
  const dom = new JSDOM('<!doctype html><body></body>', { url: 'http://gw.test/dashboard.html', runScripts: 'outside-only', pretendToBeVisual: true });
  const w = dom.window;
  w.fetch = fetchImpl;
  w.Headers = Headers;
  w.TextDecoder = TextDecoder;
  w.AbortController = AbortController;
  w.eval(SRC);
  return w;
}

const flush = () => new Promise((r) => setTimeout(r, 20));

test('same-origin fetch carries Bearer once a key is set; cross-origin does not', async () => {
  const calls = [];
  const w = boot(async (u, init) => { calls.push({ u, h: new Headers((init && init.headers) || {}) }); return { status: 200, ok: true }; });
  w.QodiqaAdminAuth.setKey('k-test-123');
  await w.fetch('/audit-viewer/events');
  await w.fetch('http://evil.test/x');
  expect(calls[0].h.get('authorization')).toBe('Bearer k-test-123');
  expect(calls[1].h.get('authorization')).toBeNull();
});

test('a 401 shows the sign-in bar; no key means no Authorization header', async () => {
  const calls = [];
  const w = boot(async (u, init) => { calls.push(init); return { status: 401, ok: false }; });
  await w.fetch('/dashboard/data');
  expect(calls[0] && calls[0].headers).toBeUndefined();
  const bar = w.document.getElementById('qodiqa-auth-bar');
  expect(bar).not.toBeNull();
  expect(bar.textContent).toMatch(/sign in/i);
});

test('QodiqaAuthEventSource sends the header, parses named events, and reports failures', async () => {
  const enc = new TextEncoder();
  let seen;
  const w = boot(async (u, init) => {
    seen = init.headers;
    if (u === '/bad') return { status: 401, ok: false, body: null };
    const body = new ReadableStream({ start(c) { c.enqueue(enc.encode(': hi\n\nevent: snapshot\ndata: {"a":1}\n\n')); c.close(); } });
    return { status: 200, ok: true, body };
  });
  w.QodiqaAdminAuth.setKey('k-sse');
  const got = []; const opened = []; const errs = [];
  const es = new w.QodiqaAuthEventSource('/dashboard/stream');
  es.onopen = () => opened.push(1);
  es.addEventListener('snapshot', (e) => got.push(e.data));
  es.onerror = (e) => errs.push(e.status);
  await flush();
  expect(new Headers(seen).get('authorization')).toBe('Bearer k-sse');
  expect(opened).toHaveLength(1);
  expect(got).toEqual(['{"a":1}']);
  expect(errs.length).toBeGreaterThan(0); // stream end is surfaced so pages can reconnect

  const bad = new w.QodiqaAuthEventSource('/bad');
  const e2 = []; bad.onerror = (e) => e2.push(e.status);
  await flush();
  expect(e2).toEqual([401]);
});
