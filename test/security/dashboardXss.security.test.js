'use strict';

/**
 * TEST-5 remediation — dedicated red-team regression coverage for the
 * dashboard stored-XSS finding ("Stored XSS in audit dashboard via
 * investigation title → admin-session compromise").
 *
 * ── Root cause being guarded against ──────────────────────────────────────
 * The audit-viewer investigation API (src/api/routes/auditViewer.js
 * POST /audit-viewer/investigation → src/core/investigation/store.js)
 * stores `title`/`notes`/`investigator` verbatim — there is no server-side
 * HTML sanitization anywhere in that path. The ONLY thing standing between
 * an attacker-supplied investigation title and script execution in an
 * operator's browser is the dashboard's own client-side escaping at
 * render time. That makes it a classic stored-XSS setup: persist once,
 * detonate on every future view, for every operator who opens it.
 *
 * ── Current implementation (verified before writing these tests) ─────────
 * Every public/*.html dashboard defines its own `esc()` (HTML-entity
 * encode) and, in audit-viewer.html, an additional `attrJs()` helper
 * (JSON.stringify() + esc()) for safely embedding values as arguments to
 * inline `onclick="..."` handlers — a comment at public/audit-viewer.html:552
 * explicitly documents why JSON.stringify() ALONE is not sufficient in an
 * HTML-attribute context and why esc() must wrap it too. Investigation
 * title/notes/investigator ARE currently routed through esc() at every
 * render site found (public/audit-viewer.html: loadInvestigationList(),
 * openInvestigationDetail()) — already appears fixed. These tests
 * exist so that stays true.
 *
 * A related (but distinct, and NOT currently exploitable) pattern was
 * found while mapping every render site: public/policy-management.html
 * embeds `JSON.stringify(pid)`/`JSON.stringify(p.status)` directly into
 * onclick attributes WITHOUT the esc() wrapper audit-viewer.html uses for
 * the equivalent case. It is not reachable today only because
 * src/core/policy/store.js's POLICY_ID_RE (`^[A-Za-z0-9_-]{1,64}$`)
 * rejects any policyId containing HTML metacharacters before it can ever
 * reach that template — Section 5 below pins that boundary with a test so
 * a future loosening of the regex is caught immediately. Hardening the
 * client-side pattern itself is tracked separately and intentionally left
 * out of this change (no production behavior is altered here beyond what
 * these regression tests require).
 *
 * ── Testing strategy (why no Playwright/jsdom was added) ──────────────────
 * The project has no browser-testing dependency (no Playwright/Puppeteer/
 * Cypress/jsdom in package.json) and the task guidance is to not introduce
 * one unnecessarily. These dashboards are plain, dependency-free inline
 * <script> blocks with top-level function declarations (not bundled/
 * transpiled), so the REAL production source can be executed directly in
 * Node's built-in `vm` module against a minimal DOM stub — see
 * test/helpers/dashboardScriptSandbox.js. This calls the actual esc()/
 * attrJs()/render*() functions verbatim (not a reimplementation), so a
 * regression that deletes an esc() call, swaps it for raw interpolation,
 * or weakens the entity-encoding is caught by re-reading the file at test
 * time — there is nothing here to fall silently out of sync with the
 * source. console.html wraps its whole script in one IIFE (no top-level
 * functions reachable off the sandbox); its esc() is the
 * shared public/js/common/esc.js implementation (destructured off
 * window.QodiqaCommon at the top of the IIFE), so Section 1 tests that
 * module directly for console.html rather than extracting a local
 * function that no longer exists in its source.
 *
 * ── Assertion methodology ─────────────────────────────────────────────────
 * "Does the output still contain the word onerror=" is NOT a valid check —
 * escaped text can legitimately contain that substring as inert prose
 * (e.g. `&lt;img onerror=alert(1)&gt;` is completely inert; the browser
 * never parses a tag there because the angle brackets are entity-encoded).
 * The correct invariants, used throughout this file, are:
 *   (a) the exact raw payload string never appears verbatim in rendered
 *       output — proves no unescaped copy leaked through;
 *   (b) every '<' and '>' character the payload contributes is rendered as
 *       '&lt;'/'&gt;' — proves entity-encoding actually ran, not merely
 *       that the raw string is "different" some other way (e.g. truncated);
 *   (c) for isolated esc()-output checks (no surrounding safe HTML), ZERO
 *       literal '<' or '>' may survive anywhere in the string — the
 *       strongest form, valid there because the whole string IS the
 *       escaped payload;
 *   (d) for values embedded as onclick/attribute arguments (attrJs()),
 *       ZERO literal '"' may survive — a double-quoted HTML attribute can
 *       only be broken out of with a literal quote character.
 */

const {
  loadDashboardScript,
} = require('../helpers/dashboardScriptSandbox');
const commonEsc = require('../../public/js/common/esc');

// ── Shared malicious payload corpus (per TEST-5 remediation spec) ────────────

const PAYLOADS = {
  scriptTag:       '<script>alert(1)</script>',
  imgOnerror:      '<img src=x onerror=alert(1)>',
  svgOnload:       '<svg onload=alert(1)>',
  javascriptUri:   '<a href="javascript:alert(1)">click</a>',
  attrBreakout:    '" onmouseover="alert(1)',
  preEncoded:      '&lt;script&gt;alert(1)&lt;/script&gt;',
  nestedTag:       '<scr<script>ipt>alert(1)</scr</script>ipt>',
  nestedTag2:      '<<script>script>alert(1)<</script>/script>',
  templateInject:  '${alert(1)}',
  templateInject2: '{{constructor.constructor("alert(1)")()}}',
  eventHandlerDiv: '<div onclick="alert(1)">click me</div>',
};

/** Every literal '<' or '>' in `escaped` must be gone — the strongest
 * possible invariant, valid when `escaped` IS the full esc() output with no
 * surrounding safe markup. */
function expectNoRawAngleBrackets(escaped) {
  expect(escaped).not.toMatch(/[<>]/);
}

/** Valid inside a full page-fragment render: the exact raw payload must
 * never survive verbatim, and its angle brackets must show up encoded.
 *
 * Payloads with no HTML metacharacters at all (e.g. the template-injection
 * strings '${alert(1)}' / '{{...}}') are a special case: none of these
 * dashboards run stored strings through a template engine or eval() a
 * second time, so such a payload appearing verbatim as inert text is the
 * CORRECT, safe outcome — there is no sink that would ever interpret it.
 * Only payloads that could actually form markup ('<' or '>' present) are
 * required to be absent in raw form. */
function expectPayloadNeutralizedWithin(renderedHtml, rawPayload) {
  const canFormMarkup = /[<>]/.test(rawPayload);
  if (!canFormMarkup) return;
  expect(renderedHtml).not.toContain(rawPayload);
  if (rawPayload.includes('<')) expect(renderedHtml).toContain('&lt;');
  if (rawPayload.includes('>')) expect(renderedHtml).toContain('&gt;');
}

/** Valid for a value about to be embedded inside a double-quoted HTML
 * attribute (onclick="...", data-tip="..."): zero literal quote chars. */
function expectNoAttributeBreakout(attrSafeValue) {
  expect(attrSafeValue).not.toMatch(/"/);
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 1 — esc() itself, across all four dashboard files
// ─────────────────────────────────────────────────────────────────────────────

describe.each([
  ['audit-viewer.html',     () => loadDashboardScript('audit-viewer.html').ctx],
  ['dashboard.html',        () => loadDashboardScript('dashboard.html').ctx],
  ['policy-management.html', () => loadDashboardScript('policy-management.html').ctx],
  ['console.html',          () => commonEsc],
])('esc() in %s neutralizes every payload in the corpus', (_file, getCtx) => {
  let ctx;
  beforeAll(() => { ctx = getCtx(); });

  test.each(Object.entries(PAYLOADS))('%s', (_name, payload) => {
    const escaped = ctx.esc(payload);
    expectNoRawAngleBrackets(escaped);
    // esc() must not be a no-op / passthrough for any payload with markup.
    if (/[<>]/.test(payload)) expect(escaped).not.toBe(payload);
  });

  test('esc() does not throw on null/undefined (used defensively at call sites)', () => {
    // Not all four copies normalize null/undefined to '' (some just
    // stringify to the literal text "null"/"undefined", which is inert,
    // not a security issue) — the only invariant that must hold everywhere
    // is that esc() never throws and always returns a plain string.
    expect(() => ctx.esc(null)).not.toThrow();
    expect(() => ctx.esc(undefined)).not.toThrow();
    expect(typeof ctx.esc(null)).toBe('string');
    expect(typeof ctx.esc(undefined)).toBe('string');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 2 — attrJs(): the onclick-argument attribute-escaping helper
// (audit-viewer.html only — the file that actually defines it)
// ─────────────────────────────────────────────────────────────────────────────

describe('attrJs() — safe embedding of values as onclick() arguments', () => {
  let ctx;
  beforeAll(() => { ctx = loadDashboardScript('audit-viewer.html').ctx; });

  test.each(Object.entries(PAYLOADS))('%s cannot break out of a double-quoted attribute', (_name, payload) => {
    const attrValue = ctx.attrJs(payload);
    expectNoAttributeBreakout(attrValue);
  });

  test('embedding attrJs() output inside onclick="...(...)" never introduces a literal quote', () => {
    const malicious = '"); alert(document.cookie); //';
    const built = `onclick="openArtifact(${ctx.attrJs(malicious)})"`;
    // Exactly two '"' characters may exist in the whole attribute: the
    // opening and closing delimiters that this test itself added.
    expect((built.match(/"/g) || []).length).toBe(2);
  });

  test('JSON.stringify() ALONE (no esc()) — control case proving attrJs() must wrap it', () => {
    // This asserts the documented reason attrJs() exists at all: bare
    // JSON.stringify() leaves the string's own escaped quote (\") intact
    // as a literal '"' character once dropped into an HTML attribute,
    // because HTML attribute parsing has no concept of backslash-escaping.
    const malicious = '");alert(1);//';
    const bareJson  = JSON.stringify(malicious);
    expect(bareJson).toMatch(/"/); // proves the control case IS still breakable
    expect(ctx.attrJs(malicious)).not.toMatch(/"/); // proves attrJs() fixes it
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 3 — exact vector: investigation title/notes, real render path
// ─────────────────────────────────────────────────────────────────────────────

describe('investigation title/notes render through the real audit-viewer pipeline', () => {

  test.each(Object.entries(PAYLOADS))(
    'openInvestigationDetail(): title=%s never executes',
    async (_name, payload) => {
      const investigation = {
        id: 'inv-test', title: payload, status: 'OPEN',
        investigator: 'analyst', notes: payload, createdAt: Date.now(),
        summary: { totalArtifacts: 0, found: 0, allowed: 0, blocked: 0, replaysDetected: 0, verificationFailures: 0 },
        artifacts: [], artifactIds: [],
      };
      const { ctx, getElement } = loadDashboardScript('audit-viewer.html', {
        fetchImpl: async () => ({ ok: true, status: 200, statusText: 'OK', json: async () => ({ data: investigation }) }),
      });

      await ctx.openInvestigationDetail('inv-test');
      const html = getElement('inv-detail-wrap').innerHTML;

      expectPayloadNeutralizedWithin(html, payload);
    },
  );

  test.each(Object.entries(PAYLOADS))(
    'loadInvestigationList(): title=%s never executes in the list view',
    async (_name, payload) => {
      const { ctx, getElement } = loadDashboardScript('audit-viewer.html', {
        fetchImpl: async () => ({
          ok: true, status: 200, statusText: 'OK',
          json: async () => ({
            data: {
              total: 1,
              investigations: [{ id: 'inv-1', title: payload, status: 'OPEN', investigator: 'analyst', artifactIds: [], createdAt: Date.now() }],
            },
          }),
        }),
      });

      await ctx.loadInvestigationList(1);
      const html = getElement('inv-list-wrap').innerHTML;

      expectPayloadNeutralizedWithin(html, payload);
    },
  );

  test('investigator name and investigation id are also escaped (not just title)', async () => {
    const payload = '<img src=x onerror=alert(document.cookie)>';
    const { ctx, getElement } = loadDashboardScript('audit-viewer.html', {
      fetchImpl: async () => ({
        ok: true, status: 200, statusText: 'OK',
        json: async () => ({
          data: {
            id: payload, title: 'Normal title', status: 'OPEN',
            investigator: payload, notes: '', createdAt: Date.now(),
            summary: { totalArtifacts: 0, found: 0, allowed: 0, blocked: 0, replaysDetected: 0, verificationFailures: 0 },
            artifacts: [], artifactIds: [],
          },
        }),
      }),
    });

    await ctx.openInvestigationDetail('anything');
    const html = getElement('inv-detail-wrap').innerHTML;

    expectPayloadNeutralizedWithin(html, payload);
  });

  test('a malicious artifactId inside an investigation record cannot execute via its onclick handler', async () => {
    const payload = '"><img src=x onerror=alert(1)>';
    const { ctx, getElement } = loadDashboardScript('audit-viewer.html', {
      fetchImpl: async () => ({
        ok: true, status: 200, statusText: 'OK',
        json: async () => ({
          data: {
            id: 'inv-1', title: 'x', status: 'OPEN', investigator: 'a', notes: '', createdAt: Date.now(),
            summary: { totalArtifacts: 1, found: 1, allowed: 1, blocked: 0, replaysDetected: 0, verificationFailures: 0 },
            artifacts: [{ artifactId: payload, decision: 'ALLOW', signatureStatus: 'VALID', replayCount: 0, timestamp: Date.now() }],
            artifactIds: [payload],
          },
        }),
      }),
    });

    await ctx.openInvestigationDetail('inv-1');
    const html = getElement('inv-detail-wrap').innerHTML;

    expectPayloadNeutralizedWithin(html, payload);
  });

});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 4 — Broader dashboard surfaces: execution metadata, audit
// artifacts, timeline events, tenant/provider-style tabular data
// ─────────────────────────────────────────────────────────────────────────────

describe('Audit artifact / execution-metadata rendering (audit-viewer.html)', () => {
  let ctx;
  beforeAll(() => { ctx = loadDashboardScript('audit-viewer.html').ctx; });

  test.each(Object.entries(PAYLOADS))('renderArtifactDetail(): malicious provider/reason/stage — %s', (_name, payload) => {
    const html = ctx.renderArtifactDetail({
      artifactId: 'a1', decision: 'ALLOW', resolvedAt: Date.now(),
      execution: { stage: payload, reason: payload, provider: payload },
      signature: { failureReason: payload, value: payload },
      policy: { reason: payload }, consent: {}, replay: {}, chain: {},
      hashes: {}, raw: {},
    });
    expectPayloadNeutralizedWithin(html, payload);
  });

  test.each(Object.entries(PAYLOADS))('renderTimelineItem(): malicious eventType/reason/provider — %s', (_name, payload) => {
    const html = ctx.renderTimelineItem({
      eventType: payload, stage: payload, reason: payload, provider: payload,
      timestamp: Date.now(), artifactId: 'a1',
    }, false);
    expectPayloadNeutralizedWithin(html, payload);
  });

  // CLN-02 (D6 annex item 7 /): renderChainDetail()'s chain-link-detail
  // sink concatenated Object.entries(l.details) keys/values into innerHTML
  // without esc() — inconsistent with the failures/findings block two lines
  // below it, which does escape. No producer currently emits free text into
  // `details`, but the sink goes live the moment a future/custom policy
  // evaluator does.
  //
  // This sink truncates each detail value to 24 raw chars via short() BEFORE
  // escaping, so a payload's trailing metacharacters (e.g. imgOnerror's
  // closing '>') can legitimately fall past the cutoff and never appear in
  // any form — that's truncation, not a leak. expectPayloadNeutralizedWithin
  // assumes the full payload is echoed, so it doesn't fit this sink; instead
  // assert against what the sink actually emits — esc(short(value, 24)),
  // computed via the real production esc()/short() — which still fails
  // correctly the instant esc() is removed from the sink, since ctx.esc()
  // would then diverge from the (now-unescaped) rendered output.
  test.each(Object.entries(PAYLOADS))('renderChainDetail(): malicious chain-link detail value — %s', (_name, payload) => {
    const html = ctx.renderChainDetail({
      status: 'FAILED', verifiedAt: Date.now(), failures: [], findings: [],
      links: [{ label: 'link-1', verified: false, status: 'FAILED', details: { reason: payload } }],
      integrity: {},
    });
    // Payloads with none of esc()'s escapable chars (&<>"') are legitimately
    // unaltered — same "correct, safe outcome" carve-out documented at
    // expectPayloadNeutralizedWithin above (no template engine/eval() sink
    // exists to interpret them).
    if (/[&<>"']/.test(payload)) expect(html).not.toContain(payload);
    expect(html).toContain(`${ctx.esc('reason')}: ${ctx.esc(ctx.short(String(payload), 24))}`);
  });

  test('renderChainDetail(): a malicious chain-link detail key is also escaped, not just the value', () => {
    const payload = '<img src=x onerror=alert(document.cookie)>';
    const html = ctx.renderChainDetail({
      status: 'FAILED', verifiedAt: Date.now(), failures: [], findings: [],
      links: [{ label: 'link-1', verified: false, status: 'FAILED', details: { [payload]: 'somevalue' } }],
      integrity: {},
    });
    expect(html).not.toContain(payload);
    expect(html).toContain(`${ctx.esc(payload)}: ${ctx.esc(ctx.short('somevalue', 24))}`);
  });

});

describe('Search-results table rendering (audit-viewer.html runSearch — policy evidence / audit fields)', () => {
  test.each(Object.entries(PAYLOADS))('search result row: malicious reason/provider/stage — %s', async (_name, payload) => {
    const { ctx, getElement } = loadDashboardScript('audit-viewer.html', {
      fetchImpl: async () => ({
        ok: true, status: 200, statusText: 'OK',
        json: async () => ({
          data: {
            total: 1,
            results: [{
              artifactId: 'a1', timestamp: Date.now(), decision: 'ALLOW',
              signatureStatus: 'VALID', stage: payload, reason: payload, provider: payload,
            }],
          },
        }),
      }),
    });

    await ctx.runSearch(1);
    const html = getElement('search-results-wrap').innerHTML;

    expectPayloadNeutralizedWithin(html, payload);
  });
});

describe('Generic tabular rendering (dashboard.html renderTable — tenant/provider-style data)', () => {
  test.each(Object.entries(PAYLOADS))('malicious cell value — %s', (_name, payload) => {
    const { ctx, getElement } = loadDashboardScript('dashboard.html');
    ctx.renderTable('tbl-wrap', [{ key: 'name', label: 'Name' }], [{ name: payload }], 'No data');
    const html = getElement('tbl-wrap').innerHTML;
    expectPayloadNeutralizedWithin(html, payload);
  });
});

describe('Policy list rendering (policy-management.html loadPolicies — policy evidence)', () => {
  test.each(Object.entries(PAYLOADS))('malicious policy name/modifiedBy — %s', async (_name, payload) => {
    const { ctx, getElement } = loadDashboardScript('policy-management.html', {
      fetchImpl: async () => ({
        ok: true, status: 200, statusText: 'OK',
        json: async () => ({
          policies: [{
            policyId: 'safe-id-1', name: payload, type: 'RATE_LIMIT', status: 'ACTIVE',
            version: 1, updatedAt: Date.now(), updatedBy: payload,
          }],
          total: 1,
        }),
      }),
    });

    await ctx.loadPolicies();
    const html = getElement('pol-table-wrap').innerHTML;

    expectPayloadNeutralizedWithin(html, payload);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 5 — Defense-in-depth boundary: server-side policyId validation
// (why policy-management.html's raw JSON.stringify()-in-onclick pattern is
// not currently exploitable — see file header)
// ─────────────────────────────────────────────────────────────────────────────

describe('Server-side policyId charset validation (src/core/policy/store.js)', () => {
  const { validatePolicyCandidate } = require('../../src/core/policy/store');

  const attributeBreakoutIds = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    '" onmouseover="alert(1)',
    "'; alert(1); '",
    'id with spaces',
    'id/with/slashes',
  ];

  test.each(attributeBreakoutIds)('policyId %j is rejected before it can reach any dashboard template', (maliciousId) => {
    const result = validatePolicyCandidate({
      id: maliciousId, type: 'RATE_LIMIT', priority: 100, enabled: true, config: {},
    }, null);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('id must match'))).toBe(true);
  });

  test('a normal alphanumeric/dash/underscore policyId is accepted by the id check', () => {
    const result = validatePolicyCandidate({
      id: 'valid_policy-id-123', type: 'RATE_LIMIT', priority: 100, enabled: true, config: {},
    }, null);
    expect(result.errors.some(e => e.includes('id must match'))).toBe(false);
  });
});
