'use strict';

/**
 * remediation — permanent automated accessibility gate for the four
 * admin UIs (public/dashboard.html, console.html, audit-viewer.html,
 * policy-management.html).
 *
 * ── Why jsdom, unlike test/security/dashboardXss.security.test.js's stub DOM ──────
 * dashboardXss.security.test.js deliberately avoids a real DOM dependency —
 * a minimal auto-vivifying element stub is enough surface for its target
 * (does esc()/attrJs() neutralize a payload string?). axe-core's checks
 * (label association, ARIA role/attribute validity, tab structure) need to
 * walk a real element tree, read real attributes, and resolve real
 * id-reference relationships (for="...", aria-controls="...",
 * aria-labelledby="...") — a fake element cannot provide that. jsdom is the
 * lightest dependency that can, so it (plus axe-core itself) is added as a
 * devDependency scoped to this one gate rather than reused elsewhere.
 *
 * `color-contrast` is disabled below: it requires an actual paint/layout
 * engine to resolve rendered background colors through possibly-transparent
 * layers, which jsdom does not have. That is a documented axe-core-under-
 * jsdom limitation, not a scope reduction for this change —'s
 * findings
 * are both structural/semantic and are fully covered by the enabled rules.
 *
 * Every production <script src="/js/..."> this page's HTML actually loads is
 * executed verbatim (not reimplemented) inside the real, HTML-parsed DOM for
 * its page, in document order — including the shared public/js/common/*.js
 * infrastructure that dashboard.js/audit-viewer.js/console.js/
 * policy-management.js now depend on — exactly as a browser would run them
 * via <script defer>, so this test fails the moment the real page's rendered
 * structure regresses — not a copy of it. Network-dependent globals (fetch,
 * EventSource) are stubbed to reject/no-op so each page's real init code
 * runs without a live backend; the accessibility structure under test
 * (labels, ARIA tab wiring) is present in the initial render and does not
 * depend on live data arriving.
 */

const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const PUBLIC_DIR = path.join(__dirname, '..', '..', 'public');
const axeSource = fs.readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');

// added tenant-login.html/tenant-portal.html — the
// tenant self-service portal's two pages, covered by the same automated
// gate as the four existing admin UIs.
// approvals.html - the operator page for human approval of agent actions.
const PAGES = ['dashboard.html', 'console.html', 'audit-viewer.html', 'policy-management.html', 'tenant-login.html', 'tenant-portal.html', 'approvals.html'];

/**
 * Builds a jsdom window for fileName with its real production script loaded
 * and running, same as a browser would via <script defer>. Network globals
 * (fetch, EventSource) are stubbed so init code resolves harmlessly instead
 * of throwing, and recurring timers (setInterval — e.g. console.js's clock
 * tick, dashboard.js's live-stream reconnect backoff) are stubbed to a no-op
 * so the jsdom window has no open handles keeping the test process alive —
 * none of that polling/animation state affects the static accessibility
 * structure under test here.
 */
function loadPageWindow(fileName) {
  const html = fs.readFileSync(path.join(PUBLIC_DIR, fileName), 'utf8');
  // derive every local <script src="/js/..."> from the page's own
  // HTML, in document order, instead of hardcoding "the one main script" —
  // this also makes the helper self-maintaining if the script list changes
  // again later, since it now always matches whatever the HTML actually
  // loads (shared public/js/common/*.js files first, page script last).
  const scriptSrcs = [...html.matchAll(/<script\s+src="(\/js\/[^"]+)"/g)].map((m) => m[1]);
  const scripts = scriptSrcs.map((src) => fs.readFileSync(path.join(PUBLIC_DIR, src), 'utf8'));

  const dom = new JSDOM(html, {
    url: `http://localhost/${fileName}`,
    pretendToBeVisual: true,
    runScripts: 'outside-only',
  });
  const { window } = dom;

  window.fetch = () => Promise.reject(new Error('network disabled in accessibility test'));
  window.scrollTo = () => {};
  window.setInterval = () => 0;
  window.clearInterval = () => {};
  class EventSourceStub {
    addEventListener() {}
    close() {}
  }
  window.EventSource = EventSourceStub;

  try {
    scripts.forEach((script) => window.eval(script));
  } catch (err) {
    throw new Error(`${fileName}: production script threw during load — ${err.message}`);
  }

  return dom;
}

async function scanPage(fileName) {
  const dom = loadPageWindow(fileName);
  const { window } = dom;

  window.eval(axeSource);
  const results = await window.axe.run(window.document, {
    rules: {
      // See file header: jsdom does not paint, so this rule cannot reliably
      // resolve rendered background color through possibly-transparent
      // layers here. Not part's scope.
      'color-contrast': { enabled: false },
    },
  });

  window.close();
  return results;
}

function formatViolations(fileName, violations) {
  return (
    `axe-core found ${violations.length} violation(s) in public/${fileName}:\n\n` +
    violations
      .map(
        (v) =>
          `${v.id} (${v.impact}): ${v.help}\n` +
          v.nodes.map((n) => `  - ${n.target.join(' ')}`).join('\n')
      )
      .join('\n\n')
  );
}

describe.each(PAGES)('accessibility scan: %s', (fileName) => {
  let results;

  beforeAll(async () => {
    results = await scanPage(fileName);
  }, 30000);

  test('has zero axe-core violations', () => {
    if (results.violations.length > 0) {
      throw new Error(formatViolations(fileName, results.violations));
    }
    expect(results.violations).toEqual([]);
  });
});

describe('console.html — WAI-ARIA tab pattern', () => {
  let dom;
  let document;

  beforeAll(() => {
    dom = loadPageWindow('console.html');
    document = dom.window.document;
  });

  afterAll(() => {
    dom.window.close();
  });

  test('tablist contains only tab children, each wired to an existing tabpanel', () => {
    const tablist = document.getElementById('tabbar');
    expect(tablist.getAttribute('role')).toBe('tablist');

    const tabs = [...tablist.querySelectorAll('.tab-btn')];
    expect(tabs.length).toBeGreaterThan(0);

    for (const tab of tabs) {
      expect(tab.getAttribute('role')).toBe('tab');
      expect(['true', 'false']).toContain(tab.getAttribute('aria-selected'));
      const panelId = tab.getAttribute('aria-controls');
      expect(panelId).toBeTruthy();
      const panel = document.getElementById(panelId);
      expect(panel).not.toBeNull();
      expect(panel.getAttribute('role')).toBe('tabpanel');
      expect(panel.getAttribute('aria-labelledby')).toBe(tab.id);
    }
  });

  test('exactly one tab is selected with tabindex 0; the rest are -1 (roving tabindex)', () => {
    const tabs = [...document.querySelectorAll('.tab-btn')];
    const selected = tabs.filter((t) => t.getAttribute('aria-selected') === 'true');
    expect(selected).toHaveLength(1);
    for (const tab of tabs) {
      expect(tab.tabIndex).toBe(tab === selected[0] ? 0 : -1);
    }
  });

  test('clicking a tab updates aria-selected/tabindex and shows only its panel', () => {
    const window = document.defaultView;
    const subsystemsTab = document.getElementById('tab-subsystems');
    subsystemsTab.dispatchEvent(new window.MouseEvent('click', { bubbles: true }));

    expect(subsystemsTab.getAttribute('aria-selected')).toBe('true');
    expect(subsystemsTab.tabIndex).toBe(0);

    const overviewTab = document.getElementById('tab-overview');
    expect(overviewTab.getAttribute('aria-selected')).toBe('false');
    expect(overviewTab.tabIndex).toBe(-1);

    expect(document.getElementById('panel-subsystems').classList.contains('active')).toBe(true);
    expect(document.getElementById('panel-overview').classList.contains('active')).toBe(false);
  });
});

describe('form controls — no orphan labels, no duplicate ids', () => {
  test.each(PAGES)('%s has no duplicate element ids', (fileName) => {
    const html = fs.readFileSync(path.join(PUBLIC_DIR, fileName), 'utf8');
    const dom = new JSDOM(html);
    const ids = [...dom.window.document.querySelectorAll('[id]')].map((el) => el.id);
    const dupes = ids.filter((id, i) => ids.indexOf(id) !== i);
    expect([...new Set(dupes)]).toEqual([]);
  });
});
