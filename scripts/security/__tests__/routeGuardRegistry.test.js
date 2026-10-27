'use strict';

/**
 * step 9 — every mounted route has a declared, tested guard.
 *
 * Builds the REAL app (scripts/security/routeGuardTable.js, the same factories
 * as server/startup.js) in a child process and holds its measured guards to
 * docs/security/route-guard-registry.json:
 *   - a mounted route with no declaration fails;
 *   - a declaration with no mounted route fails;
 *   - a route whose guards differ from its declaration fails;
 *   - every generator gap must be covered by a declared, approved exception;
 * - the invariants hold (rate limit everywhere, RBAC on every operator
 *     route, MFA step-up on the S1 surfaces, D7 optional auth on the public
 *     verification routes, certification evaluate authenticated).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const lib = require('../routeGuardRegistryLib');

const REPO = path.join(__dirname, '..', '..', '..');
const registry = JSON.parse(fs.readFileSync(path.join(REPO, 'docs', 'security', 'route-guard-registry.json'), 'utf8'));
let rows;
let live;

beforeAll(() => {
  const dir = path.join(os.tmpdir(), 'qodiqa-route-guard-table', 'registry-test');
  fs.mkdirSync(dir, { recursive: true });
  const json = path.join(dir, 'table.json');
  execFileSync(process.execPath, [path.join(REPO, 'scripts', 'security', 'routeGuardTable.js'), '--json', json, '--md', path.join(dir, 'table.md')],
    { cwd: REPO, stdio: 'pipe', timeout: 120_000 });
  rows = JSON.parse(fs.readFileSync(json, 'utf8')).rows;
  live = lib.build(rows, registry.exceptions).declare;
}, 150_000);

describe('route-guard registry ↔ live app', () => {
  test('the app mounts a plausible number of routes (generator ran)', () => {
    expect(rows.length).toBeGreaterThan(250);
  });

  test('every mounted route has a declared guard entry', () => {
    const undeclared = Object.keys(live).filter((k) => !(k in registry.routes));
    expect(undeclared).toEqual([]);
  });

  test('every declared route is still mounted', () => {
    const stale = Object.keys(registry.routes).filter((k) => !(k in live));
    expect(stale).toEqual([]);
  });

  test('every route’s guards match its declaration', () => {
    const diffs = Object.keys(live).filter((k) => k in registry.routes)
      .filter((k) => JSON.stringify(live[k]) !== JSON.stringify(registry.routes[k]))
      .map((k) => ({ route: k, declared: registry.routes[k], live: live[k] }));
    expect(diffs).toEqual([]);
  });

  test('every generator gap is covered by a declared exception', () => {
    const uncovered = rows.flatMap((r) => lib.coverGaps(r, registry.exceptions).uncovered);
    expect(uncovered).toEqual([]);
  });
});

describe('invariants over the live app', () => {
  const rk = (r) => `${r.methods.join(',')} ${r.path}`;

  test('every route has a rate-limit bucket (probes excepted)', () => {
    const bad = rows.filter((r) => r.rateLimitBuckets.length === 0 && !/^GET \/(health|health\/redis|ready)$/.test(rk(r))).map(rk);
    expect(bad).toEqual([]);
  });

  test('every operator-authenticated route carries an RBAC permission (D8/self-MFA excepted)', () => {
    const bad = rows.filter((r) => r.auth.includes('ops-api-key') && r.permissions.length === 0)
      .map(rk).filter((k) => !/^(GET|POST) \/(metrics|diagnostics)(\/|$)/.test(k) && !/^(GET|POST) \/rbac\/me\/mfa(\/enroll|\/confirm)?$/.test(k));
    expect(bad).toEqual([]);
  });

  test('/D4: every privileged mutation carries MFA step-up', () => {
    const S1 = /^\/(rbac|key-admin|signing-identities|policy-ui|v1\/webhooks|v1\/prq|v1\/admin)(\/|$)/;
    const bad = rows.filter((r) => S1.test(r.path) && r.methods.some((m) => !['GET', 'HEAD', 'OPTIONS'].includes(m)) && !r.mfaStepUp)
      .map(rk).filter((k) => !/^POST \/rbac\/me\/mfa\/(enroll|confirm)$/.test(k));
    expect(bad).toEqual([]);
    const gov = rows.filter((r) => /^\/v1\/policy\/governance\/.*\/(approve|publish|schedule|activate|retro-approve)$/.test(r.path));
    expect(gov.length).toBeGreaterThanOrEqual(5);
    expect(gov.filter((r) => !r.mfaStepUp).map(rk)).toEqual([]);
  });

  test('POST /v1/certification/evaluate requires operator auth + permission', () => {
    const r = rows.find((x) => x.path === '/v1/certification/evaluate' && x.methods.includes('POST'));
    expect(r.auth).toContain('ops-api-key');
    expect(r.permissions).toContain('SUBMIT_BATCH_CERTIFICATION');
    expect(r.rateLimitBuckets).toContain('certification_evaluate');
  });

  test('D7: public writing verification routes carry optional admin auth with the write permission', () => {
    // (NF-2): /v1/attestation/chain/verify is no longer public (6, was 7) — asserted in its own test below.
    const pub = rows.filter((r) => /^(\/v1)?\/(portal\/verify|transparency\/verify\/:transparencyId)$|^\/v1\/attestation\/(verify|evidence\/verify)$/.test(r.path));
    expect(pub.length).toBe(6);
    for (const r of pub) {
      expect(r.optionalAuth.join()).toMatch(/ops-api-key\(optional\)\[(MANAGE_VERIFICATION_PORTAL|READ_TRANSPARENCY_LOG|MANAGE_ATTESTATIONS)\]/);
      expect(r.rateLimitBuckets).toContain('public_verify');
    }
  });

  test('NF-2: POST /v1/attestation/chain/verify requires operator auth + MANAGE_ATTESTATIONS', () => {
    const r = rows.find((x) => x.path === '/v1/attestation/chain/verify' && x.methods.includes('POST'));
    expect(r.access).toBe('authenticated');
    expect(r.auth).toContain('ops-api-key');
    expect(r.permissions).toContain('MANAGE_ATTESTATIONS');
    expect(r.optionalAuth).toEqual([]);
  });

  test('/ai/chat has the per-IP limiter on every alias', () => {
    const chat = rows.filter((r) => /^(\/v1)?\/ai\/chat(\/stream)?$/.test(r.path));
    expect(chat.length).toBe(4);
    for (const r of chat) expect(r.rateLimitBuckets).toContain('ai_chat_ip');
  });
});

describe('the checker itself fails on an unguarded route', () => {
  test('a public writing route with no limiter produces uncovered gaps', () => {
    const fake = { methods: ['POST'], path: '/new-unguarded', gaps: ['PUBLIC WRITE (db)', 'NO RATE LIMIT'] };
    expect(lib.coverGaps(fake, registry.exceptions).uncovered).toHaveLength(2);
  });
});
