#!/usr/bin/env node
'use strict';
/**
 * Writes docs/security/route-guard-registry.json: the DECLARED guard
 * for every mounted route, from a fresh run of scripts/security/routeGuardTable.js.
 *
 * The registry is what scripts/security/__tests__/routeGuardRegistry.test.js holds
 * the live app to: a route that is mounted but not declared, declared but not
 * mounted, or whose guards differ from the declaration fails the unit gate.
 * Regenerating is a deliberate act — review the diff (it is the change in the
 * perimeter) before committing it. Every generator gap must be covered by an
 * EXCEPTION below, each documented; an uncovered gap makes
 * this script exit 1 instead of writing.
 *
 *   node scripts/security/writeRouteGuardRegistry.js [--table <route-guard-table.json>]
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const REPO = path.join(__dirname, '..', '..');
const OUT = path.join(REPO, 'docs', 'security', 'route-guard-registry.json');

// Declared exceptions: gap label (prefix) → { routes: RegExp over "METHOD PATH", reason }.
const EXCEPTIONS = [
  { id: 'probe-no-limit', gap: 'no rate limit (probe', routes: /^GET \/(health|health\/redis|ready)$/, reason: 'Liveness/readiness probes are not rate limited (loopback/health-token gated instead).' },
  { id: 'ops-token-only', gap: 'AUTHENTICATED, NO RBAC PERMISSION', routes: /^(GET|POST) \/(metrics|diagnostics)(\/|$)/, reason: 'Ops-token-only by design (docs/security/RBAC_MODEL.md §6); READ_METRICS/READ_DIAGNOSTICS are planned.' },
  { id: 'self-service-mfa', gap: 'AUTHENTICATED, NO RBAC PERMISSION', routes: /^(GET|POST) \/rbac\/me\/mfa(\/enroll|\/confirm)?$/, reason: 'An operator manages only their OWN MFA enrolment; enrol is refused once enrolled, reset needs MANAGE_USERS + step-up.' },
  { id: 'signed-artifact-pre-auth', gap: 'WRITES REACHABLE BEFORE CALLER AUTH', routes: /^POST \/(v1\/)?(ai\/chat(\/stream)?|verify(\/v2)?)$/, reason: 'Every reject before the artifact signature verifies is counter+sampled-log only (qodiqa_preauth_rejects_total); audit/transparency writes happen only after verification. /verify writes only the lazy keystore bootstrap.' },
  { id: 'lazy-keystore-bootstrap', gap: 'PUBLIC WRITE (files)', routes: /^GET \/(\.well-known\/qodiqa\/(keys|transparency-keys|checkpoint-keys)(\/:keyId)?|public-keys?|keys)$/, reason: 'The only write is the keystore creating its first key when none exists (process bootstrap, not caller-controlled, idempotent).' },
  { id: 'idempotent-merkle-checkpoint', gap: 'PUBLIC WRITE (db)', routes: /^GET \/(v1\/)?transparency\/proof\/:transparencyId$/, reason: 'Proof lookup persists deterministic Merkle block checkpoints (INSERT … ON CONFLICT DO NOTHING); bounded by the log size, rate limited.' },
  { id: 'ephemeral-unless-authenticated', gap: 'PUBLIC WRITE', routes: /^(GET \/(v1\/)?transparency\/verify\/:transparencyId|POST \/(v1\/)?portal\/verify|POST \/v1\/attestation\/(verify|evidence\/verify|chain\/verify))$/, reason: 'Anonymous calls are ephemeral (nothing persisted); only a caller authenticated through the full admin stack with the write permission persists. A presented-but-invalid credential is refused. Proven in publicVerifyEphemeral.test.js.' },
  { id: 'portal-login', gap: 'PUBLIC WRITE (control-plane)', routes: /^GET \/tenant-portal\/(callback|dev-login)$/, reason: 'Tenant-portal login endpoints (OIDC callback; dev stub refused in production by boot rule) create the session user by design; portal-only (QODIQA_PORTAL_ENABLED). The write goes to the control plane (PostgreSQL), no longer to a file.' },
];

const argTable = process.argv.indexOf('--table');
let tablePath = argTable > 0 ? process.argv[argTable + 1] : null;
if (!tablePath) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-rgr-'));
  tablePath = path.join(dir, 'table.json');
  execFileSync(process.execPath, [path.join(__dirname, 'routeGuardTable.js'), '--json', tablePath, '--md', path.join(dir, 'table.md')], { stdio: 'inherit' });
}
const table = JSON.parse(fs.readFileSync(tablePath, 'utf8'));

const { declare, uncovered } = require('./routeGuardRegistryLib').build(table.rows, EXCEPTIONS);
if (uncovered.length) {
  console.error('Uncovered gaps — fix the route or add a documented exception:');
  for (const u of uncovered) console.error('  ', u);
  process.exit(1);
}
const out = {
  about: 'Declared route guards. Held to the live app by scripts/security/__tests__/routeGuardRegistry.test.js. Regenerate with scripts/security/writeRouteGuardRegistry.js and review the diff.',
  exceptions: EXCEPTIONS.map(({ id, gap, routes, reason }) => ({ id, gap, routes: routes.source, reason })),
  routes: declare,
};
fs.writeFileSync(OUT, JSON.stringify(out, null, 1) + '\n');
console.log(JSON.stringify({ routes: Object.keys(declare).length, exceptions: EXCEPTIONS.length, out: path.relative(REPO, OUT) }));
