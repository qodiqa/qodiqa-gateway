'use strict';

/**
 * audit schema v7 — EXPLICIT TEST-ONLY stand-in for src/core/dsr/subjectPseudonym.js.
 *
 * Production (R-12 / R-14): every v7 audit append that carries consentProvenance.subject or callerContext.callerId
 * replaces it with the pseudonym `ap1:` + HMAC(K_subject, tenant ‖ 0x00 ‖ actorId), where K_subject lives in
 * PostgreSQL (subject_pseudonym_keys); without PostgreSQL the append is REFUSED (fail-closed). That behaviour is NOT
 * changed for tests — unit suites that exercise the audit path without a database opt in to this mock explicitly:
 *
 *   jest.mock('<rel>/src/core/dsr/subjectPseudonym', () => require('<rel>/tests/helpers/subjectPseudonymMock'));
 *
 * The stand-in keeps the production value FORMAT (`ap1:` + 64 hex) and contract (deterministic per (tenant, actor),
 * idempotent on values that already are pseudonyms), but derives from a fixed, test-only key — never a real key, never
 * a cache. `pseudonymFor` is a jest.fn so a suite can make it reject (to prove the fail-closed path) without a DB.
 * Real-key behaviour (key creation, RLS, erasure) is covered by the PostgreSQL integration suites, not by this mock.
 */

const crypto = require('crypto');

const PREFIX = 'ap1:';
const TEST_ONLY_KEY = Buffer.from('qodiqa-w7-test-only-subject-pseudonym-key', 'utf8');

function isPseudonym(v) { return typeof v === 'string' && /^ap1:[0-9a-f]{64}$/.test(v); }

function _pseudonymWithKey(key, tenantId, actorId) {
  return PREFIX + crypto.createHmac('sha256', key).update(`${tenantId ?? ''}\u0000${actorId}`).digest('hex');
}

/** The value the mock returns for (tenantId, actorId) — for assertions. */
function expectedPseudonym(tenantId, actorId) {
  return isPseudonym(actorId) ? actorId : _pseudonymWithKey(TEST_ONLY_KEY, tenantId, actorId);
}

const pseudonymFor = jest.fn(async (tenantId, actorId) => {
  if (!actorId) throw new Error('actorId is required');
  return expectedPseudonym(tenantId, actorId);
});

module.exports = {
  pseudonymFor,
  pseudonymForWithClient: jest.fn(async (_client, tenantId, actorId) => expectedPseudonym(tenantId, actorId)),
  subjectRef: jest.fn((tenantId, actorId) => crypto.createHmac('sha256', TEST_ONLY_KEY).update(`ledger\u0000${tenantId ?? ''}\u0000${actorId}`).digest('hex')),
  isPseudonym,
  PREFIX,
  _pseudonymWithKey,
  expectedPseudonym,
  __W7_TEST_ONLY_MOCK__: true,
};
