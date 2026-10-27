'use strict';

/**
 * Regression test for (hidden PostgreSQL consent dependency).
 *
 * The default `policies.json` ships with POL-001 (REQUIRE_CONSENT) enabled,
 * which unconditionally requires PostgreSQL-backed consent. That dependency
 * must stay documented in the onboarding path — this test fails loudly if
 * docs/guides/quickstart.md, docs/operations/troubleshooting.md, or deploy/env/production.env.example ever regress
 * to omitting it, independent of whether the underlying code changes.
 */

const fs   = require('fs');
const path = require('path');

const REPO_ROOT = path.join(__dirname, '..');
const read = (relPath) => fs.readFileSync(path.join(REPO_ROOT, relPath), 'utf8');

describe('regression — PostgreSQL consent dependency stays documented', () => {
  test('docs/guides/quickstart.md documents QODIQA_PG_ENABLED and how to provision consent before first execution', () => {
    const quickstart = read('docs/guides/quickstart.md');

    expect(quickstart).toMatch(/Provision Consent \(PostgreSQL\)/);
    expect(quickstart).toMatch(/QODIQA_PG_ENABLED=true/);
    expect(quickstart).toMatch(/CONSENT_STORE_UNAVAILABLE/);

    // The consent-provisioning section must appear before the first
    // "Execute First Authorized Request" walkthrough, not after — an
    // onboarding fix that documents the dependency too late doesn't help.
    const provisionIndex = quickstart.indexOf('Provision Consent (PostgreSQL)');
    const executeIndex   = quickstart.indexOf('Execute First Authorized Request');
    expect(provisionIndex).toBeGreaterThan(-1);
    expect(executeIndex).toBeGreaterThan(-1);
    expect(provisionIndex).toBeLessThan(executeIndex);
  });

  test('docs/operations/troubleshooting.md documents every consent-registry reason code the enforcement pipeline can return', () => {
    const troubleshooting = read('docs/operations/troubleshooting.md');

    for (const reason of [
      'CONSENT_STORE_UNAVAILABLE',
      'CONSENT_NOT_FOUND',
      'CONSENT_REVOKED',
      'CONSENT_SCOPE_MISMATCH',
      'CONSENT_CONTEXT_INCOMPLETE',
      'CONSENT_EVALUATION_ERROR',
    ]) {
      expect(troubleshooting).toContain(reason);
    }
  });

  test('deploy/env/production.env.example documents the QODIQA_PG_* variables required for consent enforcement', () => {
    const envExample = read('deploy/env/production.env.example');

    expect(envExample).toMatch(/QODIQA_PG_ENABLED/);
    expect(envExample).toMatch(/QODIQA_PG_HOST/);
    expect(envExample).toMatch(/CONSENT_STORE_UNAVAILABLE/);
  });

  test('docs/configuration/reference.md documents QODIQA_PG_ENABLED as required for consent enforcement, not only audit dual-write', () => {
    const configRef = read('docs/configuration/reference.md');

    expect(configRef).toMatch(/Runtime Consent Registry/);
    expect(configRef).toMatch(/CONSENT_STORE_UNAVAILABLE/);
  });
});
