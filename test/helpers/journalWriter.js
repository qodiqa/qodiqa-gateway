'use strict';

/**
 * test helper — the "process before the restart": registers N enforcement-decision leaves while PostgreSQL is unreachable, so each one goes
 * to the file journal on QODIQA_PRQ_JOURNAL_DIR. Prints one JSON line per leaf. Used by test/integration/journalRestart.integration.test.js, which then
 * plays the "process after the restart" against a live database.
 *
 *   node test/helpers/journalWriter.js <count> <requestIdPrefix>
 */

const { registerEnforcementDecision } = require('../../src/core/transparency/enforcementBridge');
const journalHealth = require('../../src/core/transparency/journalHealth');

(async () => {
  require('../../src/infra/postgres/pool').initialize();                    // a pool that cannot connect: PostgreSQL is "down"
  try { require('../../src/core/transparency/transparencyKeyStore').getActiveKey(); } catch { require('../../src/core/transparency/transparencyKeyStore').rotateKey(); }
  const n = Number(process.argv[2] || 3);
  const prefix = process.argv[3] || 'f52';
  for (let i = 0; i < n; i++) {
    const r = await registerEnforcementDecision({ requestId: `${prefix}-${i}`, decision: 'BLOCK', reason: 'TEST', stage: 'VALIDATION', tenantId: 't1', bestEffort: true });
    process.stdout.write(`${JSON.stringify({ i, transparencyId: r.transparencyId, persisted: r.persisted, durable: r.durable, payloadHash: r.payloadHash })}\n`);
    await new Promise((res) => setTimeout(res, 15));          // distinct recordedAt for an unambiguous original order
  }
  process.stdout.write(`${JSON.stringify({ health: journalHealth.snapshot() })}\n`);
  process.exit(0);
})().catch((e) => { process.stderr.write(`${e.stack}\n`); process.exit(1); });
