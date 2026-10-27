'use strict';
// test helper: a "previous process" that writes INTENT + DECISION of one request and is KILLED before it writes the COMMIT.
// usage: node crash.js <requestId>   (env: QODIQA_AUDIT_LOG, QODIQA_AUDIT_SCHEMA_V8=true)
const H = (c) => c.repeat(64);
(async () => {
  const rid = process.argv[2];
  const a = require('../../audit-log');
  const eb = require('../../entryBuilder');
  const { writeLifecycleEntry } = require('../../lifecycleEntry');
  const deps = { append: (f, o) => a.appendMandatory(f, o), register: async () => ({ persisted: true }) };
  await writeLifecycleEntry('INTENT', { requestId: rid, inputHash: H('a'), signature: H('s'), requestHash: H('b'), policyHash: H('c'), tenantId: 't', publicKeyId: 'default:key_v1',
    provider: 'openai', model: 'gpt-4', executingProvider: 'openai', issuedAt: 1790000000000, protocolVersion: 1 }, deps);
  await a.appendMandatory({ artifactId: rid, entryType: 'DECISION', decision: 'ALLOW', inputHash: H('a'), signature: H('s'), requestHash: H('b'), policyHash: H('c'), verificationResult: true,
    tenantId: 't', requestId: rid, executingProvider: 'openai', outputHash: eb.outputHashOf('hello'), stage: 'PROVIDER_EXECUTION', issuedAt: 1790000000000, protocolVersion: 1 }, { stage: 'ALLOW' });
  await a.drainPendingWrites();
  process.kill(process.pid, 'SIGKILL');            // the process dies between the DECISION and the COMMIT
  setTimeout(() => {}, 10_000);
})();
