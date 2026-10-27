#!/usr/bin/env node
'use strict';

/**
 * reference WITNESS for QODIQA_WITNESS_MODE=exec. Run it in ANOTHER trust domain (a customer-controlled
 * host or account; the gateway reaches it through whatever transport the operator wires into QODIQA_WITNESS_EXEC,
 * e.g. an ssh/agent wrapper). It reads { statement } on stdin, enforces the witness rules against its own
 * append-only log, and prints { witnessId, keyId, signature, cosignedAt } on stdout.
 *
 *   WITNESS_ID=customer-witness WITNESS_KEY_PATH=/secure/witness-key.json WITNESS_LOG_PATH=/secure/witness-log.jsonl \
 *     node scripts/anchor/witness-cosign.js < statement.json
 *   node scripts/anchor/witness-cosign.js --public-key     # the trust-set record to publish out of band (no secret)
 *
 * Refusals exit 3 with the code on stderr: WITNESS_ROLLBACK_REFUSED / WITNESS_EQUIVOCATION_REFUSED.
 * The statement format and signing digest are src/core/audit/anchoring/witness.js (statementDigest).
 */

const fs = require('fs');
const { LocalFileWitness } = require('../../src/core/audit/anchoring/witness');

function witness() {
  const { WITNESS_ID, WITNESS_KEY_PATH, WITNESS_LOG_PATH } = process.env;
  if (!WITNESS_ID || !WITNESS_KEY_PATH || !WITNESS_LOG_PATH) { console.error('WITNESS_ID, WITNESS_KEY_PATH and WITNESS_LOG_PATH are required'); process.exit(64); }
  return new LocalFileWitness({ witnessId: WITNESS_ID, keyPath: WITNESS_KEY_PATH, logPath: WITNESS_LOG_PATH });
}

if (process.argv.includes('--public-key')) { console.log(JSON.stringify(witness().publicKeyRecord())); process.exit(0); }

let input;
try { input = JSON.parse(fs.readFileSync(0, 'utf8')); } catch { console.error('stdin must be JSON { statement }'); process.exit(64); }
const st = input && input.statement;
// phase 7: strict statement shape (fail-closed, exit 64). The old check accepted a missing headHash /
// checkpointId / createdAt (signed as null) and a non-positive chainLength.
const str = (v, max = 256) => typeof v === 'string' && v.length > 0 && v.length <= max;
if (!st || typeof st !== 'object' || st.v !== 1 || !/^[0-9a-f]{64}$/.test(String(st.checkpointPayloadHash))
  || !Number.isSafeInteger(st.chainLength) || st.chainLength < 1 || !str(st.headHash) || !str(st.checkpointId) || !str(st.checkpointCreatedAt, 64)
  || !(st.previousCheckpointHash === null || st.previousCheckpointHash === undefined || /^[0-9a-f]{64}$/.test(String(st.previousCheckpointHash)))) {
  console.error('malformed statement'); process.exit(64);
}
const w = witness();
if (st.witnessId !== w.witnessId) { console.error(`statement is for witness ${st.witnessId}, this is ${w.witnessId}`); process.exit(64); }
// LocalFileWitness.cosign() takes a signed checkpoint; rebuild the fields the statement is derived from.
const asCheckpoint = { payloadHash: st.checkpointPayloadHash, payload: { checkpointId: st.checkpointId, chainLength: st.chainLength,
  headHash: st.headHash, previousCheckpointHash: st.previousCheckpointHash, createdAt: st.checkpointCreatedAt } };
try {
  process.stdout.write(JSON.stringify(w.cosign(asCheckpoint)) + '\n');
} catch (e) {
  console.error(`${e.code || 'WITNESS_ERROR'}: ${e.message}`);
  process.exit(e.code === 'WITNESS_ROLLBACK_REFUSED' || e.code === 'WITNESS_EQUIVOCATION_REFUSED' || e.code === 'WITNESS_FORK_REFUSED' ? 3 : 1 /* a fork refusal is a refusal (3), not a failure to retry */);
}
