#!/usr/bin/env node
'use strict';

/**
 * QODIQA Webhook Protocol — Vector Drift Check
 *
 * Regenerates the vector set and compares it against what's checked in,
 * ignoring the always-changing `generatedBy.generatedAt` timestamp field.
 * Reports exactly which vector id(s) changed and exits non-zero if any did.
 *
 * Normal usage (what CI runs) uses the REAL production signer and
 * overwrites test-vectors/webhook-v1.json with the fresh regeneration
 * before comparing — this is what guarantees the checked-in vectors can
 * never go silently stale relative to src/core/webhooks/webhookDelivery.js:
 *
 *   node test-vectors/check-vector-drift.js
 *
 * Signer injection (isolated regression-simulation / testing only):
 * `--signer <path>` swaps in an alternate module exporting `computeSignature`
 * instead of the real production one. When `--signer` is given, this script
 * NEVER writes to disk — it only reads the checked-in file (read-only) and
 * compares it in memory against what the alternate signer would produce, so
 * a regression simulation can prove the detector works without touching any
 * repository file:
 *
 *   node test-vectors/check-vector-drift.js --signer /path/to/fake-signer.js
 */

const fs = require('fs');
const path = require('path');
const { buildVectorFile, withStableTimestamp, DEFAULT_OUTPUT_PATH } = require('./generate-webhook-vectors');

function normalize(vectorFileObj) {
  const clone = JSON.parse(JSON.stringify(vectorFileObj));
  if (clone.generatedBy) delete clone.generatedBy.generatedAt;
  return clone;
}

function changedVectorIds(beforeObj, afterObj) {
  const beforeById = new Map(beforeObj.vectors.map((v) => [v.id, v]));
  const afterById = new Map(afterObj.vectors.map((v) => [v.id, v]));
  const allIds = new Set([...beforeById.keys(), ...afterById.keys()]);
  const changed = [];
  for (const id of allIds) {
    if (JSON.stringify(beforeById.get(id)) !== JSON.stringify(afterById.get(id))) {
      changed.push(id);
    }
  }
  return changed.sort();
}

/**
 * @param {object}   [opts]
 * @param {string}   [opts.vectorsPath]        Checked-in file to compare against (read-only).
 * @param {Function} [opts.computeSignature]   Override signer (testing only).
 * @param {string}   [opts.serverImplementationLabel]
 * @param {string|null} [opts.writeOutputPath] Where to write the regenerated file, or
 *   null to skip writing entirely. Callers using a custom signer MUST pass null
 *   (or omit it — see the CLI guard below) so a regression simulation can never
 *   mutate repository state.
 * @returns {{ drift: boolean, changedVectorIds: string[] }}
 */
function checkDrift(opts = {}) {
  const vectorsPath = opts.vectorsPath || DEFAULT_OUTPUT_PATH;
  const before = normalize(JSON.parse(fs.readFileSync(vectorsPath, 'utf8')));

  const regenerated = buildVectorFile({
    computeSignature: opts.computeSignature,
    serverImplementationLabel: opts.serverImplementationLabel,
  });

  const after = normalize(regenerated);
  const ids = changedVectorIds(before, after);

  // Audit remediation 2026-10-27 (item 12): the regenerated file is written, with the committed timestamp kept when nothing
  // changed, so a check on an unchanged tree leaves `git diff` empty (it used to rewrite generatedAt on every run).
  if (opts.writeOutputPath) {
    fs.writeFileSync(opts.writeOutputPath, JSON.stringify(withStableTimestamp(regenerated, opts.writeOutputPath), null, 2) + '\n', 'utf8');
  }

  return { drift: ids.length > 0, changedVectorIds: ids };
}

module.exports = { checkDrift };

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

if (require.main === module) {
  const args = process.argv.slice(2);
  let signerPath = null;
  let vectorsPath = null;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--signer' && args[i + 1]) {
      signerPath = path.resolve(args[++i]);
    } else if (args[i] === '--vectors' && args[i + 1]) {
      vectorsPath = path.resolve(args[++i]);
    }
  }

  const computeSignature = signerPath ? require(signerPath).computeSignature : undefined;
  const serverImplementationLabel = signerPath ? `[TEST SIGNER OVERRIDE] ${signerPath}` : undefined;

  // Only the real production signer path is allowed to overwrite the
  // checked-in vector file. A --signer override is for isolated regression
  // testing of this script itself and must never touch repository state.
  const writeOutputPath = signerPath ? null : DEFAULT_OUTPUT_PATH;

  const result = checkDrift({ vectorsPath, computeSignature, serverImplementationLabel, writeOutputPath });

  if (result.drift) {
    console.error('');
    console.error(
      `DRIFT DETECTED in ${result.changedVectorIds.length} vector(s): ${result.changedVectorIds.join(', ')}`,
    );
    console.error('');
    if (signerPath) {
      console.error(`test-vectors/webhook-v1.json does not match the output of signer override ${signerPath}.`);
    } else {
      console.error('test-vectors/webhook-v1.json does not match what generate-webhook-vectors.js');
      console.error('currently produces from the real server signer.');
      console.error('');
      console.error('This means either:');
      console.error('  - src/core/webhooks/webhookDelivery.js\'s signing behavior changed, or');
      console.error('  - generate-webhook-vectors.js\'s scenarios were edited');
      console.error('without regenerating and committing the vector file.');
      console.error('');
      console.error('Run `node test-vectors/generate-webhook-vectors.js` and commit the result.');
      console.error('If the protocol changed intentionally, see test-vectors/README.md for the');
      console.error('full version-bump procedure before committing.');
    }
    process.exit(1);
  }

  console.log('No drift: test-vectors/webhook-v1.json matches the current signer.');
}
