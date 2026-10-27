#!/usr/bin/env node
'use strict';

/**
 * qodiqa-proof-verify — verify a downloadable proof (`qodiqa-proof/1`, docs/protocol/VECTORS-FORMAT.md section 3) offline.
 *
 *   node scripts/audit-repro/verify/qodiqa-proof-verify.js --proof proof.json [--artifact artifact.json] [--out report.json]
 *       [--anchors-repo <dir> [--require-signed]]
 *
 * --anchors-repo <dir> "trust from the anchor": the checkpoint keys and the anchored checkpoints come from that anchors repository (a git
 *     working tree outside the gateway's control), not from the proof; --require-signed also demands valid git signatures on its commits.
 *     Without it a proof can never be better than VALID_PARTIAL (nothing independent says the checkpoint existed).
 * --proof may be the proof itself or the response envelope of GET /v1/proofs/{requestId} (the CLI unwraps `data`).
 * --artifact adds (or replaces) the `artifact` part: the gateway does not store artifacts, the caller holds it.
 * Prints the verdict JSON; exit 0 = VALID, 3 = VALID_PARTIAL, 1 = INVALID, 2 = usage / input error.
 * Imports nothing from src/ (Node built-ins and the sibling verifier modules only).
 */

const fs = require('fs');
const { verifyProof } = require('./proof');
const { loadAnchorRepo } = require('./anchorTrust');

function args(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) if (argv[i].startsWith('--')) out[argv[i].slice(2)] = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
  return out;
}
const readJson = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));

function main() {
  const a = args(process.argv.slice(2));
  if (!a.proof || a.proof === true) { process.stderr.write('usage: qodiqa-proof-verify --proof <file> [--artifact <file>] [--out <file>] [--anchors-repo <dir> [--require-signed]]\n'); return 2; }
  let doc;
  try {
    doc = readJson(a.proof);
    // the response of GET /v1/proofs/{requestId} is the usual envelope { status, data }: the proof is `data`
    if (doc && doc.status === 'success' && doc.data && doc.data.format === 'qodiqa-proof/1') doc = doc.data;
    if (a.artifact && a.artifact !== true) doc = { ...doc, artifact: readJson(a.artifact) };
  } catch (e) { process.stderr.write(`cannot read input: ${e.message}\n`); return 2; }
  const opts = {};
  if (a['anchors-repo'] && a['anchors-repo'] !== true) opts.anchorTrust = loadAnchorRepo(a['anchors-repo'], { requireSigned: a['require-signed'] === true });
  const report = verifyProof(doc, opts);
  if (a.out && a.out !== true) fs.writeFileSync(a.out, `${JSON.stringify(report, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify({ verdict: report.verdict, failed: report.failed, partial: report.partial })}\n`);
  return report.verdict === 'VALID' ? 0 : (report.verdict === 'VALID_PARTIAL' ? 3 : 1);
}

if (require.main === module) process.exit(main());
module.exports = { main };
