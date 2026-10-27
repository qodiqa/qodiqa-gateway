#!/usr/bin/env node
'use strict';

/**
 * qodiqa-receipt-verify — offline verification of a signed receipt (docs/protocol/PROTOCOL-V2.md section 6).
 * Node built-ins only; nothing from src/.
 *
 *   node scripts/audit-repro/verify/qodiqa-receipt-verify.js --receipt receipt.json --keys transparency-keys.json
 *        [--trusted-at <ms>]    timed mode for a receipt signed by a since-revoked key
 *        [--entry-hash <hex>] [--leaf-hash <hex>]   also require the receipt to name exactly this audit entry / leaf
 *        [--request-id <id>] [--decision ALLOW|BLOCK]   ... and exactly this request and decision
 *
 * --receipt: the receipt object, or a response body that has a `receipt` field, or `{ data: { receipt } }` (the body of
 * GET /v1/transparency/receipt/{requestId}). --keys: the body of GET /.well-known/qodiqa/transparency-keys.
 * Exit 0 = verified, 1 = not verified, 2 = usage / input error.
 */

const fs = require('fs');
const { verifyReceiptDocument, bindsTo } = require('./receipt');

function args(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) if (argv[i].startsWith('--')) out[argv[i].slice(2)] = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
  return out;
}
function readJson(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }

function main() {
  const a = args(process.argv.slice(2));
  if (!a.receipt || !a.keys) { process.stderr.write('usage: qodiqa-receipt-verify --receipt <file> --keys <file> [--trusted-at <ms>] [--entry-hash <hex>] [--leaf-hash <hex>] [--request-id <id>] [--decision ALLOW|BLOCK]\n'); return 2; }
  let doc; let keys;
  try { doc = readJson(a.receipt); keys = readJson(a.keys); } catch (e) { process.stderr.write(`cannot read input: ${e.message}\n`); return 2; }
  const receipt = doc && doc.data && doc.data.receipt ? doc.data.receipt : (doc && doc.receipt && doc.v === undefined ? doc.receipt : doc);
  const verdict = verifyReceiptDocument(receipt, keys, a['trusted-at'] !== undefined ? { trustedAt: Number(a['trusted-at']) } : {});
  const binding = bindsTo(receipt || {}, { entryHash: a['entry-hash'], leafHash: a['leaf-hash'], requestId: a['request-id'], decision: a['decision'] });
  const ok = verdict.ok && binding.ok;
  process.stdout.write(`${JSON.stringify({ valid: ok, signature: verdict, binding })}\n`);
  return ok ? 0 : 1;
}

if (require.main === module) process.exit(main());
module.exports = { main };
