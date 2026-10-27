#!/usr/bin/env node
'use strict';

/**
 * QODIQA Webhook Protocol — Canonical Test Vector Generator
 *
 * Regenerates test-vectors/webhook-v1.json from the PRODUCTION server
 * signing implementation (src/core/webhooks/webhookDelivery.js). Every
 * `expectedSignature` in the output file is computed by calling the real
 * `computeSignature()` — nothing in this file hand-writes a signature.
 *
 * Run this only when the webhook protocol intentionally changes (new
 * signature version, new header, etc). See test-vectors/README.md for the
 * full update procedure. Running it with no protocol changes must produce
 * byte-identical output (module the `generatedAt` timestamp) to what's
 * already checked in — if it doesn't, something about the server's signing
 * behavior drifted and the diff itself is the thing to investigate before
 * committing. `check-vector-drift.js` automates exactly that check.
 *
 * Signer injection (for isolated regression-simulation / testing only):
 * `buildVectorFile()` accepts a `computeSignature` override so tooling can
 * prove drift detection works without ever touching the real production
 * signer. The CLI defaults to the real one and also supports `--signer
 * <path-to-module-exporting-computeSignature>` for the same purpose from
 * the command line.
 */

const fs = require('fs');
const path = require('path');

const DEFAULT_OUTPUT_PATH = path.join(__dirname, 'webhook-v1.json');
const DEFAULT_SIGNER_PATH = path.join(__dirname, '../src/core/webhooks/webhookDelivery');
const PROTOCOL_VERSION = 'v1';

// ---------------------------------------------------------------------------
// Positive scenarios (one per required payload category)
// ---------------------------------------------------------------------------

const SCENARIOS = [
  {
    id: 'standard-json',
    description: 'A typical certification.completed event payload, standard JSON shape.',
    tags: ['json'],
    secret: 'whsec_conformance_standard_7f2a91',
    timestamp: '2026-01-01T00:00:00.000Z',
    body: JSON.stringify({
      eventId: 'evt_conformance_001',
      eventType: 'certification.completed',
      certificationId: 'cert_9001',
      tenantId: 'tenant_042',
      level: 'L2',
      score: 0.94,
      status: 'PASS',
    }),
  },
  {
    id: 'unicode-mixed-scripts',
    description: 'JSON payload with a message field mixing Japanese, Korean, Cyrillic, and Arabic scripts.',
    tags: ['unicode'],
    secret: 'whsec_conformance_unicode_a83c1d',
    timestamp: '2026-01-01T00:00:01.000Z',
    body: JSON.stringify({
      eventId: 'evt_conformance_002',
      eventType: 'attestation.completed',
      message: 'こんにちは 안녕하세요 Привет مرحبا',
    }),
  },
  {
    id: 'empty-payload',
    description: 'A zero-length body.',
    tags: ['empty'],
    secret: 'whsec_conformance_empty_5e6f2b',
    timestamp: '2026-01-01T00:00:02.000Z',
    body: '',
  },
  {
    id: 'plain-text-payload',
    description: 'A non-JSON, plain ASCII text body.',
    tags: ['plain-text'],
    secret: 'whsec_conformance_plaintext_c94b7e',
    timestamp: '2026-01-01T00:00:03.000Z',
    body: 'This is a plain text webhook body, not JSON at all.',
  },
  {
    id: 'long-payload',
    description: 'A large (~50 KB) JSON payload, to exercise HMAC over a non-trivial byte count.',
    tags: ['long'],
    secret: 'whsec_conformance_long_1b7d4a',
    timestamp: '2026-01-01T00:00:04.000Z',
    body: JSON.stringify({
      eventId: 'evt_conformance_005',
      eventType: 'certification.completed',
      data: 'x'.repeat(50_000),
    }),
  },
  {
    id: 'escaped-characters-payload',
    description: 'JSON payload whose serialized form contains backslash, tab, and escaped-quote sequences.',
    tags: ['escaping'],
    secret: 'whsec_conformance_escaped_44de91',
    timestamp: '2026-01-01T00:00:05.000Z',
    body: JSON.stringify({
      eventId: 'evt_conformance_006',
      note: 'Tab:\tBackslash:\\ Quote:" End.',
    }),
  },
  {
    id: 'newline-payload',
    description: 'Plain-text body containing raw (unescaped) newline bytes between lines.',
    tags: ['newlines'],
    secret: 'whsec_conformance_newline_9c2f6a',
    timestamp: '2026-01-01T00:00:06.000Z',
    body: 'Line one\nLine two\nLine three\n',
  },
  {
    id: 'quotes-payload',
    description: 'Plain-text body containing double quotes, single quotes, and backticks.',
    tags: ['quotes'],
    secret: 'whsec_conformance_quotes_3ad817',
    timestamp: '2026-01-01T00:00:07.000Z',
    body: 'He said "hello" and \'goodbye\' -- quotes, apostrophes, and `backticks` all present.',
  },
  {
    id: 'utf8-payload',
    description: 'Plain-text body of accented Latin (non-ASCII UTF-8) characters.',
    tags: ['utf8'],
    secret: 'whsec_conformance_utf8_71fe0c',
    timestamp: '2026-01-01T00:00:08.000Z',
    body: 'Café résumé naïve façade Zürich Møller',
  },
  {
    id: 'emoji-payload',
    description: 'Plain-text body containing emoji, including a ZWJ family sequence and a flag sequence.',
    tags: ['emoji'],
    secret: 'whsec_conformance_emoji_bb219e',
    timestamp: '2026-01-01T00:00:09.000Z',
    body: '🎉🚀🌍👨‍👩‍👧‍👦🇺🇸',
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildPositiveVector(scenario, computeSignature) {
  const expectedSignature = computeSignature(scenario.secret, scenario.timestamp, scenario.body);
  return {
    id: scenario.id,
    description: scenario.description,
    protocolVersion: PROTOCOL_VERSION,
    tags: scenario.tags,
    scenario: {
      secret: scenario.secret,
      timestamp: scenario.timestamp,
      body: scenario.body,
      expectedSignature,
    },
    verify: {
      body: scenario.body,
      signature: expectedSignature,
      timestamp: scenario.timestamp,
      secrets: [scenario.secret],
      verifyAt: scenario.timestamp,
      tolerance: 300,
    },
    expectedResult: 'valid',
    expectedError: null,
  };
}

function isoPlusSeconds(iso, seconds) {
  return new Date(new Date(iso).getTime() + seconds * 1000).toISOString();
}

function flipLastHexChar(hex) {
  const last = hex[hex.length - 1];
  const flipped = last === 'a' ? 'b' : 'a';
  return hex.slice(0, -1) + flipped;
}

/**
 * Negative vectors (one per required category, plus one bonus
 * "expired-timestamp" vector covering the replay-tolerance mechanism, which
 * is protocol-critical even though it wasn't separately itemized).
 *
 * Every negative vector is built by deterministically transforming a real,
 * server-signed base scenario — never by inventing a signature by hand.
 */
function buildNegativeVectors(base) {
  const negatives = [];

  negatives.push({
    id: 'modified-payload',
    description: 'Base scenario body tampered by one character after signing; signature/timestamp unchanged.',
    category: 'modified-payload',
    body: base.body.replace('"PASS"', '"FASS"'),
    signature: base.expectedSignature,
    timestamp: base.timestamp,
    secrets: [base.secret],
    verifyAt: base.timestamp,
    expectedError: 'InvalidSignatureError',
  });

  negatives.push({
    id: 'modified-signature',
    description: 'Base scenario signature tampered by flipping the last hex character.',
    category: 'modified-signature',
    body: base.body,
    signature: 'sha256=' + flipLastHexChar(base.expectedSignature.slice(7)),
    timestamp: base.timestamp,
    secrets: [base.secret],
    verifyAt: base.timestamp,
    expectedError: 'InvalidSignatureError',
  });

  negatives.push({
    id: 'modified-timestamp',
    description: 'Timestamp header shifted by +1s after signing; original signature presented unchanged.',
    category: 'modified-timestamp',
    body: base.body,
    signature: base.expectedSignature,
    timestamp: isoPlusSeconds(base.timestamp, 1),
    secrets: [base.secret],
    verifyAt: isoPlusSeconds(base.timestamp, 1),
    expectedError: 'InvalidSignatureError',
  });

  negatives.push({
    id: 'wrong-secret',
    description: 'Body/timestamp/signature are all genuine and self-consistent, but the verifier is configured with a different secret than the one that actually signed the delivery.',
    category: 'wrong-secret',
    body: base.body,
    signature: base.expectedSignature,
    timestamp: base.timestamp,
    secrets: ['whsec_completely_different_secret_000'],
    verifyAt: base.timestamp,
    expectedError: 'InvalidSignatureError',
  });

  negatives.push({
    id: 'malformed-signature',
    description: 'Signature header value is not valid hex.',
    category: 'malformed-signature',
    body: base.body,
    signature: 'sha256=not-valid-hex-zzzz',
    timestamp: base.timestamp,
    secrets: [base.secret],
    verifyAt: base.timestamp,
    expectedError: 'MalformedSignatureError',
  });

  negatives.push({
    id: 'malformed-timestamp',
    description: 'Timestamp header value is not a valid ISO-8601 UTC timestamp (invalid calendar date).',
    category: 'malformed-timestamp',
    body: base.body,
    signature: base.expectedSignature,
    timestamp: '2026-13-40T00:00:00.000Z',
    secrets: [base.secret],
    verifyAt: base.timestamp,
    expectedError: 'InvalidTimestampError',
  });

  negatives.push({
    id: 'missing-signature',
    description: 'X-QODIQA-Signature header is absent (empty string).',
    category: 'missing-signature',
    body: base.body,
    signature: '',
    timestamp: base.timestamp,
    secrets: [base.secret],
    verifyAt: base.timestamp,
    expectedError: 'MalformedSignatureError',
  });

  negatives.push({
    id: 'missing-timestamp',
    description: 'X-QODIQA-Timestamp header is absent (empty string).',
    category: 'missing-timestamp',
    body: base.body,
    signature: base.expectedSignature,
    timestamp: '',
    secrets: [base.secret],
    verifyAt: base.timestamp,
    expectedError: 'InvalidTimestampError',
  });

  negatives.push({
    id: 'duplicate-signature-headers',
    description: 'Two X-QODIQA-Signature headers folded by an intermediary into one comma-joined value; neither candidate is valid.',
    category: 'duplicate-signature-headers',
    body: base.body,
    signature: `sha256=${'a'.repeat(64)}, sha256=${'b'.repeat(64)}`,
    timestamp: base.timestamp,
    secrets: [base.secret],
    verifyAt: base.timestamp,
    expectedError: 'InvalidSignatureError',
  });

  negatives.push({
    id: 'duplicate-timestamp-headers',
    description: 'Two X-QODIQA-Timestamp headers folded by an intermediary into one comma-joined value.',
    category: 'duplicate-timestamp-headers',
    body: base.body,
    signature: base.expectedSignature,
    timestamp: `${base.timestamp}, ${isoPlusSeconds(base.timestamp, 1)}`,
    secrets: [base.secret],
    verifyAt: base.timestamp,
    expectedError: 'InvalidTimestampError',
  });

  negatives.push({
    id: 'unsupported-signature-format',
    description: 'Signature header uses a scheme other than sha256= (e.g. a hypothetical legacy sha1= scheme); no supported component is present.',
    category: 'unsupported-signature-format',
    body: base.body,
    signature: 'sha1=' + 'c'.repeat(40),
    timestamp: base.timestamp,
    secrets: [base.secret],
    verifyAt: base.timestamp,
    expectedError: 'MalformedSignatureError',
  });

  negatives.push({
    id: 'expired-timestamp',
    description: '[Additional coverage beyond the required list] Genuine, self-consistent signature/timestamp presented for verification 301 seconds after signing — 1 second past the default 300s replay tolerance.',
    category: 'expired-timestamp',
    body: base.body,
    signature: base.expectedSignature,
    timestamp: base.timestamp,
    secrets: [base.secret],
    verifyAt: isoPlusSeconds(base.timestamp, 301),
    expectedError: 'ExpiredSignatureError',
  });

  return negatives.map((n) => ({
    id: n.id,
    description: n.description,
    protocolVersion: PROTOCOL_VERSION,
    tags: ['negative', n.category],
    scenario: {
      secret: base.secret,
      timestamp: base.timestamp,
      body: base.body,
      expectedSignature: base.expectedSignature,
    },
    verify: {
      body: n.body,
      signature: n.signature,
      timestamp: n.timestamp,
      secrets: n.secrets,
      verifyAt: n.verifyAt,
      tolerance: 300,
    },
    expectedResult: 'invalid',
    expectedError: n.expectedError,
  }));
}

// ---------------------------------------------------------------------------
// Public API — build the vector file in memory
// ---------------------------------------------------------------------------

/**
 * Build the full vector-file object in memory.
 *
 * @param {object}   [opts]
 * @param {Function} [opts.computeSignature]      Signer function
 *   `(secret, timestamp, body) => "sha256=<hex>"`. Defaults to the real
 *   production `computeSignature` from
 *   src/core/webhooks/webhookDelivery.js. Override ONLY for isolated
 *   regression-simulation/testing of the drift detector itself — never to
 *   change what ships in the committed vector file.
 * @param {string}   [opts.serverImplementationLabel]  Recorded into the
 *   output's `generatedBy.serverImplementation` field for provenance.
 * @returns {object} The vector-file object (not yet written to disk).
 */
function buildVectorFile(opts = {}) {
  const computeSignature = opts.computeSignature || require(DEFAULT_SIGNER_PATH).computeSignature;
  const serverImplementationLabel =
    opts.serverImplementationLabel || 'src/core/webhooks/webhookDelivery.js#computeSignature';

  const positiveVectors = SCENARIOS.map((s) => buildPositiveVector(s, computeSignature));

  const std = positiveVectors.find((v) => v.id === 'standard-json');
  const baseForNegatives = {
    secret: std.scenario.secret,
    timestamp: std.scenario.timestamp,
    body: std.scenario.body,
    expectedSignature: std.scenario.expectedSignature,
  };

  const negativeVectors = buildNegativeVectors(baseForNegatives);

  return {
    $schema: './webhook-v1.schema.json',
    protocolVersion: PROTOCOL_VERSION,
    description:
      'Canonical, language-neutral conformance vectors for the QODIQA webhook signing protocol. ' +
      'Every expectedSignature was generated by calling the production signer directly — see ' +
      '"generatedBy" below and test-vectors/README.md for the full process and update procedure.',
    generatedBy: {
      generatorScript: 'test-vectors/generate-webhook-vectors.js',
      serverImplementation: serverImplementationLabel,
      generatedAt: new Date().toISOString(),
    },
    vectorCount: {
      positive: positiveVectors.length,
      negative: negativeVectors.length,
      total: positiveVectors.length + negativeVectors.length,
    },
    vectors: [...positiveVectors, ...negativeVectors],
  };
}

/**
 * Audit remediation 2026-10-27 (item 12): `generatedBy.generatedAt` is the only field that changes on every run, which left
 * test-vectors/webhook-v1.json dirty in git after any check or regeneration with unchanged content. When the file already
 * on disk carries the same vectors, its timestamp is kept, so re-running the generator or the drift check is a byte-for-byte no-op.
 */
function withStableTimestamp(output, existingPath) {
  try {
    const existing = JSON.parse(fs.readFileSync(existingPath, 'utf8'));
    const strip = (o) => { const c = JSON.parse(JSON.stringify(o)); if (c.generatedBy) delete c.generatedBy.generatedAt; return JSON.stringify(c); };
    if (existing && existing.generatedBy && existing.generatedBy.generatedAt && strip(existing) === strip(output)) {
      output.generatedBy.generatedAt = existing.generatedBy.generatedAt;
    }
  } catch { /* no readable previous file: keep the fresh timestamp */ }
  return output;
}

module.exports = { buildVectorFile, withStableTimestamp, DEFAULT_SIGNER_PATH, DEFAULT_OUTPUT_PATH };

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

if (require.main === module) {
  const args = process.argv.slice(2);
  let signerPath = null;
  let outputPath = DEFAULT_OUTPUT_PATH;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--signer' && args[i + 1]) {
      signerPath = path.resolve(args[++i]);
    } else if (args[i] === '--out' && args[i + 1]) {
      outputPath = path.resolve(args[++i]);
    }
  }

  const computeSignature = signerPath
    ? require(signerPath).computeSignature
    : undefined; // let buildVectorFile() default to the real production signer

  const serverImplementationLabel = signerPath
    ? `[TEST SIGNER OVERRIDE] ${signerPath}`
    : undefined;

  const output = withStableTimestamp(buildVectorFile({ computeSignature, serverImplementationLabel }), outputPath);

  fs.writeFileSync(outputPath, JSON.stringify(output, null, 2) + '\n', 'utf8');

  console.log(
    `Wrote ${output.vectors.length} vectors (${output.vectorCount.positive} positive, ` +
      `${output.vectorCount.negative} negative) to ${outputPath}` +
      (signerPath ? ` [using overridden signer: ${signerPath}]` : ''),
  );
}
