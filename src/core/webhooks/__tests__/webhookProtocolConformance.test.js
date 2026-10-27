'use strict';

/**
 * QODIQA Webhook Protocol — Server-Side Conformance Test
 *
 * Loads the shared, language-neutral vector file (test-vectors/webhook-v1.json)
 * and recomputes every vector's signature with the REAL production signer.
 * This is the "source of truth" side of the conformance suite: if anyone
 * changes computeSignature()'s canonical message, hashing algorithm, or
 * header format, this test fails immediately — before any SDK-side drift
 * can even be observed. See test-vectors/README.md for the full contract.
 */

const fs = require('fs');
const path = require('path');
const { computeSignature } = require('../webhookDelivery');

const VECTORS_PATH = path.join(__dirname, '../../../../test-vectors/webhook-v1.json');
const vectorFile = JSON.parse(fs.readFileSync(VECTORS_PATH, 'utf8'));

describe('webhook protocol conformance — server signer', () => {
  test('the shared vector file exists and is non-empty', () => {
    expect(Array.isArray(vectorFile.vectors)).toBe(true);
    expect(vectorFile.vectors.length).toBeGreaterThan(0);
  });

  test('vectorCount metadata matches the actual vector array', () => {
    const positive = vectorFile.vectors.filter((v) => v.expectedResult === 'valid').length;
    const negative = vectorFile.vectors.filter((v) => v.expectedResult === 'invalid').length;
    expect(vectorFile.vectorCount.positive).toBe(positive);
    expect(vectorFile.vectorCount.negative).toBe(negative);
    expect(vectorFile.vectorCount.total).toBe(vectorFile.vectors.length);
  });

  test.each(vectorFile.vectors.map((v) => [v.id, v]))(
    'vector "%s": computeSignature(scenario) === scenario.expectedSignature',
    (_id, vector) => {
      const { secret, timestamp, body, expectedSignature } = vector.scenario;
      const actual = computeSignature(secret, timestamp, body);
      expect(actual).toBe(expectedSignature);
    },
  );

  test('every expectedSignature is a well-formed sha256=<64-hex> value', () => {
    for (const vector of vectorFile.vectors) {
      expect(vector.scenario.expectedSignature).toMatch(/^sha256=[0-9a-f]{64}$/);
    }
  });

  test('positive vectors present an unmodified scenario to the verifier', () => {
    const positives = vectorFile.vectors.filter((v) => v.expectedResult === 'valid');
    expect(positives.length).toBeGreaterThan(0);
    for (const vector of positives) {
      expect(vector.verify.body).toBe(vector.scenario.body);
      expect(vector.verify.signature).toBe(vector.scenario.expectedSignature);
      expect(vector.verify.timestamp).toBe(vector.scenario.timestamp);
      expect(vector.verify.secrets).toEqual([vector.scenario.secret]);
      expect(vector.expectedError).toBeNull();
    }
  });

  test('negative vectors declare a canonical expectedError', () => {
    const CANONICAL_ERRORS = new Set([
      'MalformedSignatureError',
      'InvalidTimestampError',
      'ExpiredSignatureError',
      'InvalidSignatureError',
    ]);
    const negatives = vectorFile.vectors.filter((v) => v.expectedResult === 'invalid');
    expect(negatives.length).toBeGreaterThan(0);
    for (const vector of negatives) {
      expect(CANONICAL_ERRORS.has(vector.expectedError)).toBe(true);
    }
  });
});
