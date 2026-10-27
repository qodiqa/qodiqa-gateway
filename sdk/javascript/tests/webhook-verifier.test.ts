/**
 * Comprehensive tests for webhook signature verification.
 *
 * The signature scheme under test is the QODIQA server's actual wire format
 * (`src/core/webhooks/webhookDelivery.js`): an `X-QODIQA-Signature:
 * sha256=<hex>` header, a *separate* `X-QODIQA-Timestamp` header carrying an
 * ISO-8601 UTC timestamp, and HMAC-SHA256 computed over
 * `${timestamp}.${body}`.
 *
 * The `cross-implementation vectors` suite below uses signatures generated
 * by actually calling the server's own `computeSignature()` (via Node)
 * rather than duplicating the algorithm in a second, potentially-diverging
 * TypeScript helper — that is what makes those specific cases a genuine
 * interop check rather than a self-referential fixture.
 */

import crypto from 'node:crypto';
import {
  verifyWebhookSignature,
  WebhookVerifier,
  DEFAULT_TOLERANCE_SECONDS,
  InvalidSignatureError,
  ExpiredSignatureError,
  MalformedSignatureError,
  InvalidTimestampError,
  QodiqaError,
} from '../src/index';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SECRET = 'whsec_test_secret_abc123';
const BODY = '{"event":"sign.created","artifactId":"art-001"}';
const BODY_BYTES = Buffer.from(BODY, 'utf8');

const NOW_ISO = '2026-01-01T00:00:00.000Z';
const NOW_EPOCH = Date.parse(NOW_ISO) / 1000;

/** Format a Unix epoch as the ISO-8601 UTC string Date.toISOString() produces. */
function isoTs(epoch: number): string {
  return new Date(epoch * 1000).toISOString();
}

/** Generate a valid X-QODIQA-Signature header value (mirrors computeSignature()). */
function makeSig(body: string | Buffer, secret = SECRET, ts = NOW_ISO): string {
  const prefix = Buffer.from(`${ts}.`, 'utf8');
  const bodyBuf = body instanceof Buffer ? body : Buffer.from(body, 'utf8');
  const payload = Buffer.concat([prefix, bodyBuf]);
  const digest = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  return `sha256=${digest}`;
}

function verify(opts: {
  body?: string | Buffer;
  signature?: string;
  timestamp?: string;
  secret?: string | string[];
  tolerance?: number;
  now?: number;
} = {}): void {
  const body = opts.body ?? BODY;
  const timestamp = opts.timestamp ?? NOW_ISO;
  const secret = opts.secret ?? SECRET;
  const now = opts.now ?? NOW_EPOCH;
  const sig = opts.signature ?? makeSig(
    body,
    Array.isArray(secret) ? secret[0] : secret,
    timestamp,
  );
  verifyWebhookSignature({
    body,
    signature: sig,
    timestamp,
    secret,
    tolerance: opts.tolerance ?? DEFAULT_TOLERANCE_SECONDS,
    _now: now,
  });
}

// ---------------------------------------------------------------------------
// Valid signatures
// ---------------------------------------------------------------------------

describe('valid signatures', () => {
  it('accepts a valid string body', () => {
    expect(() => verify()).not.toThrow();
  });

  it('accepts a valid Buffer body', () => {
    const sig = makeSig(BODY_BYTES);
    expect(() =>
      verify({ body: BODY_BYTES, signature: sig }),
    ).not.toThrow();
  });

  it('accepts an empty string body', () => {
    const sig = makeSig('');
    expect(() => verify({ body: '', signature: sig })).not.toThrow();
  });

  it('accepts an empty Buffer body', () => {
    const sig = makeSig(Buffer.alloc(0));
    expect(() =>
      verify({ body: Buffer.alloc(0), signature: sig }),
    ).not.toThrow();
  });

  it('accepts a Unicode body', () => {
    const body = '{"message":"こんにちは 🌏"}';
    expect(() => verify({ body, signature: makeSig(body) })).not.toThrow();
  });

  it('accepts a large body (1 MB)', () => {
    const body = 'x'.repeat(1_000_000);
    expect(() => verify({ body, signature: makeSig(body) })).not.toThrow();
  });

  it('accepts a timestamp exactly at the tolerance boundary', () => {
    const ts = isoTs(NOW_EPOCH - DEFAULT_TOLERANCE_SECONDS);
    expect(() =>
      verify({ timestamp: ts, signature: makeSig(BODY, SECRET, ts) }),
    ).not.toThrow();
  });

  it('accepts a future timestamp within tolerance', () => {
    const ts = isoTs(NOW_EPOCH + 60);
    expect(() =>
      verify({ timestamp: ts, signature: makeSig(BODY, SECRET, ts) }),
    ).not.toThrow();
  });

  it('accepts an uppercase hex signature', () => {
    const digest = makeSig(BODY).split('sha256=')[1].toUpperCase();
    expect(() =>
      verify({ signature: `sha256=${digest}` }),
    ).not.toThrow();
  });

  it('accepts a signature header with surrounding whitespace', () => {
    const digest = makeSig(BODY).split('sha256=')[1];
    expect(() =>
      verify({ signature: `  sha256=${digest}  ` }),
    ).not.toThrow();
  });

  it('accepts duplicate signature headers folded by a proxy, one correct', () => {
    const correct = makeSig(BODY).split('sha256=')[1];
    const wrong = 'a'.repeat(64);
    expect(() =>
      verify({ signature: `sha256=${wrong}, sha256=${correct}` }),
    ).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Invalid signatures
// ---------------------------------------------------------------------------

describe('invalid signatures', () => {
  it('throws InvalidSignatureError for wrong secret', () => {
    expect(() =>
      verify({ secret: 'wrong_secret', signature: makeSig(BODY) }),
    ).toThrow(InvalidSignatureError);
  });

  it('throws InvalidSignatureError for modified payload', () => {
    const sig = makeSig(BODY);
    expect(() =>
      verify({ body: BODY + '_modified', signature: sig }),
    ).toThrow(InvalidSignatureError);
  });

  it('throws for a truncated signature', () => {
    const sigHeader = makeSig(BODY);
    const truncated = sigHeader.slice(0, -4);
    expect(() => verify({ signature: truncated })).toThrow(QodiqaError);
  });

  it('throws InvalidSignatureError for all-zeros digest', () => {
    const zeros = '0'.repeat(64);
    expect(() =>
      verify({ signature: `sha256=${zeros}` }),
    ).toThrow(InvalidSignatureError);
  });

  it('throws InvalidSignatureError for bit-flipped signature', () => {
    const correct = makeSig(BODY).split('sha256=')[1];
    const flipped =
      ((parseInt(correct.slice(0, 2), 16) ^ 0xff) >>> 0)
        .toString(16)
        .padStart(2, '0') + correct.slice(2);
    expect(() =>
      verify({ signature: `sha256=${flipped}` }),
    ).toThrow(InvalidSignatureError);
  });
});

// ---------------------------------------------------------------------------
// Replay / timestamp attacks
// ---------------------------------------------------------------------------

describe('replay protection', () => {
  it('throws ExpiredSignatureError when timestamp is too old', () => {
    const ts = isoTs(NOW_EPOCH - DEFAULT_TOLERANCE_SECONDS - 1);
    expect(() =>
      verify({ timestamp: ts, signature: makeSig(BODY, SECRET, ts) }),
    ).toThrow(ExpiredSignatureError);
  });

  it('throws ExpiredSignatureError when timestamp is far in the future', () => {
    const ts = isoTs(NOW_EPOCH + DEFAULT_TOLERANCE_SECONDS + 1);
    expect(() =>
      verify({ timestamp: ts, signature: makeSig(BODY, SECRET, ts) }),
    ).toThrow(ExpiredSignatureError);
  });

  it('throws InvalidSignatureError when the timestamp header is modified (within tolerance)', () => {
    // Digest was computed with NOW_ISO; presenting a different (but still
    // in-tolerance) timestamp header means the canonical message no longer
    // matches, so this must fail the HMAC check, not the freshness check.
    const correctSig = makeSig(BODY, SECRET, NOW_ISO);
    const forgedTs = isoTs(NOW_EPOCH - 60); // within 300s tolerance
    expect(() =>
      verify({ timestamp: forgedTs, signature: correctSig }),
    ).toThrow(InvalidSignatureError);
  });

  it('respects a custom tolerance — passes within window', () => {
    const ts = isoTs(NOW_EPOCH - 60);
    expect(() =>
      verify({ timestamp: ts, signature: makeSig(BODY, SECRET, ts), tolerance: 300 }),
    ).not.toThrow();
  });

  it('respects a custom tolerance — fails outside window', () => {
    const ts = isoTs(NOW_EPOCH - 90);
    expect(() =>
      verify({ timestamp: ts, signature: makeSig(BODY, SECRET, ts), tolerance: 30 }),
    ).toThrow(ExpiredSignatureError);
  });

  it('zero tolerance rejects any aged timestamp', () => {
    const ts = isoTs(NOW_EPOCH - 1);
    expect(() =>
      verify({ timestamp: ts, signature: makeSig(BODY, SECRET, ts), tolerance: 0 }),
    ).toThrow(ExpiredSignatureError);
  });
});

// ---------------------------------------------------------------------------
// Malformed / missing headers
// ---------------------------------------------------------------------------

describe('malformed headers', () => {
  it('throws MalformedSignatureError for empty signature header', () => {
    expect(() => verify({ signature: '' })).toThrow(MalformedSignatureError);
  });

  it('throws MalformedSignatureError for whitespace-only signature header', () => {
    expect(() => verify({ signature: '   ' })).toThrow(MalformedSignatureError);
  });

  it('throws MalformedSignatureError for component without "="', () => {
    expect(() => verify({ signature: 'noequalssign' })).toThrow(
      MalformedSignatureError,
    );
  });

  it('throws MalformedSignatureError for non-hex signature', () => {
    expect(() => verify({ signature: 'sha256=ZZZZZZZZ' })).toThrow(
      MalformedSignatureError,
    );
  });

  it('throws MalformedSignatureError for empty sha256 value', () => {
    expect(() => verify({ signature: 'sha256=' })).toThrow(
      MalformedSignatureError,
    );
  });

  it('throws MalformedSignatureError when only an unsupported scheme is present', () => {
    expect(() => verify({ signature: 'sha1=deadbeef' })).toThrow(
      MalformedSignatureError,
    );
  });

  it('throws InvalidTimestampError when timestamp header is missing', () => {
    const digest = makeSig(BODY).split('sha256=')[1];
    expect(() =>
      verify({ timestamp: '', signature: `sha256=${digest}` }),
    ).toThrow(InvalidTimestampError);
  });

  it('throws InvalidTimestampError for whitespace-only timestamp header', () => {
    const digest = makeSig(BODY).split('sha256=')[1];
    expect(() =>
      verify({ timestamp: '   ', signature: `sha256=${digest}` }),
    ).toThrow(InvalidTimestampError);
  });

  it('throws InvalidTimestampError for a non-ISO timestamp', () => {
    const digest = makeSig(BODY).split('sha256=')[1];
    expect(() =>
      verify({ timestamp: '1700000000', signature: `sha256=${digest}` }),
    ).toThrow(InvalidTimestampError);
  });

  it('throws InvalidTimestampError for a timestamp missing the Z suffix', () => {
    const digest = makeSig(BODY).split('sha256=')[1];
    expect(() =>
      verify({
        timestamp: '2026-01-01T00:00:00.000',
        signature: `sha256=${digest}`,
      }),
    ).toThrow(InvalidTimestampError);
  });

  it('throws InvalidTimestampError for an invalid calendar date', () => {
    const digest = makeSig(BODY).split('sha256=')[1];
    expect(() =>
      verify({
        timestamp: '2026-13-40T00:00:00.000Z',
        signature: `sha256=${digest}`,
      }),
    ).toThrow(InvalidTimestampError);
  });

  it('throws InvalidTimestampError for duplicate timestamp headers folded by a proxy', () => {
    const digest = makeSig(BODY).split('sha256=')[1];
    expect(() =>
      verify({
        timestamp: `${NOW_ISO}, ${isoTs(NOW_EPOCH + 1)}`,
        signature: `sha256=${digest}`,
      }),
    ).toThrow(InvalidTimestampError);
  });
});

// ---------------------------------------------------------------------------
// Multiple secrets / rotation
// ---------------------------------------------------------------------------

describe('multiple secrets / rotation', () => {
  const OLD_SECRET = 'old_secret';
  const NEW_SECRET = 'new_secret';

  it('succeeds when first secret matches', () => {
    const sig = makeSig(BODY, NEW_SECRET);
    expect(() =>
      verify({ secret: [NEW_SECRET, OLD_SECRET], signature: sig }),
    ).not.toThrow();
  });

  it('succeeds when second secret matches', () => {
    const sig = makeSig(BODY, OLD_SECRET);
    expect(() =>
      verify({ secret: [NEW_SECRET, OLD_SECRET], signature: sig }),
    ).not.toThrow();
  });

  it('throws when no secret matches', () => {
    const sig = makeSig(BODY, 'completely_different');
    expect(() =>
      verify({ secret: [OLD_SECRET, NEW_SECRET], signature: sig }),
    ).toThrow(InvalidSignatureError);
  });

  it('accepts a single-element array', () => {
    expect(() => verify({ secret: [SECRET] })).not.toThrow();
  });

  it('throws InvalidSignatureError for empty secret array', () => {
    expect(() => verify({ secret: [] })).toThrow(InvalidSignatureError);
  });
});

// ---------------------------------------------------------------------------
// WebhookVerifier class
// ---------------------------------------------------------------------------

describe('WebhookVerifier', () => {
  it('verifies a valid signature', () => {
    const verifier = new WebhookVerifier(SECRET);
    expect(() =>
      verifier.verify(BODY, makeSig(BODY, SECRET, NOW_ISO), NOW_ISO, { _now: NOW_EPOCH }),
    ).not.toThrow();
  });

  it('is callable from the verify function directly', () => {
    expect(() =>
      verifyWebhookSignature({
        body: BODY,
        signature: makeSig(BODY),
        timestamp: NOW_ISO,
        secret: SECRET,
        _now: NOW_EPOCH,
      }),
    ).not.toThrow();
  });

  it('throws for wrong secret', () => {
    const verifier = new WebhookVerifier(SECRET);
    const sig = makeSig(BODY, 'wrong', NOW_ISO);
    expect(() =>
      verifier.verify(BODY, sig, NOW_ISO, { _now: NOW_EPOCH }),
    ).toThrow(InvalidSignatureError);
  });

  it('throws for expired timestamp', () => {
    const verifier = new WebhookVerifier(SECRET);
    const ts = isoTs(NOW_EPOCH - DEFAULT_TOLERANCE_SECONDS - 1);
    expect(() =>
      verifier.verify(BODY, makeSig(BODY, SECRET, ts), ts, { _now: NOW_EPOCH }),
    ).toThrow(ExpiredSignatureError);
  });

  it('accepts multiple secrets', () => {
    expect(() =>
      verifyWebhookSignature({
        body: BODY,
        signature: makeSig(BODY),
        timestamp: NOW_ISO,
        secret: ['new_sec', SECRET],
        _now: NOW_EPOCH,
      }),
    ).not.toThrow();
  });

  it('throws InvalidSignatureError when constructed with empty array', () => {
    expect(() => new WebhookVerifier([])).toThrow(InvalidSignatureError);
  });

  it('accepts Buffer body', () => {
    const sig = makeSig(BODY_BYTES);
    expect(() =>
      verifyWebhookSignature({
        body: BODY_BYTES,
        signature: sig,
        timestamp: NOW_ISO,
        secret: SECRET,
        _now: NOW_EPOCH,
      }),
    ).not.toThrow();
  });

  it('is reusable across multiple requests', () => {
    const verifier = new WebhookVerifier(SECRET);
    for (let i = 0; i < 5; i++) {
      expect(() =>
        verifier.verify(BODY, makeSig(BODY, SECRET, NOW_ISO), NOW_ISO, { _now: NOW_EPOCH }),
      ).not.toThrow();
    }
  });
});

// ---------------------------------------------------------------------------
// Error inheritance
// ---------------------------------------------------------------------------

describe('error hierarchy', () => {
  it('InvalidSignatureError is a QodiqaError', () => {
    expect(new InvalidSignatureError('x')).toBeInstanceOf(QodiqaError);
  });

  it('ExpiredSignatureError is a QodiqaError', () => {
    expect(new ExpiredSignatureError('x')).toBeInstanceOf(QodiqaError);
  });

  it('MalformedSignatureError is a QodiqaError', () => {
    expect(new MalformedSignatureError('x')).toBeInstanceOf(QodiqaError);
  });

  it('InvalidTimestampError is a QodiqaError', () => {
    expect(new InvalidTimestampError('x')).toBeInstanceOf(QodiqaError);
  });

  it('InvalidSignatureError has status 401', () => {
    expect(new InvalidSignatureError('x').status).toBe(401);
  });

  it('ExpiredSignatureError has status 401', () => {
    expect(new ExpiredSignatureError('x').status).toBe(401);
  });

  it('MalformedSignatureError has status 400', () => {
    expect(new MalformedSignatureError('x').status).toBe(400);
  });

  it('InvalidTimestampError has status 400', () => {
    expect(new InvalidTimestampError('x').status).toBe(400);
  });

  it('error name matches class name', () => {
    expect(new InvalidSignatureError('x').name).toBe('InvalidSignatureError');
    expect(new ExpiredSignatureError('x').name).toBe('ExpiredSignatureError');
    expect(new MalformedSignatureError('x').name).toBe('MalformedSignatureError');
    expect(new InvalidTimestampError('x').name).toBe('InvalidTimestampError');
  });
});

// ---------------------------------------------------------------------------
// Cross-implementation vectors
//
// These signatures were NOT computed by this test file's own makeSig()
// helper. They were generated by directly invoking the server's real
// `computeSignature()` from src/core/webhooks/webhookDelivery.js under
// Node.js:
//
//   node -e "
//     const { computeSignature } = require('./src/core/webhooks/webhookDelivery');
//     console.log(computeSignature(secret, timestamp, body));
//   "
//
// A verifier that reimplements the wrong protocol (or the right protocol
// with a subtle byte-level divergence) will fail these regardless of how
// internally self-consistent its own test suite is. Vectors 2-4 use the
// same secret/timestamp/body as the Python SDK's equivalent vectors,
// confirming three-way (server / Python / JS) agreement on the same digest.
// ---------------------------------------------------------------------------

describe('cross-implementation vectors', () => {
  it('vector 1: standard ASCII body', () => {
    expect(() =>
      verifyWebhookSignature({
        body: '{"type":"sign.created","id":"evt-001"}',
        timestamp: '2026-01-01T00:00:00.000Z',
        signature: 'sha256=cebf118f96f90b48eb4c5e80440d3ab12222e8e342d496cd31d6e11052ddba82',
        secret: 'test_secret_CROSS_SDK',
        tolerance: 9_999_999_999,
        _now: NOW_EPOCH,
      }),
    ).not.toThrow();
  });

  it('vector 2: Unicode body and secret', () => {
    expect(() =>
      verifyWebhookSignature({
        body: '{"message":"안녕하세요 🎉"}',
        timestamp: '2026-01-01T00:00:01.500Z',
        signature: 'sha256=c98374601cbed53b2a6516c5513c3c66d8a9f676eaeb6e7b63732fc05e6be0c0',
        secret: 'unicode_secret_テスト',
        tolerance: 9_999_999_999,
        _now: NOW_EPOCH,
      }),
    ).not.toThrow();
  });

  it('vector 3: empty body', () => {
    expect(() =>
      verifyWebhookSignature({
        body: '',
        timestamp: '2026-01-01T00:00:02.000Z',
        signature: 'sha256=ce64da80c774b8e0d77195b97edc186ce0a3c1eb4f338b926d524db8d826b6ef',
        secret: 'empty_body_secret',
        tolerance: 9_999_999_999,
        _now: NOW_EPOCH,
      }),
    ).not.toThrow();
  });

  it('vector 4: arbitrary timestamp', () => {
    expect(() =>
      verifyWebhookSignature({
        body: 'Hello, QODIQA!',
        timestamp: '2026-06-15T12:34:56.789Z',
        signature: 'sha256=22c4507cff278a08f85b7270b025c29b4ac15cd9e7f4bb5d48b49b00b3240d54',
        secret: 'explicit_check_secret',
        tolerance: 9_999_999_999,
        _now: NOW_EPOCH,
      }),
    ).not.toThrow();
  });

  it('wrong secret fails against a real server-generated vector', () => {
    expect(() =>
      verifyWebhookSignature({
        body: '{"type":"sign.created","id":"evt-001"}',
        timestamp: '2026-01-01T00:00:00.000Z',
        signature: 'sha256=cebf118f96f90b48eb4c5e80440d3ab12222e8e342d496cd31d6e11052ddba82',
        secret: 'definitely_wrong_secret',
        tolerance: 9_999_999_999,
        _now: NOW_EPOCH,
      }),
    ).toThrow(InvalidSignatureError);
  });

  it('tampered body fails against a real server-generated vector', () => {
    expect(() =>
      verifyWebhookSignature({
        body: '{"type":"sign.created","id":"evt-002"}', // changed
        timestamp: '2026-01-01T00:00:00.000Z',
        signature: 'sha256=cebf118f96f90b48eb4c5e80440d3ab12222e8e342d496cd31d6e11052ddba82',
        secret: 'test_secret_CROSS_SDK',
        tolerance: 9_999_999_999,
        _now: NOW_EPOCH,
      }),
    ).toThrow(InvalidSignatureError);
  });
});

// ---------------------------------------------------------------------------
// Forward compatibility
// ---------------------------------------------------------------------------

describe('forward compatibility', () => {
  it('ignores an unknown scheme alongside a valid sha256= component', () => {
    const digest = makeSig(BODY).split('sha256=')[1];
    const sig = `sha512=someunknownvalue, sha256=${digest}`;
    expect(() => verify({ signature: sig })).not.toThrow();
  });
});
