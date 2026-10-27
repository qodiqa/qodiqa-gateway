/**
 * QODIQA Webhook Signature Verification
 *
 * Verifies that incoming webhook requests were genuinely sent by QODIQA and
 * were not modified in transit.
 *
 * ## Signature format
 *
 * QODIQA signs each webhook delivery with HMAC-SHA256 and sends the result
 * in the {@code X-QODIQA-Signature} request header, with the delivery
 * timestamp sent *separately* in its own {@code X-QODIQA-Timestamp} header:
 *
 * ```
 * X-QODIQA-Timestamp: 2026-01-01T00:00:00.000Z
 * X-QODIQA-Signature: sha256=<hex_hmac>
 * ```
 *
 * If an intermediary proxy folds duplicate {@code X-QODIQA-Signature}
 * headers of the same name into one comma-separated value, each
 * {@code sha256=} component is checked in turn.
 *
 * ## Canonical message
 *
 * The HMAC is computed over:
 *
 * ```
 * <raw_X-QODIQA-Timestamp_header_value> + "." + <raw_request_body>
 * ```
 *
 * The timestamp must be passed through exactly as received in the
 * {@code X-QODIQA-Timestamp} header — never reformatted or re-serialised —
 * and the body must be the **raw bytes** as received, never a
 * re-serialised JSON string.
 *
 * @module
 */

import crypto from 'node:crypto';

import {
  ExpiredSignatureError,
  InvalidSignatureError,
  InvalidTimestampError,
  MalformedSignatureError,
} from '../errors.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default timestamp tolerance in seconds (5 minutes). */
export const DEFAULT_TOLERANCE_SECONDS = 300;

const SIGNATURE_SCHEME = 'sha256';

// Matches the ISO-8601 UTC format produced by JavaScript's
// Date.prototype.toISOString(), e.g. "2026-01-01T00:00:00.000Z".
// Fractional seconds are optional.
const ISO8601_UTC_RE =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Parse the {@code X-QODIQA-Signature} header value.
 *
 * Accepts one or more comma-separated {@code sha256=<hex>} components (an
 * intermediary may fold duplicate headers of the same name into a single
 * comma-joined value). Components using an unrecognised scheme prefix are
 * ignored for forward compatibility, as long as at least one
 * {@code sha256=} component is present.
 *
 * @throws {@link MalformedSignatureError} when the header cannot be parsed.
 */
function parseSignatureHeader(header: string): string[] {
  if (!header || !header.trim()) {
    throw new MalformedSignatureError(
      'The X-QODIQA-Signature header is empty or missing.',
    );
  }

  const digests: string[] = [];
  let sawUnrecognizedScheme = false;

  for (const part of header.split(',')) {
    const value = part.trim();
    if (!value) continue;

    const eqIdx = value.indexOf('=');
    if (eqIdx === -1) {
      throw new MalformedSignatureError(
        `Malformed component in X-QODIQA-Signature: ${JSON.stringify(value)}`,
      );
    }

    const scheme = value.slice(0, eqIdx).trim().toLowerCase();
    const digest = value.slice(eqIdx + 1).trim();

    if (scheme !== SIGNATURE_SCHEME) {
      // Forward-compatible: unrecognised schemes (e.g. a future sha512=)
      // are silently ignored.
      sawUnrecognizedScheme = true;
      continue;
    }

    if (digest.length === 0) {
      throw new MalformedSignatureError(
        'Found an empty sha256 signature value in X-QODIQA-Signature.',
      );
    }
    if (!/^[0-9a-f]+$/i.test(digest)) {
      throw new MalformedSignatureError(
        `Non-hex sha256 signature value in X-QODIQA-Signature: ${JSON.stringify(digest)}`,
      );
    }
    digests.push(digest.toLowerCase());
  }

  if (digests.length === 0) {
    if (sawUnrecognizedScheme) {
      throw new MalformedSignatureError(
        'X-QODIQA-Signature contains no supported signature scheme; ' +
          'expected a "sha256=" component.',
      );
    }
    throw new MalformedSignatureError(
      'No "sha256=" signature found in X-QODIQA-Signature header.',
    );
  }

  return digests;
}

/**
 * Parse the {@code X-QODIQA-Timestamp} header value into Unix epoch seconds.
 *
 * The header carries an ISO-8601 UTC timestamp exactly as produced by
 * {@code Date.prototype.toISOString()} (e.g. `"1970-01-01T00:00:00.000Z"`).
 *
 * @throws {@link InvalidTimestampError} when the header is missing or not a
 * valid ISO-8601 UTC timestamp.
 */
function parseTimestampHeader(value: string): number {
  if (!value || !value.trim()) {
    throw new InvalidTimestampError(
      'The X-QODIQA-Timestamp header is empty or missing.',
    );
  }

  const match = ISO8601_UTC_RE.exec(value.trim());
  if (!match) {
    throw new InvalidTimestampError(
      `Invalid timestamp in X-QODIQA-Timestamp: ${JSON.stringify(value)}. ` +
        'Expected ISO-8601 UTC format, e.g. "2026-01-01T00:00:00.000Z".',
    );
  }

  const [, year, month, day, hour, minute, second, frac] = match;
  const ms = frac ? Math.trunc(Number(frac.padEnd(3, '0').slice(0, 3))) : 0;

  const epochMs = Date.UTC(
    Number(year),
    Number(month) - 1,
    Number(day),
    Number(hour),
    Number(minute),
    Number(second),
    ms,
  );

  if (Number.isNaN(epochMs)) {
    throw new InvalidTimestampError(
      `Invalid timestamp in X-QODIQA-Timestamp: ${JSON.stringify(value)}.`,
    );
  }

  // Date.UTC() silently normalises out-of-range fields (e.g. month 13 rolls
  // into the next year) rather than raising, so cross-check the round trip.
  const roundTrip = new Date(epochMs);
  if (
    roundTrip.getUTCFullYear() !== Number(year) ||
    roundTrip.getUTCMonth() !== Number(month) - 1 ||
    roundTrip.getUTCDate() !== Number(day)
  ) {
    throw new InvalidTimestampError(
      `Invalid timestamp in X-QODIQA-Timestamp: ${JSON.stringify(value)} (invalid calendar date).`,
    );
  }

  return epochMs / 1000;
}

/**
 * Compute the expected HMAC-SHA256 for a given timestamp, body, and secret.
 *
 * `timestamp` must be the raw {@code X-QODIQA-Timestamp} header value —
 * never reparsed or reformatted — since the server signs the literal
 * header string.
 *
 * Returns the raw digest bytes (not hex) so we can use {@code timingSafeEqual}.
 */
function computeExpectedDigest(
  timestamp: string,
  body: string | Buffer,
  secret: string,
): Buffer {
  const prefix = Buffer.from(`${timestamp}.`, 'utf8');
  const bodyBuf = typeof body === 'string' ? Buffer.from(body, 'utf8') : body;
  const payload = Buffer.concat([prefix, bodyBuf]);

  return crypto.createHmac('sha256', secret).update(payload).digest();
}

// ---------------------------------------------------------------------------
// Public API — function
// ---------------------------------------------------------------------------

/** Options for {@link verifyWebhookSignature}. */
export interface WebhookVerifyOptions {
  /**
   * Raw request body exactly as received — either a UTF-8 string or a Buffer.
   * Do not parse and re-serialise JSON before passing this value.
   */
  body: string | Buffer;
  /**
   * Value of the {@code X-QODIQA-Signature} request header
   * ({@code sha256=<hex>}).
   */
  signature: string;
  /**
   * Value of the {@code X-QODIQA-Timestamp} request header, passed through
   * exactly as received — never reformatted.
   */
  timestamp: string;
  /**
   * Your webhook signing secret(s).  Pass an array during secret rotation to
   * accept signatures from multiple active secrets simultaneously.
   */
  secret: string | string[];
  /**
   * Maximum age of the webhook timestamp in seconds.
   *
   * Requests with a timestamp outside this window are rejected to prevent
   * replay attacks.  Defaults to {@link DEFAULT_TOLERANCE_SECONDS} (300 s).
   */
  tolerance?: number;
  /**
   * @internal Override the current Unix time (seconds) for testing.
   */
  _now?: number;
}

/**
 * Verify a QODIQA webhook signature.
 *
 * Call this at the top of every webhook handler before trusting the payload.
 *
 * @example
 * ```typescript
 * import { verifyWebhookSignature } from "@qodiqa/sdk";
 *
 * verifyWebhookSignature({
 *   body:      rawBody,
 *   signature: req.headers["x-qodiqa-signature"] as string,
 *   timestamp: req.headers["x-qodiqa-timestamp"] as string,
 *   secret:    process.env.QODIQA_WEBHOOK_SECRET!,
 * });
 * ```
 *
 * @throws {@link MalformedSignatureError} when the header cannot be parsed.
 * @throws {@link InvalidTimestampError} when the timestamp is not a valid ISO-8601 UTC value.
 * @throws {@link ExpiredSignatureError} when the timestamp is outside the tolerance window.
 * @throws {@link InvalidSignatureError} when no secret produces a matching HMAC.
 */
export function verifyWebhookSignature(options: WebhookVerifyOptions): void {
  const { body, signature, timestamp, tolerance = DEFAULT_TOLERANCE_SECONDS } = options;
  const now = options._now ?? Date.now() / 1000;
  const secrets = Array.isArray(options.secret) ? options.secret : [options.secret];

  if (secrets.length === 0) {
    throw new InvalidSignatureError(
      'At least one webhook secret must be provided.',
    );
  }

  const digests = parseSignatureHeader(signature);
  const tsEpoch = parseTimestampHeader(timestamp);

  // Timestamp tolerance — prevents replay attacks.
  const age = Math.abs(now - tsEpoch);
  if (age > tolerance) {
    throw new ExpiredSignatureError(
      `Webhook timestamp is ${age.toFixed(3)}s away from current time ` +
        `(tolerance: ${tolerance}s). ` +
        'This may indicate a replay attack or a clock skew issue.',
    );
  }

  // Try every (secret x digest) combination with constant-time comparison.
  for (const secret of secrets) {
    const expected = computeExpectedDigest(timestamp, body, secret);

    for (const digestHex of digests) {
      const actual = Buffer.from(digestHex, 'hex');
      if (
        expected.length === actual.length &&
        crypto.timingSafeEqual(expected, actual)
      ) {
        return; // Valid
      }
    }
  }

  throw new InvalidSignatureError(
    'Webhook signature verification failed: no active secret produces a matching HMAC. ' +
      'Ensure you are using the correct webhook secret and that the request body ' +
      'has not been modified.',
  );
}

// ---------------------------------------------------------------------------
// Public API — class
// ---------------------------------------------------------------------------

/**
 * Reusable webhook signature verifier.
 *
 * Configure your secret(s) and tolerance once; call {@link verify} for each
 * incoming request.  Prefer this class when handling multiple endpoints or
 * when you want to encapsulate the verifier in middleware.
 *
 * @example
 * ```typescript
 * const verifier = new WebhookVerifier(process.env.QODIQA_WEBHOOK_SECRET!);
 *
 * app.post("/webhooks/qodiqa", (req, res) => {
 *   verifier.verify(
 *     req.rawBody,
 *     req.headers["x-qodiqa-signature"] as string,
 *     req.headers["x-qodiqa-timestamp"] as string,
 *   );
 *   // Signature is valid — process the event.
 * });
 * ```
 *
 * @example Secret rotation
 * ```typescript
 * const verifier = new WebhookVerifier([
 *   process.env.QODIQA_WEBHOOK_SECRET_NEW!,
 *   process.env.QODIQA_WEBHOOK_SECRET_OLD!,
 * ]);
 * ```
 */
export class WebhookVerifier {
  private readonly secrets: readonly string[];
  private readonly tolerance: number;

  constructor(
    secret: string | string[],
    options?: { tolerance?: number },
  ) {
    const arr = Array.isArray(secret) ? [...secret] : [secret];
    if (arr.length === 0) {
      throw new InvalidSignatureError(
        'At least one webhook secret must be provided.',
      );
    }
    this.secrets = arr;
    this.tolerance = options?.tolerance ?? DEFAULT_TOLERANCE_SECONDS;
  }

  /**
   * Verify the signature on a single webhook delivery.
   *
   * @param body      Raw request body (string or Buffer).
   * @param signature Value of the {@code X-QODIQA-Signature} header.
   * @param timestamp Value of the {@code X-QODIQA-Timestamp} header.
   * @param options   Optional overrides — {@code _now} is for testing only.
   *
   * @throws {@link MalformedSignatureError}
   * @throws {@link InvalidTimestampError}
   * @throws {@link ExpiredSignatureError}
   * @throws {@link InvalidSignatureError}
   */
  verify(
    body: string | Buffer,
    signature: string,
    timestamp: string,
    options?: { _now?: number },
  ): void {
    verifyWebhookSignature({
      body,
      signature,
      timestamp,
      secret: this.secrets as string[],
      tolerance: this.tolerance,
      _now: options?._now,
    });
  }
}
