/**
 * QODIQA local artifact verification — remediation.
 *
 * Performs the complete verification pipeline entirely offline: schema
 * validation, canonical JSON reconstruction, payload-hash computation,
 * public-key resolution, Ed25519 signature verification, signed-metadata
 * validation, and optional transparency-proof verification. None of this
 * depends on calling the server's `/verify` endpoint or trusting its
 * response — `resources/verify.ts`'s `POST /verify` remains available as an
 * optional remote convenience only and is never used internally here.
 *
 * @module
 */

import { ValidationError } from '../errors.js';
import type { Artifact } from '../types.js';
import { envelopeHash } from './domainHash.js';
import { verifyEd25519 } from './ed25519.js';
import type { KeyProvider } from './keyProviders.js';
import { verifyTransparencyProof, transparencyDetailAllPassed } from './transparencyProof.js';
import type { ArtifactVerificationResult, TransparencyInclusionProof } from './types.js';

const ARTIFACT_SCHEMA = new Set(['expiry', 'payload', 'publicKeyId', 'signature', 'timestamp']);
const BASE64_RE = /^[A-Za-z0-9+/]+=*$/;
const SIG_BYTE_LEN = 64;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function hasUndefined(value: unknown, seen: Set<unknown> = new Set()): boolean {
  if (value === undefined) return true;
  if (value === null || typeof value !== 'object') return false;
  if (seen.has(value)) return false;
  seen.add(value);
  if (Array.isArray(value)) {
    return value.some((v) => hasUndefined(v, seen));
  }
  return Object.values(value as Record<string, unknown>).some((v) => hasUndefined(v, seen));
}

function emptyResult(verifiedAt: number): ArtifactVerificationResult {
  return {
    verificationStatus: 'invalid',
    signatureValid: false,
    payloadHashValid: false,
    canonicalizationValid: false,
    keyValid: false,
    keyId: null,
    keyStatus: null,
    keySource: null,
    expiryValid: false,
    timestampValid: false,
    transparencyVerified: 'unavailable',
    transparencyDetail: null,
    verificationErrors: [],
    verificationWarnings: [],
    failedStage: null,
    verifiedAt,
  };
}

export interface ArtifactVerifierOptions {
  /** Trust source for artifact-signing keys. Required. */
  keys: KeyProvider;
  /**
   * Trust source for transparency-log signing keys. A completely separate
   * trust domain from `keys` — never point both at the same source, or the
   * cryptographic separation between artifact and transparency signing is
   * silently defeated.
   */
  transparencyKeys?: KeyProvider;
  /** Clock tolerance applied to both the future-timestamp and expiry checks. Default 0 (matches server). */
  clockToleranceMs?: number;
  /** If true, a `verify()` call without a `transparencyProof` is treated as an overall verification failure. Default false. */
  requireTransparency?: boolean;
  /** @internal Override the current time (ms epoch) for deterministic testing. */
  _now?: number;
}

export interface VerifyCallOptions {
  /** A transparency inclusion proof fetched out-of-band, verified fully locally if supplied. */
  transparencyProof?: TransparencyInclusionProof;
}

/**
 * Local, offline verifier for QODIQA execution artifacts.
 *
 * @example
 * ```typescript
 * const verifier = new ArtifactVerifier({
 *   keys: new RemoteKeyProvider({ discoveryUrl: 'https://api.example.com/.well-known/qodiqa/keys' }),
 * });
 * const result = await verifier.verify(artifact);
 * if (result.verificationStatus !== 'valid') {
 *   // result.verificationErrors / result.failedStage explain exactly why.
 * }
 * ```
 */
export class ArtifactVerifier {
  private readonly keys: KeyProvider;
  private readonly transparencyKeys: KeyProvider | undefined;
  private readonly clockToleranceMs: number;
  private readonly requireTransparency: boolean;
  private readonly _now: number | undefined;

  constructor(options: ArtifactVerifierOptions) {
    if (!options || !options.keys) {
      throw new ValidationError('ArtifactVerifier requires a `keys` KeyProvider.');
    }
    if (options.requireTransparency && !options.transparencyKeys) {
      throw new ValidationError(
        'ArtifactVerifier: requireTransparency=true requires a `transparencyKeys` KeyProvider.',
      );
    }
    this.keys = options.keys;
    this.transparencyKeys = options.transparencyKeys;
    this.clockToleranceMs = options.clockToleranceMs ?? 0;
    this.requireTransparency = options.requireTransparency ?? false;
    this._now = options._now;
  }

  /**
   * Run the full local verification pipeline against `artifact`. Never
   * throws for content problems (malformed artifact, bad signature, unknown
   * key, expired, bad transparency proof, even a key-provider network
   * failure) — every such case resolves to a structured result instead.
   */
  async verify(artifact: unknown, callOptions?: VerifyCallOptions): Promise<ArtifactVerificationResult> {
    const now = this._now ?? Date.now();
    const result = emptyResult(now);

    // ── Stage 1: structural / schema validation ──────────────────────────────
    if (!isPlainObject(artifact)) {
      result.failedStage = 'STRUCTURE';
      result.verificationErrors.push('Artifact must be a plain object.');
      return result;
    }

    for (const key of Object.keys(artifact)) {
      if (!ARTIFACT_SCHEMA.has(key)) {
        result.failedStage = 'STRUCTURE';
        result.verificationErrors.push(`Unexpected field "${key}" is not part of the artifact envelope.`);
        return result;
      }
    }
    for (const field of ARTIFACT_SCHEMA) {
      if (!(field in artifact) || artifact[field] === undefined) {
        result.failedStage = 'STRUCTURE';
        result.verificationErrors.push(`Missing required field "${field}".`);
        return result;
      }
    }

    const { expiry, payload, publicKeyId, signature, timestamp } = artifact as unknown as Artifact;

    if (!isPlainObject(payload)) {
      result.failedStage = 'STRUCTURE';
      result.verificationErrors.push('Artifact payload must be a plain object.');
      return result;
    }
    if (hasUndefined(payload)) {
      result.failedStage = 'STRUCTURE';
      result.verificationErrors.push('Artifact payload contains an undefined value; use null instead.');
      return result;
    }
    // same numeric rule as the gateway: positive safe integers, and timestamp < expiry.
    if (typeof timestamp !== 'number' || !Number.isSafeInteger(timestamp) || timestamp <= 0) {
      result.failedStage = 'STRUCTURE';
      result.verificationErrors.push('Artifact timestamp must be a positive safe integer (Unix ms).');
      return result;
    }
    if (typeof expiry !== 'number' || !Number.isSafeInteger(expiry) || expiry <= 0) {
      result.failedStage = 'STRUCTURE';
      result.verificationErrors.push('Artifact expiry must be a positive safe integer (Unix ms).');
      return result;
    }
    if (timestamp >= expiry) {
      result.failedStage = 'STRUCTURE';
      result.verificationErrors.push('Artifact expiry must be greater than its timestamp.');
      return result;
    }
    if (typeof signature !== 'string' || !BASE64_RE.test(signature) || Buffer.from(signature, 'base64').length !== SIG_BYTE_LEN) {
      result.failedStage = 'STRUCTURE';
      result.verificationErrors.push(`Artifact signature must be base64 decoding to exactly ${SIG_BYTE_LEN} bytes.`);
      return result;
    }
    if (typeof publicKeyId !== 'string' || !publicKeyId.trim()) {
      result.failedStage = 'STRUCTURE';
      result.verificationErrors.push('Artifact publicKeyId must be a non-empty string.');
      return result;
    }

    // ── Stage 2: canonicalization + envelope-hash computation ────────────────
    let hashBuf: Buffer;
    try {
      hashBuf = envelopeHash({ expiry, payload, publicKeyId, timestamp });
      result.canonicalizationValid = true;
      result.payloadHashValid = true;
    } catch (err) {
      result.failedStage = 'CANONICALIZATION';
      result.verificationErrors.push(
        `Envelope canonicalization failed: ${err instanceof Error ? err.message : String(err)}`,
      );
      return result;
    }

    // ── Stage 3: key resolution ───────────────────────────────────────────────
    result.keyId = publicKeyId;
    let resolved;
    try {
      resolved = await this.keys.getPublicKey(publicKeyId);
    } catch (err) {
      result.verificationStatus = 'error';
      result.failedStage = 'KEY_RESOLUTION';
      result.verificationErrors.push(
        `Key provider failed to resolve "${publicKeyId}": ${err instanceof Error ? err.message : String(err)}`,
      );
      return result;
    }
    if (!resolved) {
      result.failedStage = 'KEY_RESOLUTION';
      result.verificationErrors.push(`Unknown key id "${publicKeyId}".`);
      return result;
    }
    result.keyStatus = resolved.status;
    result.keySource = resolved.source ?? 'live';
    result.keyValid = resolved.status === 'active' || resolved.status === 'deprecated';
    if (!result.keyValid) {
      result.failedStage = 'KEY_RESOLUTION';
      result.verificationErrors.push(`Key "${publicKeyId}" has status "${resolved.status}" and cannot verify.`);
      return result;
    }

    // ── Stage 4: timestamp checks (zero-tolerance by default, matching the server) ──
    result.timestampValid = timestamp <= now + this.clockToleranceMs;
    if (!result.timestampValid) {
      result.failedStage = 'FUTURE_TIMESTAMP';
      result.verificationErrors.push('Artifact timestamp is in the future.');
      return result;
    }
    result.expiryValid = now - this.clockToleranceMs < expiry;
    if (!result.expiryValid) {
      result.failedStage = 'EXPIRED';
      result.verificationErrors.push('Artifact has expired.');
      return result;
    }

    // ── Stage 5: Ed25519 signature verification ───────────────────────────────
    result.signatureValid = verifyEd25519(hashBuf, signature, resolved.pubDer);
    if (!result.signatureValid) {
      result.failedStage = 'INVALID_SIGNATURE';
      result.verificationErrors.push('Ed25519 signature verification failed.');
      return result;
    }

    // ── Stage 6: optional transparency-proof verification ─────────────────────
    if (callOptions?.transparencyProof) {
      if (!this.transparencyKeys) {
        result.transparencyVerified = 'unavailable';
        result.verificationWarnings.push(
          'A transparencyProof was supplied but no transparencyKeys provider is configured; skipping transparency verification.',
        );
      } else {
        result.transparencyDetail = await verifyTransparencyProof(callOptions.transparencyProof, this.transparencyKeys);
        result.transparencyVerified = transparencyDetailAllPassed(result.transparencyDetail) ? 'verified' : 'failed';
        if (result.transparencyVerified === 'failed') {
          result.failedStage = 'TRANSPARENCY';
          result.verificationErrors.push('Transparency inclusion proof verification failed.');
          return result;
        }
      }
    } else if (this.requireTransparency) {
      result.transparencyVerified = 'unavailable';
      result.failedStage = 'TRANSPARENCY';
      result.verificationErrors.push('Transparency verification is required but no transparencyProof was supplied.');
      return result;
    } else {
      result.transparencyVerified = 'unavailable';
    }

    result.verificationStatus = 'valid';
    return result;
  }
}

/**
 * One-shot convenience wrapper around {@link ArtifactVerifier}.
 *
 * @example
 * ```typescript
 * const result = await verifyArtifact(artifact, {
 *   keys: new StaticKeyProvider([{ keyId: 'dev-local:key_v1', publicKey: base64Der, status: 'active' }]),
 * });
 * ```
 */
export async function verifyArtifact(
  artifact: unknown,
  options: ArtifactVerifierOptions & VerifyCallOptions,
): Promise<ArtifactVerificationResult> {
  const verifier = new ArtifactVerifier(options);
  return verifier.verify(artifact, { transparencyProof: options.transparencyProof });
}
