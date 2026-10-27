/**
 * QODIQA domain-separated hashing — SDK-side port of
 * `src/infra/crypto/hashing.js` and `src/validation/canonicalize.js`.
 *
 * @module
 */

import crypto from 'node:crypto';

import { stableStringify } from './canonicalJson.js';
import type { Artifact } from '../types.js';

/**
 * Canonical domain identifiers — one per artifact class. Never share domains
 * across classes; cross-protocol reuse must be impossible. Only the domains
 * relevant to local artifact/transparency verification are ported here.
 */
export const DOMAINS = Object.freeze({
  /** Full-envelope artifact-signing domain — covers payload+timestamp+expiry+publicKeyId. */
  ARTIFACT: 'QODIQA::ARTIFACT::V1',
  /** Transparency-log entry-signing domain. */
  TRANSPARENCY_ENTRY: 'QODIQA::TRANSPARENCY::V1',
  /** Transparency-log root-signing domain. */
  TRANSPARENCY_ROOT: 'QODIQA::TRANSPARENCY_ROOT::V1',
  REQUEST: 'QODIQA::REQUEST::V1',
});

/**
 * Generic domain-separated hash: SHA-256(domain || canonical).
 * Prevents cross-protocol signature reuse between artifact classes.
 */
export function domainSeparatedHash(domain: string, canonical: string): Buffer {
  return crypto.createHash('sha256').update(domain, 'utf8').update(canonical, 'utf8').digest();
}

/** The four fields that are included in the signed artifact envelope. */
type SignedEnvelopeKey = 'expiry' | 'payload' | 'publicKeyId' | 'timestamp';

/**
 * Compute the 32-byte domain-separated hash over the full artifact envelope —
 * this is the exact Ed25519 message the server signs/verifies.
 *
 * SHA-256("QODIQA::ARTIFACT::V1" || stableStringify({expiry, payload, publicKeyId, timestamp}))
 *
 * @throws {@link CanonicalizationError} if the payload cannot be canonicalized.
 */
export function envelopeHash(artifact: Pick<Artifact, SignedEnvelopeKey>): Buffer {
  const { expiry, payload, publicKeyId, timestamp } = artifact;
  const canonical = stableStringify({ expiry, payload, publicKeyId, timestamp });
  return domainSeparatedHash(DOMAINS.ARTIFACT, canonical);
}

/**
 * The V1 request hash an artifact's `payload.requestHash` binds: hex(SHA-256("QODIQA::REQUEST::V1" || canonical({ body, method: UPPER(method), path }))). `path` has no query string.
 * (The V2 binding, which also covers the query and chosen headers, is a different construction and is not implemented in this SDK yet.)
 */
export function requestHash(method: string, path: string, body: unknown): string {
  const canonical = stableStringify({ body, method: method.toUpperCase(), path });
  return domainSeparatedHash(DOMAINS.REQUEST, canonical).toString('hex');
}
