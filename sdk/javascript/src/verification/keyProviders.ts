/**
 * Public-key resolution for local artifact/transparency verification.
 *
 * Three supported approaches: an embedded/supplied static trust bundle, a
 * remote discovery endpoint with TTL caching, or a fully custom provider.
 * Unknown key IDs always resolve to `null` — the verifier fails closed.
 *
 * @module
 */

import type { KeyStatus } from '../types.js';

export interface ResolvedKey {
  pubDer: Buffer;
  status: KeyStatus;
  /**
   * Which discovery tier resolved this key. `'archived'` means the key was
   * no longer present in the live `/.well-known/qodiqa/keys` list and was
   * resolved via the archived-key fallback instead. Purely
   * diagnostic — it never affects whether the key is treated as valid for
   * verification (`status` alone determines that); providers that don't
   * distinguish tiers (e.g. `StaticKeyProvider`) simply omit it.
   */
  source?: 'live' | 'archived';
}

/** A source of truth for `keyId -> public key` resolution. */
export interface KeyProvider {
  /** Resolve a key id to its public key + status, or `null` if unknown. */
  getPublicKey(keyId: string): Promise<ResolvedKey | null>;
}

export interface StaticKeyEntry {
  keyId: string;
  /** Base64-encoded SPKI DER public key (the same encoding served by `/.well-known/qodiqa/keys`). */
  publicKey: string;
  status: KeyStatus;
}

/**
 * Trust bundle supplied directly by the caller — either embedded at build
 * time or fetched/pinned out-of-band. No network access.
 */
export class StaticKeyProvider implements KeyProvider {
  private readonly keys = new Map<string, ResolvedKey>();

  constructor(entries: StaticKeyEntry[]) {
    for (const entry of entries) {
      this.keys.set(entry.keyId, {
        pubDer: Buffer.from(entry.publicKey, 'base64'),
        status: entry.status,
      });
    }
  }

  async getPublicKey(keyId: string): Promise<ResolvedKey | null> {
    return this.keys.get(keyId) ?? null;
  }
}

interface DiscoveryKeyEntry {
  keyId: string;
  algorithm: string;
  publicKey: string;
  // The live endpoint always sends a real KeyStatus ('active' | 'deprecated').
  // The archived endpoint sends the literal string 'archived',
  // which is not itself a KeyStatus — fetchKeyList() below normalizes it to
  // 'deprecated' (the status it actually held immediately before being
  // purged) rather than propagating the wire-only 'archived' marker into
  // ResolvedKey.status, so `string` is used here rather than `KeyStatus`.
  status: string;
}

interface DiscoveryListResponse {
  keys: DiscoveryKeyEntry[];
}

export interface RemoteKeyProviderOptions {
  /** Full discovery URL, e.g. `https://api.example.com/.well-known/qodiqa/keys`. */
  discoveryUrl: string;
  /**
   * Discovery URL for the archived-key fallback tier, queried only
   * when a keyId is absent from the primary `discoveryUrl` list. Defaults to
   * `<discoveryUrl>/archived` when `discoveryUrl` ends with `/qodiqa/keys`
   * (i.e. the artifact-signing key discovery URL) — the archived tier only
   * exists for that endpoint, not for `/qodiqa/transparency-keys`. Set to
   * `null` explicitly to disable the fallback even for a `/qodiqa/keys` URL.
   */
  archivedDiscoveryUrl?: string | null;
  /** How long a fetched key list is trusted before being refetched. Default 5 minutes. */
  cacheTtlMs?: number;
  /** Injectable fetch implementation, primarily for testing. Defaults to the global `fetch`. */
  fetch?: typeof fetch;
  /** Request timeout in milliseconds. Default 10s. */
  timeoutMs?: number;
}

/**
 * Resolves keys from a `/.well-known/qodiqa/keys`-shaped discovery endpoint
 * (or the transparency-key sibling, `/.well-known/qodiqa/transparency-keys`),
 * with an in-memory TTL cache so repeated verifications don't refetch on
 * every call. A network failure never throws out of `getPublicKey` — it is
 * surfaced to the caller as a resolution failure (`null` cannot distinguish
 * "unknown key" from "fetch failed", so callers needing that distinction
 * should catch `refresh()` directly).
 *
 * when a keyId isn't found in the primary list (but the primary
 * fetch itself succeeded), and an archived-tier URL is configured/derived,
 * this transparently retries against `GET /.well-known/qodiqa/keys/archived`
 * before giving up — extending verification to keys that have since been
 * purged from the live keystore. The archived list is cached independently
 * (same TTL) and is only ever fetched after a primary-list miss, so primary
 * lookup latency and cache behavior are completely unchanged.
 */
export class RemoteKeyProvider implements KeyProvider {
  private readonly discoveryUrl: string;
  private readonly archivedDiscoveryUrl: string | null;
  private readonly cacheTtlMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  private cache: Map<string, ResolvedKey> | null = null;
  private cachedAt = 0;
  private pending: Promise<Map<string, ResolvedKey>> | null = null;

  private archivedCache: Map<string, ResolvedKey> | null = null;
  private archivedCachedAt = 0;
  private archivedPending: Promise<Map<string, ResolvedKey>> | null = null;

  constructor(options: RemoteKeyProviderOptions) {
    this.discoveryUrl = options.discoveryUrl;
    this.archivedDiscoveryUrl =
      options.archivedDiscoveryUrl !== undefined
        ? options.archivedDiscoveryUrl
        : RemoteKeyProvider.deriveArchivedUrl(this.discoveryUrl);
    this.cacheTtlMs = options.cacheTtlMs ?? 300_000;
    this.fetchImpl = options.fetch ?? fetch;
    this.timeoutMs = options.timeoutMs ?? 10_000;
  }

  private static deriveArchivedUrl(discoveryUrl: string): string | null {
    // Only the artifact-signing key discovery endpoint has an archived tier
    // (see src/api/routes/well-known.js) — never derive one for
    // /qodiqa/transparency-keys or a custom URL shape we can't be sure of.
    return discoveryUrl.endsWith('/qodiqa/keys') ? `${discoveryUrl}/archived` : null;
  }

  /** Force a re-fetch of the key list (both the live and, if configured, archived tiers), bypassing the cache. */
  async refresh(): Promise<void> {
    this.cache = null;
    this.archivedCache = null;
    await this.loadKeys();
  }

  async getPublicKey(keyId: string): Promise<ResolvedKey | null> {
    let keys: Map<string, ResolvedKey>;
    try {
      keys = await this.loadKeys();
    } catch {
      return null;
    }
    const hit = keys.get(keyId);
    if (hit) return hit;

    if (!this.archivedDiscoveryUrl) return null;
    try {
      const archivedKeys = await this.loadArchivedKeys();
      return archivedKeys.get(keyId) ?? null;
    } catch {
      return null;
    }
  }

  private async loadKeys(): Promise<Map<string, ResolvedKey>> {
    const now = Date.now();
    if (this.cache && now - this.cachedAt < this.cacheTtlMs) {
      return this.cache;
    }
    if (this.pending) {
      return this.pending;
    }

    this.pending = this.fetchKeyList(this.discoveryUrl, 'live').finally(() => {
      this.pending = null;
    });

    const keys = await this.pending;
    this.cache = keys;
    this.cachedAt = Date.now();
    return keys;
  }

  private async loadArchivedKeys(): Promise<Map<string, ResolvedKey>> {
    const now = Date.now();
    if (this.archivedCache && now - this.archivedCachedAt < this.cacheTtlMs) {
      return this.archivedCache;
    }
    if (this.archivedPending) {
      return this.archivedPending;
    }

    // this.archivedDiscoveryUrl is checked non-null by the only caller (getPublicKey/refresh).
    this.archivedPending = this.fetchKeyList(this.archivedDiscoveryUrl as string, 'archived').finally(() => {
      this.archivedPending = null;
    });

    const keys = await this.archivedPending;
    this.archivedCache = keys;
    this.archivedCachedAt = Date.now();
    return keys;
  }

  private async fetchKeyList(url: string, source: 'live' | 'archived'): Promise<Map<string, ResolvedKey>> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await this.fetchImpl(url, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`Key discovery request failed: HTTP ${response.status}`);
      }

      const body = (await response.json()) as DiscoveryListResponse;
      const keys = new Map<string, ResolvedKey>();
      for (const entry of body.keys ?? []) {
        // Archived entries carry the wire-only status 'archived' — normalize
        // to 'deprecated', the real KeyStatus they held immediately before
        // being purged (see the DiscoveryKeyEntry.status comment above).
        const status = (source === 'archived' ? 'deprecated' : entry.status) as KeyStatus;
        keys.set(entry.keyId, { pubDer: Buffer.from(entry.publicKey, 'base64'), status, source });
      }
      return keys;
    } finally {
      clearTimeout(timeoutId);
    }
  }
}

/** Adapt an arbitrary async lookup function into a {@link KeyProvider}. */
export function createKeyProvider(fn: (keyId: string) => Promise<ResolvedKey | null>): KeyProvider {
  return { getPublicKey: fn };
}
