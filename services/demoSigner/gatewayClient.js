'use strict';

/**
 * Calls the gateway's real POST /sign with a demo identity's key.
 *
 * Only two headers are ever sent: Content-Type and Authorization. Nothing from
 * the visitor's request (in particular no Idempotency-Key, cookies or forwarded
 * headers) is propagated. The key is never included in errors or results.
 */

function createGatewayClient({ gatewayUrl, timeoutMs, fetchImpl = globalThis.fetch }) {
  const signUrl = new URL('/sign', gatewayUrl).toString();

  /**
   * @returns {Promise<{ ok: true, artifactId: string, artifact: object, expiresAt: string } | { ok: false, status: number|null, reason: string }>}
   */
  async function sign({ key, request, provider }) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    let res;
    try {
      res = await fetchImpl(signUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${key}` },
        body: JSON.stringify({ request, payload: { provider } }),
        signal: ac.signal,
      });
    } catch (err) {
      return { ok: false, status: null, reason: err && err.name === 'AbortError' ? 'GATEWAY_TIMEOUT' : 'GATEWAY_UNREACHABLE' };
    } finally {
      clearTimeout(timer);
    }
    let json = null;
    try { json = await res.json(); } catch { /* non-JSON body */ }
    if (res.status !== 200 || !json || !json.artifact || typeof json.artifactId !== 'string') {
      const reason = json && typeof json.reason === 'string' ? json.reason : 'GATEWAY_REJECTED';
      return { ok: false, status: res.status, reason };
    }
    return {
      ok: true,
      artifactId: json.artifactId,
      artifact: json.artifact,
      expiresAt: json.meta && json.meta.expiresAt ? json.meta.expiresAt : null,
    };
  }

  return { sign };
}

module.exports = { createGatewayClient };
