'use strict';

/**
 * Outbound JSON fetch for identity providers: the one network door of OIDC discovery and JWKS retrieval (and of the SAML metadata fetch).
 *
 *   fetchJson(url, { timeoutMs, maxBytes, allowInsecure, agentFactory }) -> parsed JSON
 *
 * https only (plain http and loopback/private hosts only when `allowInsecure` - a development IdP, never in production), a public DNS name otherwise (the shared SSRF policy:
 * no IP literal, no private or loopback name), connection through the guarded agent (every resolved address re-checked, so a name that later resolves to a private or metadata
 * address is refused), NO redirects (a 3xx is an error), a time bound, a size bound that is enforced while reading (not after), and a JSON content type. Errors carry a code and
 * never the response body.
 */

const https = require('https');
const http = require('http');
const { validateProviderUrl, createGuardedAgent } = require('../../../services/providers/ssrf');

class IdpFetchError extends Error { constructor(code, message) { super(message || code); this.name = 'IdpFetchError'; this.code = code; } }

const HOST_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;

function checkUrl(raw, allowInsecure) {
  let u; try { u = new URL(raw); } catch { throw new IdpFetchError('IDP_URL_INVALID'); }
  if (u.username || u.password || u.hash) throw new IdpFetchError('IDP_URL_INVALID');
  if (allowInsecure) { if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new IdpFetchError('IDP_URL_INVALID'); return u; }
  if (u.protocol !== 'https:') throw new IdpFetchError('IDP_URL_NOT_HTTPS');
  const probe = validateProviderUrl(`${u.origin}/`);                      // IP literals and private / loopback names are refused here for good
  if (!probe.valid && probe.reason !== 'HOSTNAME_NOT_ALLOWED') throw new IdpFetchError('IDP_URL_REFUSED');
  if (!HOST_RE.test(u.hostname.toLowerCase())) throw new IdpFetchError('IDP_URL_REFUSED');
  return u;
}

function fetchJson(raw, { timeoutMs = 5000, maxBytes = 256 * 1024, allowInsecure = false, agentFactory = createGuardedAgent, requestImpl } = {}) {
  const u = checkUrl(raw, allowInsecure);
  return new Promise((resolve, reject) => {
    const lib = u.protocol === 'https:' ? https : http;
    const env = allowInsecure ? process.env : { ...process.env, LOCAL_PROVIDER_BLOCK_PRIVATE_NETWORKS: 'true', PROVIDER_GUARD_STRICT_PUBLIC: 'true' };
    const req = (requestImpl || lib.request)(u, { method: 'GET', agent: agentFactory(u.href, env), headers: { accept: 'application/json' }, timeout: timeoutMs }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400) { res.resume(); return reject(new IdpFetchError('IDP_REDIRECT_REFUSED')); }
      if (res.statusCode !== 200) { res.resume(); return reject(new IdpFetchError('IDP_HTTP_ERROR', `HTTP ${res.statusCode}`)); }
      if (!/json/i.test(String(res.headers['content-type'] || ''))) { res.resume(); return reject(new IdpFetchError('IDP_NOT_JSON')); }
      const declared = Number(res.headers['content-length']);
      if (Number.isFinite(declared) && declared > maxBytes) { res.resume(); return reject(new IdpFetchError('IDP_TOO_LARGE')); }
      const chunks = []; let total = 0;
      res.on('data', (c) => { total += c.length; if (total > maxBytes) { res.destroy(); reject(new IdpFetchError('IDP_TOO_LARGE')); } else chunks.push(c); });
      res.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(new IdpFetchError('IDP_NOT_JSON')); } });
      res.on('error', () => reject(new IdpFetchError('IDP_READ_ERROR')));
    });
    req.on('timeout', () => { req.destroy(); reject(new IdpFetchError('IDP_TIMEOUT')); });
    req.on('error', (e) => reject(e instanceof IdpFetchError ? e : new IdpFetchError('IDP_NETWORK_ERROR')));
    req.end();
    const hard = setTimeout(() => { req.destroy(); reject(new IdpFetchError('IDP_TIMEOUT')); }, timeoutMs * 2); hard.unref();
  });
}

module.exports = { fetchJson, checkUrl, IdpFetchError };
