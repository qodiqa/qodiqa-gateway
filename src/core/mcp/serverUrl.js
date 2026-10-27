'use strict';

/**
 * Destination policy for MCP servers - the same SSRF protection as the model providers (services/providers/ssrf.js), applied to the registered URL at
 * registration AND again, on the resolved address, at every connection.
 *
 *   validateMcpServerUrl(url, { allowLocal })   syntax and shape: https only, no credentials in the URL, no fragment, a name and not an IP literal, not a private /
 *                                               loopback / link-local / metadata destination. `allowLocal` (QODIQA_MCP_ALLOW_LOCAL=true, refused in production)
 *                                               admits http and loopback / private names - for the operator's own test servers - and nothing else.
 *   createMcpAgent(url, { allowLocal, pin })    the connection: every resolved address and every IP literal is checked again (DNS rebinding), a redirect is never
 *                                               followed (the client does not), and for https the server certificate's public key must match the pinned SHA-256.
 *
 * The pin is the SHA-256 (hex) of the DER SubjectPublicKeyInfo of the leaf certificate: it survives certificate renewal with the same key, and a different CA
 * or a man in the middle cannot present it.
 */

const net = require('net');
const dns = require('dns');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { blockedAddressReason } = require('../../../services/providers/ssrf');

const MAX_URL = 2048;
const PRIVATE_NAME = [/^localhost$/i, /\.localhost$/i, /\.local$/i, /\.internal$/i, /\.lan$/i, /\.home$/i, /\.corp$/i, /^metadata\.google\.internal$/i];

class McpUrlError extends Error { constructor(code, detail) { super(detail ? `${code}: ${detail}` : code); this.name = 'McpUrlError'; this.code = code; } }

function allowLocalFromEnv(env = process.env) {
  if (env.QODIQA_MCP_ALLOW_LOCAL !== 'true') return false;
  if (env.NODE_ENV === 'production' || env.QODIQA_ENVIRONMENT === 'production') return false;                          // never in production, whatever the flag says
  return true;
}

/** @returns {{ url: string, host: string, port: number, protocol: string, local: boolean }} the normalised destination; throws McpUrlError */
function validateMcpServerUrl(raw, { allowLocal = false } = {}) {
  if (typeof raw !== 'string' || !raw || raw.length > MAX_URL || /[\u0000- \u007f]/.test(raw)) throw new McpUrlError('MCP_URL_INVALID');
  let u;
  try { u = new URL(raw); } catch { throw new McpUrlError('MCP_URL_INVALID'); }
  if (u.protocol !== 'https:' && !(allowLocal && u.protocol === 'http:')) throw new McpUrlError('MCP_URL_NOT_HTTPS');
  if (u.username || u.password) throw new McpUrlError('MCP_URL_CREDENTIALS');
  if (u.hash) throw new McpUrlError('MCP_URL_FRAGMENT');
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');   // 'localhost.' is localhost
  if (!host) throw new McpUrlError('MCP_URL_INVALID');
  const isIp = net.isIP(host) !== 0 || /^\d+$/.test(host) || /^0x[0-9a-f]+$/i.test(host) || /^[\d.]+$/.test(host);         // dotted, decimal and hex spellings of an address
  const local = PRIVATE_NAME.some((r) => r.test(host)) || (isIp && !!blockedAddressReason(host, { blockPrivate: true, blockLoopback: true }));
  const loopbackName = host === 'localhost' || host.endsWith('.localhost');
  if (!allowLocal) {
    if (isIp) throw new McpUrlError('MCP_URL_IP_LITERAL');
    if (local) throw new McpUrlError('MCP_URL_PRIVATE_DESTINATION');
  } else if (isIp && blockedAddressReason(host, { blockPrivate: false, blockLoopback: false })) {
    throw new McpUrlError('MCP_URL_PRIVATE_DESTINATION', 'metadata / link-local / reserved addresses are never allowed');
  }
  const port = u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 80);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new McpUrlError('MCP_URL_INVALID');
  u.hash = '';
  return { url: u.toString(), host, port, protocol: u.protocol, local: local || loopbackName || isIp };
}

/** SHA-256 (hex) of the DER SubjectPublicKeyInfo of a certificate (PEM string or DER buffer). */
function spkiPinOf(cert) {
  const x = new crypto.X509Certificate(cert);
  return crypto.createHash('sha256').update(x.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
}

function guardedLookup(allowLocal) {
  return function lookup(hostname, options, callback) {
    const cb = typeof options === 'function' ? options : callback;
    const opts = options && typeof options === 'object' ? options : {};
    dns.lookup(hostname, { all: true, family: opts.family, hints: opts.hints }, (err, addrs) => {
      if (err) return cb(err);
      for (const { address } of addrs) {
        const reason = blockedAddressReason(address, allowLocal ? { blockPrivate: false, blockLoopback: false } : { blockPrivate: true, blockLoopback: true });
        if (reason) { const e = new Error(`SSRF guard: ${hostname} resolved to a refused address (${reason})`); e.code = 'SSRF_BLOCKED_RESOLVED_ADDRESS'; return cb(e); }
      }
      if (opts.all) return cb(null, addrs.map((x) => ({ address: x.address, family: x.family })));
      return cb(null, addrs[0].address, addrs[0].family);
    });
  };
}

/** An http(s).Agent for ONE registered server. `pinOnly`: the pin REPLACES CA validation (a private server with a self-signed certificate) - never without a pin.
 *  @param {{ allowLocal?: boolean, pin?: string|null, pinOnly?: boolean }} o */
function createMcpAgent(rawUrl, { allowLocal = false, pin = null, pinOnly = false } = {}) {
  if (pinOnly && !pin) throw new McpUrlError('MCP_PIN_REQUIRED');
  const protocol = new URL(rawUrl).protocol;
  const Base = protocol === 'https:' ? https.Agent : http.Agent;
  const block = allowLocal ? { blockPrivate: false, blockLoopback: false } : { blockPrivate: true, blockLoopback: true };
  class McpAgent extends Base {
    createConnection(options, cb) {
      const host = String((options && (options.host || options.hostname)) || '').replace(/^\[|\]$/g, '');
      const reason = net.isIP(host) ? blockedAddressReason(host, block) : null;
      if (reason) {
        const e = new Error(`SSRF guard: connection to ${host} refused (${reason})`); e.code = 'SSRF_BLOCKED_RESOLVED_ADDRESS';
        const sock = new net.Socket(); process.nextTick(() => sock.destroy(e)); return sock;
      }
      const sock = super.createConnection(options, cb);
      if (protocol === 'https:' && pin) {
        sock.once('secureConnect', () => {
          try {
            const cert = sock.getPeerCertificate(true);
            const got = cert && cert.raw ? spkiPinOf(cert.raw) : null;
            if (!got || !crypto.timingSafeEqual(Buffer.from(got, 'hex'), Buffer.from(pin, 'hex'))) throw Object.assign(new Error('MCP_PIN_MISMATCH'), { code: 'MCP_PIN_MISMATCH' });
          } catch (e) { sock.destroy(e.code === 'MCP_PIN_MISMATCH' ? e : Object.assign(new Error('MCP_PIN_MISMATCH'), { code: 'MCP_PIN_MISMATCH' })); }
        });
      }
      return sock;
    }
  }
  // maxCachedSessions 0: a RESUMED TLS session carries no peer certificate (getPeerCertificate() is empty), so the pin could not be checked on the second
  // connection to the same host - every later call would be refused as MCP_PIN_MISMATCH. Found by the production-stack run; a full handshake per call is the
  // price of checking the pin on every connection.
  return new McpAgent({ lookup: guardedLookup(allowLocal), keepAlive: false, maxSockets: 8, ...(protocol === 'https:' ? { maxCachedSessions: 0 } : {}), ...(protocol === 'https:' && pinOnly ? { rejectUnauthorized: false } : {}) });
}

module.exports = { McpUrlError, allowLocalFromEnv, validateMcpServerUrl, spkiPinOf, createMcpAgent };
