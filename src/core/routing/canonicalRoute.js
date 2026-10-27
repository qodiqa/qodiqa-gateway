'use strict';

/**
 * Canonical route resolver —.
 *
 * ONE definition of "which enforcement route does this path reach", shared by
 * POST /sign (which decides whether the provider-scope checks apply to the
 * artifact it signs) and the /ai/chat verifier (which re-checks that scope on
 * execution)., /sign compared the bound path to the literal
 * '/ai/chat', so an identity restricted by allowedProviders could sign for
 * '/v1/ai/chat', '/ai/chat/stream', '/ai/chat/', '/AI/Chat' or an encoded path
 * — every one of which the router maps to the same /ai/chat handler — and skip
 * both the allowedProviders and the provider-enabled checks.
 *
 * Normalisation mirrors (and over-approximates) how the path can reach the
 * router: percent-decoding (repeated, bounded), backslash → slash, query and
 * fragment removed, repeated slashes collapsed, dot segments resolved,
 * trailing slashes removed, case folded (Express 4 routes case-insensitively).
 * An undecodable path is treated as reaching the AI route (the stricter
 * branch — the provider checks then run), never as "other".
 */

const AI_CHAT_ALIASES = Object.freeze(['/ai/chat', '/ai/chat/stream', '/v1/ai/chat', '/v1/ai/chat/stream']);
const _AI = new Set(AI_CHAT_ALIASES);

function _decodeRepeatedly(p) {
  let cur = p;
  for (let i = 0; i < 4; i++) {
    let next;
    try { next = decodeURIComponent(cur); } catch { return { ok: false, value: cur }; }
    if (next === cur) return { ok: true, value: cur };
    cur = next;
  }
  return { ok: true, value: cur };
}

/**
 * @param {string} rawPath  a request path as a client may send or sign it
 * @returns {{ route: 'ai_chat'|'other', normalizedPath: string|null, decodable: boolean }}
 */
function resolveRoute(rawPath) {
  if (typeof rawPath !== 'string' || rawPath.length === 0) return { route: 'other', normalizedPath: null, decodable: true };
  let p = rawPath.split(/[?#]/)[0];
  const dec = _decodeRepeatedly(p);
  p = dec.value.split(/[?#]/)[0].replace(/\\/g, '/');
  const out = [];
  for (const seg of p.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') { out.pop(); continue; }
    out.push(seg.toLowerCase());
  }
  const normalizedPath = '/' + out.join('/');
  if (!dec.ok) return { route: 'ai_chat', normalizedPath, decodable: false };
  return { route: _AI.has(normalizedPath) ? 'ai_chat' : 'other', normalizedPath, decodable: true };
}

function isAiChatRoute(rawPath) { return resolveRoute(rawPath).route === 'ai_chat'; }

module.exports = { resolveRoute, isAiChatRoute, AI_CHAT_ALIASES };
