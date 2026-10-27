'use strict';

const crypto = require('crypto');
const http   = require('http');
const https  = require('https');
const fs     = require('fs');

// ── Canonical serialization (mirrors services/utils/stableStringify.js exactly) ──

// this standalone copy is CONFORMANT with the server's canonicalizer
// (src/utils/stableStringify.js, docs/protocol/QODIQA-PROTOCOL.md §3): JSON string escaping (control characters,
// lone surrogates), JS number formatting, keys sorted by UTF-16 code units, undefined → null, and the same refusals
// (non-finite number, unsupported type, forbidden key). It stays dependency-free so this file can be copied out and run
// alone; test/externalVerifierCanonicalConformance.test.js holds every copy to the server output.
const _FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function _encodeString(str) {
  return JSON.stringify(str);
}

function stableStringify(value) {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('NON_FINITE_NUMBER');
    return JSON.stringify(value);
  }
  if (typeof value === 'string')  return _encodeString(value);
  if (Array.isArray(value)) {
    return '[' + value.map(stableStringify).join(',') + ']';
  }
  if (typeof value === 'object') {
    const proto = Object.getPrototypeOf(value);
    if (proto !== null && proto !== Object.prototype) throw new Error('UNSUPPORTED_TYPE');
    const keys = Object.keys(value);
    for (const k of keys) if (_FORBIDDEN_KEYS.has(k)) throw new Error('FORBIDDEN_KEY');
    return '{' + keys.sort()
      .map(k => _encodeString(k) + ':' + stableStringify(value[k]))
      .join(',') + '}';
  }
  throw new Error('UNSUPPORTED_TYPE');
}

// ── Domain-separated hash (mirrors src/infra/crypto/hashing.js) ──────────────

function domainSeparatedHash(domain, canonical) {
  return crypto.createHash('sha256')
    .update(domain,    'utf8')
    .update(canonical, 'utf8')
    .digest();
}

// ── Envelope hash (mirrors src/validation/canonicalize.js envelopeHash) ──────

function envelopeHash(artifact) {
  const { expiry, payload, publicKeyId, timestamp } = artifact;
  const canonical = stableStringify({ expiry, payload, publicKeyId, timestamp });
  return domainSeparatedHash('QODIQA::ARTIFACT::V1', canonical);
}

// ── Request hash (mirrors src/validation/requestHash.js) ─────────────────────

function computeRequestHash(method, path, body) {
  const canonical = stableStringify({ body, method: method.toUpperCase(), path });
  return domainSeparatedHash('QODIQA::REQUEST::V1', canonical).toString('hex');
}

// ── HTTP fetch (no external dependencies) ────────────────────────────────────

// the key set is the trust anchor of online mode, so it must not be fetched over
// plain http from anywhere but this machine — a network attacker could otherwise substitute keys.
// https:// is required; http:// is accepted only for localhost / 127.0.0.1 / [::1] (local dev).
function isAllowedKeySource(baseUrl) {
  let u;
  try { u = new URL(String(baseUrl)); } catch { return false; }
  if (u.protocol === 'https:') return true;
  if (u.protocol !== 'http:') return false;
  return u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '[::1]' || u.hostname === '::1';
}

function fetchJSON(url) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https://') ? https : http;
    mod.get(url, (res) => {
      let raw = '';
      res.on('data', chunk => { raw += chunk; });
      res.on('end', () => {
        try { resolve(JSON.parse(raw)); }
        catch (e) { reject(new Error(`Failed to parse JSON from ${url}: ${e.message}`)); }
      });
    }).on('error', reject);
  });
}

// ── Offline trust material ─────────────────────────────────────────
// Loads a locally-supplied key list instead of fetching `/keys` over the
// network. Accepts the exact same shape the server returns from `/keys` or
// `/.well-known/qodiqa/keys` (`{ keys: [...] }`), or a bare `[...]` array.

function _readJSONFile(filePath, label) {
  let raw;
  try {
    raw = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') throw new Error(`${label} not found: ${filePath}`);
    throw new Error(`Failed to read ${label} (${filePath}): ${err.message}`);
  }
  try {
    return JSON.parse(raw);
  } catch (err) {
    throw new Error(`${label} is not valid JSON (${filePath}): ${err.message}`);
  }
}

function _normalizeKeysData(data, label) {
  if (Array.isArray(data)) return { keys: data };
  if (data && Array.isArray(data.keys)) return data;
  throw new Error(`${label} does not contain a "keys" array — expected the same shape as GET /keys or /.well-known/qodiqa/keys`);
}

function loadKeysFromFile(filePath) {
  return _normalizeKeysData(_readJSONFile(filePath, 'Key file'), 'Key file');
}

// ── Production-equivalent strictness ───────────────────────
// Mirrors src/validation/validateArtifact.js + src/validation/keyLifecycle.js + timeCheck.js:
//   * the envelope is EXACTLY these five fields — an unknown field is INVALID_ARTIFACT;
//   * the signature has ONE accepted spelling: padded standard base64 of 64 bytes (88 chars),
//     round-trip exact — any other spelling is INVALID_SIGNATURE;
//   * max age: an artifact older than MAX_ARTIFACT_AGE_MS is TIME_SKEW_EXCEEDED whatever its expiry;
//   * key lifecycle: revoked/compromised and archived keys never verify a current artifact; a
//     deprecated key verifies only an artifact signed BEFORE its retirement and only until
//     deprecatedAt + 65 s; a deprecated key with no known retirement time is refused.
// Inlined (not imported) because this verifier is designed to be copied out and run alone.

const ARTIFACT_FIELDS       = Object.freeze(['expiry', 'payload', 'publicKeyId', 'signature', 'timestamp']);
const CANONICAL_SIG_RE      = /^[A-Za-z0-9+/]{86}==$/;
const MAX_ARTIFACT_AGE_MS   = 60_000;                               // timeCheck.js MAX_SKEW_MS
const FUTURE_SKEW_MS        = 5_000;                                // timeCheck.js FUTURE_SKEW_MS
const DEPRECATED_WINDOW_MS  = MAX_ARTIFACT_AGE_MS + FUTURE_SKEW_MS;  // keyLifecycle.js (65 s)
const REVOKED_STATUSES      = new Set(['revoked', 'compromised']);
const ISO_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?(Z|[+-]\d{2}:\d{2})$/;

function isCanonicalSignature(s) {
  return typeof s === 'string' && CANONICAL_SIG_RE.test(s) && Buffer.from(s, 'base64').toString('base64') === s;
}

/** Strict lifecycle time: ISO-8601 with an explicit zone (Z or ±hh:mm), or positive Unix ms. Else null. */
function _timeMs(v) {
  if (typeof v === 'number') return Number.isFinite(v) && v > 0 ? v : null;
  if (typeof v !== 'string') return null;
  const m = ISO_RE.exec(v);
  if (!m) return null;
  const [Y, Mo, D, h, mi, s] = m.slice(1, 7).map(Number);
  if (Mo < 1 || Mo > 12 || D < 1 || D > 31 || h > 23 || mi > 59 || s > 59) return null;
  const frac = m[7] ? Number(m[7].padEnd(3, '0')) : 0;
  let off = 0;
  if (m[8] !== 'Z') {
    const sign = m[8][0] === '-' ? -1 : 1;
    off = sign * (Number(m[8].slice(1, 3)) * 60 + Number(m[8].slice(4, 6))) * 60_000;
  }
  return Date.UTC(Y, Mo - 1, D, h, mi, s, frac) - off;
}

/** keyLifecycle.checkExecution — may this key verify an artifact asking to be honoured NOW? */
function _checkKeyExecution(entry, tsMs, nowMs) {
  const status = typeof entry.status === 'string' ? entry.status.toLowerCase() : null;
  if (REVOKED_STATUSES.has(status)) return { reason: 'KEY_REVOKED', detail: `key status: ${status}` };
  if (status === 'archived') return { reason: 'KEY_ARCHIVED', detail: 'an archived key never verifies a current artifact (use --historical for archival verification)' };
  if (status === 'deprecated') {
    const dep = _timeMs(entry.deprecatedAt);
    if (dep === null) return { reason: 'KEY_DEPRECATED', detail: 'retirement time unknown (trusted key entry has no deprecatedAt)' };
    if (tsMs >= dep) return { reason: 'KEY_DEPRECATED', detail: 'signed after the key was retired' };
    if (nowMs >= dep + DEPRECATED_WINDOW_MS) return { reason: 'KEY_DEPRECATED', detail: 'deprecated-key window elapsed' };
    return null;
  }
  if (status === 'active') {
    const act = _timeMs(entry.activatedAt);
    if (act !== null && tsMs < act - FUTURE_SKEW_MS) return { reason: 'KEY_NOT_YET_ACTIVE', detail: 'signed before the key was activated' };
    return null;
  }
  return { reason: 'KEY_STATUS_UNKNOWN', detail: `key status: ${status === null ? 'missing' : status}` };
}

/** keyLifecycle.checkHistorical — was this key valid at the artifact's own signing time? */
function _checkKeyHistorical(entry, signedAtMs) {
  const status = typeof entry.status === 'string' ? entry.status.toLowerCase() : null;
  if (REVOKED_STATUSES.has(status)) return { reason: 'KEY_REVOKED', detail: `key status: ${status} (compromise invalidates everything it signed)` };
  if (!['active', 'deprecated', 'archived'].includes(status)) return { reason: 'KEY_STATUS_UNKNOWN', detail: `key status: ${status === null ? 'missing' : status}` };
  const act = _timeMs(entry.activatedAt);
  if (act !== null && signedAtMs < act - FUTURE_SKEW_MS) return { reason: 'KEY_NOT_ACTIVE_AT_SIGNING_TIME', detail: 'signed before the key existed' };
  const dep = _timeMs(entry.deprecatedAt);
  const end = dep !== null ? dep : _timeMs(entry.archivedAt);
  if (status !== 'active' && end === null) return { reason: 'KEY_NOT_ACTIVE_AT_SIGNING_TIME', detail: 'retirement time unknown (trusted key entry has no deprecatedAt/archivedAt)' };
  if (end !== null && signedAtMs >= end) return { reason: 'KEY_NOT_ACTIVE_AT_SIGNING_TIME', detail: 'signed after the key was retired' };
  return null;
}

function _keyBytes(b64) {
  if (typeof b64 !== 'string' || !b64) return null;
  try { return Buffer.from(b64, 'base64'); } catch { return null; }
}

// ── Signature verification ────────────────────────────────────────────────────

function verifySignature(artifact, publicKeyDerB64) {
  try {
    if (!isCanonicalSignature(artifact.signature)) return false;
    const pubDer = Buffer.from(publicKeyDerB64, 'base64');
    const pubKey = crypto.createPublicKey({ key: pubDer, format: 'der', type: 'spki' });
    if (pubKey.asymmetricKeyType !== 'ed25519') return false;
    const hash   = envelopeHash(artifact);
    const sigBuf = Buffer.from(artifact.signature, 'base64');
    if (sigBuf.length !== 64) return false;
    return crypto.verify(null, hash, pubKey, sigBuf);
  } catch {
    return false;
  }
}

// ── Main verification logic ───────────────────────────────────────────────────
//
// options:
//   keysData    { keys: [...] } — the TRUSTED key set (from --key-file / --trusted-keys, obtained out
//               of band). It is the only key material that can authenticate an artifact offline.
//   bundleKeys { keys: [...] } — keys a verification bundle carries. these are CANDIDATES
//               only, never a trust anchor: a candidate must match the trusted entry for the same
//               keyId byte-for-byte, and the trusted entry (never the bundle's) supplies status/timeline.
//   offline     never fetch; without keysData fail closed.
//   historical archival mode: skip the "now" expiry/max-age checks; instead require that the
//               artifact was valid at its own signing time (timestamp < expiry, not in the future) and
//               that the trusted key was valid at that signing time (not revoked, inside its
//               [activatedAt, deprecatedAt/archivedAt) window). It never says the artifact may run now.
//   _clock      deterministic-test escape hatch only (like validateArtifact's _clock).

async function verify(baseUrl, artifact, request, options = {}) {
  const historical = options.historical === true;
  const mode = historical ? 'HISTORICAL' : 'CURRENT';

  if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) {
    return { valid: false, reason: 'MISSING_ARTIFACT' };
  }
  const proto = Object.getPrototypeOf(artifact);
  if (proto !== null && proto !== Object.prototype) {
    return { valid: false, reason: 'INVALID_ARTIFACT', detail: 'artifact must be a plain object' };
  }

  // strict schema — exactly the five envelope fields (validateArtifact.js step 2).
  for (const key of Object.keys(artifact)) {
    if (!ARTIFACT_FIELDS.includes(key)) {
      return { valid: false, reason: 'INVALID_ARTIFACT', detail: `unknown field: ${key}` };
    }
  }

  for (const field of ARTIFACT_FIELDS) {
    if (!(field in artifact) || artifact[field] === undefined || artifact[field] === null) {
      return { valid: false, reason: 'INVALID_ARTIFACT', detail: `missing field: ${field}` };
    }
  }

  const { expiry, payload, publicKeyId, signature, timestamp } = artifact;

  if (typeof timestamp !== 'number' || !Number.isFinite(timestamp) || timestamp <= 0) {
    return { valid: false, reason: 'INVALID_ARTIFACT', detail: 'timestamp must be a positive finite number' };
  }
  if (typeof expiry !== 'number' || !Number.isFinite(expiry) || expiry <= 0) {
    return { valid: false, reason: 'INVALID_ARTIFACT', detail: 'expiry must be a positive finite number' };
  }
  if (typeof signature !== 'string') {
    return { valid: false, reason: 'INVALID_ARTIFACT', detail: 'signature must be a string' };
  }
  // one canonical signature spelling (validateArtifact.js step 9).
  if (!isCanonicalSignature(signature)) {
    return { valid: false, reason: 'INVALID_SIGNATURE', detail: 'signature is not the canonical encoding (standard base64, padded, 88 characters, round-trip exact)' };
  }
  if (typeof publicKeyId !== 'string' || !publicKeyId.trim()) {
    return { valid: false, reason: 'INVALID_ARTIFACT', detail: 'publicKeyId must be a non-empty string' };
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { valid: false, reason: 'INVALID_ARTIFACT', detail: 'payload must be a plain object' };
  }

  const now = typeof options._clock === 'function' ? options._clock() : Date.now();

  if (timestamp > now) {
    return { valid: false, reason: 'FUTURE_TIMESTAMP' };
  }
  if (historical) {
    // the artifact must have been valid at its own signing time.
    if (!(expiry > timestamp)) {
      return { valid: false, reason: 'INVALID_ARTIFACT', detail: 'expiry must be after timestamp (artifact was never valid)' };
    }
  } else {
    if (expiry <= now) {
      return { valid: false, reason: 'EXPIRED', detail: 'for archival verification of an expired artifact use --historical' };
    }
    // max age (timeCheck.js checkSkew) — a held artifact is stale whatever its expiry says.
    if (now - timestamp > MAX_ARTIFACT_AGE_MS) {
      return { valid: false, reason: 'TIME_SKEW_EXCEEDED', detail: `artifact older than ${MAX_ARTIFACT_AGE_MS} ms; for archival verification use --historical` };
    }
  }

  // ── Trust material ──────────────────────────────────────────────────────────
  // `options.keysData` (the TRUSTED set) takes precedence and never triggers a network call. Offline
  // without it fails closed — and bundle-carried keys can never stand in for it. Online
  // (neither) fetches `/keys` from the operator-supplied base URL, over https (or localhost http).
  const bundleKeys = options.bundleKeys && Array.isArray(options.bundleKeys.keys) ? options.bundleKeys.keys : null;
  let keysData;
  if (options.keysData) {
    keysData = options.keysData;
  } else if (bundleKeys) {
    return {
      valid:  false,
      reason: 'TRUST_ANCHOR_REQUIRED',
      detail: 'keys embedded in a verification bundle cannot authenticate it; supply the trusted published key set out of band (--key-file / --trusted-keys)',
    };
  } else if (options.offline) {
    return {
      valid:  false,
      reason: 'OFFLINE_TRUST_MATERIAL_MISSING',
      detail: 'Offline mode requires locally-supplied trust material (--key-file / --trusted-keys); no network fallback is attempted.',
    };
  } else {
    if (!isAllowedKeySource(baseUrl)) {
      return { valid: false, reason: 'INSECURE_KEY_SOURCE', detail: 'the key set must be fetched over https:// (plain http:// is allowed only for localhost)' };
    }
    try {
      keysData = await fetchJSON(`${baseUrl}/keys`);
      // the live /keys endpoint wraps its payload in the same
      // { status, timestamp, requestId, data: {...} } envelope every other
      // route in this API uses (confirmed live: GET /keys -> { data: { keys:
      // [...] } }) — not the bare { keys: [...] } shape this function's own
      // offline (--key-file/--bundle) path documents and accepts. Unwrap
      // only when the fetched envelope actually has that nested shape, so a
      // hypothetical future server returning the bare shape directly still
      // works.
      if (keysData && !Array.isArray(keysData.keys) && keysData.data && Array.isArray(keysData.data.keys)) {
        keysData = keysData.data;
      }
    } catch (err) {
      return { valid: false, reason: 'KEYS_FETCH_FAILED', detail: err.message };
    }
  }

  const trustedList = (keysData && Array.isArray(keysData.keys)) ? keysData.keys : [];
  const keyEntry = trustedList.find(k => k && typeof k === 'object' && k.keyId === publicKeyId);
  const candidate = bundleKeys ? bundleKeys.find(k => k && typeof k === 'object' && k.keyId === publicKeyId) : null;
  if (!keyEntry) {
    if (candidate) {
      return { valid: false, reason: 'UNTRUSTED_KEY', detail: `keyId ${publicKeyId} is carried by the bundle but is not in the trusted key set` };
    }
    return { valid: false, reason: 'KEY_NOT_FOUND', detail: `keyId: ${publicKeyId}` };
  }
  if (candidate) {
    const a = _keyBytes(candidate.publicKey);
    const b = _keyBytes(keyEntry.publicKey);
    if (!a || !b || !a.equals(b)) {
      return { valid: false, reason: 'KEY_MISMATCH', detail: `the bundle's key material for ${publicKeyId} differs from the trusted key set` };
    }
  }

  if (!verifySignature(artifact, keyEntry.publicKey)) {
    return { valid: false, reason: 'INVALID_SIGNATURE' };
  }

  // Key lifecycle — from the TRUSTED entry only, after the signature (production order).
  const lifecycle = historical ? _checkKeyHistorical(keyEntry, timestamp) : _checkKeyExecution(keyEntry, timestamp, now);
  if (lifecycle) {
    return { valid: false, reason: lifecycle.reason, detail: `keyId ${publicKeyId}: ${lifecycle.detail}` };
  }

  if (!request || typeof request !== 'object') {
    return { valid: false, reason: 'MISSING_REQUEST' };
  }
  const { method, path, body } = request;
  if (typeof method !== 'string' || !method.trim()) {
    return { valid: false, reason: 'INVALID_REQUEST', detail: 'method must be a non-empty string' };
  }
  if (typeof path !== 'string' || !path) {
    return { valid: false, reason: 'INVALID_REQUEST', detail: 'path must be a non-empty string' };
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { valid: false, reason: 'INVALID_REQUEST', detail: 'body must be a plain object' };
  }

  const expectedHash = computeRequestHash(method, path, body);
  const storedHash   = payload.requestHash;

  if (typeof storedHash !== 'string' || storedHash.length !== 64) {
    return { valid: false, reason: 'INVALID_ARTIFACT', detail: 'payload.requestHash must be a 64-char hex string' };
  }

  const stored   = Buffer.from(storedHash,   'hex');
  const expected = Buffer.from(expectedHash, 'hex');
  if (stored.length !== 32 || expected.length !== 32 || !crypto.timingSafeEqual(stored, expected)) {
    return { valid: false, reason: 'REQUEST_MISMATCH' };
  }

  // ── caller attribution ──────────────────────────────────────────
  // callerContext was embedded in payload at /sign time and is therefore
  // already covered by the envelope signature verified above — no extra
  // crypto step needed, only surfacing what verifySignature() already
  // proved was not tampered with. null means either this artifact predates
  // the remediation (key-attribution only) or payload never had it.
  const callerContext = (payload.callerContext && typeof payload.callerContext === 'object')
    ? payload.callerContext
    : null;

  const result = {
    valid:  true,
    reason: 'PASS',
    mode,
    callerContext,
    attribution: callerContext
      ? 'CALLER_BOUND — non-repudiation proves which authenticated caller (callerContext.callerId) requested this signature, not merely which key produced it'
      : 'KEY_ONLY — this artifact carries no caller binding; non-repudiation proves only which signing key (publicKeyId) produced it',
  };
  if (historical) {
    result.note = 'HISTORICAL — the artifact was validly signed by a trusted key that was valid at the artifact\'s own signing time; this does NOT mean it may be executed now';
  }
  return result;
}

// ── Verification bundle ──────────────────────────────────────────────
// A bundle { artifact, request, keys? } is a convenient archive, but it is supplied by whoever hands
// it over, so its `keys` can never authenticate it. trustedKeys (the published key set obtained out
// of band) is REQUIRED; bundle keys are only candidates that must match it byte-for-byte.

async function verifyBundle(bundle, options = {}) {
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle) || !bundle.artifact || !bundle.request) {
    return { valid: false, reason: 'MALFORMED_BUNDLE', detail: 'verification bundle must be a JSON object with "artifact" and "request" (and optionally "keys")' };
  }
  let bundleKeys = null;
  if (bundle.keys !== undefined) {
    try { bundleKeys = _normalizeKeysData(bundle.keys, 'Verification bundle'); }
    catch (err) { return { valid: false, reason: 'MALFORMED_BUNDLE', detail: err.message }; }
  }
  if (!options.trustedKeys) {
    return {
      valid:  false,
      reason: 'TRUST_ANCHOR_REQUIRED',
      detail: 'keys embedded in a verification bundle cannot authenticate it; supply the trusted published key set out of band (--key-file / --trusted-keys)',
    };
  }
  let trusted;
  try { trusted = _normalizeKeysData(options.trustedKeys, 'Trusted key set'); }
  catch (err) { return { valid: false, reason: 'TRUST_ANCHOR_REQUIRED', detail: err.message }; }
  return verify(null, bundle.artifact, bundle.request, {
    offline: true, keysData: trusted, bundleKeys: bundleKeys || { keys: [] },
    historical: options.historical === true, _clock: options._clock,
  });
}

// ── CLI argument parsing ───────────────────────────
// Recognizes --offline, --key-file <path> (alias --trusted-keys <path>, also
// with =), --bundle <path>/--bundle=<path> and --historical anywhere in argv;
// everything else is collected as positional args, in order. An invocation
// with no flags collects the exact same three positionals the original CLI
// always has, so the pre-VERIFY-4 online syntax is untouched.

function _parseArgs(argv) {
  const flags = { offline: false, keyFile: null, bundle: null, historical: false };
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--offline') { flags.offline = true; continue; }
    if (a === '--historical') { flags.historical = true; continue; }
    if (a === '--key-file' || a === '--trusted-keys') { flags.keyFile = argv[++i]; continue; }
    if (a === '--bundle') { flags.bundle = argv[++i]; continue; }
    if (a.startsWith('--key-file=')) { flags.keyFile = a.slice('--key-file='.length); continue; }
    if (a.startsWith('--trusted-keys=')) { flags.keyFile = a.slice('--trusted-keys='.length); continue; }
    if (a.startsWith('--bundle=')) { flags.bundle = a.slice('--bundle='.length); continue; }
    positional.push(a);
  }
  return { flags, positional };
}

// ── CLI entry point ───────────────────────────────────────────────────────────

if (require.main === module) {
  const USAGE =
    'Usage:\n' +
    '  Online:  node tools/verify/verify.external.js [--historical] <https_base_url> <artifact_json> <request_json>\n' +
    '  Offline (trusted key file): node tools/verify/verify.external.js --offline [--historical] --key-file <keys.json> <artifact_json> <request_json>\n' +
    '  Offline (bundle):           node tools/verify/verify.external.js --offline [--historical] --key-file <keys.json> --bundle <bundle.json>\n' +
    '  <keys.json> is the published key set (GET /.well-known/qodiqa/keys) obtained out of band; keys inside a\n' +
    '  bundle are never trusted on their own. --historical verifies an expired artifact as of its own signing time.\n';

  const { flags, positional } = _parseArgs(process.argv.slice(2));
  if (flags.bundle) flags.offline = true;

  let baseUrl = null;
  let artifact, request, keysData, bundle = null;

  if (flags.offline) {
    if (!flags.keyFile) {
      if (flags.bundle) {
        process.stderr.write(`Error: TRUST_ANCHOR_REQUIRED — keys embedded in a verification bundle cannot authenticate it; pass the trusted published key set with --key-file <keys.json>\n\n${USAGE}`);
      } else {
        process.stderr.write(`Error: OFFLINE_MISSING_TRUST_MATERIAL — --offline requires --key-file <path>\n\n${USAGE}`);
      }
      process.exit(1);
    }
    try { keysData = loadKeysFromFile(flags.keyFile); }
    catch (err) { process.stderr.write(`Error: KEY_BUNDLE_UNAVAILABLE — ${err.message}\n`); process.exit(1); }

    if (flags.bundle) {
      if (positional.length !== 0) {
        process.stderr.write('Error: --bundle already supplies artifact and request; do not also pass them positionally\n');
        process.exit(1);
      }
      try { bundle = _readJSONFile(flags.bundle, 'Verification bundle'); }
      catch (err) { process.stderr.write(`Error: TRUST_BUNDLE_NOT_FOUND — ${err.message}\n`); process.exit(1); }
    } else {
      if (positional.length !== 2) {
        process.stderr.write(`Error: --offline --key-file requires <artifact_json> <request_json>\n\n${USAGE}`);
        process.exit(1);
      }
      const [artifactArg, requestArg] = positional;
      try { artifact = JSON.parse(artifactArg); }
      catch { process.stderr.write('Error: artifact_json is not valid JSON\n'); process.exit(1); }
      try { request = JSON.parse(requestArg); }
      catch { process.stderr.write('Error: request_json is not valid JSON\n'); process.exit(1); }
    }
  } else {
    // Online path: identical positional contract to pre-VERIFY-4.
    if (positional.length !== 3) {
      process.stderr.write(USAGE);
      process.exit(1);
    }
    const [baseUrlArg, artifactArg, requestArg] = positional;
    baseUrl = baseUrlArg;
    try { artifact = JSON.parse(artifactArg); }
    catch { process.stderr.write('Error: artifact_json is not valid JSON\n'); process.exit(1); }
    try { request = JSON.parse(requestArg); }
    catch { process.stderr.write('Error: request_json is not valid JSON\n'); process.exit(1); }
  }

  const run = bundle
    ? verifyBundle(bundle, { trustedKeys: keysData, historical: flags.historical })
    : verify(baseUrl, artifact, request, flags.offline
      ? { offline: true, keysData, historical: flags.historical }
      : { historical: flags.historical });

  run.then(result => {
    process.stdout.write(JSON.stringify(result) + '\n');
    process.exit(result.valid ? 0 : 1);
  }).catch(err => {
    process.stderr.write(`Error: ${err.message}\n`);
    process.exit(2);
  });
}

module.exports = { verify, verifyBundle, stableStringify, computeRequestHash, loadKeysFromFile, isCanonicalSignature };
