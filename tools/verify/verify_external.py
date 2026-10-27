#!/usr/bin/env python3
"""
QODIQA External Verifier — Python
Verifies execution artifacts without access to internal system modules.

Usage:
    python tools/verify/verify_external.py [--historical] <https_base_url> <artifact_json> <request_json>
    python tools/verify/verify_external.py --offline [--historical] --key-file <keys.json> <artifact_json> <request_json>
    python tools/verify/verify_external.py --offline [--historical] --key-file <keys.json> --bundle <bundle.json>

<keys.json> is the published key set (GET /.well-known/qodiqa/keys) obtained out of band. Keys
carried inside a bundle are never a trust anchor. --historical verifies an expired
artifact as of its own signing time, against the key's validity window at that time.

Example:
    python tools/verify/verify_external.py http://localhost:3000 '{"payload":...}' '{"method":"POST","path":"/ai/chat","body":{}}'
"""

import hashlib
import base64
import calendar
import json
import math
import re
import sys
import time
import urllib.request
import urllib.error
from urllib.parse import urlsplit


# ── Canonical serialization (mirrors services/utils/stableStringify.js exactly) ──

# CONFORMANT with the server's canonicalizer (src/utils/stableStringify.js,
# docs/protocol/QODIQA-PROTOCOL.md §3), so the JavaScript and Python verifiers can never disagree:
#   strings  escaped exactly like JavaScript JSON.stringify (\b \f \n \r \t, other C0 controls as \u00xx, lone
#            surrogates as \udxxx, everything else literal)
#   numbers  formatted like JavaScript Number#toString (1.0 -> 1, 1e-7 -> 1e-7, 1e16 -> 10000000000000000)
#   keys     sorted by UTF-16 code units (JavaScript's default sort), not by code point
#   refusals non-finite numbers, unsupported types and the keys __proto__ / constructor / prototype
# test/externalVerifierCanonicalConformance.test.js holds this copy to the server output.
_FORBIDDEN_KEYS = {'__proto__', 'constructor', 'prototype'}
_SHORT_ESCAPES = {'"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t'}


def _encode_string(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[ch])
        elif o < 0x20 or 0xD800 <= o <= 0xDFFF:
            out.append('\\u%04x' % o)
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def _js_number(x):
    import math
    if isinstance(x, bool):
        raise ValueError('UNSUPPORTED_TYPE')
    if isinstance(x, int):
        x = float(x) if abs(x) > 2 ** 53 else x
        if isinstance(x, int):
            return str(x)
    if math.isnan(x) or math.isinf(x):
        raise ValueError('NON_FINITE_NUMBER')
    if x == 0:
        return '0'
    sign = '-' if x < 0 else ''
    r = repr(abs(x))  # shortest round-trip digits, as ECMAScript requires
    if 'e' in r:
        mant, exp = r.split('e')
        exp = int(exp)
    else:
        mant, exp = r, 0
    if '.' in mant:
        ip, fp = mant.split('.')
    else:
        ip, fp = mant, ''
    digits = (ip + fp).lstrip('0')
    n = len(ip.lstrip('0')) + exp if ip.strip('0') else exp - (len(fp) - len(fp.lstrip('0')))
    digits = digits.rstrip('0') or '0'
    k = len(digits)
    if k <= n <= 21:
        s = digits + '0' * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + '.' + digits[n:]
    elif -6 < n <= 0:
        s = '0.' + '0' * (-n) + digits
    else:
        e = n - 1
        s = digits[0] + ('.' + digits[1:] if k > 1 else '') + 'e' + ('+' if e >= 0 else '-') + str(abs(e))
    return sign + s


def _utf16_key(k):
    return k.encode('utf-16-be', 'surrogatepass')


def stable_stringify(value):
    if value is None:
        return 'null'
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (int, float)):
        return _js_number(value)
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, list):
        return '[' + ','.join(stable_stringify(v) for v in value) + ']'
    if isinstance(value, dict):
        for k in value:
            if k in _FORBIDDEN_KEYS:
                raise ValueError('FORBIDDEN_KEY')
        items = sorted(value.items(), key=lambda x: _utf16_key(x[0]))
        return '{' + ','.join(_encode_string(k) + ':' + stable_stringify(v) for k, v in items) + '}'
    raise ValueError('UNSUPPORTED_TYPE')


# ── Domain-separated hash (mirrors src/infra/crypto/hashing.js) ──────────────

def domain_separated_hash(domain, canonical):
    h = hashlib.sha256()
    h.update(domain.encode('utf-8'))
    h.update(canonical.encode('utf-8'))
    return h.digest()


# ── Envelope hash (mirrors src/validation/canonicalize.js envelopeHash) ──────

def envelope_hash(artifact):
    envelope = {
        'expiry':      artifact['expiry'],
        'payload':     artifact['payload'],
        'publicKeyId': artifact['publicKeyId'],
        'timestamp':   artifact['timestamp'],
    }
    canonical = stable_stringify(envelope)
    return domain_separated_hash('QODIQA::ARTIFACT::V1', canonical)


# ── Request hash (mirrors src/validation/requestHash.js) ─────────────────────

def compute_request_hash(method, path, body):
    canonical = stable_stringify({'body': body, 'method': method.upper(), 'path': path})
    return domain_separated_hash('QODIQA::REQUEST::V1', canonical).hex()


# ── Production-equivalent strictness ───────────────────────
# Mirrors src/validation/validateArtifact.js + keyLifecycle.js + timeCheck.js, identically to
# tools/verify/verify.external.js:
#   * the envelope is EXACTLY these five fields - an unknown field is INVALID_ARTIFACT;
#   * the signature has ONE accepted spelling: padded standard base64 of 64 bytes (88 chars),
#     round-trip exact - any other spelling is INVALID_SIGNATURE;
#   * max age: an artifact older than MAX_ARTIFACT_AGE_MS is TIME_SKEW_EXCEEDED whatever its expiry;
#   * key lifecycle: revoked/compromised and archived keys never verify a current artifact; a
#     deprecated key verifies only an artifact signed BEFORE its retirement and only until
#     deprecatedAt + 65 s; a deprecated key with no known retirement time is refused.

ARTIFACT_FIELDS = ('expiry', 'payload', 'publicKeyId', 'signature', 'timestamp')
_CANONICAL_SIG_RE = re.compile(r'\A[A-Za-z0-9+/]{86}==\Z')
MAX_ARTIFACT_AGE_MS = 60_000
FUTURE_SKEW_MS = 5_000
DEPRECATED_WINDOW_MS = MAX_ARTIFACT_AGE_MS + FUTURE_SKEW_MS
_REVOKED_STATUSES = {'revoked', 'compromised'}
_ISO_RE = re.compile(r'\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?(Z|[+-]\d{2}:\d{2})\Z')

_TRUST_ANCHOR_DETAIL = (
    'keys embedded in a verification bundle cannot authenticate it; supply the trusted published '
    'key set out of band (--key-file / --trusted-keys)'
)


def is_canonical_signature(s):
    if not isinstance(s, str) or not _CANONICAL_SIG_RE.match(s):
        return False
    try:
        return base64.b64encode(base64.b64decode(s, validate=True)).decode('ascii') == s
    except Exception:
        return False


def _is_number(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


def _time_ms(v):
    """Strict lifecycle time: ISO-8601 with an explicit zone (Z or +-hh:mm), or positive Unix ms. Else None."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return v if (math.isfinite(v) and v > 0) else None
    if not isinstance(v, str):
        return None
    m = _ISO_RE.match(v)
    if not m:
        return None
    y, mo, d, h, mi, s = (int(g) for g in m.groups()[:6])
    if mo < 1 or mo > 12 or d < 1 or d > 31 or h > 23 or mi > 59 or s > 59:
        return None
    frac = int(m.group(7).ljust(3, '0')) if m.group(7) else 0
    off = 0
    tz = m.group(8)
    if tz != 'Z':
        sign = -1 if tz[0] == '-' else 1
        off = sign * (int(tz[1:3]) * 60 + int(tz[4:6])) * 60_000
    try:
        return calendar.timegm((y, mo, 1, h, mi, s, 0, 0, 0)) * 1000 + (d - 1) * 86_400_000 + frac - off
    except (ValueError, OverflowError):
        return None


def _status_of(entry):
    st = entry.get('status')
    return st.lower() if isinstance(st, str) else None


def _check_key_execution(entry, ts_ms, now_ms):
    """keyLifecycle.checkExecution - may this key verify an artifact asking to be honoured NOW?"""
    status = _status_of(entry)
    if status in _REVOKED_STATUSES:
        return ('KEY_REVOKED', f'key status: {status}')
    if status == 'archived':
        return ('KEY_ARCHIVED', 'an archived key never verifies a current artifact (use --historical for archival verification)')
    if status == 'deprecated':
        dep = _time_ms(entry.get('deprecatedAt'))
        if dep is None:
            return ('KEY_DEPRECATED', 'retirement time unknown (trusted key entry has no deprecatedAt)')
        if ts_ms >= dep:
            return ('KEY_DEPRECATED', 'signed after the key was retired')
        if now_ms >= dep + DEPRECATED_WINDOW_MS:
            return ('KEY_DEPRECATED', 'deprecated-key window elapsed')
        return None
    if status == 'active':
        act = _time_ms(entry.get('activatedAt'))
        if act is not None and ts_ms < act - FUTURE_SKEW_MS:
            return ('KEY_NOT_YET_ACTIVE', 'signed before the key was activated')
        return None
    return ('KEY_STATUS_UNKNOWN', f"key status: {'missing' if status is None else status}")


def _check_key_historical(entry, signed_at_ms):
    """keyLifecycle.checkHistorical - was this key valid at the artifact's own signing time?"""
    status = _status_of(entry)
    if status in _REVOKED_STATUSES:
        return ('KEY_REVOKED', f'key status: {status} (compromise invalidates everything it signed)')
    if status not in ('active', 'deprecated', 'archived'):
        return ('KEY_STATUS_UNKNOWN', f"key status: {'missing' if status is None else status}")
    act = _time_ms(entry.get('activatedAt'))
    if act is not None and signed_at_ms < act - FUTURE_SKEW_MS:
        return ('KEY_NOT_ACTIVE_AT_SIGNING_TIME', 'signed before the key existed')
    dep = _time_ms(entry.get('deprecatedAt'))
    end = dep if dep is not None else _time_ms(entry.get('archivedAt'))
    if status != 'active' and end is None:
        return ('KEY_NOT_ACTIVE_AT_SIGNING_TIME', 'retirement time unknown (trusted key entry has no deprecatedAt/archivedAt)')
    if end is not None and signed_at_ms >= end:
        return ('KEY_NOT_ACTIVE_AT_SIGNING_TIME', 'signed after the key was retired')
    return None


def _key_bytes(b64):
    if not isinstance(b64, str) or not b64:
        return None
    try:
        return base64.b64decode(b64)
    except Exception:
        return None


def is_allowed_key_source(base_url):
    """https:// required for the online key set; plain http:// only for localhost."""
    try:
        u = urlsplit(str(base_url))
        host = u.hostname
    except Exception:
        return False
    if u.scheme == 'https':
        return bool(host)
    if u.scheme != 'http':
        return False
    return host in ('localhost', '127.0.0.1', '::1')


# ── Ed25519 signature verification ────────────────────────────────────────────

class CryptoBackendUnavailable(Exception):
    """Neither `cryptography` nor `pynacl` is importable.

    Before this, that case returned False and a GENUINE artifact was reported as INVALID_SIGNATURE,
    i.e. a missing library was presented to an auditor as a forgery. It is now its own verdict.
    """


def verify_signature(artifact, public_key_b64):
    if not is_canonical_signature(artifact.get('signature')):
        return False
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature

        pub_der  = base64.b64decode(public_key_b64)
        pub_key  = load_der_public_key(pub_der)
        if not isinstance(pub_key, Ed25519PublicKey):
            return False
        digest   = envelope_hash(artifact)
        sig      = base64.b64decode(artifact['signature'])
        if len(sig) != 64:
            return False
        pub_key.verify(sig, digest)
        return True
    except ImportError:
        return _verify_signature_pynacl(artifact, public_key_b64)
    except Exception:
        return False


def _verify_signature_pynacl(artifact, public_key_b64):
    try:
        import nacl.signing
        import nacl.exceptions

        pub_der = base64.b64decode(public_key_b64)
        raw_key = pub_der[-32:]
        vk      = nacl.signing.VerifyKey(raw_key)
        digest  = envelope_hash(artifact)
        sig     = base64.b64decode(artifact['signature'])
        vk.verify(digest, sig)
        return True
    except ImportError:
        raise CryptoBackendUnavailable()
    except Exception:
        return False


# ── HTTP fetch ────────────────────────────────────────────────────────────────

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # never follow a redirect for the trust-anchor fetch (an https -> http downgrade, or a
    # hop to another host, would bypass is_allowed_key_source). tools/verify/verify.external.js's http.get
    # likewise does not follow redirects.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_json(url):
    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(url, timeout=10) as resp:
        return json.loads(resp.read().decode('utf-8'))


# ── Offline trust material ─────────────────────────────────────────
# Loads a locally-supplied key list instead of fetching `/keys` over the
# network. Accepts the exact same shape the server returns from `/keys` or
# `/.well-known/qodiqa/keys` (`{"keys": [...]}`), or a bare `[...]` array.

def _read_json_file(path, label):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            raw = f.read()
    except FileNotFoundError:
        raise ValueError(f'{label} not found: {path}')
    except OSError as e:
        raise ValueError(f'Failed to read {label} ({path}): {e}')
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f'{label} is not valid JSON ({path}): {e}')


def _normalize_keys_data(data, label):
    if isinstance(data, list):
        return {'keys': data}
    if isinstance(data, dict) and isinstance(data.get('keys'), list):
        return data
    raise ValueError(
        f'{label} does not contain a "keys" array - expected the same shape '
        f'as GET /keys or /.well-known/qodiqa/keys'
    )


def load_keys_from_file(path):
    return _normalize_keys_data(_read_json_file(path, 'Key file'), 'Key file')


# ── Timing-safe bytes comparison ──────────────────────────────────────────────

def _timing_safe_equal(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


# ── Main verification logic ───────────────────────────────────────────────────
#
# keys_data    {"keys": [...]} - the TRUSTED key set (--key-file / --trusted-keys, obtained out of
#              band). It is the only key material that can authenticate an artifact offline.
# bundle_keys {"keys": [...]} - keys a verification bundle carries. CANDIDATES only, never a
#              trust anchor: a candidate must match the trusted entry for the same keyId byte-for-byte,
#              and the trusted entry (never the bundle's) supplies status/timeline.
# historical archival mode: skip the "now" expiry/max-age checks; require instead that the
#              artifact was valid at its own signing time and that the trusted key was valid at that
#              signing time. It never says the artifact may run now.
# _clock       deterministic-test escape hatch only.

def verify(base_url, artifact, request, *, offline=False, keys_data=None, bundle_keys=None,
           historical=False, _clock=None):
    mode = 'HISTORICAL' if historical else 'CURRENT'

    if not artifact or not isinstance(artifact, dict):
        return {'valid': False, 'reason': 'MISSING_ARTIFACT'}

    # strict schema - exactly the five envelope fields (validateArtifact.js step 2).
    for key in artifact:
        if key not in ARTIFACT_FIELDS:
            return {'valid': False, 'reason': 'INVALID_ARTIFACT', 'detail': f'unknown field: {key}'}

    for field in ARTIFACT_FIELDS:
        if field not in artifact or artifact[field] is None:
            return {'valid': False, 'reason': 'INVALID_ARTIFACT', 'detail': f'missing field: {field}'}

    timestamp    = artifact['timestamp']
    expiry       = artifact['expiry']
    public_key_id = artifact['publicKeyId']
    signature    = artifact['signature']
    payload      = artifact['payload']

    if not _is_number(timestamp) or timestamp <= 0:
        return {'valid': False, 'reason': 'INVALID_ARTIFACT', 'detail': 'timestamp must be a positive finite number'}
    if not _is_number(expiry) or expiry <= 0:
        return {'valid': False, 'reason': 'INVALID_ARTIFACT', 'detail': 'expiry must be a positive finite number'}
    if not isinstance(signature, str):
        return {'valid': False, 'reason': 'INVALID_ARTIFACT', 'detail': 'signature must be a string'}
    # one canonical signature spelling (validateArtifact.js step 9).
    if not is_canonical_signature(signature):
        return {'valid': False, 'reason': 'INVALID_SIGNATURE',
                'detail': 'signature is not the canonical encoding (standard base64, padded, 88 characters, round-trip exact)'}
    if not isinstance(public_key_id, str) or not public_key_id.strip():
        return {'valid': False, 'reason': 'INVALID_ARTIFACT', 'detail': 'publicKeyId must be a non-empty string'}
    if not isinstance(payload, dict):
        return {'valid': False, 'reason': 'INVALID_ARTIFACT', 'detail': 'payload must be a plain object'}

    now_ms = _clock() if callable(_clock) else time.time() * 1000

    if timestamp > now_ms:
        return {'valid': False, 'reason': 'FUTURE_TIMESTAMP'}
    if historical:
        # the artifact must have been valid at its own signing time.
        if not expiry > timestamp:
            return {'valid': False, 'reason': 'INVALID_ARTIFACT',
                    'detail': 'expiry must be after timestamp (artifact was never valid)'}
    else:
        if expiry <= now_ms:
            return {'valid': False, 'reason': 'EXPIRED',
                    'detail': 'for archival verification of an expired artifact use --historical'}
        # max age (timeCheck.js checkSkew) - a held artifact is stale whatever its expiry says.
        if now_ms - timestamp > MAX_ARTIFACT_AGE_MS:
            return {'valid': False, 'reason': 'TIME_SKEW_EXCEEDED',
                    'detail': f'artifact older than {MAX_ARTIFACT_AGE_MS} ms; for archival verification use --historical'}

    # ── Trust material ─────────────────────────────────────────────────────────
    # `keys_data` (the TRUSTED set) takes precedence and never triggers a network call. Offline
    # without it fails closed - and bundle-carried keys can never stand in for it. Online
    # (neither) fetches `/keys` from the operator-supplied base URL, over https (or localhost http).
    b_keys = bundle_keys.get('keys') if isinstance(bundle_keys, dict) and isinstance(bundle_keys.get('keys'), list) else None
    if keys_data is not None:
        resolved_keys = keys_data
    elif b_keys is not None:
        return {'valid': False, 'reason': 'TRUST_ANCHOR_REQUIRED', 'detail': _TRUST_ANCHOR_DETAIL}
    elif offline:
        return {
            'valid': False,
            'reason': 'OFFLINE_TRUST_MATERIAL_MISSING',
            'detail': 'Offline mode requires locally-supplied trust material (--key-file / --trusted-keys); no network fallback is attempted.',
        }
    else:
        if not is_allowed_key_source(base_url):
            return {'valid': False, 'reason': 'INSECURE_KEY_SOURCE',
                    'detail': 'the key set must be fetched over https:// (plain http:// is allowed only for localhost)'}
        try:
            resolved_keys = fetch_json(f'{base_url}/keys')
            # the live /keys endpoint wraps its payload in the same
            # {status, timestamp, requestId, data: {...}} envelope every
            # other route in this API uses (confirmed live: GET /keys ->
            # {"data": {"keys": [...]}} ) -- not the bare {"keys": [...]}
            # shape this function's own offline (--key-file/--bundle) path
            # documents and accepts. Unwrap only when the fetched envelope
            # actually has that nested shape, so a hypothetical future
            # server returning the bare shape directly still works.
            if (
                isinstance(resolved_keys, dict)
                and 'keys' not in resolved_keys
                and isinstance(resolved_keys.get('data'), dict)
                and 'keys' in resolved_keys['data']
            ):
                resolved_keys = resolved_keys['data']
        except Exception as e:
            return {'valid': False, 'reason': 'KEYS_FETCH_FAILED', 'detail': str(e)}

    trusted_list = resolved_keys.get('keys') if isinstance(resolved_keys, dict) else None
    if not isinstance(trusted_list, list):
        trusted_list = []
    key_entry = next((k for k in trusted_list if isinstance(k, dict) and k.get('keyId') == public_key_id), None)
    candidate = next((k for k in b_keys if isinstance(k, dict) and k.get('keyId') == public_key_id), None) if b_keys else None
    if key_entry is None:
        if candidate is not None:
            return {'valid': False, 'reason': 'UNTRUSTED_KEY',
                    'detail': f'keyId {public_key_id} is carried by the bundle but is not in the trusted key set'}
        return {'valid': False, 'reason': 'KEY_NOT_FOUND', 'detail': f'keyId: {public_key_id}'}
    if candidate is not None:
        a = _key_bytes(candidate.get('publicKey'))
        b = _key_bytes(key_entry.get('publicKey'))
        if not a or not b or a != b:
            return {'valid': False, 'reason': 'KEY_MISMATCH',
                    'detail': f"the bundle's key material for {public_key_id} differs from the trusted key set"}

    try:
        signature_ok = verify_signature(artifact, key_entry.get('publicKey'))
    except CryptoBackendUnavailable:
        return {'valid': False, 'reason': 'CRYPTO_BACKEND_UNAVAILABLE',
                'detail': 'no Ed25519 implementation: install `cryptography` (or `pynacl`) and re-run; '
                          'the signature was NOT checked and this is not evidence of tampering'}
    if not signature_ok:
        return {'valid': False, 'reason': 'INVALID_SIGNATURE'}

    # Key lifecycle - from the TRUSTED entry only, after the signature (production order).
    lifecycle = _check_key_historical(key_entry, timestamp) if historical else _check_key_execution(key_entry, timestamp, now_ms)
    if lifecycle:
        return {'valid': False, 'reason': lifecycle[0], 'detail': f'keyId {public_key_id}: {lifecycle[1]}'}

    if not request or not isinstance(request, dict):
        return {'valid': False, 'reason': 'MISSING_REQUEST'}

    method = request.get('method')
    path   = request.get('path')
    body   = request.get('body')

    if not isinstance(method, str) or not method.strip():
        return {'valid': False, 'reason': 'INVALID_REQUEST', 'detail': 'method must be a non-empty string'}
    if not isinstance(path, str) or not path:
        return {'valid': False, 'reason': 'INVALID_REQUEST', 'detail': 'path must be a non-empty string'}
    if not isinstance(body, dict):
        return {'valid': False, 'reason': 'INVALID_REQUEST', 'detail': 'body must be a plain object'}

    expected_hash = compute_request_hash(method, path, body)
    stored_hash   = payload.get('requestHash')

    if not isinstance(stored_hash, str) or len(stored_hash) != 64:
        return {'valid': False, 'reason': 'INVALID_ARTIFACT', 'detail': 'payload.requestHash must be a 64-char hex string'}

    try:
        stored_bytes   = bytes.fromhex(stored_hash)
        expected_bytes = bytes.fromhex(expected_hash)
    except ValueError:
        return {'valid': False, 'reason': 'REQUEST_MISMATCH'}

    if not _timing_safe_equal(stored_bytes, expected_bytes):
        return {'valid': False, 'reason': 'REQUEST_MISMATCH'}

    # ── caller attribution ──────────────────────────────────────────
    # callerContext was embedded in payload at /sign time and is therefore
    # already covered by the envelope signature verified above — no extra
    # crypto step needed, only surfacing what verify_signature() already
    # proved was not tampered with. None means either this artifact predates
    # the remediation (key-attribution only) or payload never had it.
    caller_context = payload.get('callerContext')
    if not isinstance(caller_context, dict):
        caller_context = None

    attribution = (
        'CALLER_BOUND — non-repudiation proves which authenticated caller '
        '(callerContext.callerId) requested this signature, not merely which key produced it'
        if caller_context else
        'KEY_ONLY — this artifact carries no caller binding; non-repudiation '
        'proves only which signing key (publicKeyId) produced it'
    )

    result = {
        'valid': True,
        'reason': 'PASS',
        'mode': mode,
        'callerContext': caller_context,
        'attribution': attribution,
    }
    if historical:
        result['note'] = ("HISTORICAL — the artifact was validly signed by a trusted key that was valid at the "
                          "artifact's own signing time; this does NOT mean it may be executed now")
    return result


# ── Verification bundle ──────────────────────────────────────────────
# A bundle {artifact, request, keys?} is a convenient archive, but it is supplied by whoever hands it
# over, so its `keys` can never authenticate it. trusted_keys (the published key set obtained out of
# band) is REQUIRED; bundle keys are only candidates that must match it byte-for-byte.

def verify_bundle(bundle, *, trusted_keys=None, historical=False, _clock=None):
    if not isinstance(bundle, dict) or not bundle.get('artifact') or not bundle.get('request'):
        return {'valid': False, 'reason': 'MALFORMED_BUNDLE',
                'detail': 'verification bundle must be a JSON object with "artifact" and "request" (and optionally "keys")'}
    bundle_keys = None
    if 'keys' in bundle:
        try:
            bundle_keys = _normalize_keys_data(bundle['keys'], 'Verification bundle')
        except ValueError as e:
            return {'valid': False, 'reason': 'MALFORMED_BUNDLE', 'detail': str(e)}
    if not trusted_keys:
        return {'valid': False, 'reason': 'TRUST_ANCHOR_REQUIRED', 'detail': _TRUST_ANCHOR_DETAIL}
    try:
        trusted = _normalize_keys_data(trusted_keys, 'Trusted key set')
    except ValueError as e:
        return {'valid': False, 'reason': 'TRUST_ANCHOR_REQUIRED', 'detail': str(e)}
    return verify(None, bundle['artifact'], bundle['request'], offline=True, keys_data=trusted,
                  bundle_keys=bundle_keys or {'keys': []}, historical=historical, _clock=_clock)


# ── CLI argument parsing ───────────────────────────
# Recognizes --offline, --key-file <path> (alias --trusted-keys <path>, also
# with =), --bundle <path>/--bundle=<path> and --historical anywhere in argv;
# everything else is collected as positional args, in order. An invocation
# with no flags collects the exact same three positionals the original CLI
# always has, so the pre-VERIFY-4 online syntax is untouched.

def _parse_cli_args(argv):
    flags = {'offline': False, 'key_file': None, 'bundle': None, 'historical': False}
    positional = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == '--offline':
            flags['offline'] = True
        elif a == '--historical':
            flags['historical'] = True
        elif a in ('--key-file', '--trusted-keys'):
            i += 1
            flags['key_file'] = argv[i] if i < len(argv) else None
        elif a == '--bundle':
            i += 1
            flags['bundle'] = argv[i] if i < len(argv) else None
        elif a.startswith('--key-file='):
            flags['key_file'] = a.split('=', 1)[1]
        elif a.startswith('--trusted-keys='):
            flags['key_file'] = a.split('=', 1)[1]
        elif a.startswith('--bundle='):
            flags['bundle'] = a.split('=', 1)[1]
        else:
            positional.append(a)
        i += 1
    return flags, positional


# ── CLI entry point ───────────────────────────────────────────────────────────

if __name__ == '__main__':
    USAGE = (
        'Usage:\n'
        '  Online:  python tools/verify/verify_external.py [--historical] <https_base_url> <artifact_json> <request_json>\n'
        '  Offline (trusted key file): python tools/verify/verify_external.py --offline [--historical] --key-file <keys.json> <artifact_json> <request_json>\n'
        '  Offline (bundle):           python tools/verify/verify_external.py --offline [--historical] --key-file <keys.json> --bundle <bundle.json>\n'
        '  <keys.json> is the published key set (GET /.well-known/qodiqa/keys) obtained out of band; keys inside a\n'
        '  bundle are never trusted on their own. --historical verifies an expired artifact as of its own signing time.\n'
    )

    cli_flags, cli_positional = _parse_cli_args(sys.argv[1:])
    if cli_flags['bundle']:
        cli_flags['offline'] = True

    base_url = None
    keys_data = None
    bundle = None
    artifact_obj = request_obj = None

    if cli_flags['offline']:
        if not cli_flags['key_file']:
            if cli_flags['bundle']:
                sys.stderr.write(
                    'Error: TRUST_ANCHOR_REQUIRED - keys embedded in a verification bundle cannot authenticate it; '
                    f'pass the trusted published key set with --key-file <keys.json>\n\n{USAGE}'
                )
            else:
                sys.stderr.write(f'Error: OFFLINE_MISSING_TRUST_MATERIAL - --offline requires --key-file <path>\n\n{USAGE}')
            sys.exit(1)
        try:
            keys_data = load_keys_from_file(cli_flags['key_file'])
        except ValueError as e:
            sys.stderr.write(f'Error: KEY_BUNDLE_UNAVAILABLE - {e}\n')
            sys.exit(1)

        if cli_flags['bundle']:
            if cli_positional:
                sys.stderr.write('Error: --bundle already supplies artifact and request; do not also pass them positionally\n')
                sys.exit(1)
            try:
                bundle = _read_json_file(cli_flags['bundle'], 'Verification bundle')
            except ValueError as e:
                sys.stderr.write(f'Error: TRUST_BUNDLE_NOT_FOUND - {e}\n')
                sys.exit(1)
        else:
            if len(cli_positional) != 2:
                sys.stderr.write(f"Error: --offline --key-file requires <artifact_json> <request_json>\n\n{USAGE}")
                sys.exit(1)
            artifact_arg, request_arg = cli_positional
            try:
                artifact_obj = json.loads(artifact_arg)
            except json.JSONDecodeError as e:
                sys.stderr.write(f'Error: artifact_json is not valid JSON: {e}\n')
                sys.exit(1)
            try:
                request_obj = json.loads(request_arg)
            except json.JSONDecodeError as e:
                sys.stderr.write(f'Error: request_json is not valid JSON: {e}\n')
                sys.exit(1)
    else:
        # Online path: identical positional contract to pre-VERIFY-4.
        if len(cli_positional) != 3:
            sys.stderr.write(USAGE)
            sys.exit(1)

        base_url, artifact_arg, request_arg = cli_positional

        try:
            artifact_obj = json.loads(artifact_arg)
        except json.JSONDecodeError as e:
            sys.stderr.write(f'Error: artifact_json is not valid JSON: {e}\n')
            sys.exit(1)

        try:
            request_obj = json.loads(request_arg)
        except json.JSONDecodeError as e:
            sys.stderr.write(f'Error: request_json is not valid JSON: {e}\n')
            sys.exit(1)

    if bundle is not None:
        result = verify_bundle(bundle, trusted_keys=keys_data, historical=cli_flags['historical'])
    else:
        result = verify(base_url, artifact_obj, request_obj, offline=cli_flags['offline'],
                        keys_data=keys_data, historical=cli_flags['historical'])
    sys.stdout.write(json.dumps(result) + '\n')
    # 2 = the verifier could not decide (missing crypto backend), distinct from 1 = invalid.
    sys.exit(0 if result['valid'] else (2 if result.get('reason') == 'CRYPTO_BACKEND_UNAVAILABLE' else 1))
