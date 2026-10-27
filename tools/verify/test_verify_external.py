"""Tests for the standalone external verifier's offline mode, its bundle
trust model, production-equivalent strictness and --historical
archival mode.

Covers the same contract as verify.external.test.js:
  - the online path is unchanged (still fetches /keys over HTTP by default);
  - offline verification succeeds using only locally-supplied trust
    material, with zero network calls;
  - offline verification fails closed when trust material is missing;
  - load_keys_from_file() accepts both shapes and fails clearly otherwise;
  - the CLI itself, exercised as a real subprocess, for both the new flag
    syntax and the untouched legacy positional syntax.

Run with pytest (if available) or plain unittest:
    python -m unittest tools/verify/test_verify_external.py
    python -m pytest tools/verify/test_verify_external.py -v
"""

import base64
import hashlib
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import verify_external as ve

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    _HAVE_CRYPTOGRAPHY = True
except ImportError:
    _HAVE_CRYPTOGRAPHY = False


def _domain_separated_hash(domain, canonical):
    h = hashlib.sha256()
    h.update(domain.encode('utf-8'))
    h.update(canonical.encode('utf-8'))
    return h.digest()


def build_signed_fixture(expires_in_ms=300_000, key_id='dev-local:key_v1'):
    """Genuine Ed25519 signing, mirroring tools/verify/verify_external.py's own
    envelope_hash() exactly, so this is a real signature, not a stub."""
    if not _HAVE_CRYPTOGRAPHY:
        raise unittest.SkipTest('cryptography package not installed')

    priv = Ed25519PrivateKey.generate()
    pub_der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_b64 = base64.b64encode(pub_der).decode('ascii')

    request = {'method': 'POST', 'path': '/demo', 'body': {'hello': 'world'}}
    request_hash = ve.compute_request_hash(request['method'], request['path'], request['body'])

    now_ms = time.time() * 1000
    artifact = {
        'expiry': now_ms + expires_in_ms,
        'payload': {'requestId': 'req-1', 'requestHash': request_hash, 'tenantId': 'dev-local'},
        'publicKeyId': key_id,
        'timestamp': now_ms - 10,
    }
    canonical = ve.stable_stringify({
        'expiry': artifact['expiry'], 'payload': artifact['payload'],
        'publicKeyId': artifact['publicKeyId'], 'timestamp': artifact['timestamp'],
    })
    digest = _domain_separated_hash('QODIQA::ARTIFACT::V1', canonical)
    signature = priv.sign(digest)
    artifact['signature'] = base64.b64encode(signature).decode('ascii')

    keys_data = {'keys': [{'keyId': key_id, 'publicKey': pub_b64, 'status': 'active'}]}
    return artifact, request, keys_data


class _KeysHandler(http.server.BaseHTTPRequestHandler):
    keys_payload = {'keys': []}

    def do_GET(self):
        body = json.dumps(self.keys_payload).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # silence test output


def start_keys_server(keys_data):
    handler = type('Handler', (_KeysHandler,), {'keys_payload': keys_data})
    server = http.server.HTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f'http://127.0.0.1:{server.server_address[1]}'
    return server, base_url


class OnlinePathUnchangedTests(unittest.TestCase):
    """The default (no offline kwargs) call path must be unchanged."""

    def test_fetches_keys_over_http_and_verifies(self):
        artifact, request, keys_data = build_signed_fixture()
        server, base_url = start_keys_server(keys_data)
        try:
            result = ve.verify(base_url, artifact, request)
            self.assertTrue(result['valid'])
            self.assertEqual(result['reason'], 'PASS')
        finally:
            server.shutdown()
            server.server_close()

    def test_keys_fetch_failed_when_unreachable(self):
        artifact, request, _ = build_signed_fixture()
        result = ve.verify('http://127.0.0.1:1', artifact, request)
        self.assertFalse(result['valid'])
        self.assertEqual(result['reason'], 'KEYS_FETCH_FAILED')


class OfflineModeTests(unittest.TestCase):
    """offline verification using only local trust material."""

    def test_succeeds_with_local_keys_data_no_network(self):
        artifact, request, keys_data = build_signed_fixture()
        start = time.time()
        result = ve.verify(None, artifact, request, offline=True, keys_data=keys_data)
        self.assertLess(time.time() - start, 2.0)  # proves no network round trip
        self.assertTrue(result['valid'])
        self.assertEqual(result['reason'], 'PASS')

    def test_local_keys_data_honored_even_with_base_url_present(self):
        artifact, request, keys_data = build_signed_fixture()
        result = ve.verify('http://127.0.0.1:1', artifact, request, keys_data=keys_data)
        self.assertTrue(result['valid'])

    def test_fails_closed_without_trust_material(self):
        artifact, request, _ = build_signed_fixture()
        result = ve.verify(None, artifact, request, offline=True)
        self.assertFalse(result['valid'])
        self.assertEqual(result['reason'], 'OFFLINE_TRUST_MATERIAL_MISSING')

    def test_unknown_key_id_fails_closed(self):
        artifact, request, _ = build_signed_fixture()
        result = ve.verify(None, artifact, request, offline=True, keys_data={'keys': []})
        self.assertFalse(result['valid'])
        self.assertEqual(result['reason'], 'KEY_NOT_FOUND')

    def test_tampered_payload_fails_signature_offline(self):
        artifact, request, keys_data = build_signed_fixture()
        artifact['payload'] = dict(artifact['payload'], tenantId='tampered')
        result = ve.verify(None, artifact, request, offline=True, keys_data=keys_data)
        self.assertFalse(result['valid'])
        self.assertEqual(result['reason'], 'INVALID_SIGNATURE')

    def test_expiry_enforced_offline(self):
        artifact, request, keys_data = build_signed_fixture(expires_in_ms=-1000)
        result = ve.verify(None, artifact, request, offline=True, keys_data=keys_data)
        self.assertFalse(result['valid'])
        self.assertEqual(result['reason'], 'EXPIRED')


class LoadKeysFromFileTests(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix='verify-ext-py-')

    def tearDown(self):
        for name in os.listdir(self.tmp_dir):
            os.remove(os.path.join(self.tmp_dir, name))
        os.rmdir(self.tmp_dir)

    def _write(self, name, content):
        path = os.path.join(self.tmp_dir, name)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        return path

    def test_accepts_keys_object_shape(self):
        path = self._write('keys.json', json.dumps({'keys': [{'keyId': 'a:key_v1', 'publicKey': 'AA==', 'status': 'active'}]}))
        data = ve.load_keys_from_file(path)
        self.assertEqual(len(data['keys']), 1)

    def test_accepts_bare_array_shape(self):
        path = self._write('keys.json', json.dumps([{'keyId': 'a:key_v1', 'publicKey': 'AA==', 'status': 'active'}]))
        data = ve.load_keys_from_file(path)
        self.assertEqual(len(data['keys']), 1)

    def test_missing_file_raises_clear_error(self):
        with self.assertRaisesRegex(ValueError, 'not found'):
            ve.load_keys_from_file(os.path.join(self.tmp_dir, 'missing.json'))

    def test_malformed_json_raises_clear_error(self):
        path = self._write('bad.json', '{not json')
        with self.assertRaisesRegex(ValueError, 'not valid JSON'):
            ve.load_keys_from_file(path)

    def test_wrong_shape_raises_clear_error(self):
        path = self._write('wrong-shape.json', json.dumps({'notKeys': []}))
        with self.assertRaisesRegex(ValueError, '"keys" array'):
            ve.load_keys_from_file(path)


class CLISubprocessTests(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix='verify-ext-py-cli-')
        self.script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tools/verify/verify_external.py')

    def tearDown(self):
        for name in os.listdir(self.tmp_dir):
            os.remove(os.path.join(self.tmp_dir, name))
        os.rmdir(self.tmp_dir)

    def _write(self, name, content):
        path = os.path.join(self.tmp_dir, name)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        return path

    def _run(self, args):
        return subprocess.run(
            [sys.executable, self.script, *args],
            capture_output=True, text=True, timeout=5,
        )

    def test_offline_key_file_verifies_genuine_artifact(self):
        artifact, request, keys_data = build_signed_fixture()
        keys_file = self._write('keys.json', json.dumps(keys_data))
        proc = self._run(['--offline', '--key-file', keys_file, json.dumps(artifact), json.dumps(request)])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(json.loads(proc.stdout)['valid'])

    def test_offline_bundle_verifies_from_single_archive(self):
        # a bundle verifies only together with the trusted key set supplied out of band.
        # (Before this test passed the bundle alone, which is exactly the forgery path.)
        artifact, request, keys_data = build_signed_fixture()
        bundle_file = self._write('bundle.json', json.dumps({'artifact': artifact, 'request': request, 'keys': keys_data['keys']}))
        keys_file = self._write('keys.json', json.dumps(keys_data))
        proc = self._run(['--offline', '--key-file', keys_file, '--bundle', bundle_file])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(json.loads(proc.stdout)['valid'])

    def test_offline_bundle_alone_is_refused(self):
        # the bundle's own keys are never a trust anchor.
        artifact, request, keys_data = build_signed_fixture()
        bundle_file = self._write('bundle.json', json.dumps({'artifact': artifact, 'request': request, 'keys': keys_data['keys']}))
        proc = self._run(['--offline', '--bundle', bundle_file])
        self.assertEqual(proc.returncode, 1)
        self.assertIn('TRUST_ANCHOR_REQUIRED', proc.stderr)
        self.assertNotIn('"valid": true', proc.stdout)

    def test_offline_without_trust_material_exits_1(self):
        artifact, request, _ = build_signed_fixture()
        proc = self._run(['--offline', json.dumps(artifact), json.dumps(request)])
        self.assertEqual(proc.returncode, 1)
        self.assertIn('OFFLINE_MISSING_TRUST_MATERIAL', proc.stderr)

    def test_legacy_positional_only_invocation_unchanged(self):
        proc = self._run([])
        self.assertEqual(proc.returncode, 1)
        self.assertIn('Usage:', proc.stderr)


# ── ─────────────────
# Same contract as.

_DAY = 86_400_000
_REQ = {'method': 'POST', 'path': '/ai/chat', 'body': {'prompt': 'hello'}}


def _new_key(key_id, **extra):
    if not _HAVE_CRYPTOGRAPHY:
        raise unittest.SkipTest('cryptography package not installed')
    priv = Ed25519PrivateKey.generate()
    pub_der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    entry = {'keyId': key_id, 'algorithm': 'ed25519', 'publicKey': base64.b64encode(pub_der).decode('ascii'), 'status': 'active'}
    for k, v in extra.items():
        if v is None:
            entry.pop(k, None)
        else:
            entry[k] = v
    return priv, entry


def _sign(priv, key_id, timestamp=None, ttl=60_000):
    ts = timestamp if timestamp is not None else int(time.time() * 1000) - 10
    artifact = {
        'expiry': ts + ttl,
        'payload': {
            'requestId': 'req-1',
            'requestHash': ve.compute_request_hash(_REQ['method'], _REQ['path'], _REQ['body']),
            'tenantId': 'victim',
            'callerContext': {'callerId': 'ceo@victim'},
        },
        'publicKeyId': key_id,
        'timestamp': ts,
    }
    canonical = ve.stable_stringify({k: artifact[k] for k in ('expiry', 'payload', 'publicKeyId', 'timestamp')})
    artifact['signature'] = base64.b64encode(priv.sign(_domain_separated_hash('QODIQA::ARTIFACT::V1', canonical))).decode('ascii')
    return artifact


def _iso(ms):
    import datetime
    return datetime.datetime.fromtimestamp(ms / 1000, tz=datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.') + '%03dZ' % (ms % 1000)


class DD002BundleTrustTests(unittest.TestCase):
    """a bundle's own keys are never the trust anchor."""

    def test_attacker_key_bundle_rejected(self):
        _, victim = _new_key('victim:key_v1')
        att_priv, att_entry = _new_key('victim:key_v1')       # attacker claims the victim's keyId
        forged = _sign(att_priv, 'victim:key_v1')
        bundle = {'artifact': forged, 'request': _REQ, 'keys': [att_entry]}
        self.assertEqual(ve.verify_bundle(bundle)['reason'], 'TRUST_ANCHOR_REQUIRED')
        r = ve.verify_bundle(bundle, trusted_keys={'keys': [victim]})
        self.assertFalse(r['valid'])
        self.assertEqual(r['reason'], 'KEY_MISMATCH')
        # the audit's exact API shape: bundle keys passed as candidates only, no trusted set
        r = ve.verify(None, forged, _REQ, offline=True, bundle_keys={'keys': [att_entry]})
        self.assertEqual((r['valid'], r['reason']), (False, 'TRUST_ANCHOR_REQUIRED'))

    def test_bundle_key_not_in_trusted_set_is_untrusted(self):
        _, victim = _new_key('victim:key_v1')
        att_priv, att_entry = _new_key('attacker:key_v1')
        r = ve.verify_bundle({'artifact': _sign(att_priv, 'attacker:key_v1'), 'request': _REQ, 'keys': [att_entry]},
                             trusted_keys={'keys': [victim]})
        self.assertEqual((r['valid'], r['reason']), (False, 'UNTRUSTED_KEY'))

    def test_genuine_artifact_with_trusted_key_accepted(self):
        priv, entry = _new_key('victim:key_v1')
        r = ve.verify_bundle({'artifact': _sign(priv, 'victim:key_v1'), 'request': _REQ, 'keys': [entry]},
                             trusted_keys=[entry])
        self.assertEqual((r['valid'], r['reason'], r['mode']), (True, 'PASS', 'CURRENT'))


class DD023StrictnessTests(unittest.TestCase):
    """mirror src/validation/validateArtifact.js + keyLifecycle.js."""

    def _v(self, artifact, entry, **kw):
        return ve.verify(None, artifact, _REQ, offline=True, keys_data={'keys': [entry]}, **kw)

    def test_extra_envelope_field_rejected(self):
        priv, entry = _new_key('t:key_v1')
        r = self._v(dict(_sign(priv, 't:key_v1'), extra='x'), entry)
        self.assertEqual((r['valid'], r['reason']), (False, 'INVALID_ARTIFACT'))
        self.assertIn('unknown field: extra', r['detail'])

    def test_non_canonical_signature_rejected(self):
        priv, entry = _new_key('t:key_v1')
        art = _sign(priv, 't:key_v1')
        self.assertTrue(self._v(art, entry)['valid'])
        variants = {art['signature'].rstrip('='),
                    art['signature'].replace('+', '-').replace('/', '_'),
                    ' ' + art['signature']}
        variants.discard(art['signature'])
        self.assertGreaterEqual(len(variants), 2)
        for sig in variants:
            r = self._v(dict(art, signature=sig), entry)
            self.assertEqual((r['valid'], r['reason']), (False, 'INVALID_SIGNATURE'), sig)

    def test_deprecated_key_outside_window_rejected(self):
        now = int(time.time() * 1000)
        priv, entry = _new_key('t:key_v1', status='deprecated')
        self.assertEqual(self._v(_sign(priv, 't:key_v1'), entry)['reason'], 'KEY_DEPRECATED')
        priv, entry = _new_key('t:key_v2', status='deprecated', deprecatedAt=_iso(now - 30_000))
        self.assertEqual(self._v(_sign(priv, 't:key_v2'), entry)['reason'], 'KEY_DEPRECATED')
        priv, entry = _new_key('t:key_v3', status='deprecated', deprecatedAt=_iso(now - 1_000))
        self.assertTrue(self._v(_sign(priv, 't:key_v3', timestamp=now - 5_000), entry)['valid'])

    def test_archived_revoked_statusless_keys_rejected(self):
        for extra, reason in ((dict(status='archived'), 'KEY_ARCHIVED'),
                              (dict(status='revoked'), 'KEY_REVOKED'),
                              (dict(status='compromised'), 'KEY_REVOKED'),
                              (dict(status=None), 'KEY_STATUS_UNKNOWN')):
            priv, entry = _new_key('t:key_v1', **extra)
            self.assertEqual(self._v(_sign(priv, 't:key_v1'), entry)['reason'], reason, extra)

    def test_max_age_enforced(self):
        priv, entry = _new_key('t:key_v1')
        art = _sign(priv, 't:key_v1', timestamp=int(time.time() * 1000) - 120_000, ttl=_DAY)
        self.assertEqual(self._v(art, entry)['reason'], 'TIME_SKEW_EXCEEDED')

    def test_plain_http_key_fetch_refused_unless_localhost(self):
        priv, _ = _new_key('t:key_v1')
        art = _sign(priv, 't:key_v1')
        for base in ('http://keys.example.invalid', 'http://10.0.0.5:3000', 'file:///etc', 'ftp://x', 'not a url'):
            self.assertEqual(ve.verify(base, art, _REQ)['reason'], 'INSECURE_KEY_SOURCE', base)
        self.assertEqual(ve.verify('http://127.0.0.1:1', art, _REQ)['reason'], 'KEYS_FETCH_FAILED')


class DD024HistoricalModeTests(unittest.TestCase):
    """archival verification of genuine expired artifacts (historical)."""

    def setUp(self):
        self.signed_at = int(time.time() * 1000) - 2 * _DAY

    def _v(self, artifact, entry, historical=True, request=_REQ):
        return ve.verify(None, artifact, request, offline=True, keys_data={'keys': [entry]}, historical=historical)

    def test_default_mode_still_rejects_expired(self):
        priv, entry = _new_key('v:key_v1')
        self.assertEqual(self._v(_sign(priv, 'v:key_v1', timestamp=self.signed_at), entry, historical=False)['reason'], 'EXPIRED')

    def test_historical_accepts_genuine_expired_artifact(self):
        priv, entry = _new_key('v:key_v1')
        r = self._v(_sign(priv, 'v:key_v1', timestamp=self.signed_at), entry)
        self.assertEqual((r['valid'], r['reason'], r['mode']), (True, 'PASS', 'HISTORICAL'))
        self.assertIn('does NOT mean it may be executed now', r['note'])

    def test_historical_rejects_forged_artifact(self):
        _, victim = _new_key('v:key_v1')
        att_priv, att_entry = _new_key('v:key_v1')
        forged = _sign(att_priv, 'v:key_v1', timestamp=self.signed_at)
        self.assertEqual(ve.verify_bundle({'artifact': forged, 'request': _REQ, 'keys': [att_entry]},
                                          trusted_keys={'keys': [victim]}, historical=True)['reason'], 'KEY_MISMATCH')
        self.assertEqual(ve.verify_bundle({'artifact': forged, 'request': _REQ},
                                          trusted_keys={'keys': [victim]}, historical=True)['reason'], 'INVALID_SIGNATURE')
        self.assertEqual(ve.verify_bundle({'artifact': forged, 'request': _REQ, 'keys': [att_entry]},
                                          historical=True)['reason'], 'TRUST_ANCHOR_REQUIRED')

    def test_historical_enforces_key_window_at_signing_time(self):
        sa = self.signed_at
        cases = (
            (dict(status='deprecated', deprecatedAt=_iso(sa + _DAY)), True, 'PASS'),
            (dict(status='archived', deprecatedAt=_iso(sa + _DAY)), True, 'PASS'),
            (dict(status='deprecated', deprecatedAt=_iso(sa - _DAY)), False, 'KEY_NOT_ACTIVE_AT_SIGNING_TIME'),
            (dict(status='archived'), False, 'KEY_NOT_ACTIVE_AT_SIGNING_TIME'),
            (dict(status='active', activatedAt=_iso(sa + _DAY)), False, 'KEY_NOT_ACTIVE_AT_SIGNING_TIME'),
            (dict(status='revoked', deprecatedAt=_iso(sa + _DAY)), False, 'KEY_REVOKED'),
        )
        for extra, valid, reason in cases:
            priv, entry = _new_key('v:key_v1', **extra)
            r = self._v(_sign(priv, 'v:key_v1', timestamp=sa), entry)
            self.assertEqual((r['valid'], r['reason']), (valid, reason), extra)

    def test_historical_still_refuses_never_valid_and_future(self):
        priv, entry = _new_key('v:key_v1')
        self.assertEqual(self._v(_sign(priv, 'v:key_v1', timestamp=self.signed_at, ttl=0), entry)['reason'], 'INVALID_ARTIFACT')
        future = _sign(priv, 'v:key_v1', timestamp=int(time.time() * 1000) + _DAY)
        self.assertEqual(self._v(future, entry)['reason'], 'FUTURE_TIMESTAMP')

    def test_historical_still_binds_request(self):
        priv, entry = _new_key('v:key_v1')
        r = self._v(_sign(priv, 'v:key_v1', timestamp=self.signed_at), entry,
                    request=dict(_REQ, body={'prompt': 'other'}))
        self.assertEqual(r['reason'], 'REQUEST_MISMATCH')

    def test_cli_historical_bundle_with_trusted_keys(self):
        priv, entry = _new_key('v:key_v1')
        art = _sign(priv, 'v:key_v1', timestamp=self.signed_at)
        tmp = tempfile.mkdtemp(prefix='verify-ext-py-hist-')
        try:
            keys_file = os.path.join(tmp, 'keys.json')
            bundle_file = os.path.join(tmp, 'bundle.json')
            with open(keys_file, 'w', encoding='utf-8') as f:
                json.dump({'keys': [entry]}, f)
            with open(bundle_file, 'w', encoding='utf-8') as f:
                json.dump({'artifact': art, 'request': _REQ, 'keys': [entry]}, f)
            script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tools/verify/verify_external.py')
            ok = subprocess.run([sys.executable, script, '--offline', '--historical', '--trusted-keys', keys_file,
                                 '--bundle', bundle_file], capture_output=True, text=True, timeout=10)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertEqual(json.loads(ok.stdout)['mode'], 'HISTORICAL')
            default = subprocess.run([sys.executable, script, '--offline', '--key-file', keys_file,
                                      '--bundle', bundle_file], capture_output=True, text=True, timeout=10)
            self.assertEqual(default.returncode, 1)
            self.assertEqual(json.loads(default.stdout)['reason'], 'EXPIRED')
        finally:
            for name in os.listdir(tmp):
                os.remove(os.path.join(tmp, name))
            os.rmdir(tmp)

if __name__ == '__main__':
    unittest.main()
