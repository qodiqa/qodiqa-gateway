'use strict';

/**
 * Protocol error-code / HTTP-status golden consistency — Task #29,
 * server-half remediation.
 *
 * QODIQA-PROTOCOL-SPEC.md §13 and §30 previously stated a normative rule
 * discovered during Task #29's error-code audit: HTTP status for a pipeline
 * BLOCK reason was a property of the ENDPOINT, not of the reason code
 * itself — /ai/chat returned 403 for every pipeline BLOCK reason while
 * /verify's dry-run returned the identical `reason` at HTTP 200.
 *
 * removed that asymmetry: /ai/chat now returns 200 {decision:'BLOCK',
 * reason} for the same policy/verification BLOCK family /verify already
 * used 200 for (see aiChat.js's own _blockStatus() comment) — 403 is no
 * longer used by /ai/chat's own pipeline at all, since this route has no
 * bearer-token/RBAC auth layer of its own to reserve it for. This suite now
 * proves the OPPOSITE of its original premise: /ai/chat and /verify give
 * the IDENTICAL status for the SAME underlying failure (a tampered Ed25519
 * signature), so the two endpoints' status-code models can never silently
 * drift back into a per-endpoint asymmetry.
 *
 * (QODIQA-PROTOCOL-SPEC.md §13/§30's own prose still describes the earlier
 * rule — flagged as a known, disclosed documentation-drift follow-up
 * outside's own approved doc-update scope; see
 *.)
 */

const request        = require('supertest');
const express        = require('express');
const requestId      = require('../../../../middleware/requestId');
const attachClientIp = require('../../../../middleware/clientIp');

const createVerifyRouter = require('../verify');
const createAiChatRouter = require('../aiChat');

const { signBoundArtifact }       = require('../../../validation/signBoundArtifact');
const { rotateKey, getActiveKey } = require('../../../../services/artifact/keyStore');
const { makeNonceStore, makeOpenAnomalyStore } = require('../../../testing/stores');
const { validateAndPrepare } = require('../../../../services/policy/loader');
const { createStore }        = require('../../../../services/policy/store');

function _makeDryNonceBackend() { return { async isRegistered() { return false; } }; }
function _makeDryAnomalyBackend() { return { async peek() { return { count: 0 }; } }; }

const OPEN_THRESH = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 1_000_000, GLOBAL_MAX: 1_000_000 });
const POLICIES = validateAndPrepare({ policies: [{
  id: 'POL-ALLOW', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
  config: { requireValidArtifact: true },
}] });

let KEY;
beforeAll(() => {
  try   { KEY = getActiveKey('endpoint-status-conformance'); }
  catch { rotateKey('endpoint-status-conformance'); KEY = getActiveKey('endpoint-status-conformance'); }
});

function freshArtifact() {
  const req = { method: 'POST', path: '/ai/chat', body: { prompt: 'hello', model: 'gpt-4' } };
  const now = Date.now();
  const artifact = signBoundArtifact(
    req,
    { payload: { provider: 'openai', policyHash: 'a'.repeat(64) }, timestamp: now, expiry: now + 60_000, publicKeyId: KEY.keyId },
    KEY.privDer,
  );
  return { artifact, request: req };
}

function makeAiChatApp() {
  const app = express();
  app.use(requestId);
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/ai/chat', createAiChatRouter({
    _store:        makeNonceStore(),
    _anomalyStore: makeOpenAnomalyStore(),
    _thresholds:   OPEN_THRESH,
    _getPolicies:  () => POLICIES,
    _policyStore:  createStore(),
    _providerFn:   () => Promise.resolve({ output: 'ok' }),
  }));
  return app;
}

function makeVerifyApp() {
  const app = express();
  app.use(requestId);
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/verify', createVerifyRouter({
    _dryRunNonceStore:   _makeDryNonceBackend(),
    _dryRunAnomalyStore: _makeDryAnomalyBackend(),
    _thresholds:         OPEN_THRESH,
    _getPolicies:        () => POLICIES,
    _policyStore:        createStore(),
  }));
  return app;
}

describe('/ai/chat and /verify give the identical HTTP status for the same pipeline BLOCK reason', () => {
  test('a tampered signature (reason: INVALID_SIGNATURE) is 200 BLOCK on /ai/chat', async () => {
    const { artifact, request: req } = freshArtifact();
    const tampered = { ...artifact, signature: Buffer.alloc(64).toString('base64') };
    const encoded = Buffer.from(JSON.stringify(tampered)).toString('base64url');

    const resp = await request(makeAiChatApp())
      .post('/ai/chat')
      .set('x-qodiqa-artifact', encoded)
      .set('Content-Type', 'application/json')
      .send(req.body);

    expect(resp.status).toBe(200);
    expect(resp.body).toMatchObject({ decision: 'BLOCK', reason: 'INVALID_SIGNATURE' });
  });

  test('the identical tampered signature is 200 BLOCK on /verify (dry-run never returns non-200 for a pipeline reason)', async () => {
    const { artifact, request: req } = freshArtifact();
    const tampered = { ...artifact, signature: Buffer.alloc(64).toString('base64') };

    const resp = await request(makeVerifyApp())
      .post('/verify')
      .send({ artifact: tampered, request: req });

    expect(resp.status).toBe(200);
    expect(resp.body).toMatchObject({ decision: 'BLOCK', reason: 'INVALID_SIGNATURE' });
  });
});
