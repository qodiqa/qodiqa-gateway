'use strict';

/**
 * CRYPTO-4 / REPLAY-5 remediation — request-binding path reflects the ACTUAL
 * request path, not a hardcoded '/ai/chat' constant.
 *
 * Previously this router's request-binding hash always used a literal
 * CHAT_PATH = '/ai/chat', regardless of which of the four mounted aliases
 * (/ai/chat, /ai/chat/stream, /v1/ai/chat, /v1/ai/chat/stream — see
 * src/app.js) actually received the request. An artifact signed for one
 * alias therefore verified identically at every other one — the documented
 * "binds to the exact request path" guarantee (src/validation/requestHash.js)
 * was not actually true. Both official SDKs always sign+send to the literal
 * '/ai/chat' (confirmed by reading sdk/javascript/src/resources/chat.ts and
 * sdk/python/qodiqa/resources/chat.py — streaming uses a body flag, never a
 * different URL), so this fix is a no-op for all real SDK traffic.
 */

jest.mock('../../../core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'CONSENT_VERIFIED' }),
}));

const fs           = require('fs');
const path         = require('path');
const express      = require('express');
const request      = require('supertest');
const requestId    = require('../../../../middleware/requestId');
const attachClientIp = require('../../../../middleware/clientIp');
const createAiChatRouter = require('../aiChat');
const { signBoundArtifact }       = require('../../../validation/signBoundArtifact');
const { rotateKey, getActiveKey } = require('../../../../services/artifact/keyStore');
const { makeNonceStore, makeOpenAnomalyStore } = require('../../../testing/stores');
const { validateAndPrepare } = require('../../../../services/policy/loader');
const { createStore }        = require('../../../../services/policy/store');

let KEY;
beforeAll(() => {
  try   { KEY = getActiveKey('path-binding-test'); }
  catch { rotateKey('path-binding-test'); KEY = getActiveKey('path-binding-test'); }
});

const CHAT_BODY = { prompt: 'hello', model: 'gpt-4' };
const _PASS_POLICY = validateAndPrepare({ policies: [{
  id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
  config: { requireValidArtifact: true },
}] });

// One isolated app per alias, each with its own router instance mounted at
// exactly one path — this isolates the assertions to path-binding behavior
// itself, distinct from the multi-mount topology src/app.js actually uses.
// (The real multi-mount interaction — mounting one router instance at all
// four aliases on a single app, as src/app.js does — is covered separately
// below: OPS-02 (#14) found and fixed a real Express mount-prefix bug there
// during live verification. This comment previously said that gap was
// "flagged separately" — it never actually was, in either tracking
// document; see the "real multi-mount topology" describe block below for
// the fix and its regression coverage.)
function makeAliasApp(mountPath, { nonceStore } = {}) {
  const app = express();
  app.use(requestId);
  app.use(attachClientIp);
  app.use(express.json());
  const router = createAiChatRouter({
    _store:        nonceStore || makeNonceStore(),
    _anomalyStore: makeOpenAnomalyStore(),
    _providerFn:   () => Promise.resolve({ output: 'mock response' }),
    _getPolicies:  () => _PASS_POLICY,
    _policyStore:  createStore(),
  });
  app.use(mountPath, router);
  return app;
}

function signFor(path, overrides = {}) {
  const req = { method: 'POST', path, body: CHAT_BODY };
  const now = Date.now();
  return signBoundArtifact(
    req,
    { payload: { provider: 'openai', ...overrides }, timestamp: now, expiry: now + 60_000, publicKeyId: KEY.keyId },
    KEY.privDer,
  );
}

function postArtifact(app, urlPath, artifact) {
  return request(app)
    .post(urlPath)
    .set('x-qodiqa-artifact', Buffer.from(JSON.stringify(artifact)).toString('base64'))
    .send(CHAT_BODY);
}

describe('CRYPTO-4/REPLAY-5 — request-binding path matches the actual request', () => {
  test('an artifact signed for /ai/chat succeeds when sent to /ai/chat', async () => {
    const app = makeAliasApp('/ai/chat');
    const artifact = signFor('/ai/chat', { tag: 'same-path-1' });
    const res = await postArtifact(app, '/ai/chat', artifact);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('EXECUTE');
  });

  test('an artifact signed for /v1/ai/chat succeeds when sent to /v1/ai/chat', async () => {
    const app = makeAliasApp('/v1/ai/chat');
    const artifact = signFor('/v1/ai/chat', { tag: 'same-path-2' });
    const res = await postArtifact(app, '/v1/ai/chat', artifact);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('EXECUTE');
  });

  test('an artifact signed for /ai/chat is REJECTED when sent to /v1/ai/chat (cross-alias substitution closed)', async () => {
    const app = makeAliasApp('/v1/ai/chat');
    const artifact = signFor('/ai/chat', { tag: 'cross-alias-1' });
    const res = await postArtifact(app, '/v1/ai/chat', artifact);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
    expect(res.body.reason).toBe('REQUEST_MISMATCH');
  });

  test('an artifact signed for /ai/chat is REJECTED when sent to /ai/chat/stream', async () => {
    const app = makeAliasApp('/ai/chat/stream');
    const artifact = signFor('/ai/chat', { tag: 'cross-alias-2' });
    const res = await postArtifact(app, '/ai/chat/stream', artifact);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
    expect(res.body.reason).toBe('REQUEST_MISMATCH');
  });

  test('an artifact signed for /v1/ai/chat/stream is REJECTED when sent to /ai/chat', async () => {
    const app = makeAliasApp('/ai/chat');
    const artifact = signFor('/v1/ai/chat/stream', { tag: 'cross-alias-3' });
    const res = await postArtifact(app, '/ai/chat', artifact);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
    expect(res.body.reason).toBe('REQUEST_MISMATCH');
  });

  test('a query string on the actual request is stripped before binding — an artifact signed for the bare path still matches', async () => {
    // This endpoint is body-based (no client ever legitimately sends a query
    // string), and requestHash.js's own contract says path is bound "exact
    // bytes, no normalization" — the choice of what "path" means (with or
    // without query string) is made once, here, at the call site. Stripping
    // the query string means an attacker appending harmless-looking query
    // params can't turn a previously-valid request into an unexpectedly
    // rejected one; it does NOT reopen the cross-alias gap this fix closes,
    // since the alias segment itself is still part of the bound path.
    const app = makeAliasApp('/ai/chat');
    const artifact = signFor('/ai/chat', { tag: 'query-string' });
    const res = await postArtifact(app, '/ai/chat?extra=param', artifact);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('EXECUTE');
  });
});

// OPS-02 (#14) — src/app.js registers the streaming alias before the base
// path. Static guard: fails loudly, with no Express boot required, if anyone
// ever reorders these lines back — see src/app.js's own mount-site comment
// for the full mechanism (Express path-segment-prefix matching + first-match-
// wins registration order).
describe('OPS-02 (#14) — src/app.js registers the streaming alias before the base path (static regression guard)', () => {
  test('app.js mounts /ai/chat/stream before /ai/chat, and /v1/ai/chat/stream before /v1/ai/chat', () => {
    const appSrc = fs.readFileSync(path.join(__dirname, '../../../app.js'), 'utf8');

    const streamIdx   = appSrc.indexOf("app.use('/ai/chat/stream'");
    const baseIdx     = appSrc.indexOf("app.use('/ai/chat'");
    const v1StreamIdx = appSrc.indexOf("app.use('/v1/ai/chat/stream'");
    const v1BaseIdx   = appSrc.indexOf("app.use('/v1/ai/chat'");

    expect(streamIdx).toBeGreaterThan(-1);
    expect(baseIdx).toBeGreaterThan(-1);
    expect(v1StreamIdx).toBeGreaterThan(-1);
    expect(v1BaseIdx).toBeGreaterThan(-1);

    expect(streamIdx).toBeLessThan(baseIdx);
    expect(v1StreamIdx).toBeLessThan(v1BaseIdx);
  });
});

// OPS-02 (#14) — the real multi-mount topology src/app.js uses: the SAME
// router instance mounted at both the streaming alias and the base path, in
// the SAME registration order app.js uses. Unlike makeAliasApp() above (one
// router per isolated app, exactly one mount path each — deliberately
// chosen to isolate path-binding assertions from mount-topology concerns),
// this reproduces the multi-mount interaction itself: Express matches
// app.use(path, ...) by path-segment prefix and tries mounts in registration
// order, stopping at whichever one responds first. Mounting '/ai/chat'
// before '/ai/chat/stream' silently swallows every '/ai/chat/stream'
// request (the router only ever sees req.url stripped to '/stream', which
// matches no route, 405ing via the catch-all) — a real, live,
// previously-undiscovered defect found during OPS-02/#14's manual
// verification and fixed in src/app.js alongside this test.
describe('OPS-02 (#14) — /ai/chat/stream and /ai/chat are both reachable through the real multi-mount topology', () => {
  function makeMultiMountApp() {
    const app = express();
    app.use(requestId);
    app.use(attachClientIp);
    app.use(express.json());
    const router = createAiChatRouter({
      _store:        makeNonceStore(),
      _anomalyStore: makeOpenAnomalyStore(),
      _providerFn:   () => Promise.resolve({ output: 'mock response' }),
      _getPolicies:  () => _PASS_POLICY,
      _policyStore:  createStore(),
    });
    // Same order as the fixed src/app.js: the streaming alias registered
    // before the base path. Swap these two lines and the test below fails —
    // that is the regression this test exists to catch.
    app.use('/ai/chat/stream', router);
    app.use('/ai/chat', router);
    return app;
  }

  test('POST /ai/chat/stream reaches the real handler, not the 405 catch-all', async () => {
    const app = makeMultiMountApp();
    const artifact = signFor('/ai/chat/stream', { tag: 'multi-mount-stream' });
    const res = await postArtifact(app, '/ai/chat/stream', artifact);
    expect(res.status).not.toBe(405);
    expect(res.body?.reason).not.toBe('METHOD_NOT_ALLOWED');
  });

  test('POST /ai/chat still reaches the real handler when co-mounted with /ai/chat/stream (fix does not break the base alias)', async () => {
    const app = makeMultiMountApp();
    const artifact = signFor('/ai/chat', { tag: 'multi-mount-base' });
    const res = await postArtifact(app, '/ai/chat', artifact);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('EXECUTE');
  });
});
