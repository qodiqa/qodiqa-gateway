'use strict';

/**
 * EXAMPLE-1/DOC-1 strengthened regression.
 *
 * test/guards/exampleDocsProviderDrift.conformance.test.js only checks that
 * explanatory prose sits near each example's /ai/chat sign() call — a
 * purely textual check. It would NOT fail if a future change to
 * src/validation/schemas/sign.schema.js or src/api/routes/sign.js added a
 * new required field, tightened validation, or otherwise broke every
 * shipped example, as long as the surrounding comments were left in place.
 *
 * This test closes that gap. For every example/doc file that ships a
 * /ai/chat sign() call, it:
 *   1. Re-parses the file's OWN source text (not a hand-copied fixture) to
 *      extract the literal object/dict argument passed to .sign.sign() —
 *      via test/helpers/extractSignRequest.js (vm-based, JS/TS) or
 *      test/helpers/extract_python_sign_calls.py (ast-based, Python).
 *   2. Sends that exact extracted request through the REAL Express routers
 *      (src/api/routes/sign.js, src/api/routes/aiChat.js) — the same
 *      Zod schemas and provider-resolution logic production uses — via
 *      supertest, exactly as src/api/routes/__tests__/quickstartFlow.test.js
 *      does for the docs/guides/quickstart.md curl example.
 *   3. Asserts the request reaches EXECUTE.
 *
 * Because step 2 exercises the real implementation, any of the following
 * future changes will fail this test for every affected example, with no
 * dependency on comment wording:
 *   - a new required field added to signBodySchema / aiChatBodySchema
 *   - a payload/body shape the schema now rejects
 *   - a change to /sign's provider auto-resolution or PROVIDER_REQUIRED gate
 *   - any other change that causes /sign or /ai/chat to stop accepting the
 *     example's documented request
 *
 * Coverage note: sdk/python/examples/basic_client.py is intentionally
 * excluded — it builds its sign request via an intermediate `sign_request`
 * variable rather than an inline literal, which the extractor can't
 * evaluate generically. When QODIQA_PROVIDER is unset (the documented
 * common case), that variable reduces to exactly the same shape as
 * docs/guides/quickstart.md's documented body (no payload.provider) — already covered,
 * byte-for-byte, by SIGN-PROV-02 in signProviderResolution.test.js and by
 * quickstartFlow.test.js. express/middleware.js, fastify/middleware.js, and
 * sdk/python/examples/{cli,fastapi_integration,flask_integration}.py are
 * excluded because they sign a caller-supplied path, not a literal
 * '/ai/chat' — there is no fixed request for this test to extract and
 * execute; they still carry the provider-explanation comment checked by
 * exampleDocsProviderDrift.conformance.test.js.
 */

process.env.QODIQA_CLIENT_ID  = 'default';
process.env.OPENAI_API_KEY    = process.env.OPENAI_API_KEY || require('../helpers/providerFixtureKeys').PROVIDER_FIXTURE_KEYS.openai; // D-E: placeholder keys leave the provider disabled

const fs      = require('fs');
const path    = require('path');
const request = require('supertest');
const express = require('express');

// TRUST-1 remediation: /sign no longer accepts a shared QODIQA_SIGN_TOKEN via
// x-qodiqa-sign-token — every caller authenticates with its own per-identity
// signing API key via Authorization: Bearer.
const { provisionTestSigningIdentity } = require('../helpers/signingIdentity');
const { apiKey: SIGN_TOKEN } = provisionTestSigningIdentity({ tenantId: 'default' });

// v7 (R-12 / R-14): audit appends pseudonymize consentProvenance.subject / callerContext.callerId, which needs
// PostgreSQL in production (fail-closed without it). This suite runs without a database, so it opts in to the
// EXPLICIT test-only pseudonym stand-in (test/helpers/subjectPseudonymMock.js).
jest.mock('../../src/core/dsr/subjectPseudonym', () => require('../helpers/subjectPseudonymMock'));
jest.mock('../../src/core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

const createSignRouter   = require('../../src/api/routes/sign');
const createAiChatRouter = require('../../src/api/routes/aiChat');
const attachClientIp     = require('../../middleware/clientIp');
const { getActiveKey, rotateKey } = require('../../services/artifact/keyStore');
const { validateAndPrepare }      = require('../../services/policy/loader');
const { createStore }             = require('../../services/policy/store');
const { makeNonceStore, makeOpenAnomalyStore } = require('../../src/testing/stores');

const { extractAiChatSignRequests, extractFencedBlocks } = require('../helpers/extractSignRequest');
const { extractPythonAiChatSignRequests } = require('../helpers/extractPythonSignRequest');

const ROOT = path.resolve(__dirname, '..', '..');

beforeAll(() => {
  try   { getActiveKey('default'); }
  catch { rotateKey('default'); }
});

// Same policy set /sign and /ai/chat share in production (server.js mounts
// both routers against the same `policies` variable) — mirrors
// quickstartFlow.test.js exactly.
const POLICIES = validateAndPrepare({ policies: [{
  id: 'POL-001', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
  config: { requireValidArtifact: true },
}] });
const POLICY_STORE = createStore();

function makeApp() {
  const app = express();
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/sign', createSignRouter(() => POLICIES));
  app.use('/ai/chat', createAiChatRouter({
    _store:        makeNonceStore(),
    _anomalyStore: makeOpenAnomalyStore(),
    _getPolicies:  () => POLICIES,
    _policyStore:  POLICY_STORE,
    _providerFn:   () => Promise.resolve({ output: 'stub response' }),
  }));
  return app;
}

/**
 * Sends `signBody` (an extracted { request, payload?, ttl? } object) to the
 * real /sign route, then the resulting artifact to the real /ai/chat route,
 * and asserts EXECUTE. A fresh app/nonce store per call avoids replay
 * collisions between examples that happen to sign identical bodies.
 */
async function assertExtractedRequestExecutes(signBody) {
  const app = makeApp();

  const signRes = await request(app)
    .post('/sign')
    .set('Content-Type', 'application/json')
    .set('Authorization', `Bearer ${SIGN_TOKEN}`)
    .send(signBody);

  expect(signRes.status).toBe(200);
  expect(signRes.body.artifact.payload.provider).toBe('openai');

  const artifactHeader = Buffer.from(JSON.stringify(signRes.body.artifact)).toString('base64');

  const chatRes = await request(app)
    .post('/ai/chat')
    .set('Content-Type', 'application/json')
    .set('x-qodiqa-artifact', artifactHeader)
    .send(signBody.request.body);

  expect(chatRes.status).toBe(200);

  // C1: a streaming request (body.stream: true) never returns a JSON
  // {decision} body — it's SSE (streamEnforcer.js's stream_started/
  // chunk_forwarded/stream_completed/stream_cancelled frame family, kept
  // deliberately outside the JSON envelope registry per item 26). This
  // test file is a routing/schema/auth trip-wire over documented examples,
  // not a behavioral test — full frame-level SSE coverage is already owned
  // by test/streaming.test.js — so the bar here is just: does the
  // documented request body genuinely reach and start the real streaming
  // path, not full frame-sequence verification.
  if (signBody.request.body && signBody.request.body.stream === true) {
    expect(chatRes.text).toContain('event: stream_started');
  } else {
    expect(chatRes.body.decision).toBe('EXECUTE');
  }
}

function readFile(relPath) {
  // Normalize line endings at the test's own read site so fence/markdown
  // extraction is correct regardless of checkout config (defense in depth
  // alongside .gitattributes' eol=lf — see P4-2-CRLF-REPORT.md). The
  // production-side extractor (test/helpers/extractSignRequest.js) is left
  // untouched; it only ever receives already-normalized strings from here.
  return fs.readFileSync(path.join(ROOT, relPath), 'utf8').replace(/\r\n/g, '\n');
}

// Free variables referenced (but not assigned) inside these files' extracted
// .sign.sign() argument literal — stubbed with representative values so the
// literal evaluates exactly as written. Extend when a new example
// introduces a new free variable inside its sign() call.
const JS_CONTEXT = {
  flags:     {},
  prompt:    'Test prompt',
  model:     undefined,
  userId:    'anonymous',
  PROVIDER:  undefined,
  CHAT_BODY: { prompt: 'Test prompt' },
};

describe('EXAMPLE-1/DOC-1 strengthened regression: examples validated against the real /sign + /ai/chat implementation', () => {
  describe('JavaScript / TypeScript example files', () => {
    const files = [
      'examples/quickstart.js',
      'sdk/javascript/examples/node/basic.js',
      'sdk/javascript/examples/node/cli.js',
      'sdk/javascript/examples/typescript/basic.ts',
      'sdk/javascript/examples/nextjs/route.ts',
    ];

    test.each(files)('%s: every extracted .sign.sign() request reaches EXECUTE', async (relPath) => {
      const requests = extractAiChatSignRequests(readFile(relPath), JS_CONTEXT);
      expect(requests.length).toBeGreaterThan(0); // guard the guard — a file with no extractable call is a bug in this test's file list, not a pass
      for (const body of requests) {
        await assertExtractedRequestExecutes(body);
      }
    });
  });

  describe('Markdown-embedded JavaScript/TypeScript examples', () => {
    const files = [
      ['sdk/javascript/README.md', ['typescript']],
      ['docs/sdk/javascript/README.md', ['typescript']],
      ['docs/sdk/javascript/api.md', ['typescript']],
    ];

    test.each(files)('%s: every extracted .sign.sign() request reaches EXECUTE', async (relPath, langs) => {
      const md = readFile(relPath);
      const requests = langs
        .flatMap((lang) => extractFencedBlocks(md, lang))
        .flatMap((block) => extractAiChatSignRequests(block, JS_CONTEXT));

      expect(requests.length).toBeGreaterThan(0);
      for (const body of requests) {
        await assertExtractedRequestExecutes(body);
      }
    });
  });

  describe('Python example files', () => {
    const files = ['sdk/python/examples/async_client.py'];

    test.each(files)('%s: every extracted .sign.sign() request reaches EXECUTE', async (relPath) => {
      const requests = extractPythonAiChatSignRequests(readFile(relPath));
      expect(requests.length).toBeGreaterThan(0);
      for (const body of requests) {
        await assertExtractedRequestExecutes(body);
      }
    });
  });

  describe('Markdown-embedded Python examples', () => {
    const files = ['sdk/python/README.md', 'docs/sdk/python/README.md', 'docs/sdk/python/api.md'];

    test.each(files)('%s: every extracted .sign.sign() request reaches EXECUTE', async (relPath) => {
      const md = readFile(relPath);
      // Only feed blocks that plausibly contain a relevant sign() call to
      // the Python parser — doc pages also embed intentionally-incomplete
      // signature fragments (e.g. `QodiqaClient(\n    *,\n    ...\n)`) as
      // fenced ```python blocks, which are not valid standalone syntax and
      // aren't sign() calls in the first place.
      const relevantBlocks = extractFencedBlocks(md, 'python')
        .filter((b) => b.includes('/ai/chat') && /\.sign\.sign\(/.test(b));
      const requests = relevantBlocks.flatMap(extractPythonAiChatSignRequests);
      expect(requests.length).toBeGreaterThan(0);
      for (const body of requests) {
        await assertExtractedRequestExecutes(body);
      }
    });
  });
});
