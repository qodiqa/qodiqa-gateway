'use strict';

/**
 * regression: the repository-root examples/quickstart.js used to require
 * a helper whose enforce() throws synchronously
 * (`TypeError: QODIQA: signToken is required`) whenever QODIQA_SIGN_TOKEN
 * isn't set — the very first thing a new user would run failed with an
 * uncaught exception before printing any result. examples/quickstart.js now requires
 * the maintained sdk/javascript SDK instead and validates
 * QODIQA_SIGN_TOKEN itself, up front, before making any network call.
 *
 * This test spawns the REAL examples/quickstart.js as a genuine child OS process — never
 * require()'d, never mocked — so a future regression that reintroduces an
 * unconditional throw (in examples/quickstart.js or in whichever SDK it requires) fails
 * this test the same way it would fail a real user's terminal, not just a
 * unit test of some helper function.
 *
 * See also test/guards/exampleRequestContract.conformance.test.js, which validates
 * examples/quickstart.js's extracted .sign.sign() request body against the real /sign +
 * /ai/chat routes without spawning the process — this file is the
 * complementary end-to-end check that the whole script, run exactly as a
 * user would run it, produces the promised first-run experience.
 */

process.env.QODIQA_CLIENT_ID = 'default';
process.env.OPENAI_API_KEY   = process.env.OPENAI_API_KEY || require('./helpers/providerFixtureKeys').PROVIDER_FIXTURE_KEYS.openai; // D-E: placeholder keys leave the provider disabled

const path   = require('path');
const { spawn } = require('child_process');
const express = require('express');

const { provisionTestSigningIdentity } = require('./helpers/signingIdentity');

// v7 (R-12 / R-14): audit appends pseudonymize consentProvenance.subject / callerContext.callerId, which needs
// PostgreSQL in production (fail-closed without it). This suite runs without a database, so it opts in to the
// EXPLICIT test-only pseudonym stand-in (test/helpers/subjectPseudonymMock.js).
jest.mock('../src/core/dsr/subjectPseudonym', () => require('./helpers/subjectPseudonymMock'));
jest.mock('../src/core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

const createSignRouter   = require('../src/api/routes/sign');
const createAiChatRouter = require('../src/api/routes/aiChat');
const attachClientIp     = require('../middleware/clientIp');
const { getActiveKey, rotateKey } = require('../services/artifact/keyStore');
const { validateAndPrepare }      = require('../services/policy/loader');
const { createStore }             = require('../services/policy/store');
const { makeNonceStore, makeOpenAnomalyStore } = require('../src/testing/stores');

const ROOT         = path.resolve(__dirname, '..');
const EXAMPLE_PATH = path.join(ROOT, 'examples/quickstart.js');

beforeAll(() => {
  try   { getActiveKey('default'); }
  catch { rotateKey('default'); }
});

// Same policy set /sign and /ai/chat share in production — mirrors
// test/guards/exampleRequestContract.conformance.test.js exactly.
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

// Deliberately NOT execFileSync: that blocks this test file's own event
// loop for as long as the child runs. The happy-path test below serves the
// child's HTTP requests from an Express app listening in THIS same process
// — a synchronous, blocking spawn would deadlock (the child waits for a
// response the parent's frozen event loop can never send) rather than fail
// fast, which is a confusing way for this regression test itself to break.
function runExample(env, timeoutMs = 15_000) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [EXAMPLE_PATH], { cwd: ROOT, env });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (buf) => { stdout += buf.toString(); });
    child.stderr.on('data', (buf) => { stderr += buf.toString(); });

    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`examples/quickstart.js did not exit within ${timeoutMs}ms.\nstdout:\n${stdout}\nstderr:\n${stderr}`));
    }, timeoutMs);

    child.on('error', (err) => { clearTimeout(timer); reject(err); });
    child.on('exit', (code) => { clearTimeout(timer); resolve({ status: code, stdout, stderr }); });
  });
}

// A Node uncaught-exception dump always includes a stack-frame line of the
// form "    at ... (file:line:col)". No run of examples/quickstart.js — successful or
// gracefully handled — should ever print one.
function hasUncaughtStackTrace(text) {
  return /^\s+at .+\(.*:\d+:\d+\)/m.test(text);
}

describe('regression: examples/quickstart.js first-run experience (real child process)', () => {
  test('missing QODIQA_SIGN_TOKEN: controlled exit with an actionable message, never an uncaught exception', async () => {
    const env = { ...process.env };
    delete env.QODIQA_SIGN_TOKEN;
    env.QODIQA_BASE_URL = 'http://127.0.0.1:1'; // must never be reached — the guard fires before any fetch

    const result = await runExample(env);

    expect(result.status).toBe(1);
    expect(hasUncaughtStackTrace(result.stdout)).toBe(false);
    expect(hasUncaughtStackTrace(result.stderr)).toBe(false);
    expect(result.stderr).toMatch(/QODIQA_SIGN_TOKEN is not set/);
    expect(result.stderr).toMatch(/npm run dev/);
    expect(result.stderr).not.toMatch(/TypeError/);
  });

  test('valid signToken and a running server: examples/quickstart.js completes end-to-end and prints the EXECUTE decision', async () => {
    const { apiKey } = provisionTestSigningIdentity({ tenantId: 'default' });
    const app = makeApp();

    const server = await new Promise((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const { port } = server.address();

    try {
      const env = {
        ...process.env,
        QODIQA_BASE_URL:   `http://127.0.0.1:${port}`,
        QODIQA_SIGN_TOKEN: apiKey,
      };

      const result = await runExample(env);

      expect(hasUncaughtStackTrace(result.stdout)).toBe(false);
      expect(hasUncaughtStackTrace(result.stderr)).toBe(false);
      expect(result.status).toBe(0);
      expect(result.stdout).toMatch(/Decision:\s+EXECUTE/);
      expect(result.stdout).toMatch(/AI text:\s+stub response/);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  }, 20_000);
});
