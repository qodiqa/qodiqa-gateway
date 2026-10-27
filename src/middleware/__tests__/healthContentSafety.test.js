'use strict';

// Regression guard for the security assumption underpinning the default-open
// /health and /ready model (see src/middleware/healthAuth.js): these two
// routes are reachable WITHOUT a credential by default because they are
// contractually restricted to minimal, non-sensitive output. If either route
// ever grows a field from the banned list below, this test fails the build —
// it is the enforcement mechanism for that contract, not just documentation.

const request        = require('supertest');
const express         = require('express');
const healthRouter    = require('../../api/routes/health');
const readyRouter     = require('../../api/routes/ready');
const readinessState  = require('../../runtime/readinessState');

// Recursively collect every key name that appears anywhere in an object graph.
function collectKeys(value, out = new Set()) {
  if (value === null || typeof value !== 'object') return out;
  for (const [k, v] of Object.entries(value)) {
    out.add(k.toLowerCase());
    collectKeys(v, out);
  }
  return out;
}

// Any of these substrings appearing as (part of) a key name is disallowed.
// Deliberately broad — this is a safety net, false positives are cheap,
// false negatives are a real information-disclosure incident.
const BANNED_KEY_SUBSTRINGS = [
  'version', 'build', 'commit', 'sha',
  'stack', 'trace',
  'secret', 'token', 'apikey', 'api_key', 'password', 'credential',
  'key', // catches privateKey/publicKey/keyId — none belong in these responses
  'env', 'environment',
  'config', 'configuration',
  'provider',
  'pid',
  'node_version', 'nodeversion',
  'hostname', 'host',
  'redis', 'postgres', 'database', 'db',
];

function assertNoSensitiveKeys(body) {
  const keys = collectKeys(body);
  for (const key of keys) {
    for (const banned of BANNED_KEY_SUBSTRINGS) {
      if (key.includes(banned)) {
        throw new Error(
          `Health/ready response contains disallowed key "${key}" (matches banned pattern "${banned}"). ` +
          `/health and /ready are unauthenticated by default and MUST NOT leak operational detail.`
        );
      }
    }
  }
}

describe('content-safety contract — /health', () => {
  afterEach(() => readinessState._reset());

  it('never exposes a banned key in any readiness state', async () => {
    const app = express();
    app.use('/health', healthRouter);

    for (const ready of [true, false]) {
      readinessState.setReady(ready);
      const res = await request(app).get('/health');
      assertNoSensitiveKeys(res.body);
    }
  });

  it('response body is exactly the documented minimal shape', async () => {
    const app = express();
    app.use('/health', healthRouter);
    const res = await request(app).get('/health');
    expect(Object.keys(res.body).sort()).toEqual(['status', 'uptime']);
  });
});

describe('content-safety contract — /ready', () => {
  afterEach(() => readinessState._reset());

  it('never exposes a banned key in any readiness state', async () => {
    const app = express();
    app.use('/ready', readyRouter);

    for (const ready of [true, false]) {
      readinessState.setReady(ready);
      const res = await request(app).get('/ready');
      assertNoSensitiveKeys(res.body);
    }
  });

  it('response body is exactly the documented minimal shape', async () => {
    const app = express();
    app.use('/ready', readyRouter);
    readinessState.setReady(true);
    const res = await request(app).get('/ready');
    expect(Object.keys(res.body).sort()).toEqual(['components', 'ready']);
    // Component values must be booleans only — never descriptive strings,
    // error messages, or connection details (that level of detail belongs
    // exclusively behind /diagnostics, which stays fully authenticated).
    for (const v of Object.values(res.body.components)) {
      expect(typeof v).toBe('boolean');
    }
  });
});
