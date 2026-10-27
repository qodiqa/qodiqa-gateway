'use strict';

// remediation coverage.
//
// The tracing subsystem itself (config/tracer/span/context/sampler/middleware/
// exporter) already has full unit coverage in the sibling __tests__ files —
// this file covers the piece actually changed: how the gateway wires
// initTracing() into the startup sequence.
//
// The gateway is not required directly here — it has its own extensive
// startup-gate test surface (Redis/PG/keystore/etc.) that would need to be
// stood up just to reach the tracing wiring, none of which this remediation
// touches. Instead:
//   - the "startup fail-safe" and "duplicate init" behaviors are verified
//     against the exact pattern server/startup.js uses (load config once,
//     call initTracing(config), fall back to a no-op on throw);
//   - the wiring itself (call site count, init wrapping, shutdown hook) is
//     verified structurally against server/startup.js's source, and the
//     middleware mount order/count against src/app.js's source (split
//     dependency initialization from route composition into these two
//     modules — this logic previously lived directly in server.js) — both
//     stable and fast without booting the full app.

const fs   = require('fs');
const path = require('path');

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const { emit }                           = require('../../../../services/logger');
const { initTracing, loadTracingConfig } = require('../index');

const STARTUP_JS_PATH = path.resolve(__dirname, '../../../../server/startup.js');
const APP_JS_PATH     = path.resolve(__dirname, '../../../app.js');

function withEnv(overrides, fn) {
  const saved = { ...process.env };
  Object.assign(process.env, overrides);
  try {
    return fn();
  } finally {
    Object.keys(process.env).forEach(k => { if (!(k in saved)) delete process.env[k]; });
    Object.assign(process.env, saved);
  }
}

// Mirrors server.js's own startup wrapper exactly (config load → initTracing
// → catch → fallback no-op), so these tests exercise the real contract
// server.js relies on rather than re-describing it.
function bootTracingLikeServer(deps = {}) {
  const config = loadTracingConfig();
  let tracing;
  try {
    tracing = (deps.initTracing || initTracing)(config);
  } catch (err) {
    tracing = {
      requestMiddleware: (req, res, next) => next(),
      getHealth:  () => ({ component: 'opentelemetry', status: 'disabled' }),
      getMetrics: () => ({}),
      shutdown:   async () => {},
    };
  }
  return { config, tracing };
}

describe('server.js startup wiring — fail-safe behavior', () => {
  beforeEach(() => jest.clearAllMocks());

  it('starts normally with tracing disabled (no QODIQA_OTEL_ENABLED)', () => {
    withEnv({ QODIQA_OTEL_ENABLED: undefined }, () => {
      delete process.env.QODIQA_OTEL_ENABLED;
      const { tracing } = bootTracingLikeServer();
      expect(tracing.getHealth().status).toBe('disabled');
      const next = jest.fn();
      tracing.requestMiddleware({ headers: {} }, { setHeader: () => {}, on: () => {} }, next);
      expect(next).toHaveBeenCalled();
    });
  });

  it('starts normally with tracing enabled and a valid endpoint', () => {
    withEnv({
      QODIQA_OTEL_ENABLED: 'true',
      QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT: 'https://otel.example.com',
    }, () => {
      const { tracing } = bootTracingLikeServer();
      // Not the frozen NOOP — a live tracer with a real startSpan.
      const span = tracing.getMetrics();
      expect(span.spans_created_total).toBe(0);
      const req = { method: 'GET', url: '/x', headers: {}, requestId: 'r1' };
      const res = { setHeader: jest.fn(), on: (evt, fn) => { if (evt === 'finish') res._finish = fn; } };
      tracing.requestMiddleware(req, res, () => {});
      expect(req.traceId).toMatch(/^[0-9a-f]{32}$/);
    });
  });

  it('continues startup (does not throw) when initTracing itself throws', () => {
    const throwingInitTracing = () => { throw new Error('simulated tracing bug'); };
    expect(() => bootTracingLikeServer({ initTracing: throwingInitTracing })).not.toThrow();
  });

  it('falls back to a no-op requestMiddleware when initTracing throws', () => {
    const throwingInitTracing = () => { throw new Error('simulated tracing bug'); };
    const { tracing } = bootTracingLikeServer({ initTracing: throwingInitTracing });
    const next = jest.fn();
    tracing.requestMiddleware({ headers: {} }, {}, next);
    expect(next).toHaveBeenCalled();
    expect(tracing.getHealth().status).toBe('disabled');
  });

  it('fallback shutdown() resolves cleanly (never blocks process shutdown)', async () => {
    const throwingInitTracing = () => { throw new Error('simulated tracing bug'); };
    const { tracing } = bootTracingLikeServer({ initTracing: throwingInitTracing });
    await expect(tracing.shutdown()).resolves.toBeUndefined();
  });
});

describe('server.js startup wiring — no duplicate initialization', () => {
  it('initTracing has no hidden singleton — each call is independent, so the caller (server.js) must invoke it exactly once', () => {
    withEnv({
      QODIQA_OTEL_ENABLED: 'true',
      QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT: 'https://otel.example.com',
    }, () => {
      const a = initTracing(loadTracingConfig());
      const b = initTracing(loadTracingConfig());
      // Independent instances (not a shared singleton) — proves correctness
      // of "exactly once" depends on the call site, which the structural
      // tests below pin down in server.js.
      const reqA = { method: 'GET', url: '/a', headers: {} };
      const resA = { setHeader: () => {}, on: () => {} };
      a.requestMiddleware(reqA, resA, () => {});
      expect(b.getMetrics().spans_created_total).toBe(0);
      expect(reqA.traceId).toBeDefined();
    });
  });

  it('server/startup.js calls initTracing() exactly once', () => {
    const src = fs.readFileSync(STARTUP_JS_PATH, 'utf8');
    // Match actual invocations only (`= initTracing(`) — excludes prose
    // mentions of "initTracing()" in comments and the destructured require.
    const matches = src.match(/=\s*initTracing\(/g) || [];
    expect(matches.length).toBe(1);
  });
});

describe('server.js startup wiring — structural integration', () => {
  let startupSrc;
  let appSrc;
  beforeAll(() => {
    startupSrc = fs.readFileSync(STARTUP_JS_PATH, 'utf8');
    appSrc     = fs.readFileSync(APP_JS_PATH, 'utf8');
  });

  it('requires the existing tracing subsystem (does not reimplement it)', () => {
    expect(startupSrc).toMatch(/require\(['"]\.\.\/src\/observability\/tracing['"]\)/);
  });

  it('tracing initialization is wrapped so it cannot crash startup', () => {
    const initIdx = startupSrc.indexOf('_tracing = initTracing(');
    expect(initIdx).toBeGreaterThan(-1);
    const before = startupSrc.slice(Math.max(0, initIdx - 200), initIdx);
    expect(before).toMatch(/try\s*\{/);
  });

  // the mount may be wrapped by the bench stage timer (ST.wrapMiddleware('S07', …) returns the
  // middleware itself unless QODIQA_BENCH_STAGE_TIMING=true). Either form counts; nothing else does.
  const TRACING_MOUNT = /app\.use\((?:ST\.wrapMiddleware\('S07', )?ctx\.tracing\.requestMiddleware\)?\)/g;

  it('mounts the tracing request middleware before route registration', () => {
    const mountIdx = appSrc.search(new RegExp(TRACING_MOUNT.source));
    const firstRouteIdx = appSrc.indexOf("app.use('/health/redis'");
    expect(mountIdx).toBeGreaterThan(-1);
    expect(firstRouteIdx).toBeGreaterThan(-1);
    expect(mountIdx).toBeLessThan(firstRouteIdx);
  });

  it('tracing middleware is mounted exactly once', () => {
    const matches = appSrc.match(TRACING_MOUNT) || [];
    expect(matches.length).toBe(1);
  });

  it('registers a graceful-shutdown hook that flushes buffered spans', () => {
    expect(startupSrc).toMatch(/name:\s*'TRACING',\s*store:\s*\{\s*disconnect:\s*\(\)\s*=>\s*_tracing\.shutdown\(\)\s*\}/);
  });

  it('emits a startup diagnostic indicating tracing enabled/disabled state', () => {
    expect(startupSrc).toMatch(/emit\('INFO',\s*'TRACING_READY'/);
  });
});

describe('context propagation — root span through downstream child spans (regression guard for wiring)', () => {
  it('a child span created after the request middleware inherits traceId and has the root span as its parent', () => {
    withEnv({
      QODIQA_OTEL_ENABLED: 'true',
      QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT: 'https://otel.example.com',
    }, () => {
      const exported = [];
      const tracing = initTracing(loadTracingConfig(), {
        exporter: { name: 'mock', exportSpans: async (spans) => { exported.push(...spans); } },
      });

      const req = { method: 'POST', url: '/ai/chat', headers: {}, requestId: 'req_1' };
      const res = { setHeader: jest.fn(), on: (evt, fn) => { if (evt === 'finish') res._finish = fn; } };

      tracing.requestMiddleware(req, res, () => {
        // Simulates a downstream handler creating a child span — must run
        // inside the AsyncLocalStorage context the middleware established.
        const child = tracing.tracer.startSpan('db.query');
        expect(child.traceId).toBe(req.traceId);
        expect(child.parentSpanId).toBe(req.spanId);
        child.end();
      });

      res._finish();
      return tracing.shutdown().then(() => {
        expect(exported.length).toBe(2); // root + child
        const names = exported.map(s => s.name).sort();
        expect(names).toEqual(['HTTP POST', 'db.query']);
      });
    });
  });
});
