'use strict';

const { emitStartupDiagnostics, emitClockDiagnostics } = require('../startupDiagnostics');
// THROUGHPUT-12: services/logger.js now batches INFO/WARN/ERROR stdout writes
// and flushes asynchronously (see that file's header comment). Every test
// below awaits flush() right after the emit-triggering call so it observes
// the same synchronously-written record it always did — no assertion here
// changed, only when the write is guaranteed to have happened.
const { flush } = require('../../../services/logger');

// ── Test lifecycle ────────────────────────────────────────────────────────────

let written;
let writeSpy;

beforeEach(() => {
  written  = [];
  writeSpy = jest.spyOn(process.stdout, 'write').mockImplementation(data => {
    if (typeof data === 'string') written.push(data);
    return true;
  });
});

afterEach(() => {
  writeSpy.mockRestore();
});

function events() {
  // A single write() call may contain multiple '\n'-joined records (batched
  // stdout flush — see services/logger.js), including ones emitted by
  // test/support/jest.setup.js's key-store provisioning before this test file's own spy
  // was installed — split before parsing.
  return written
    .join('')
    .split('\n')
    .filter(line => line.trim())
    .map(line => { try { return JSON.parse(line); } catch { return null; } })
    .filter(Boolean);
}

// ── STARTUP_DIAGNOSTICS ───────────────────────────────────────────────────────

describe('emitStartupDiagnostics', () => {
  it('emits exactly one STARTUP_DIAGNOSTICS event', async () => {
    emitStartupDiagnostics({ activeKeys: 1, policyCount: 3 });
    await flush();
    const diags = events().filter(e => e.eventType === 'STARTUP_DIAGNOSTICS');
    expect(diags).toHaveLength(1);
  });

  it('event contains nodeVersion matching process.version', async () => {
    emitStartupDiagnostics();
    await flush();
    const ev = events().find(e => e.eventType === 'STARTUP_DIAGNOSTICS');
    expect(ev.nodeVersion).toBe(process.version);
  });

  it('event contains environment (string)', async () => {
    emitStartupDiagnostics();
    await flush();
    const ev = events().find(e => e.eventType === 'STARTUP_DIAGNOSTICS');
    expect(typeof ev.environment).toBe('string');
  });

  it('event contains pid equal to process.pid', async () => {
    emitStartupDiagnostics();
    await flush();
    const ev = events().find(e => e.eventType === 'STARTUP_DIAGNOSTICS');
    expect(ev.pid).toBe(process.pid);
  });

  it('event contains startupTimestamp as an ISO 8601 string', async () => {
    emitStartupDiagnostics();
    await flush();
    const ev = events().find(e => e.eventType === 'STARTUP_DIAGNOSTICS');
    expect(typeof ev.startupTimestamp).toBe('string');
    expect(() => new Date(ev.startupTimestamp)).not.toThrow();
    expect(new Date(ev.startupTimestamp).toISOString()).toBe(ev.startupTimestamp);
  });

  it('event contains redisUrl as a non-empty string', async () => {
    emitStartupDiagnostics();
    await flush();
    const ev = events().find(e => e.eventType === 'STARTUP_DIAGNOSTICS');
    expect(typeof ev.redisUrl).toBe('string');
    expect(ev.redisUrl.length).toBeGreaterThan(0);
  });

  it('event contains redisAuthConfigured, redisTlsEnabled, redisTlsVerified as booleans', async () => {
    emitStartupDiagnostics();
    await flush();
    const ev = events().find(e => e.eventType === 'STARTUP_DIAGNOSTICS');
    expect(typeof ev.redisAuthConfigured).toBe('boolean');
    expect(typeof ev.redisTlsEnabled).toBe('boolean');
    expect(typeof ev.redisTlsVerified).toBe('boolean');
  });

  it('event contains auditLogConfigured (boolean) and auditLogPath (string)', async () => {
    emitStartupDiagnostics();
    await flush();
    const ev = events().find(e => e.eventType === 'STARTUP_DIAGNOSTICS');
    expect(typeof ev.auditLogConfigured).toBe('boolean');
    expect(typeof ev.auditLogPath).toBe('string');
  });

  it('event reflects the activeKeys value passed in', async () => {
    emitStartupDiagnostics({ activeKeys: 2 });
    await flush();
    const ev = events().find(e => e.eventType === 'STARTUP_DIAGNOSTICS');
    expect(ev.activeSigningKeys).toBe(2);
  });

  it('event reflects the policyCount value passed in', async () => {
    emitStartupDiagnostics({ policyCount: 5 });
    await flush();
    const ev = events().find(e => e.eventType === 'STARTUP_DIAGNOSTICS');
    expect(ev.policiesLoaded).toBe(5);
  });

  it('never logs the raw QODIQA_KEY_ENCRYPTION_KEY value', async () => {
    const kek = process.env.QODIQA_KEY_ENCRYPTION_KEY;
    if (!kek) return; // env not set in this context — skip

    emitStartupDiagnostics({ activeKeys: 1, policyCount: 1 });
    await flush();
    const output = written.join('');
    expect(output).not.toContain(kek);
  });

  it('never logs the raw REDIS_PASSWORD value when set', async () => {
    const prev = process.env.REDIS_PASSWORD;
    process.env.REDIS_PASSWORD = 'super-secret-redis-pass';
    try {
      emitStartupDiagnostics({ activeKeys: 1, policyCount: 1 });
      await flush();
      const output = written.join('');
      expect(output).not.toContain('super-secret-redis-pass');
    } finally {
      if (prev === undefined) delete process.env.REDIS_PASSWORD;
      else process.env.REDIS_PASSWORD = prev;
    }
  });
});

// ── CLOCK_DIAGNOSTICS ─────────────────────────────────────────────────────────

describe('emitClockDiagnostics', () => {
  it('emits exactly one CLOCK_DIAGNOSTICS event', async () => {
    emitClockDiagnostics();
    await flush();
    const clocks = events().filter(e => e.eventType === 'CLOCK_DIAGNOSTICS');
    expect(clocks).toHaveLength(1);
  });

  it('event contains utcTime as an ISO 8601 string', async () => {
    emitClockDiagnostics();
    await flush();
    const ev = events().find(e => e.eventType === 'CLOCK_DIAGNOSTICS');
    expect(typeof ev.utcTime).toBe('string');
    expect(ev.utcTime).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
  });

  it('event contains localTime as a non-empty string', async () => {
    emitClockDiagnostics();
    await flush();
    const ev = events().find(e => e.eventType === 'CLOCK_DIAGNOSTICS');
    expect(typeof ev.localTime).toBe('string');
    expect(ev.localTime.length).toBeGreaterThan(0);
  });

  it('event contains timezone as a non-empty string', async () => {
    emitClockDiagnostics();
    await flush();
    const ev = events().find(e => e.eventType === 'CLOCK_DIAGNOSTICS');
    expect(typeof ev.timezone).toBe('string');
    expect(ev.timezone.length).toBeGreaterThan(0);
  });

  it('event contains offsetMinutes as a number', async () => {
    emitClockDiagnostics();
    await flush();
    const ev = events().find(e => e.eventType === 'CLOCK_DIAGNOSTICS');
    expect(typeof ev.offsetMinutes).toBe('number');
    expect(Number.isFinite(ev.offsetMinutes)).toBe(true);
  });
});
