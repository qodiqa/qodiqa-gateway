'use strict';

const {
  SigningCircuitBreaker,
  getCircuitBreaker,
  resetAll,
  snapshot,
  STATE_CLOSED,
  STATE_OPEN,
  STATE_HALF_OPEN,
} = require('../circuitBreaker');

const CONFIG = Object.freeze({
  cbFailureThreshold: 3,
  cbSuccessThreshold: 2,
  cbWindowMs:         60_000,
  cbRecoveryMs:       50,
});

afterEach(() => resetAll());

describe('SigningCircuitBreaker — state machine', () => {
  test('starts CLOSED and allows requests', () => {
    const cb = new SigningCircuitBreaker('vault:transit:test', CONFIG);
    expect(cb.state).toBe(STATE_CLOSED);
    expect(cb.allowRequest()).toBe(true);
  });

  test('opens after cbFailureThreshold consecutive failures', () => {
    const cb = new SigningCircuitBreaker('vault:transit:test', CONFIG);
    cb.onFailure();
    cb.onFailure();
    expect(cb.state).toBe(STATE_CLOSED); // below threshold
    cb.onFailure();
    expect(cb.state).toBe(STATE_OPEN);
  });

  test('while OPEN, rejects immediately without any wait', () => {
    const cb = new SigningCircuitBreaker('vault:transit:test', CONFIG);
    for (let i = 0; i < CONFIG.cbFailureThreshold; i++) cb.onFailure();
    expect(cb.state).toBe(STATE_OPEN);
    expect(cb.allowRequest()).toBe(false);
  });

  test('a success resets the consecutive-failure counter while CLOSED', () => {
    const cb = new SigningCircuitBreaker('vault:transit:test', CONFIG);
    cb.onFailure();
    cb.onFailure();
    cb.onSuccess();
    cb.onFailure();
    cb.onFailure();
    expect(cb.state).toBe(STATE_CLOSED); // counter was reset, only 2 consecutive now
  });

  test('transitions OPEN -> HALF_OPEN after cbRecoveryMs elapses', async () => {
    const cb = new SigningCircuitBreaker('vault:transit:test', CONFIG);
    for (let i = 0; i < CONFIG.cbFailureThreshold; i++) cb.onFailure();
    expect(cb.state).toBe(STATE_OPEN);

    await new Promise((r) => setTimeout(r, CONFIG.cbRecoveryMs + 10));
    expect(cb.allowRequest()).toBe(true); // the probe
    expect(cb.state).toBe(STATE_HALF_OPEN);
  });

  test('HALF_OPEN -> CLOSED after cbSuccessThreshold consecutive successes', async () => {
    const cb = new SigningCircuitBreaker('vault:transit:test', CONFIG);
    for (let i = 0; i < CONFIG.cbFailureThreshold; i++) cb.onFailure();
    await new Promise((r) => setTimeout(r, CONFIG.cbRecoveryMs + 10));
    cb.allowRequest(); // -> HALF_OPEN

    cb.onSuccess();
    expect(cb.state).toBe(STATE_HALF_OPEN); // one success, threshold is 2
    cb.onSuccess();
    expect(cb.state).toBe(STATE_CLOSED);
  });

  test('HALF_OPEN -> OPEN immediately on any failure', async () => {
    const cb = new SigningCircuitBreaker('vault:transit:test', CONFIG);
    for (let i = 0; i < CONFIG.cbFailureThreshold; i++) cb.onFailure();
    await new Promise((r) => setTimeout(r, CONFIG.cbRecoveryMs + 10));
    cb.allowRequest(); // -> HALF_OPEN

    cb.onFailure();
    expect(cb.state).toBe(STATE_OPEN);
  });

  test('concurrent callers in HALF_OPEN: exactly one probe is admitted, the rest are rejected', async () => {
    const cb = new SigningCircuitBreaker('vault:transit:test', CONFIG);
    for (let i = 0; i < CONFIG.cbFailureThreshold; i++) cb.onFailure();
    await new Promise((r) => setTimeout(r, CONFIG.cbRecoveryMs + 10));

    // Simulate 50 concurrent callers racing allowRequest() the instant recovery elapses.
    const decisions = Array.from({ length: 50 }, () => cb.allowRequest());
    const admitted = decisions.filter(Boolean).length;
    expect(admitted).toBe(1);
    expect(cb.state).toBe(STATE_HALF_OPEN);
  });

  test('after a HALF_OPEN probe resolves, a new probe can be admitted', async () => {
    const cb = new SigningCircuitBreaker('vault:transit:test', CONFIG);
    for (let i = 0; i < CONFIG.cbFailureThreshold; i++) cb.onFailure();
    await new Promise((r) => setTimeout(r, CONFIG.cbRecoveryMs + 10));

    expect(cb.allowRequest()).toBe(true);
    expect(cb.allowRequest()).toBe(false); // second concurrent caller blocked
    cb.onFailure(); // probe failed -> back to OPEN, probe slot released

    expect(cb.state).toBe(STATE_OPEN);
    expect(cb.allowRequest()).toBe(false); // recovery window hasn't elapsed again yet
  });
});

describe('SigningCircuitBreaker registry', () => {
  test('getCircuitBreaker returns the same instance for the same provider name', () => {
    const a = getCircuitBreaker('aws:kms:test', CONFIG);
    const b = getCircuitBreaker('aws:kms:test', CONFIG);
    expect(a).toBe(b);
  });

  test('different provider names get independent breakers', () => {
    const a = getCircuitBreaker('aws:kms:test', CONFIG);
    const b = getCircuitBreaker('azure:kv:test', CONFIG);
    for (let i = 0; i < CONFIG.cbFailureThreshold; i++) a.onFailure();
    expect(a.state).toBe(STATE_OPEN);
    expect(b.state).toBe(STATE_CLOSED);
  });

  test('snapshot() reports state for every registered breaker', () => {
    const a = getCircuitBreaker('gcp:kms:test', CONFIG);
    a.onFailure();
    const snap = snapshot();
    expect(snap['gcp:kms:test']).toMatchObject({ state: STATE_CLOSED, consecutiveFails: 1 });
  });

  test('resetAll() clears the registry', () => {
    getCircuitBreaker('hsm:pkcs11:test', CONFIG);
    resetAll();
    expect(snapshot()).toEqual({});
  });
});
