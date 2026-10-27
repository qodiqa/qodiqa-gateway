'use strict';

const SECRET = 'c'.repeat(64);

function withSecret(fn) {
  const saved = process.env.QODIQA_PORTAL_SESSION_SECRET;
  process.env.QODIQA_PORTAL_SESSION_SECRET = SECRET;
  try {
    return fn();
  } finally {
    if (saved === undefined) delete process.env.QODIQA_PORTAL_SESSION_SECRET;
    else process.env.QODIQA_PORTAL_SESSION_SECRET = saved;
  }
}

describe('oidcFlowState', () => {
  test('round trip: mint then verify returns the same nonce/codeVerifier', () => {
    withSecret(() => {
      const { mintFlowState, verifyFlowState } = require('../oidcFlowState');
      const state = mintFlowState({ nonce: 'n1', codeVerifier: 'cv1' });
      const result = verifyFlowState(state);
      expect(result).toEqual({ nonce: 'n1', codeVerifier: 'cv1' });
    });
  });

  test('two mints of the SAME inputs produce DIFFERENT state values (random csrf component)', () => {
    withSecret(() => {
      const { mintFlowState } = require('../oidcFlowState');
      const a = mintFlowState({ nonce: 'n1', codeVerifier: 'cv1' });
      const b = mintFlowState({ nonce: 'n1', codeVerifier: 'cv1' });
      expect(a).not.toBe(b);
    });
  });

  test('tampered state fails verification', () => {
    withSecret(() => {
      const { mintFlowState, verifyFlowState } = require('../oidcFlowState');
      const state = mintFlowState({ nonce: 'n1', codeVerifier: 'cv1' });
      const [body] = state.split('.');
      expect(verifyFlowState(`${body}.${'0'.repeat(64)}`)).toBeNull();
    });
  });

  test('expired state (>5 minutes old) fails verification', () => {
    withSecret(() => {
      const { mintFlowState, verifyFlowState, FLOW_STATE_TTL_MS } = require('../oidcFlowState');
      const state = mintFlowState({ nonce: 'n1', codeVerifier: 'cv1' });
      expect(verifyFlowState(state, { _now: Date.now() + FLOW_STATE_TTL_MS + 1 })).toBeNull();
    });
  });

  test('malformed/garbage input never throws and returns null', () => {
    withSecret(() => {
      const { verifyFlowState } = require('../oidcFlowState');
      for (const g of [undefined, null, 123, {}, 'no-dot', 'a.notHex']) {
        expect(() => verifyFlowState(g)).not.toThrow();
        expect(verifyFlowState(g)).toBeNull();
      }
    });
  });

  test('mintFlowState rejects empty nonce/codeVerifier', () => {
    withSecret(() => {
      const { mintFlowState } = require('../oidcFlowState');
      expect(() => mintFlowState({ nonce: '', codeVerifier: 'cv1' })).toThrow(TypeError);
      expect(() => mintFlowState({ nonce: 'n1', codeVerifier: '' })).toThrow(TypeError);
    });
  });
});
