'use strict';

const { emit } = require('../../logger');

const VALID_KEY_BY = new Set(['userId', 'ip']);

function validate(config) {
  if (typeof config.windowSeconds !== 'number' || config.windowSeconds <= 0 || !Number.isFinite(config.windowSeconds)) {
    throw new Error('config.windowSeconds must be a positive finite number');
  }
  if (typeof config.maxRequests !== 'number' || config.maxRequests <= 0 || !Number.isInteger(config.maxRequests)) {
    throw new Error('config.maxRequests must be a positive integer');
  }
  if (!VALID_KEY_BY.has(config.keyBy)) {
    throw new Error(`config.keyBy must be one of: ${[...VALID_KEY_BY].join(', ')}`);
  }
}

function preprocess(config) {
  return config;
}

// Calls the store's atomic admission check directly — no pre-built snapshot,
// no separate commit phase. store.checkAndIncrement() performs the read,
// the admission decision, and the increment as one atomic operation, so
// concurrent requests can never read the same stale count and both pass
// (see services/policy/store.js for the atomicity guarantee).
async function evaluate(context, config, store) {
  const contextKey = context[config.keyBy];
  if (!contextKey) {
    return { pass: false, reason: 'RATE_LIMIT_KEY_MISSING' };
  }

  const key = `${config.policyId}:${contextKey}`;

  let result;
  try {
    result = await store.checkAndIncrement(key, config.windowSeconds, config.maxRequests);
  } catch {
    // Store unavailable — fail closed. Matches the prior behaviour where a
    // failed read was treated as an unbounded count, i.e. always over limit.
    return { pass: false, reason: 'RATE_LIMIT_EXCEEDED' };
  }

  if (!result.allowed) {
    emit('WARN', 'POLICY_RATE_LIMIT_EXCEEDED', {
      policyId:         config.policyId,
      contextKey,
      count:            result.count,
      threshold:        config.maxRequests,
      windowSeconds:    config.windowSeconds,
      executionBlocked: true,
    });
    return { pass: false, reason: 'RATE_LIMIT_EXCEEDED' };
  }

  return { pass: true };
}

// Batched form of evaluate() for genuinely-consecutive RATE_LIMIT policies
// (item 16 — pipeline the rate-limit lookups). Evaluates `configs` in the
// SAME order the sequential engine loop would, using exactly one store
// round trip for the store-backed portion, while reproducing every
// short-circuit rule evaluate() has:
//   - a config whose keyBy field is absent from context blocks WITHOUT ever
//     reaching the store, exactly like evaluate() — so only the contiguous
//     prefix of configs before the first such gap is even sent to the store;
//   - the first store-backed denial stops evaluation of every later config
//     in the run, real or synthetic — none of them are read, incremented,
//     or attributed a result.
// Returns an array no longer than configs.length; a shorter array means the
// run stopped early, mirroring evaluate()'s own short-circuit-and-return.
async function evaluateBatch(context, configs, store) {
  const prefix = [];       // configs safe to send to the store, in order
  let keyMissing = false;  // true once a config with no context key is hit

  for (const config of configs) {
    const contextKey = context[config.keyBy];
    if (!contextKey) { keyMissing = true; break; }
    prefix.push({ config, key: `${config.policyId}:${contextKey}` });
  }

  const results = [];

  if (prefix.length > 0) {
    let raw;
    try {
      raw = await store.checkAndIncrementBatch(
        prefix.map(p => ({ key: p.key, windowSeconds: p.config.windowSeconds, maxRequests: p.config.maxRequests })),
      );
    } catch {
      // Store unavailable — fail closed on the first config in the run,
      // matching evaluate()'s single-check catch-and-deny behaviour.
      return [{ pass: false, reason: 'RATE_LIMIT_EXCEEDED' }];
    }

    for (let k = 0; k < raw.length; k++) {
      const { allowed, count } = raw[k];
      const config = prefix[k].config;
      if (!allowed) {
        emit('WARN', 'POLICY_RATE_LIMIT_EXCEEDED', {
          policyId:         config.policyId,
          contextKey:       context[config.keyBy],
          count,
          threshold:        config.maxRequests,
          windowSeconds:    config.windowSeconds,
          executionBlocked: true,
        });
        results.push({ pass: false, reason: 'RATE_LIMIT_EXCEEDED' });
        return results;
      }
      results.push({ pass: true });
    }
  }

  if (keyMissing) {
    results.push({ pass: false, reason: 'RATE_LIMIT_KEY_MISSING' });
  }

  return results;
}

module.exports = { validate, preprocess, evaluate, evaluateBatch };
