'use strict';

/**
 * Kill-switch gate: mounted in front of `/sign` and `/ai/chat` (every alias). While the global kill switch is active
 * the request is answered BLOCK KILL_SWITCH_ACTIVE (HTTP 503, Retry-After) before any other work: nothing is signed, no
 * nonce is consumed, no provider is called, no audit entry or transparency leaf is written for the refused request.
 *
 * If the state cannot be determined (the control-plane snapshot is stale: older than 5 s) the gate refuses too — BLOCK
 * KILL_SWITCH_STATE_UNAVAILABLE, 503 — because "cannot be sure it is off" must not mean "on". Reading the state is a map
 * lookup plus a cached MAC check, so the gate adds no measurable latency when the switch is off.
 */

// Middleware never imports Core (rule no-middleware-to-core): the kill-switch implementation is injected once at startup (src/app.js). Until it is injected the gate
// fails closed (the state cannot be read, so the request is refused).
let killSwitch = null;
function setKillSwitch(impl) { killSwitch = impl; }
const { emit } = require('../../services/logger');

const RETRY_AFTER_SECONDS = 30;

function _metrics() { try { return require('../observability/metrics'); } catch { return null; } }

function createKillSwitchGate({ route } = {}) {
  return function killSwitchGate(req, res, next) {
    let s;
    try {
      s = killSwitch.state();
    } catch (err) {
      const m = _metrics();
      if (m && m.killSwitchBlocksTotal) m.killSwitchBlocksTotal.inc({ route: route || 'unknown', cause: 'state_unavailable' });
      emit('ERROR', 'KILL_SWITCH_STATE_UNAVAILABLE', { route: route || null, error: err.message, code: err.code ?? null });
      res.set('Retry-After', String(RETRY_AFTER_SECONDS));
      return res.status(503).json({ decision: 'BLOCK', reason: 'KILL_SWITCH_STATE_UNAVAILABLE', details: {}, requestId: req.requestId ?? null });
    }
    if (!s.active) return next();
    const m = _metrics();
    if (m && m.killSwitchBlocksTotal) m.killSwitchBlocksTotal.inc({ route: route || 'unknown', cause: s.tampered ? 'tampered' : 'active' });
    res.set('Retry-After', String(RETRY_AFTER_SECONDS));
    return res.status(503).json({ decision: 'BLOCK', reason: 'KILL_SWITCH_ACTIVE', details: {}, requestId: req.requestId ?? null });
  };
}

module.exports = { createKillSwitchGate, setKillSwitch, RETRY_AFTER_SECONDS };
