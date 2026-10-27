'use strict';

/**
 * The ONLY place the core reaches the DLP module. `get()` returns the module's public surface (enterprise/dlp/index.js) or null when the directory is not
 * installed - a deployment without it runs unchanged, and a policy that needs it refuses to load (services/policy/evaluators/dlp.js). Tests may install a stand-in with
 * `_set()`. Documented in docs/guides/DLP.md.
 */
let _mod; let _forced = false;

function get() {
  if (_forced) return _mod;
  if (_mod !== undefined) return _mod;
  try { _mod = require('../../../enterprise/dlp'); } catch (e) { if (e && e.code === 'MODULE_NOT_FOUND' && /enterprise[\/]dlp/.test(String(e.message))) _mod = null; else throw e; }
  return _mod;
}

function _set(mod) { _mod = mod; _forced = mod !== undefined; }
module.exports = { get, isAvailable: () => get() !== null, _set };
