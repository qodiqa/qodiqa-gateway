'use strict';

/**
 * The ONLY place the core reaches the enterprise identity module. `get()` returns the module's public surface (enterprise/identity/index.js) or null when the directory is
 * not installed - a deployment without it runs unchanged (API keys only) and a configuration that asks for federation fails at boot. Tests may install a stand-in with `_set()`.
 * Documented in docs/guides/IDENTITY.md.
 */
let _mod; let _forced = false;

function get() {
  if (_forced) return _mod;
  if (_mod !== undefined) return _mod;
  try { _mod = require('../../../enterprise/identity'); } catch (e) { if (e && e.code === 'MODULE_NOT_FOUND' && /enterprise[\/]identity/.test(String(e.message))) _mod = null; else throw e; }
  return _mod;
}

function _set(mod) { _mod = mod; _forced = mod !== undefined; }
module.exports = { get, isAvailable: () => get() !== null, _set };
