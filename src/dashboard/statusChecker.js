'use strict';

/**
 * Dashboard status checker — delegates component health to HealthRegistry.
 *
 * Additional components registered on the HealthRegistry singleton after
 * server startup (e.g. a database connection) will automatically appear in
 * the /dashboard/status response without modifying this file.
 *
 * The output shape is preserved exactly from the previous implementation
 * so that the dashboard route and all existing tests require zero changes.
 */

const healthRegistry = require('./health');
const readinessState = require('../runtime/readinessState');

let _version = 'unknown';
try { _version = require('../../package.json').version; } catch { /* ignore */ }

function getStatus() {
  return {
    service:            'qodiqa',
    version:            _version,
    status:             readinessState.isReady() ? 'ready' : 'not_ready',
    executionIntegrity: healthRegistry.executionIntegrity(),
    uptime:             process.uptime(),
    pid:                process.pid,
    nodeVersion:        process.version,
    memoryMb:           Math.round(process.memoryUsage().rss / 1_048_576),
    components:         healthRegistry.getAllStatus(),
    timestamp:          new Date().toISOString(),
  };
}

module.exports = { getStatus };
