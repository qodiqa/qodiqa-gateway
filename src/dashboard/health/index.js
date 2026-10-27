'use strict';

/**
 * HealthRegistry singleton pre-populated with the three core Redis store
 * components.  Additional components can be registered at any point before
 * or after server startup via registry.register().
 */

const { HealthRegistry } = require('./HealthRegistry');

const registry = new HealthRegistry();

registry
  .register(
    'nonceStore',
    'Nonce Store (Replay Protection)',
    () => require('../../validation/nonceStore').isReady(),
  )
  .register(
    'anomalyStore',
    'Anomaly Store (Burst Detection)',
    () => require('../../validation/anomalyStore').isReady(),
  )
  .register(
    'rateLimitStore',
    'Rate Limit Store (Policy Enforcement)',
    () => require('../../../services/policy/store').isReady(),
  );

module.exports = registry;
