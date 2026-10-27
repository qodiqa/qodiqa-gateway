'use strict';

const registry   = require('./ConsentRegistry');
const model      = require('./ConsentStateModel');
const publisher  = require('./revocation/RevocationPublisher');
const subscriber = require('./revocation/RevocationSubscriber');

module.exports = {
  // Lifecycle
  grant:       registry.grant,
  revoke:      registry.revoke,
  suspend:     registry.suspend,
  resume:      registry.resume,
  revokeAll:   registry.revokeAll,

  // Verification (enforcement hot path)
  verify:      registry.verify,

  // Reads
  get:         registry.get,
  getById:     registry.getById,
  list:        registry.list,
  getAuditLog: registry.getAuditLog,

  // Health
  health:      registry.health,

  // State model constants (for API consumers)
  STATE: model.STATE,

  // Instant revocation propagation (Component #19)
  revocationPublisher: {
    isReady:    publisher.isReady,
    disconnect: publisher.disconnect,
  },
  revocationSubscriber: {
    start:     subscriber.start,
    stop:      subscriber.stop,
    isReady:   subscriber.isReady,
    isStarted: subscriber.isStarted,
  },
};
