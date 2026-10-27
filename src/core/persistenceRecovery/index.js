'use strict';

/**
 * Persistence Recovery Queue — public API barrel — Component #13/#32
 */

const recoveryManager = require('./recoveryManager');
const dlqManager      = require('./dlqManager');
const journal         = require('./journal');

module.exports = {
  setCommitWriter:      recoveryManager.setCommitWriter,
  initialize:           recoveryManager.initialize,
  shutdown:             recoveryManager.shutdown,
  enqueue:              recoveryManager.enqueue,
  enqueueWithOutcome:   recoveryManager.enqueueWithOutcome,
  hasPendingCommit:     recoveryManager.hasPendingCommit,
  enqueueWebhookDelivery: recoveryManager.enqueueWebhookDelivery,
  isEnabled:            recoveryManager.isEnabled,
  getStats:             recoveryManager.getStats,
  listDlq:              recoveryManager.listDlq,
  isPersistenceFailure: recoveryManager.isPersistenceFailure,
  OPERATION_TYPES:      recoveryManager.OPERATION_TYPES,

  // DLQ management (Component #32)
  dlq: dlqManager,

  // Filesystem recovery journal (FAILOVER-1)
  journal,
};
