'use strict';

const { EventEmitter }     = require('events');
const { EventBusInterface } = require('./EventBusInterface');

/**
 * In-process EventBus backed by a Node.js EventEmitter.
 *
 * Suitable for single-process deployments.  For multi-instance deployments,
 * replace with a RedisPubSub implementation that satisfies the same interface.
 *
 * maxListeners is set high to accommodate many SSE connections and internal
 * subscribers without triggering Node.js memory-leak warnings.
 *
 * #7 (dashboard resilience) deliberately DEFERS building that
 * RedisPubSub implementation — it's a materially separate piece of work (a
 * new EventBusInterface implementation, ordering/at-least-once delivery
 * semantics across instances, a multi-instance test matrix) that doesn't
 * belong bundled into an observability/monitoring change. What
 * #7 DID address is the dashboard's read-path independence from what it
 * monitors (already true by construction — src/dashboard/aggregator.js is
 * an in-memory store kept current via this bus, not a per-request read of
 * Redis/Postgres/the audit log) and per-client SSE backpressure handling
 * (src/dashboard/sseManager.js). The single-process-only limitation this
 * class's own header already documented is unchanged and remains open for a
 * future WP.
 */
class LocalEventBus extends EventBusInterface {
  constructor() {
    super();
    this._emitter = new EventEmitter();
    this._emitter.setMaxListeners(200);
  }

  publish(channel, message) {
    this._emitter.emit(channel, message);
  }

  subscribe(channel, handler) {
    this._emitter.on(channel, handler);
  }

  unsubscribe(channel, handler) {
    this._emitter.off(channel, handler);
  }

  /** Number of handlers registered on a channel (test / diagnostic helper). */
  listenerCount(channel) {
    return this._emitter.listenerCount(channel);
  }
}

module.exports = { LocalEventBus };
