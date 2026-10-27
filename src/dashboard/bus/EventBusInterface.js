'use strict';

/**
 * EventBus interface contract.
 *
 * All implementations must provide:
 *   publish(channel, message)       — deliver message to all channel subscribers
 *   subscribe(channel, handler)     — register a handler for a channel
 *   unsubscribe(channel, handler)   — deregister a handler
 *
 * Implementations:
 *   LocalEventBus  — in-process EventEmitter (current)
 *   RedisPubSub    — Redis Pub/Sub (future horizontal scale)
 */
class EventBusInterface {
  // eslint-disable-next-line no-unused-vars
  publish(_channel, _message) {
    throw new Error('EventBusInterface.publish() not implemented');
  }
  // eslint-disable-next-line no-unused-vars
  subscribe(_channel, _handler) {
    throw new Error('EventBusInterface.subscribe() not implemented');
  }
  // eslint-disable-next-line no-unused-vars
  unsubscribe(_channel, _handler) {
    throw new Error('EventBusInterface.unsubscribe() not implemented');
  }
}

module.exports = { EventBusInterface };
