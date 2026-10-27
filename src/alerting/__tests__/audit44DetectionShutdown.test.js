'use strict';

/** DetectionEngine.shutdown() must detach only ITS OWN 'log' listener. */

jest.mock('../engine/AlertEngine', () => ({ createAlert: jest.fn(async () => ({})) }));

const { eventBus } = require('../../../services/logger');
const detection = require('../detection/DetectionEngine');

describe('DetectionEngine.shutdown', () => {
  test('DS-01 other subscribers (log shipper, dashboard feed, audit dispatcher) survive shutdown', () => {
    const other = jest.fn();
    eventBus.on('log', other);
    const before = eventBus.listenerCount('log');
    detection.initialize();
    expect(eventBus.listenerCount('log')).toBe(before + 1);
    other.mockClear(); // initialize() itself logs an INFO record that every subscriber sees
    detection.shutdown();
    expect(eventBus.listenerCount('log')).toBe(before); // exactly its own listener removed
    eventBus.emit('log', { eventType: 'X' });
    expect(other).toHaveBeenCalledTimes(1);
    eventBus.removeListener('log', other);
  });
});
