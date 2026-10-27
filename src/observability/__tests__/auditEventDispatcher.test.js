'use strict';

const { eventBus, emit } = require('../../../services/logger');
const auditEventDispatcher = require('../auditEventDispatcher');

describe('auditEventDispatcher', () => {
  afterEach(() => {
    auditEventDispatcher.detach();
  });

  it('is not attached until attach() is called', () => {
    expect(auditEventDispatcher.isAttached()).toBe(false);
  });

  it('forwards every eventBus "log" record to the shipper', () => {
    const shipper = { ship: jest.fn() };
    auditEventDispatcher.attach(shipper);

    emit('INFO', 'GATEWAY_ALLOW', { requestId: 'r1' });
    emit('WARN', 'GATEWAY_BLOCK', { requestId: 'r2' });

    expect(shipper.ship).toHaveBeenCalledTimes(2);
    expect(shipper.ship.mock.calls[0][0]).toMatchObject({ eventType: 'GATEWAY_ALLOW', requestId: 'r1' });
    expect(shipper.ship.mock.calls[1][0]).toMatchObject({ eventType: 'GATEWAY_BLOCK', requestId: 'r2' });
  });

  it('is idempotent — a second attach() does not add a second listener', () => {
    const shipperA = { ship: jest.fn() };
    const shipperB = { ship: jest.fn() };
    auditEventDispatcher.attach(shipperA);
    auditEventDispatcher.attach(shipperB); // no-op, already attached

    emit('INFO', 'SOME_EVENT', {});

    expect(shipperA.ship).toHaveBeenCalledTimes(1);
    expect(shipperB.ship).not.toHaveBeenCalled();
  });

  it('shipper.ship() throwing never propagates to the emit() call path', () => {
    const shipper = { ship: jest.fn(() => { throw new Error('boom'); }) };
    auditEventDispatcher.attach(shipper);

    expect(() => emit('INFO', 'SOME_EVENT', {})).not.toThrow();
    expect(shipper.ship).toHaveBeenCalled();
  });

  it('detach() stops forwarding and allows re-attaching a different shipper', () => {
    const shipperA = { ship: jest.fn() };
    auditEventDispatcher.attach(shipperA);
    auditEventDispatcher.detach();
    expect(auditEventDispatcher.isAttached()).toBe(false);

    emit('INFO', 'AFTER_DETACH', {});
    expect(shipperA.ship).not.toHaveBeenCalled();

    const shipperB = { ship: jest.fn() };
    auditEventDispatcher.attach(shipperB);
    emit('INFO', 'AFTER_REATTACH', {});
    expect(shipperB.ship).toHaveBeenCalledTimes(1);
  });

  it('does not forward the log-shipping-dispatch task\'s own BACKGROUND_TASK_COMPLETED/FAILED records (feedback-loop prevention)', () => {
    const shipper = { ship: jest.fn() };
    auditEventDispatcher.attach(shipper);

    emit('INFO', 'BACKGROUND_TASK_COMPLETED', { task: 'log-shipping-dispatch', executionTimeMs: 1 });
    emit('ERROR', 'BACKGROUND_TASK_FAILED', { task: 'log-shipping-dispatch', executionTimeMs: 1 });

    expect(shipper.ship).not.toHaveBeenCalled();
  });

  it('still forwards BACKGROUND_TASK_COMPLETED for every other background task', () => {
    const shipper = { ship: jest.fn() };
    auditEventDispatcher.attach(shipper);

    emit('INFO', 'BACKGROUND_TASK_COMPLETED', { task: 'audit-retention-cycle', executionTimeMs: 1 });

    expect(shipper.ship).toHaveBeenCalledTimes(1);
  });

  it('does not add a duplicate eventBus listener across repeated attach/detach cycles', () => {
    const before = eventBus.listenerCount('log');
    auditEventDispatcher.attach({ ship: jest.fn() });
    auditEventDispatcher.detach();
    auditEventDispatcher.attach({ ship: jest.fn() });
    auditEventDispatcher.detach();
    expect(eventBus.listenerCount('log')).toBe(before);
  });
});
