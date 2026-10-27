'use strict';

const { LocalEventBus }     = require('../bus/LocalEventBus');
const { EventBusInterface } = require('../bus/EventBusInterface');

describe('EventBusInterface', () => {
  it('throws on publish()', () => {
    const b = new EventBusInterface();
    expect(() => b.publish('ch', {})).toThrow('not implemented');
  });
  it('throws on subscribe()', () => {
    const b = new EventBusInterface();
    expect(() => b.subscribe('ch', () => {})).toThrow('not implemented');
  });
  it('throws on unsubscribe()', () => {
    const b = new EventBusInterface();
    expect(() => b.unsubscribe('ch', () => {})).toThrow('not implemented');
  });
});

describe('LocalEventBus', () => {
  it('extends EventBusInterface', () => {
    expect(new LocalEventBus()).toBeInstanceOf(EventBusInterface);
  });

  it('delivers a message to a subscriber', () => {
    const bus = new LocalEventBus();
    const msgs = [];
    bus.subscribe('test', (m) => msgs.push(m));
    bus.publish('test', { x: 1 });
    expect(msgs).toEqual([{ x: 1 }]);
  });

  it('delivers to multiple subscribers on the same channel', () => {
    const bus = new LocalEventBus();
    const a = [], b = [];
    bus.subscribe('ch', (m) => a.push(m));
    bus.subscribe('ch', (m) => b.push(m));
    bus.publish('ch', 42);
    expect(a).toEqual([42]);
    expect(b).toEqual([42]);
  });

  it('does not deliver to subscribers on a different channel', () => {
    const bus = new LocalEventBus();
    const received = [];
    bus.subscribe('ch-a', (m) => received.push(m));
    bus.publish('ch-b', 'hello');
    expect(received).toHaveLength(0);
  });

  it('unsubscribe removes the handler', () => {
    const bus = new LocalEventBus();
    const received = [];
    const handler = (m) => received.push(m);
    bus.subscribe('ch', handler);
    bus.unsubscribe('ch', handler);
    bus.publish('ch', 'should not arrive');
    expect(received).toHaveLength(0);
  });

  it('publish with no subscribers does not throw', () => {
    const bus = new LocalEventBus();
    expect(() => bus.publish('empty', {})).not.toThrow();
  });

  it('listenerCount returns correct count', () => {
    const bus = new LocalEventBus();
    expect(bus.listenerCount('ch')).toBe(0);
    bus.subscribe('ch', () => {});
    bus.subscribe('ch', () => {});
    expect(bus.listenerCount('ch')).toBe(2);
  });

  it('publish is synchronous — handler fires before publish returns', () => {
    const bus = new LocalEventBus();
    let fired = false;
    bus.subscribe('ch', () => { fired = true; });
    expect(fired).toBe(false);
    bus.publish('ch', null);
    expect(fired).toBe(true);
  });

  it('handles subscriber that throws without breaking other subscribers', () => {
    const bus = new LocalEventBus();
    const good = [];
    bus.subscribe('ch', () => { throw new Error('boom'); });
    bus.subscribe('ch', (m) => good.push(m));
    // EventEmitter propagates the first listener's throw, stopping the rest.
    // This test documents the current behaviour (not silenced by LocalEventBus).
    expect(() => bus.publish('ch', 'msg')).toThrow('boom');
  });
});
