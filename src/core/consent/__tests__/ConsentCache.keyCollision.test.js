'use strict';

/** ':' in actor_id / action must not make two different pairs share a cache key. */

const cache = require('../ConsentCache');

describe('ConsentCache._cacheKey — no collisions across component boundaries', () => {
  test('KC-01 (actor "a:b", action "c") and (actor "a", action "b:c") get different keys', () => {
    expect(cache._cacheKey('a:b', 'c', 't')).not.toBe(cache._cacheKey('a', 'b:c', 't'));
  });

  test('KC-02 a real tenant id "*" does not collide with the null-tenant sentinel', () => {
    expect(cache._cacheKey('a', 'b', null)).not.toBe(cache._cacheKey('a', 'b', '*'));
  });

  test('KC-03 glob metacharacters in an actor id are escaped so invalidateActor cannot over-match other actors', () => {
    const k = cache._cacheKey('a*', 'x', 't');
    expect(k.startsWith('qodiqa:consent:a%2A:')).toBe(true);
    expect(k).not.toMatch(/a\*/);
  });

  test('KC-04 ordinary ids keep the documented key format', () => {
    expect(cache._cacheKey('actor', 'action', 't1')).toBe('qodiqa:consent:actor:action:t1');
    expect(cache._cacheKey('actor', 'action')).toBe('qodiqa:consent:actor:action:*');
  });
});
