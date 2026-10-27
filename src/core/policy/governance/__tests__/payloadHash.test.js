'use strict';

// F13-GOV-01 / re-audit A2-02: the governance hashes are taken over the JSON form of a payload, the form the database stores and publish re-hashes.
jest.unmock('../governanceEvents');
const { hashPayload } = require('../governanceEvents');

describe('governance payload hash', () => {
  test('PH-01 undefined members do not change the hash (the stored form drops them)', () => {
    const withUndefined = { id: 'p1', name: undefined, description: undefined, type: 'DLP', priority: 5, config: { a: 1 } };
    expect(hashPayload(withUndefined)).toBe(hashPayload(JSON.parse(JSON.stringify(withUndefined))));
  });

  test('PH-02 key order does not matter, a changed value does', () => {
    expect(hashPayload({ b: 1, a: 2 })).toBe(hashPayload({ a: 2, b: 1 }));
    expect(hashPayload({ a: 2 })).not.toBe(hashPayload({ a: 3 }));
  });

  test('PH-03 null and empty payloads hash as the empty object', () => {
    expect(hashPayload(null)).toBe(hashPayload({}));
    expect(hashPayload(undefined)).toBe(hashPayload({}));
  });
});
