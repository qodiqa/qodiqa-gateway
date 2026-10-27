'use strict';

/**
 * S-02 (launch plan R-10 supplemental): LOG_SANITIZER_REDACT_IP redacted only IPv4, so IPv6 visitor addresses reached
 * the logs of a public deployment even with redaction on. IPv6 is now redacted under the same opt-in flag; candidates
 * are confirmed with net.isIPv6 so timestamps, MAC addresses and ratios are untouched. The default stays off.
 */

const { sanitize } = require('../logSanitizer');
const { defaultConfig } = require('../logSanitizerConfig');

const on = { ...defaultConfig, redactIpAddresses: true };
const s = (msg, cfg = on) => sanitize({ msg }, cfg).msg;

describe('log sanitizer IPv6 redaction (S-02)', () => {
  test.each([
    '::1', '2001:db8::1', 'fe80::1%eth0', '2001:0db8:85a3:0000:0000:8a2e:0370:7334', '::ffff:7f00:1',
  ])('redacts %s when redaction is on', (ip) => {
    expect(s(`client ${ip} connected`)).toBe('client [IP] connected');
  });

  test('IPv4-mapped IPv6 loses its IPv4 part (the address is never left readable)', () => {
    expect(s('peer ::ffff:203.0.113.9 ok')).not.toContain('203.0.113.9');
  });

  test.each([
    '2026-10-14T07:55:10.505Z', 'elapsed 12:30:45', 'mac aa:bb:cc:dd:ee:ff', 'ratio 3:2', 'key "a:b:c"', 'sha 1:2',
  ])('does not touch non-addresses: %s', (text) => {
    expect(s(text)).toBe(text);
  });

  test('IPv4 behaviour is unchanged', () => {
    expect(s('from 203.0.113.7 to 10.0.0.1')).toBe('from [IP] to [IP]');
  });

  test('default (redaction off) leaves IPv6 untouched, exactly as before', () => {
    expect(defaultConfig.redactIpAddresses).toBe(false);
    expect(s('client 2001:db8::1 connected', defaultConfig)).toBe('client 2001:db8::1 connected');
  });
});
