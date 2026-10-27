'use strict';

/**
 * S-01 (launch plan R-03 supplemental): IPv6 CIDR support in the BLOCK_IP evaluator.
 * Before S-01 an IPv6 client passed every CIDR rule and validate() rejected IPv6 CIDRs, so a
 * "deny everyone" rule (0.0.0.0/0) let every IPv6 visitor through.
 */

const blockIp = require('../evaluators/blockIp');
const { computePolicyHash } = require('../../policyHash');

function ready(config) {
  blockIp.validate(config);
  return blockIp.preprocess(config);
}

describe('BLOCK_IP IPv6 CIDRs (S-01)', () => {
  test('IPv4-only config: behaviour unchanged — IPv6 client still passes, IPv4 in range blocked', () => {
    const cfg = ready({ blocklist: [], cidrs: ['10.0.0.0/8'] });
    expect(blockIp.evaluate({ ip: '10.1.2.3' }, cfg)).toEqual({ pass: false, reason: 'IP_BLOCKED' });
    expect(blockIp.evaluate({ ip: '11.0.0.1' }, cfg)).toEqual({ pass: true });
    expect(blockIp.evaluate({ ip: '2001:db8::1' }, cfg)).toEqual({ pass: true });
    expect(cfg._cidrV6List).toBeNull();
  });

  test('::/0 blocks every IPv6 client; 0.0.0.0/0 + ::/0 blocks everyone', () => {
    const cfg = ready({ blocklist: [], cidrs: ['0.0.0.0/0', '::/0'] });
    for (const ip of ['1.2.3.4', '127.0.0.1', '255.255.255.255', '::1', '2001:db8::1', 'fe80::1', '::ffff:7f00:1']) {
      expect(blockIp.evaluate({ ip }, cfg)).toEqual({ pass: false, reason: 'IP_BLOCKED' });
    }
  });

  test('a specific IPv6 prefix blocks only addresses inside it', () => {
    const cfg = ready({ blocklist: [], cidrs: ['2001:db8::/32'] });
    expect(blockIp.evaluate({ ip: '2001:db8:1::5' }, cfg)).toEqual({ pass: false, reason: 'IP_BLOCKED' });
    expect(blockIp.evaluate({ ip: '2001:db9::5' }, cfg)).toEqual({ pass: true });
    expect(blockIp.evaluate({ ip: '10.0.0.1' }, cfg)).toEqual({ pass: true });
  });

  test.each(['::/129', '::/-1', 'zz::/64', '2001:db8::', '2001:db8::/x', ':::/0'])('invalid IPv6 CIDR %s is rejected by validate()', (cidr) => {
    expect(() => blockIp.validate({ blocklist: [], cidrs: [cidr] })).toThrow();
  });

  test('invalid IPv4 CIDRs are still rejected exactly as before', () => {
    expect(() => blockIp.validate({ blocklist: [], cidrs: ['10.0.0.0/33'] })).toThrow(/prefix length/);
    expect(() => blockIp.validate({ blocklist: [], cidrs: ['10.0.0/8'] })).toThrow(/Invalid IP address/);
  });

  test('preprocess is idempotent and the derived field never reaches the policy hash', () => {
    const raw = { blocklist: [], cidrs: ['0.0.0.0/0', '::/0'] };
    const once = blockIp.preprocess(raw);
    const twice = blockIp.preprocess(once);
    expect(blockIp.evaluate({ ip: '::1' }, twice)).toEqual({ pass: false, reason: 'IP_BLOCKED' });
    const policy = (config) => [{ id: 'P', type: 'BLOCK_IP', priority: 1, enabled: true, config }];
    expect(computePolicyHash(policy(once))).toBe(computePolicyHash(policy(raw)));
  });
});
