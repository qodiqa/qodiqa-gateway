'use strict';

/**
 * — GHSA-jqcg-44mw-7w3h (proxy-addr < 2.0.8, CVSS 9.1): an IPv6 trust subnet that is not an
 * IPv4-mapped subnet (e.g. `::/64`) matched IPv4 / IPv4-mapped peers, so a client could be treated as a trusted proxy
 * and spoof its address through X-Forwarded-For. Express's `trust proxy` uses proxy-addr; QODIQA's own resolver
 * (clientIpResolver/_makeTrustPredicate) is used for req.clientIp. Both must refuse the cross-family match.
 * With proxy-addr 2.0.7 installed, the proxy-addr assertions below fail.
 */

const proxyaddr = require('proxy-addr');
const { _makeTrustPredicate } = require('../clientIpResolver');

const CROSS_FAMILY = [
  [['::/64'], '8.8.8.8'],                 // the advisory's bypass: an IPv6 subnet matching an IPv4 peer
  [['::/64'], '::ffff:8.8.8.8'],          // same peer in IPv4-mapped form
  [['fc00::/7'], '::ffff:8.8.8.8'],
];
const LEGITIMATE = [
  [['loopback'], '::ffff:127.0.0.1'],     // dual-stack socket form of 127.0.0.1
  [['10.0.0.0/8'], '::ffff:10.1.2.3'],
  [['uniquelocal'], '10.20.30.40'],
];

describe('IPv4-mapped IPv6 trust (GHSA-jqcg-44mw-7w3h)', () => {
  test('installed proxy-addr is a fixed version (>= 2.0.8)', () => {
    const v = require('proxy-addr/package.json').version.split('.').map(Number);
    expect(v[0] > 2 || (v[0] === 2 && (v[1] > 0 || v[2] >= 8))).toBe(true);
  });

  test.each(CROSS_FAMILY)('proxy-addr does not trust %j for peer %s', (trust, ip) => {
    expect(proxyaddr.compile(trust)(ip, 0)).toBe(false);
  });

  test.each(CROSS_FAMILY)('QODIQA trust predicate does not trust %j for peer %s', (trust, ip) => {
    expect(_makeTrustPredicate(trust)(ip)).toBe(false);
  });

  test.each(LEGITIMATE)('both still trust %j for peer %s', (trust, ip) => {
    expect(proxyaddr.compile(trust)(ip, 0)).toBe(true);
    expect(_makeTrustPredicate(trust)(ip)).toBe(true);
  });
});
