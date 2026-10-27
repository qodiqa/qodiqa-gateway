'use strict';

const request = require('supertest');
const express = require('express');
const { createHealthLoopbackMiddleware, _isLoopback } = require('../healthLoopback');

function buildApp(opsConfig, socketIp) {
  const app = express();
  app.use((req, _res, next) => {
    req.requestId = 'test-req-id';
    req.socket    = { remoteAddress: socketIp };
    next();
  });
  app.use('/health', createHealthLoopbackMiddleware(opsConfig), (_req, res) => {
    res.status(200).json({ status: 'ok' });
  });
  return app;
}

describe('_isLoopback', () => {
  it('accepts 127.0.0.1', () => expect(_isLoopback('127.0.0.1')).toBe(true));
  it('accepts other 127.x.x.x addresses', () => expect(_isLoopback('127.5.5.5')).toBe(true));
  it('accepts ::1', () => expect(_isLoopback('::1')).toBe(true));
  it('accepts IPv4-mapped loopback (::ffff:127.0.0.1)', () => expect(_isLoopback('::ffff:127.0.0.1')).toBe(true));
  it('rejects a public IPv4 address', () => expect(_isLoopback('8.8.8.8')).toBe(false));
  it('rejects a private RFC1918 address', () => expect(_isLoopback('10.0.0.5')).toBe(false));
  it('rejects null/undefined/empty', () => {
    expect(_isLoopback(null)).toBe(false);
    expect(_isLoopback(undefined)).toBe(false);
    expect(_isLoopback('')).toBe(false);
  });
});

describe('createHealthLoopbackMiddleware — disabled by default', () => {
  it('allows a non-loopback request when healthRequireLoopback is false', async () => {
    const app = buildApp({ healthRequireLoopback: false }, '8.8.8.8');
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
  });
});

describe('createHealthLoopbackMiddleware — enabled', () => {
  it('allows a loopback request (200)', async () => {
    const app = buildApp({ healthRequireLoopback: true }, '127.0.0.1');
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
  });

  it('rejects a non-loopback request (403)', async () => {
    const app = buildApp({ healthRequireLoopback: true }, '8.8.8.8');
    const res = await request(app).get('/health');
    expect(res.status).toBe(403);
  });

  it('cannot be bypassed by spoofing X-Forwarded-For as loopback', async () => {
    // The middleware must key off the raw TCP socket address, never a
    // client-controlled header — otherwise any external attacker could
    // trivially claim to be loopback.
    const app = buildApp({ healthRequireLoopback: true }, '8.8.8.8');
    const res = await request(app).get('/health').set('X-Forwarded-For', '127.0.0.1');
    expect(res.status).toBe(403);
  });

  it('cannot be bypassed by spoofing X-Real-IP as loopback', async () => {
    const app = buildApp({ healthRequireLoopback: true }, '8.8.8.8');
    const res = await request(app).get('/health').set('X-Real-IP', '127.0.0.1');
    expect(res.status).toBe(403);
  });

  it('rejects when socket address is unavailable (fail-closed)', async () => {
    const app = buildApp({ healthRequireLoopback: true }, undefined);
    const res = await request(app).get('/health');
    expect(res.status).toBe(403);
  });
});
