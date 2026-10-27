'use strict';

const request        = require('supertest');
const express        = require('express');
const healthRouter   = require('../health');
const readinessState = require('../../../runtime/readinessState');

function buildApp() {
  const app = express();
  app.use('/health', healthRouter);
  return app;
}

afterEach(() => {
  readinessState._reset();
});

describe('GET /health', () => {
  it('returns HTTP 200', async () => {
    const res = await request(buildApp()).get('/health');
    expect(res.status).toBe(200);
  });

  it('returns { status: "ok" }', async () => {
    const res = await request(buildApp()).get('/health');
    expect(res.body).toMatchObject({ status: 'ok' });
  });

  it('returns 200 even when readinessState is false', async () => {
    readinessState.setReady(false);
    const res = await request(buildApp()).get('/health');
    expect(res.status).toBe(200);
  });

  it('returns 200 even when readinessState is true', async () => {
    readinessState.setReady(true);
    const res = await request(buildApp()).get('/health');
    expect(res.status).toBe(200);
  });
});
