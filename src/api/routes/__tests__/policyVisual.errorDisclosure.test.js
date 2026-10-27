'use strict';

// API-2 regression: the /visual/export render/export paths (RENDER_TREE_ERROR,
// EXPORT_SVG_ERROR, EXPORT_PNG_ERROR, EXPORT_JSON_ERROR) used to return the
// raw err.message from the policyBuilder library to the client on a 500.
// These are now routed through the centralized internalError() helper, which
// logs the real error server-side and returns only a generic message.

const express = require('express');
const request = require('supertest');

// The real module exports Object.freeze({...}), so individual functions
// can't be jest.spyOn'd in place — wrap each export in a jest.fn() that
// delegates to the real implementation by default, so tests can override
// just the one function under test.
jest.mock('../../../visual/policyBuilder', () => {
  const actual = jest.requireActual('../../../visual/policyBuilder');
  const wrapped = {};
  for (const [key, value] of Object.entries(actual)) {
    wrapped[key] = typeof value === 'function' ? jest.fn(value) : value;
  }
  return wrapped;
});

const pv = require('../../../visual/policyBuilder');
const pvActual = jest.requireActual('../../../visual/policyBuilder');
const { createPolicyVisualRouter } = require('../policyVisual');

function makeApp() {
  const app = express();
  app.use(express.json());
  app.use('/v1/policy', createPolicyVisualRouter());
  return app;
}

const SECRET_DETAIL = 'ENOENT: ffi handle 0x7f3c internal buffer overrun at /var/secrets/render.key';

describe('policyVisual API-2 error disclosure', () => {
  const validPolicy = { policyId: 'POL-1', rules: [] };

  afterEach(() => {
    for (const [key, value] of Object.entries(pvActual)) {
      if (typeof pv[key]?.mockImplementation === 'function') {
        pv[key].mockImplementation(value);
      }
    }
  });

  test('EXPORT_SVG_ERROR does not leak internal exception detail', async () => {
    pv.buildGraph.mockReturnValue({ nodes: [], edges: [] });
    pv.highlightRisks.mockImplementation(g => g);
    pv.applyLayout.mockReturnValue({ nodes: [], edges: [], bounds: {} });
    pv.exportSvg.mockImplementation(() => { throw new Error(SECRET_DETAIL); });

    const res = await request(makeApp())
      .post('/v1/policy/visual/export')
      .send({ policy: validPolicy, format: 'svg' });

    expect(res.status).toBe(500);
    expect(res.body.error?.code).toBe('EXPORT_SVG_ERROR');
    const raw = JSON.stringify(res.body);
    expect(raw).not.toContain(SECRET_DETAIL);
    expect(raw).not.toContain('/var/secrets');
  });

  test('EXPORT_PNG_ERROR does not leak internal exception detail', async () => {
    pv.buildGraph.mockReturnValue({ nodes: [], edges: [] });
    pv.highlightRisks.mockImplementation(g => g);
    pv.applyLayout.mockReturnValue({ nodes: [], edges: [], bounds: {} });
    pv.exportPng.mockImplementation(() => { throw new Error(SECRET_DETAIL); });

    const res = await request(makeApp())
      .post('/v1/policy/visual/export')
      .send({ policy: validPolicy, format: 'png' });

    expect(res.status).toBe(500);
    expect(res.body.error?.code).toBe('EXPORT_PNG_ERROR');
    const raw = JSON.stringify(res.body);
    expect(raw).not.toContain(SECRET_DETAIL);
  });

  test('EXPORT_JSON_ERROR does not leak internal exception detail', async () => {
    pv.buildGraph.mockReturnValue({ nodes: [], edges: [] });
    pv.highlightRisks.mockImplementation(g => g);
    pv.applyLayout.mockReturnValue({ nodes: [], edges: [], bounds: {} });
    pv.exportJson.mockImplementation(() => { throw new Error(SECRET_DETAIL); });

    const res = await request(makeApp())
      .post('/v1/policy/visual/export')
      .send({ policy: validPolicy, format: 'json' });

    expect(res.status).toBe(500);
    expect(res.body.error?.code).toBe('EXPORT_JSON_ERROR');
    const raw = JSON.stringify(res.body);
    expect(raw).not.toContain(SECRET_DETAIL);
  });

  test('RENDER_TREE_ERROR does not leak internal exception detail', async () => {
    pv.buildTree.mockReturnValue({ id: 'root', children: [] });
    pv.renderTreeText.mockImplementation(() => { throw new Error(SECRET_DETAIL); });

    const res = await request(makeApp())
      .post('/v1/policy/visual/tree')
      .send({ policy: validPolicy, format: 'text' });

    expect(res.status).toBe(500);
    expect(res.body.error?.code).toBe('RENDER_TREE_ERROR');
    const raw = JSON.stringify(res.body);
    expect(raw).not.toContain(SECRET_DETAIL);
  });

  test('BUILD_GRAPH_ERROR (caller input error) still surfaces a helpful message', async () => {
    const res = await request(makeApp())
      .post('/v1/policy/visual/graph')
      .send({ policy: { rules: [] } }); // missing policyId

    expect(res.status).toBe(400);
    expect(res.body.error?.code).toBe('BUILD_GRAPH_ERROR');
    expect(res.body.error?.message).toMatch(/policyId/);
  });
});

// the 400 validation paths returned ANY err.message. Only the builder's own
// authored validation messages ("<lowerCamelFunction>: <reason>") pass; everything else is masked.
describe('policyVisual 400 paths never echo unexpected error text', () => {
  const policy = { policyId: 'POL-1', rules: [] };
  afterEach(() => { pv.buildGraph.mockImplementation(pvActual.buildGraph); });
  test.each([
    ['an errno-style message', SECRET_DETAIL],
    ['a runtime TypeError', "Cannot read properties of undefined (reading 'x')"],
  ])('%s → fixed message, detail not disclosed', async (_label, detail) => {
    pv.buildGraph.mockImplementation(() => { throw new Error(detail); });
    const r = await request(makeApp()).post('/v1/policy/visual/graph').send({ policy });
    expect(r.status).toBe(400);
    expect(JSON.stringify(r.body)).not.toContain(detail);
    expect(r.body.error.message).toBe('The policy could not be processed');
  });
  test('the builder\'s own validation message is still returned', async () => {
    pv.buildGraph.mockImplementation(() => { throw new TypeError('buildGraph: policy.policyId must be a non-empty string'); });
    const r = await request(makeApp()).post('/v1/policy/visual/graph').send({ policy });
    expect([r.status, r.body.error.message]).toEqual([400, 'buildGraph: policy.policyId must be a non-empty string']);
  });
});
