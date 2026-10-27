'use strict';

/**
 * the documentation is held to the contract.
 *   AD-01 docs/api/REFERENCE.md is exactly what docs/api/openapi.json generates, and lists every operation once
 *   AD-02 every `METHOD /path` the hand-written guided tour (docs/api/overview.md) mentions is an operation of the contract, except an explicit list of mentions that are NOT routes of the
 *         contract on purpose (each with its reason): a failing line here is a stale or invented endpoint in the docs
 *   AD-03 the list of exceptions has no entry the docs no longer need (it can only shrink)
 */

const fs = require('fs');
const path = require('path');
const { build, OUT, SPEC } = require('../generate-api-reference');

const REPO = path.join(__dirname, '..', '..', '..');
const spec = JSON.parse(fs.readFileSync(SPEC, 'utf8'));
const METHODS = ['get', 'post', 'put', 'patch', 'delete'];
const norm = (p) => p.replace(/\{[^}]+\}/g, ':p').replace(/:[A-Za-z_]+/g, ':p').replace(/\/+$/, '') || '/';
const ops = new Set();
for (const [p, item] of Object.entries(spec.paths)) for (const m of METHODS) if (item[m]) ops.add(`${m.toUpperCase()} ${norm(p)}`);

// mention (as written) -> why it is not an operation of the contract
const NOT_ROUTES = {
  'GET /diagnostics/profile/memory': 'profiling plane (QODIQA_PROFILING_ENABLED, off by default): not part of the served contract',
  'GET /diagnostics/profile/gc': 'profiling plane (off by default)',
  'POST /diagnostics/profile/cpu': 'profiling plane (off by default)',
  'GET /audit': 'stated as NOT existing ("There is no GET /audit list endpoint")',
  'POST /v1/policy': 'stated as NOT existing (the older GET|POST /v1/policy pair)',
  'POST /': 'router-relative: the section names the mount prefix',
  'GET /': 'router-relative: the section names the mount prefix',
  'GET /entry': 'router-relative: the section names the mount prefix',
  'POST /approve': 'router-relative: the section names the mount prefix',
  'POST /disable': 'router-relative: the section names the mount prefix',
  'POST /policy': 'router-relative: the section names the mount prefix',
  'GET /{serverId}': 'router-relative to /v1/mcp/servers',
  'POST /{serverId}/disable': 'router-relative to /v1/mcp/servers',
  'POST /{serverId}/enable': 'router-relative to /v1/mcp/servers',
  'POST /{serverId}/identity': 'router-relative to /v1/mcp/servers',
  'POST /{serverId}/tools/refresh': 'router-relative to /v1/mcp/servers',
};

function mentions() {
  const text = fs.readFileSync(path.join(REPO, 'docs', 'api', 'overview.md'), 'utf8');
  const re = /\b(GET|POST|PUT|PATCH|DELETE)\s+(\/[A-Za-z0-9_\-./:{}]*)/g;
  const out = new Set(); let m;
  while ((m = re.exec(text)) !== null) out.add(`${m[1]} ${m[2].replace(/[.,;:)]+$/, '')}`);
  return [...out];
}

describe('API documentation vs contract', () => {
  test('AD-01 the generated reference is current and complete', () => {
    const cur = fs.readFileSync(OUT, 'utf8').replace(/\r\n/g, '\n');
    expect(cur).toBe(build(spec));
    const headings = [...cur.matchAll(/^### `(GET|POST|PUT|PATCH|DELETE) ([^`]+)`$/gm)].map((x) => `${x[1]} ${x[2]}`);
    expect(headings.length).toBe(ops.size === 0 ? -1 : [...Object.entries(spec.paths)].reduce((n, [, i]) => n + METHODS.filter((m) => i[m]).length, 0));
    expect(new Set(headings).size).toBe(headings.length);
  });

  test('AD-02 every endpoint the guided tour mentions exists in the contract (or is a listed exception)', () => {
    const unknown = mentions().filter((x) => {
      const [method, p] = [x.split(' ')[0], x.slice(x.indexOf(' ') + 1)];
      return !ops.has(`${method} ${norm(p)}`) && !Object.prototype.hasOwnProperty.call(NOT_ROUTES, x);
    });
    expect(unknown).toEqual([]);
  });

  test('AD-03 every exception is still mentioned in the guided tour', () => {
    const m = new Set(mentions());
    expect(Object.keys(NOT_ROUTES).filter((k) => !m.has(k))).toEqual([]);
  });
});
