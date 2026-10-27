'use strict';

/**
 * "specs = code" drift checks, in the unit gate, each with a negative control proving it is not vacuous.
 *
 *   PV-01 the committed protocol vectors are exactly what the production implementation produces now
 *   PV-02 the independent verifier (no production code) re-derives every vector
 *   PV-03 negative control: a vector whose verdict is changed is rejected by the independent verifier
 *   PV-04 the generated sections of docs/protocol/QODIQA-PROTOCOL.md equal the code's constants
 *   PV-05 negative control: a generated section edited by hand is reported as drift
 *   SC-01 every SDK call is a documented operation with matching auth, and the two SDKs are in parity
 * SC-02 negative control: the earlier SDK defect class (an ops-only operation called without the ops credential)
 *         is detected
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const REPO = path.join(__dirname, '..', '..', '..');
// the result line of a tool run (modules may log to stdout around it)
const resultLine = (stdout, key) => JSON.parse(stdout.split(/\r?\n/).find((l) => l.startsWith('{') && l.includes(key)));
const node = (args, env = {}) => spawnSync(process.execPath, args, { cwd: REPO, encoding: 'utf8', env: { ...process.env, ...env }, timeout: 120_000 });

jest.setTimeout(180_000);

describe('specs = code — drift checks', () => {
  let tmp;
  beforeAll(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-w12-drift-')); });
  afterAll(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

  test('PV-01 committed protocol vectors == production output (byte-identical)', () => {
    const r = node(['scripts/protocol/gen-vectors.js', '--check']);
    expect(r.status).toBe(0);
    expect(resultLine(r.stdout, '"generatedSha256"')).toMatchObject({ ok: true });
  });

  test('PV-02 the independent verifier re-derives every vector', () => {
    const r = node(['scripts/protocol/verify-vectors.js']);
    const out = JSON.parse(r.stdout);
    expect(out.failed).toBe(0);
    expect(out.checks).toBeGreaterThanOrEqual(60);
    expect(r.status).toBe(0);
  });

  test('PV-03 negative control: a tampered verdict is rejected', () => {
    const v = JSON.parse(fs.readFileSync(path.join(REPO, 'docs/protocol/vectors/qodiqa-protocol-vectors.json'), 'utf8'));
    const c = v.verification.cases.find((x) => x.name.startsWith('timestamp 5,100 ms'));
    c.expected = { decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED' };   // claim the 5,100 ms case passes
    const f = path.join(tmp, 'tampered.json'); fs.writeFileSync(f, JSON.stringify(v));
    const r = node(['scripts/protocol/verify-vectors.js', f]);
    expect(r.status).toBe(1);
    expect(JSON.parse(r.stdout).failures.map((x) => x.name)).toContain(c.name);
  });

  test('PV-04 the generated spec sections equal the code', () => {
    const r = node(['scripts/protocol/spec-check.js']);
    expect(resultLine(r.stdout, '"drifted"')).toEqual({ ok: true, missing: [], drifted: [] });
    expect(r.status).toBe(0);
  });

  test('PV-05 negative control: a hand-edited generated section is drift', () => {
    const { check, sections } = require('../spec-check');
    expect(check().ok).toBe(true);
    const spec = path.join(REPO, 'docs/protocol/QODIQA-PROTOCOL.md');
    const text = fs.readFileSync(spec, 'utf8');
    expect(text).toContain(sections().limits.split('\n')[2]);              // the 5 s tolerance row is rendered from code
    const edited = text.replace('| 5000 ms |', '| 0 ms |');               // "zero tolerance", as the 1.0.1 spec claimed
    expect(edited).not.toBe(text);
    const copy = path.join(tmp, 'spec.md'); fs.writeFileSync(copy, edited);
    const re = /<!-- BEGIN GENERATED:limits -->([\s\S]*?)<!-- END GENERATED:limits -->/;
    expect(edited.match(re)[1].trim()).not.toBe(sections().limits.trim());
  });

  test('SC-01 SDK calls ⊆ documented operations, auth matches, SDKs in parity', () => {
    const { run } = require('../../contract/sdk-openapi-check');
    const r = run();
    expect(r.violations).toEqual([]);
    expect(r.counts.jsCalls).toBeGreaterThan(40);
    expect(r.counts.pyCalls).toBeGreaterThan(40);
  });

  test('SC-02 negative control: an ops-only call without the ops credential is detected', () => {
    const src = path.join(REPO, 'sdk');
    const root = path.join(tmp, 'sdk');
    for (const rel of ['javascript/src', 'python/qodiqa']) fs.cpSync(path.join(src, rel), path.join(root, rel), { recursive: true });
    const cert = path.join(root, 'javascript/src/resources/certification.ts');
    const s = fs.readFileSync(cert, 'utf8');
    const broken = s.replace(/(async evaluate\([\s\S]*?)const headers = this\.auth\.getAuthHeader\(\);\r?\n\s*/, '$1');
    expect(broken).not.toBe(s);
    fs.writeFileSync(cert, broken);
    const r = node(['scripts/contract/sdk-openapi-check.js'], { QODIQA_SDK_ROOT: root });
    expect(r.status).toBe(1);
    expect(r.stdout).toMatch(/SC-2 js .*certification\.ts evaluate\(\): post \/v1\/certification\/evaluate requires BearerAuth/);
  });

  // / API-13: streaming calls are extracted (they were silently skipped); API-15: SC-4 required query params.
  test('SC-03 streaming calls are checked: chat.stream() in both SDKs targets the documented POST /ai/chat', () => {
    const { run } = require('../../contract/sdk-openapi-check');
    const streams = run().calls.filter((c) => /stream/i.test(c.fn) && c.path === '/ai/chat');
    expect(streams.map((c) => c.lang).sort()).toEqual(['js', 'python', 'python']); // JS; Python sync + async
  });

  test('SC-04 negative control: a per-id webhook call without the required tenantId is detected (the pre-IND-14 SDKs)', () => {
    const src = path.join(REPO, 'sdk');
    const root = path.join(tmp, 'sdk-sc4');
    for (const rel of ['javascript/src', 'python/qodiqa']) fs.cpSync(path.join(src, rel), path.join(root, rel), { recursive: true });
    const wh = path.join(root, 'javascript/src/resources/webhooks.ts');
    const s = fs.readFileSync(wh, 'utf8');
    const broken = s.replace(/(async delete\([\s\S]*?\{ headers), query: \{ tenantId \} \}/, '$1 }');
    expect(broken).not.toBe(s);
    fs.writeFileSync(wh, broken);
    const r = node(['scripts/contract/sdk-openapi-check.js'], { QODIQA_SDK_ROOT: root });
    expect(r.status).toBe(1);
    expect(r.stdout).toMatch(/SC-4 js .*webhooks\.ts delete\(\): delete \/v1\/webhooks\/\{id\} requires the query parameter \\"tenantId\\"/);
  });
});
