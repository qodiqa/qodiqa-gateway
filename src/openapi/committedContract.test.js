'use strict';

/**
 * the committed OpenAPI contract (docs/api/openapi.json) equals the generated spec, byte for byte.
 *
 *   OC-01 the OpenAPI diff is empty (scripts/openapi/contract.js --check semantics)
 *   OC-02 the generator is deterministic: two fresh generations are identical
 *   OC-03 negative control: an operation removed from, or a schema field changed in, a copy of the contract is
 *         reported (the check is not vacuous)
 * OC-04 the chat operations declare every status the route emits in the default
 *         mode — derived from src/api/routes/aiChat.js's own _providerStatus/_idempotencyStatus maps — plus 413/415,
 *         the Idempotency-Key request header and the Idempotency-Key/Idempotency-Replayed response headers; the
 *         409 text names the both-modes idempotency codes; /sign declares 429
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const contract = require('../../scripts/openapi/contract');

describe('committed OpenAPI contract', () => {
  test('OC-01 docs/api/openapi.json == generated spec (empty diff)', () => {
    const r = contract.check();
    expect(r).toMatchObject({ ok: true });
    expect(r.operations).toBeGreaterThan(300);
  });

  test('OC-02 generation is deterministic', () => {
    expect(contract.render()).toBe(contract.render());
  });

  test('OC-03 drift in a copy of the contract is detected', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-w12-oc-'));
    try {
      const doc = JSON.parse(fs.readFileSync(contract.CONTRACT, 'utf8'));
      delete doc.paths['/sign'].post;
      const f1 = path.join(dir, 'removed-op.json'); fs.writeFileSync(f1, `${JSON.stringify(doc, null, 2)}\n`);
      const r1 = contract.check(f1);
      expect(r1.ok).toBe(false);
      expect(r1.operationsAdded).toEqual(['post /sign']);   // generated has it, the drifted copy does not
      const doc2 = JSON.parse(fs.readFileSync(contract.CONTRACT, 'utf8'));
      doc2.info.version = `${doc2.info.version}-drift`;
      const f2 = path.join(dir, 'changed-field.json'); fs.writeFileSync(f2, `${JSON.stringify(doc2, null, 2)}\n`);
      const r2 = contract.check(f2);
      expect(r2.ok).toBe(false);
      expect(r2.firstDifferences).toContain('/info/version');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  test('OC-04 chat ops declare the statuses and idempotency headers the route emits; /sign declares 429', () => {
    const doc = JSON.parse(fs.readFileSync(contract.CONTRACT, 'utf8'));
    const src = fs.readFileSync(path.join(__dirname, '..', 'api', 'routes', 'aiChat.js'), 'utf8');
    const statusesOf = (fn) => {
      const body = src.match(new RegExp(`function ${fn}\\([^)]*\\) \\{([\\s\\S]*?)\\n\\}`))[1];
      return [...body.matchAll(/return (\d{3});/g)].map((m) => m[1]);
    };
    const derived = new Set([...statusesOf('_providerStatus'), ...statusesOf('_idempotencyStatus')]);
    expect([...derived].sort()).toEqual(expect.arrayContaining(['400', '409', '413', '422', '500', '502', '503', '504']));
    // + ARTIFACT_TOO_LARGE 413 (8 KB header cap) and UNSUPPORTED_MEDIA_TYPE 415 (middleware/enforceContentType.js)
    expect(src).toMatch(/res\.status\(413\)\.json\(\{ decision: 'BLOCK', reason: 'ARTIFACT_TOO_LARGE'/);
    const expected = [...derived, '413', '415', '429'];
    for (const p of ['/ai/chat', '/v1/ai/chat', '/ai/chat/stream', '/v1/ai/chat/stream']) {
      const op = doc.paths[p].post;
      for (const st of expected) expect([p, st, Boolean(op.responses[st])]).toEqual([p, st, true]);
      const idem = op.parameters.find((x) => x.in === 'header' && x.name === 'Idempotency-Key');
      expect(idem).toMatchObject({ required: false, schema: { type: 'string', maxLength: 255 } });
      expect(Object.keys(op.responses['200'].headers).sort()).toEqual(['Idempotency-Key', 'Idempotency-Replayed']);
      expect(op.responses['409'].description).toMatch(/IDEMPOTENCY_KEY_CONFLICT/);
      expect(op.responses['409'].description).toMatch(/IDEMPOTENCY_REQUEST_IN_PROGRESS/);
      expect(op.responses['409'].description).not.toMatch(/^`status` mode only/);
    }
    expect(doc.paths['/sign'].post.responses['429']).toEqual({ $ref: '#/components/responses/TooManyRequests' });
  });

  // generator text that described the wire wrongly.
  test('OC-05 SSE frame text matches a frame rendered by streamEnforcer._writeSSE', () => {
    const doc = JSON.parse(fs.readFileSync(contract.CONTRACT, 'utf8'));
    const src = fs.readFileSync(path.join(__dirname, '..', 'streaming', 'streamEnforcer.js'), 'utf8');
    const fnSrc = src.match(/function _writeSSE\([\s\S]*?\n\}\n/)[0];
    // eslint-disable-next-line no-new-func
    const writeSSE = new Function(`${fnSrc}; return _writeSSE;`)();
    let out = '';
    const res = { write: (s) => { out += s; } };
    const idOf = src.match(/const _nextFrameId = \(\) => `\$\{streamId\}:\$\{_frameSeq\+\+\}`/);
    expect(idOf).not.toBeNull(); // ids are <streamId>:<seq>
    writeSSE(res, { event: 'stream_started' }, { id: 's1:0', retry: 3000 });
    writeSSE(res, '[DONE]', { id: 's1:1' });
    expect(out).toBe('retry: 3000\nevent: stream_started\nid: s1:0\ndata: {"event":"stream_started"}\n\nid: s1:1\ndata: [DONE]\n\n');
    for (const p of ['/ai/chat', '/v1/ai/chat', '/ai/chat/stream', '/v1/ai/chat/stream']) {
      const text = doc.paths[p].post.responses['200'].content['text/event-stream'].schema.description;
      expect(text).toContain('`event: <name>` (absent on `[DONE]`)');
      expect(text).toContain('`id: <streamId>:<seq>`');
      expect(text).not.toContain('`id: <n>`');
    }
  });

  test('OC-06 /stream aliases say streaming is selected only by stream: true', () => {
    const doc = JSON.parse(fs.readFileSync(contract.CONTRACT, 'utf8'));
    const chat = fs.readFileSync(path.join(__dirname, '..', 'api', 'routes', 'aiChat.js'), 'utf8');
    expect(chat).toMatch(/const isStreaming = _bodyParsed\.data\.stream === true;/);
    for (const p of ['/ai/chat/stream', '/v1/ai/chat/stream']) {
      const { summary } = doc.paths[p].post;
      expect(summary).toMatch(/alias/);
      expect(summary).toContain('stream: true');
      expect(summary).not.toMatch(/^Stream AI request/);
    }
  });

  test('OC-07 EnforcementDecision.requestId is described as the X-Request-ID trace id, not the artifact id', () => {
    const doc = JSON.parse(fs.readFileSync(contract.CONTRACT, 'utf8'));
    const rid = doc.components.schemas.EnforcementDecision.properties.requestId;
    const text = JSON.stringify(rid);
    expect(text).toContain('X-Request-ID');
    expect(text).toContain('artifactId');
    expect(rid.oneOf[0]).toMatchObject({ type: 'string', format: 'uuid' });
  });
});
