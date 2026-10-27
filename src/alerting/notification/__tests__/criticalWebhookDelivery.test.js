'use strict';

/**
 * Gate A #23 / remediation plan 3.7 (owner D17 = webhook): a CRITICAL alert reaches the webhook channel.
 *
 * Proves, against a real local HTTP receiver, that NotificationService.notify() routes a CRITICAL alert to the
 * WEBHOOK channel when ALERT_WEBHOOK_URL is configured, delivers exactly one signed POST (X-QODIQA-Signature =
 * HMAC-SHA256 of the body) and reports it as sent. The production webhook TARGET is an design decision (plan 3.7:
 * "approval right before execution: yes, for the webhook target endpoint"); this test configures only a local
 * receiver and changes no production code or configuration. AlertStore is mocked so no store is written.
 */

const http = require('http');
const crypto = require('crypto');

describe('Gate A #23 — CRITICAL alert delivery to the default webhook channel', () => {
  let server; let received; let saved;

  beforeAll(async () => {
    received = [];
    server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => { received.push({ method: req.method, headers: req.headers, body }); res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('{"ok":true}'); });
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    saved = { url: process.env.ALERT_WEBHOOK_URL, secret: process.env.ALERT_WEBHOOK_SECRET };
  });

  afterAll(async () => {
    await new Promise((r) => server.close(r));
    if (saved.url === undefined) delete process.env.ALERT_WEBHOOK_URL; else process.env.ALERT_WEBHOOK_URL = saved.url;
    if (saved.secret === undefined) delete process.env.ALERT_WEBHOOK_SECRET; else process.env.ALERT_WEBHOOK_SECRET = saved.secret;
  });

  test('CWD-01 one CRITICAL alert → one signed POST to the configured webhook, reported as sent', async () => {
    const secret = 'test-only-webhook-secret';
    process.env.ALERT_WEBHOOK_URL = `http://127.0.0.1:${server.address().port}/alerts`;
    process.env.ALERT_WEBHOOK_SECRET = secret;
    let notify; let recorded;
    jest.isolateModules(() => {
      jest.doMock('../../storage/AlertStore', () => ({ recordNotification: jest.fn(async () => undefined) }));
      recorded = require('../../storage/AlertStore').recordNotification;
      ({ notify } = require('../NotificationService'));
    });
    const alert = { id: 'a1b2c3d4-0000-4000-8000-000000000023', type: 'SECURITY', subtype: 'GATE_A_23_TEST', severity: 'CRITICAL', status: 'OPEN', riskScore: 95, confidence: 100, title: 'Gate A #23 delivery test', description: 'CRITICAL alert delivery proof', tags: ['test'], detectedAt: new Date('2026-10-08T00:00:00Z'), evidence: {}, context: {} };

    const results = await notify(alert);

    const webhook = results.find((r) => r.channel === 'WEBHOOK');
    expect(webhook).toBeDefined();
    expect(webhook.sent).toBe(true);
    expect(received).toHaveLength(1);
    const [req] = received;
    expect(req.method).toBe('POST');
    expect(req.headers['x-qodiqa-alert-severity']).toBe('CRITICAL');
    expect(req.headers['x-qodiqa-alert-id']).toBe(alert.id);
    const expectedSig = 'sha256=' + crypto.createHmac('sha256', secret).update(req.body).digest('hex');
    expect(req.headers['x-qodiqa-signature']).toBe(expectedSig);
    const payload = JSON.parse(req.body);
    expect(payload).toMatchObject({ id: alert.id, severity: 'CRITICAL', source: 'qodiqa-alerting' });
    expect(recorded).toHaveBeenCalledWith(alert.id, expect.objectContaining({ channel: 'WEBHOOK', status: 'SENT' }));
  });
});
