'use strict';

// End-to-end wiring test for services/logger.js emit() -> eventBus ->
// auditEventDispatcher -> createLogShipper -> destination.send(). Verifies
// the complete audit stream (not just alert-shaped events) reaches the
// exporter, that a SIEM outage never blocks the emit() call path, and that
// shutdown drains in-flight work without hanging.

const { emit } = require('../../../../services/logger');
const auditEventDispatcher = require('../../auditEventDispatcher');
const { createLogShipper } = require('../index');

describe('integration — full audit stream export', () => {
  afterEach(() => {
    auditEventDispatcher.detach();
  });

  it('exports every audit event category, not just alert-shaped events', async () => {
    const sendSyslog = jest.fn().mockResolvedValue({ ok: true });
    const config = {
      elk: { enabled: false, valid: false },
      datadog: { enabled: false, valid: false },
      splunk: { enabled: false, valid: false },
      siem: { enabled: true, valid: true, mode: 'syslog', syslogHost: 'siem.internal', syslogPort: 514, syslogProto: 'udp' },
      maxRetries: 0, batchSize: 50, maxQueueDepth: 10_000,
      service: 'qodiqa', environment: 'test',
    };
    const shipper = createLogShipper(config, { siemSendSyslog: sendSyslog });
    auditEventDispatcher.attach(shipper);

    const categories = [
      ['INFO',  'REQUEST_ACCEPTED'],
      ['WARN',  'REQUEST_DENIED'],
      ['INFO',  'CONSENT_VERIFIED'],
      ['INFO',  'POLICY_EVALUATED'],
      ['INFO',  'SEMANTIC_ANALYSIS_COMPLETE'],
      ['WARN',  'REPLAY_DETECTED'],
      ['INFO',  'IDENTITY_VERIFIED'],
      ['INFO',  'EXECUTION_DECISION'],
      ['INFO',  'PROVIDER_EXECUTION'],
      ['ERROR', 'PROVIDER_FAILURE'],
      ['INFO',  'AUDIT_EXECUTION_RECORDED'],
      ['INFO',  'TRANSPARENCY_ENTRY_REGISTERED'],
      ['INFO',  'CRYPTO_VERIFICATION_OK'],
      ['INFO',  'ADMIN_ACTION'],
      ['CRITICAL', 'EXECUTION_INVARIANT_VIOLATED'],
      ['INFO',  'GATEWAY_START'],
    ];

    for (const [level, event] of categories) {
      emit(level, event, { requestId: `req-${event}` });
    }

    await new Promise(r => setImmediate(r));
    await shipper.shutdown(2000);

    const exportedEvents = sendSyslog.mock.calls.map(([line]) => line);
    for (const [, event] of categories) {
      expect(exportedEvents.some(line => line.includes(event))).toBe(true);
    }
  });

  it('a SIEM outage never throws back into the emit() call path', () => {
    const sendSyslog = jest.fn().mockRejectedValue(new Error('SIEM unreachable'));
    const config = {
      elk: { enabled: false, valid: false },
      datadog: { enabled: false, valid: false },
      splunk: { enabled: false, valid: false },
      siem: { enabled: true, valid: true, mode: 'syslog', syslogHost: 'down.internal', syslogPort: 514, syslogProto: 'udp' },
      maxRetries: 0, batchSize: 50, maxQueueDepth: 10_000,
      service: 'qodiqa', environment: 'test',
    };
    const shipper = createLogShipper(config, { siemSendSyslog: sendSyslog });
    auditEventDispatcher.attach(shipper);

    expect(() => emit('INFO', 'DURING_OUTAGE', {})).not.toThrow();
    expect(() => emit('INFO', 'STILL_SERVING_REQUESTS', {})).not.toThrow();
  });

  it('does not export duplicate events under normal (non-retry) operation', async () => {
    const sendSyslog = jest.fn().mockResolvedValue({ ok: true });
    const config = {
      elk: { enabled: false, valid: false },
      datadog: { enabled: false, valid: false },
      splunk: { enabled: false, valid: false },
      siem: { enabled: true, valid: true, mode: 'syslog', syslogHost: 'siem.internal', syslogPort: 514, syslogProto: 'udp' },
      maxRetries: 3, batchSize: 50, maxQueueDepth: 10_000,
      service: 'qodiqa', environment: 'test',
    };
    const shipper = createLogShipper(config, { siemSendSyslog: sendSyslog });
    auditEventDispatcher.attach(shipper);

    emit('INFO', 'SINGLE_EVENT', { requestId: 'once' });
    await new Promise(r => setImmediate(r));
    await shipper.shutdown(2000);

    expect(sendSyslog).toHaveBeenCalledTimes(1);
  });

  it('shutdown drains in-flight exports rather than dropping them silently', async () => {
    let resolveSend;
    const sendSyslog = jest.fn(() => new Promise(r => { resolveSend = r; })).mockName('sendSyslog');
    const config = {
      elk: { enabled: false, valid: false },
      datadog: { enabled: false, valid: false },
      splunk: { enabled: false, valid: false },
      siem: { enabled: true, valid: true, mode: 'syslog', syslogHost: 'siem.internal', syslogPort: 514, syslogProto: 'udp' },
      maxRetries: 0, batchSize: 50, maxQueueDepth: 10_000,
      service: 'qodiqa', environment: 'test',
    };
    const shipper = createLogShipper(config, {
      siemSendSyslog: (...args) => {
        const p = new Promise(r => { resolveSend = () => r({ ok: true }); });
        setImmediate(() => resolveSend());
        return p;
      },
    });
    auditEventDispatcher.attach(shipper);

    emit('INFO', 'DRAIN_ME', {});
    await shipper.shutdown(2000);

    expect(shipper.getMetrics().siem.logs_exported_total).toBe(1);
  });

  // #6: real emit() -> ... -> ELK destination, with schema='ecs',
  // proves the full pipeline (not just the mapper in isolation) produces an
  // ECS-shaped payload validated against SIEM_EXPORT_SCHEMA.md's documented shape.
  it('emit() -> logShipping -> ELK destination produces an ECS-mapped payload when schema="ecs"', async () => {
    let capturedBody;
    const elkHttpsPost = jest.fn().mockImplementation((_url, _headers, body) => {
      capturedBody = body;
      return Promise.resolve({ status: 200, body: '' });
    });
    const config = {
      elk: { enabled: true, valid: true, url: 'https://logstash.internal', schema: 'ecs' },
      datadog: { enabled: false, valid: false },
      splunk: { enabled: false, valid: false },
      siem: { enabled: false, valid: false },
      maxRetries: 0, batchSize: 50, maxQueueDepth: 10_000,
      service: 'qodiqa', environment: 'test',
    };
    const shipper = createLogShipper(config, { elkHttpsPost });
    auditEventDispatcher.attach(shipper);

    emit('CRITICAL', 'AUDIT_CHAIN_CORRUPTED', { requestId: 'req-ecs-1', tenantId: 'tenant-ecs' });
    await new Promise(r => setImmediate(r));
    await shipper.shutdown(2000);

    expect(elkHttpsPost).toHaveBeenCalledTimes(1);
    const shipped = JSON.parse(capturedBody.split('\n')[0]);
    expect(shipped).toMatchObject({
      ecs: { version: '8.11' },
      event: { action: 'audit_chain_corrupted', severity: 10, outcome: 'failure' },
      qodiqa: expect.objectContaining({ event_type: 'AUDIT_CHAIN_CORRUPTED', tenant: { id: 'tenant-ecs', slug: null } }),
    });
    expect(shipped).toHaveProperty('@timestamp');
  });
});
