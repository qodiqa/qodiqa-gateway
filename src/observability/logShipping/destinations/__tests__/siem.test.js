'use strict';

const { createSiemDestination, _formatEventCEF } = require('../siem');

const BASE_CONFIG = {
  service: 'qodiqa',
  siem: {
    enabled: true,
    valid:   true,
    mode:    'http',
    url:     'https://siem.example.com/hec',
    token:   'test-token',
  },
};

describe('_formatEventCEF', () => {
  it('formats a normalized event as CEF:0', () => {
    const cef = _formatEventCEF({
      timestamp:  '2026-01-01T00:00:00.000Z',
      severity:   'ERROR',
      eventType:  'RBAC_DENY',
      requestId:  'req-1',
      traceId:    'trace-1',
      tenantId:   'tenant-1',
      message:    'denied',
    });
    expect(cef).toMatch(/^CEF:0\|QODIQA\|QODIQA Platform\|1\.0\.0\|RBAC_DENY\|RBAC_DENY\|8\|/);
    expect(cef).toContain('requestId=req-1');
    expect(cef).toContain('tenantId=tenant-1');
    expect(cef).toContain('msg=denied');
  });

  it('maps unknown severities to a default CEF severity', () => {
    const cef = _formatEventCEF({ timestamp: Date.now(), eventType: 'X' });
    expect(cef).toMatch(/\|3\|/);
  });

  it('maps CRITICAL/FATAL to CEF severity 10', () => {
    expect(_formatEventCEF({ timestamp: Date.now(), severity: 'CRITICAL', eventType: 'X' })).toMatch(/\|10\|/);
    expect(_formatEventCEF({ timestamp: Date.now(), severity: 'FATAL',    eventType: 'X' })).toMatch(/\|10\|/);
  });
});

describe('createSiemDestination — http mode', () => {
  it('POSTs a CEF-embedded JSON batch and resolves on 2xx', async () => {
    const httpsPost = jest.fn().mockResolvedValue({ status: 200, body: '' });
    const dest = createSiemDestination(BASE_CONFIG, { httpsPost });

    await dest.send([{ timestamp: Date.now(), eventType: 'GATEWAY_ALLOW', severity: 'INFO' }]);

    expect(httpsPost).toHaveBeenCalledTimes(1);
    const [url, headers, body] = httpsPost.mock.calls[0];
    expect(url).toBe('https://siem.example.com/hec');
    expect(headers.Authorization).toBe('Splunk test-token');
    expect(body).toContain('"cef":"CEF:0');
  });

  it('marks network errors as retryable', async () => {
    const httpsPost = jest.fn().mockRejectedValue(new Error('ECONNREFUSED'));
    const dest = createSiemDestination(BASE_CONFIG, { httpsPost });

    await expect(dest.send([{ timestamp: Date.now(), eventType: 'X' }]))
      .rejects.toMatchObject({ retryable: true });
  });

  it('marks 5xx as retryable and 4xx (non-429) as non-retryable', async () => {
    const dest500 = createSiemDestination(BASE_CONFIG, { httpsPost: jest.fn().mockResolvedValue({ status: 500 }) });
    await expect(dest500.send([{ timestamp: Date.now(), eventType: 'X' }]))
      .rejects.toMatchObject({ retryable: true });

    const dest401 = createSiemDestination(BASE_CONFIG, { httpsPost: jest.fn().mockResolvedValue({ status: 401 }) });
    await expect(dest401.send([{ timestamp: Date.now(), eventType: 'X' }]))
      .rejects.toMatchObject({ retryable: false });
  });

  it('omits Authorization header when no token configured', async () => {
    const httpsPost = jest.fn().mockResolvedValue({ status: 200 });
    const config = { ...BASE_CONFIG, siem: { ...BASE_CONFIG.siem, token: '' } };
    const dest = createSiemDestination(config, { httpsPost });

    await dest.send([{ timestamp: Date.now(), eventType: 'X' }]);
    expect(httpsPost.mock.calls[0][1].Authorization).toBeUndefined();
  });
});

describe('createSiemDestination — syslog mode', () => {
  const SYSLOG_CONFIG = {
    service: 'qodiqa',
    siem: {
      enabled: true, valid: true, mode: 'syslog',
      syslogHost: 'siem-collector.internal', syslogPort: 514, syslogProto: 'udp',
    },
  };

  it('sends one syslog line per event', async () => {
    const sendSyslog = jest.fn().mockResolvedValue({ ok: true });
    const dest = createSiemDestination(SYSLOG_CONFIG, { sendSyslog });

    await dest.send([
      { timestamp: Date.now(), eventType: 'A' },
      { timestamp: Date.now(), eventType: 'B' },
    ]);

    expect(sendSyslog).toHaveBeenCalledTimes(2);
    expect(sendSyslog.mock.calls[0][0]).toContain('CEF:0');
    expect(sendSyslog.mock.calls[0][1]).toBe('siem-collector.internal');
    expect(sendSyslog.mock.calls[0][2]).toBe(514);
    expect(sendSyslog.mock.calls[0][3]).toBe('udp');
  });

  it('throws retryable error when a syslog send fails', async () => {
    const sendSyslog = jest.fn().mockResolvedValue({ ok: false, message: 'unreachable' });
    const dest = createSiemDestination(SYSLOG_CONFIG, { sendSyslog });

    await expect(dest.send([{ timestamp: Date.now(), eventType: 'A' }]))
      .rejects.toMatchObject({ retryable: true, message: 'unreachable' });
  });
});
